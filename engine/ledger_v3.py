"""ledger_v3.py: 1차 장부로 설치 전 로그의 BOLA 사용자를 찾아 confirmed.json(영구 차단 명단)에 넣기

솔루션을 처음 설치할 때 한 번 쓴다 (설치 전 로그는 판단 서버가 본 적이 없어서 여기서 찾음).
설치 뒤의 공격자는 판단 서버(judge.py)가 실시간으로 찾아 confirmed.json에 넣는다.

  ① python ledger_v2.py                 로그 → ledger_days/ + ledger.json (1차 장부)
  ② python ledger_v3.py                 ledger.json으로 BOLA 사용자·요청 ID 찾기 → confirmed.json에 합침  ← 이 파일
  ③ python ledger_v2.py                 confirmed.json의 사용자·요청을 빼고 다시 학습 → 깨끗한 ledger.json
  ④ docker compose up -d                판단 서버가 켜지면서 confirmed.json 명단을 Redis에 영구 차단

  ledger_days/*.json ──┐
                       ├─▶ 의심 사용자 찾기 (사용자별 30일치) ──▶ confirmed.json users
  ledger.json (주인) ──┤
                       └─▶ 원본 로그에서 그 사용자의 공격 요청 ID ──▶ confirmed.json requests

실행 (engine 폴더가 아니어도 됨, 경로는 이 파일 위치 기준)
  python ledger_v3.py                      찾아서 confirmed.json에 합침 (판단 서버가 켜져 있으면 거부)
  python ledger_v3.py --dry-run            찾기만 하고 결과 출력 (아무 파일도 안 바꿈)
  python ledger_v3.py --log 다른로그.json   원본 로그 지정 (기본: data\\access_fake.json, ledger_v2.py와 같음)
  python ledger_v3.py --truth ..\\data\\attacks_truth.csv   정답지와 비교 (가짜 로그 시험용)
  python ledger_v3.py --min-victims 3      의심 기준 (서로 다른 피해자 수)

의심 사용자 판정 (사용자별로 30일치를 모아서)
  - URL 번호가 곧 사용자 번호인 API(/members/{id}, /profiles/{id})에서 남의 번호 → 확실한 남의 것 (장부를 보지 않음)
  - 그 밖의 API에서 ledger.json의 주인이 요청자가 아님 → 남의 것 (주인이 null인 객체는 셀 수 없음)
  - 서로 다른 피해자(주인)가 --min-victims명 이상이면 의심 사용자
  - 403/404만 낸 사용자(시도만 함)는 ledger_days에 없어서 찾을 수 없음 (상태 200 요청만 집계됨)

confirmed.json에 합치는 것 (기존 내용은 지우지 않음)
  users:    {"43": <처음 남의 것을 본 날 00:00 KST, ms>}  → 판단 서버가 영구 차단, ledger_v2.py는 이 시각 이후 요청을 뺌
  requests: 의심 사용자의 요청 중 ① 상태 200이고 남의 것 = BOLA ② 객체 URL에 403/404 = ATTEMPT → ledger_v2.py가 뺌
  - 이미 확정된 사용자는 시각을 더 이른 쪽으로만 바꿈
  - 관리자가 해제한 사용자(released)는 다시 넣지 않음 (오탐으로 판단한 사람)
  ⚠️ 판단 서버가 켜져 있으면 쓰지 않는다. 켜진 판단 서버는 메모리 명단으로 confirmed.json을 덮어써서 넣은 내용이 사라짐
     (판단 서버 소비자가 Redis를 최근 15초 안에 읽었으면 켜진 것으로 봄)
  ⚠️ 가짜 로그로 시험하면 로그 속 공격자 번호의 실제 계정이 영구 차단된다 (해제는 judge/unblock.py)
"""
import argparse
import csv
import glob
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
from common import parse_line  # noqa: E402
from ledger_v2 import object_key  # noqa: E402  (1차 학습과 같은 객체 키)

KST = timezone(timedelta(hours=9))
LEDGER_PATH = os.path.join(BASE_DIR, "ledger.json")
CONFIRMED_PATH = os.path.join(BASE_DIR, "confirmed.json")          # 판단 서버와 ledger_v2.py가 쓰는 파일
DEFAULT_LOG = os.path.join(BASE_DIR, "data", "access_fake.json")   # ledger_v2.py의 LOG_PATH와 같은 파일
DAYS_CANDIDATES = [os.path.join(BASE_DIR, "ledger_days"),                    # ledger_v2.py 기본 위치
                   os.path.join(BASE_DIR, "..", "data", "ledger_days")]       # D:\python-rule\data\ledger_days
JUDGE_DIR = os.path.join(BASE_DIR, "..", "judge")
JUDGE_CONFIG = os.path.join(JUDGE_DIR, "config.json")
DEFAULT_PATH_OWNERS = ["/members/{id}", "/profiles/{id}"]
MIN_VICTIMS = 3
JUDGE_ALIVE_MS = 15000              # 판단 서버는 5초마다 Redis를 읽으므로, 이보다 최근이면 켜진 것


def load_judge_config():
    """판단 서버 config.json (path_owners, redis). 없으면 {}"""
    try:
        with open(JUDGE_CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def path_owner_prefixes(cfg):
    """URL 번호 = 사용자 번호인 경로 (판단 서버 config.json의 path_owners와 같게). 예: [["members", "{id}"], ...]"""
    owners = cfg.get("path_owners") or DEFAULT_PATH_OWNERS
    return [[s for s in p.split("/") if s] for p in owners]


def path_owner(api, oid, prefixes):
    """api "GET /members/{id}/addresses", oid "4/55" → "4" (URL 번호가 주인인 API면), 아니면 None"""
    segs = [s for s in api.split(" ", 1)[-1].split("/") if s]
    for p in prefixes:
        if segs[:len(p)] == p:
            return oid.split("/")[0]
    return None


def find_days_dir(arg):
    if arg:
        return os.path.abspath(arg)
    for d in DAYS_CANDIDATES:
        if os.path.isdir(d):
            return os.path.abspath(d)
    sys.exit("ledger_days 폴더를 찾지 못했습니다. 먼저 python ledger_v2.py를 실행하거나 --days-dir로 지정하세요")


def load_days(days_dir):
    """[(날짜, {"objects": ...}), ...] 날짜순"""
    days = []
    for path in sorted(glob.glob(os.path.join(days_dir, "????-??-??.json"))):
        with open(path, encoding="utf-8") as f:
            days.append((os.path.basename(path)[:10], json.load(f)))
    return days


def load_ledger(path):
    if not os.path.exists(path):
        sys.exit(f"{path}가 없습니다. 먼저 python ledger_v2.py로 1차 장부를 만드세요")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def find_suspects(ledger, days, prefixes, min_victims):
    """사용자별로 남의 것을 본 횟수·피해자를 모아 의심 사용자를 고름"""
    stats = defaultdict(lambda: {"own": 0, "foreign": 0, "path_foreign": 0, "victims": set(), "first_day": None,
                                 "apis": Counter()})
    for day, data in days:
        for api, objs in data["objects"].items():
            for oid, users in objs.items():
                owner_by_path = path_owner(api, oid, prefixes)
                owner = owner_by_path if owner_by_path is not None else ledger.get(api, {}).get(oid)
                for user, n in users.items():
                    s = stats[user]
                    if owner is None:                    # 장부 주인이 null(공유) 또는 장부에 없음 → 판단 불가
                        continue
                    if owner == user:
                        s["own"] += n
                        continue
                    s["path_foreign" if owner_by_path is not None else "foreign"] += n
                    s["victims"].add(owner)
                    s["apis"][api] += n
                    if s["first_day"] is None:
                        s["first_day"] = day
    suspects = {u: s for u, s in stats.items() if len(s["victims"]) >= min_victims}
    return stats, suspects


def day_start_ms(day):
    """"2026-10-03" → 그날 00:00 KST (ms)"""
    return int(datetime.fromisoformat(day).replace(tzinfo=KST).timestamp() * 1000)


def collect_requests(log_path, suspects, ledger, prefixes, day_set, watch_ids=frozenset()):
    """원본 로그에서 의심 사용자의 공격 요청 ID를 모음 (학습 기간 날짜만).
    BOLA: 상태 200이고 남의 것 / ATTEMPT: 객체 URL에 403/404. {request_id: (종류, uri)} (로그 순서)
    watch_ids: 로그에 실제로 있는지 셀 요청 ID (정답지가 이 로그와 맞는지 확인용)"""
    found = {}
    lines = 0
    seen = set()
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            lines += 1
            e = parse_line(line)
            if e is None:
                continue
            if watch_ids and e.get("request_id") in watch_ids:
                seen.add(e["request_id"])
            if str(e.get("user_id")) not in suspects or e.get("role") != "user":
                continue
            if e.get("time", "")[:10] not in day_set or not e.get("request_id"):
                continue
            key = object_key(e)
            if key is None:                              # 목록 API 등 객체 ID가 없는 요청
                continue
            api, oid = key
            me, status = str(e["user_id"]), e.get("status")
            if status in (403, 404):
                found[e["request_id"]] = ("ATTEMPT", e["uri"])
            elif status == 200 and not e.get("blocked"):
                p = path_owner(api, oid, prefixes)
                owner = p if p is not None else ledger.get(api, {}).get(oid)
                if owner is not None and owner != me:
                    found[e["request_id"]] = ("BOLA", e["uri"])
    return found, lines, seen


# ---------------------------------------------------------------- confirmed.json
def load_confirmed(path):
    """{"requests": [...], "users": {사용자: ms}, "released": {사용자: ms}} (없으면 빈 것)"""
    data = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    return {"requests": list(data.get("requests") or []),
            "users": {str(u): int(ms) for u, ms in (data.get("users") or {}).items()},
            "released": {str(u): int(ms) for u, ms in (data.get("released") or {}).items()}}


def merge_confirmed(current, users, requests):
    """찾은 사용자·요청을 기존 명단에 합친 새 명단과 바뀐 내역. 기존 것은 지우지 않음
    users: {사용자: ms}, requests: [요청 ID]. 해제된 사용자는 넣지 않음"""
    out = {"requests": list(current["requests"]), "users": dict(current["users"]),
           "released": dict(current["released"])}
    added, earlier, skipped = [], [], []
    for u, ms in users.items():
        if u in out["released"]:
            skipped.append(u)
        elif u not in out["users"]:
            out["users"][u] = ms
            added.append(u)
        elif ms < out["users"][u]:
            out["users"][u] = ms
            earlier.append(u)
    known = set(out["requests"])
    new_requests = [r for r in requests if r not in known]
    out["requests"] += new_requests
    return out, {"added": added, "earlier": earlier, "skipped_released": skipped, "requests": len(new_requests)}


def save_confirmed(path, data):
    """판단 서버(store.py)와 같은 모양으로, 임시 파일에 쓴 뒤 바꿔치기"""
    body = {"requests": data["requests"], "users": data["users"]}
    if data["released"]:
        body["released"] = data["released"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(body, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def read_env(path, key):
    """.env에서 값 하나"""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                if k.strip() == key:
                    return v.strip()
    except OSError:
        pass
    return None


def judge_status(cfg):
    """판단 서버가 켜져 있나: "running" / "stopped" / "unknown: 이유"
    judges 그룹의 판단 서버 소비자가 최근 15초 안에 Redis를 읽었으면 켜진 것 (judge/unblock.py와 같은 방법)"""
    rc = cfg.get("redis")
    if not rc:
        return "unknown: judge/config.json에 redis 설정이 없음"
    try:
        import redis
    except ImportError:
        return "unknown: redis 패키지가 없음 (pip install redis)"
    password = (os.getenv("REDIS_PASSWORD") or read_env(os.path.join(BASE_DIR, ".env"), "REDIS_PASSWORD")
                or read_env(os.path.join(JUDGE_DIR, ".env"), "REDIS_PASSWORD") or None)
    try:
        r = redis.Redis(host=rc["host"], port=rc["port"], password=password, decode_responses=True,
                        socket_timeout=5)
        consumers = r.xinfo_consumers(rc["stream"], rc["group"])
    except redis.ResponseError:                           # 스트림이나 그룹이 없음 = 판단 서버가 한 번도 안 떴음
        return "stopped"
    except redis.RedisError as err:
        return f"unknown: Redis 접속 실패 ({err})"
    alive = any(c["name"] == rc["consumer"] and c["idle"] < JUDGE_ALIVE_MS for c in consumers)
    return "running" if alive else "stopped"


# ---------------------------------------------------------------- 정답지 비교 (가짜 로그 시험용)
def load_truth(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def compare_requests(truth_rows, found, seen):
    """정답지와 요청 단위로 비교. 이 로그에 실제로 있는 정답 요청만 (seen)"""
    truth = {r["request_id"]: r for r in truth_rows if r["request_id"] in seen}
    print(f"\n[정답 비교: 요청 단위] 정답지 {len(truth_rows)}건 중 이 로그에 있는 것 {len(truth)}건, "
          f"찾은 요청 {len(found)}건")
    if len(truth) < len(truth_rows) / 2:
        print("  [주의] 정답지 요청 대부분이 이 로그에 없습니다. 정답지가 다른 때 만든 가짜 로그의 것일 수 있습니다 "
              "(가짜 로그를 만들 때 함께 생긴 attacks_truth.csv를 쓰세요)")
    for label in ("BOLA", "ATTEMPT"):
        t = {rid for rid, r in truth.items() if r["label"] == label}
        hit = t & set(found)
        print(f"  {label:7} 정답 {len(t):5}건 중 찾음 {len(hit):5}건, 놓침 {len(t - hit):4}건")
        missed = Counter((truth[rid]["attacker_user_id"], truth[rid]["uri"].split("/")[1]) for rid in t - hit)
        if missed:
            print(f"          놓친 것 (공격자, 자원): {dict(missed.most_common(6))}")
    extra = set(found) - set(truth)
    print(f"  정답에 없는데 공격으로 잡은 요청: {len(extra)}건"
          + (f" 예: {[found[r][1] for r in list(extra)[:5]]}" if extra else ""))


def compare_truth(truth_rows, suspects):
    """정답지(attacks_truth.csv)의 공격자와 사용자 단위로 비교"""
    by_user = defaultdict(Counter)
    for row in truth_rows:
        by_user[row["attacker_user_id"]][row["label"]] += 1
    print("\n[정답 비교: 사용자 단위]")
    for u in sorted(by_user, key=int):
        labels = dict(by_user[u])
        found = "찾음" if u in suspects else ("놓침 (403/404만 있어 ledger_days로는 못 찾음)"
                                               if set(labels) == {"ATTEMPT"} else "놓침")
        print(f"  공격자 {u:>4} {labels} → {found}")
    extra = sorted(set(suspects) - set(by_user), key=int)
    print(f"  정답에 없는데 의심으로 잡은 사용자: {extra or '없음'}")


def main():
    for stream in (sys.stdout, sys.stderr):              # sys.exit 안내문(stderr)도 한글이 깨지지 않게
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="1차 장부로 BOLA 사용자를 찾아 confirmed.json(영구 차단 명단)에 넣기")
    p.add_argument("--dry-run", action="store_true", help="찾기만 하고 confirmed.json에 쓰지 않음 (판단 서버가 켜져 있어도 됨)")
    p.add_argument("--log", default=DEFAULT_LOG, help="원본 로그 (기본: data\\access_fake.json). 공격 요청 ID를 모음")
    p.add_argument("--ledger", default=LEDGER_PATH, help="1차 장부 (기본: ledger.json)")
    p.add_argument("--days-dir", help="ledger_days 폴더 (기본: engine/ledger_days, 없으면 ../data/ledger_days)")
    p.add_argument("--min-victims", type=int, default=MIN_VICTIMS, help="의심 사용자 기준: 서로 다른 피해자 수")
    p.add_argument("--truth", help="정답지 attacks_truth.csv와 비교 (가짜 로그 시험용)")
    args = p.parse_args()

    cfg = load_judge_config()
    days_dir = find_days_dir(args.days_dir)
    days = load_days(days_dir)
    if not days:
        sys.exit(f"{days_dir}에 날짜 파일이 없습니다. 먼저 python ledger_v2.py를 실행하세요")
    if not os.path.exists(args.log):
        sys.exit(f"원본 로그 {args.log}가 없습니다. --log로 지정하세요")
    day_set = {d for d, _ in days}
    prefixes = path_owner_prefixes(cfg)
    ledger = load_ledger(args.ledger)
    print(f"학습 데이터 {days_dir} ({days[0][0]} ~ {days[-1][0]}, {len(days)}일) | 1차 장부 {args.ledger}")

    # ① 의심 사용자 찾기
    stats, suspects = find_suspects(ledger, days, prefixes, args.min_victims)
    print(f"\n[의심 사용자] 피해자 {args.min_victims}명 이상: {len(suspects)}명 / 전체 {len(stats)}명")
    print(f"  {'사용자':>5} {'본인':>6} {'남의 것(장부)':>11} {'남의 번호(URL)':>12} {'피해자':>5}  처음 본 날   주로 본 API")
    for u, s in sorted(stats.items(), key=lambda x: -len(x[1]["victims"])):
        if not s["victims"]:
            continue
        mark = "★" if u in suspects else " "
        top = ", ".join(a for a, _ in s["apis"].most_common(2))
        print(f"{mark} {u:>5} {s['own']:6} {s['foreign']:11} {s['path_foreign']:12} {len(s['victims']):5}  "
              f"{s['first_day']}  {top}")
    clean = sum(1 for s in stats.values() if not s["victims"])
    print(f"  남의 것을 한 번도 안 본 사용자: {clean}명")

    # ② 원본 로그에서 의심 사용자의 공격 요청 ID 모으기
    truth_rows = load_truth(args.truth) if args.truth else None
    watch = frozenset(r["request_id"] for r in truth_rows) if truth_rows else frozenset()
    found, n, seen = collect_requests(args.log, set(suspects), ledger, prefixes, day_set, watch)
    kinds = Counter(k for k, _ in found.values())
    print(f"\n[공격 요청] 원본 로그 {n:,}줄에서 BOLA {kinds['BOLA']}건, ATTEMPT {kinds['ATTEMPT']}건")

    if truth_rows is not None:
        compare_truth(truth_rows, suspects)
        compare_requests(truth_rows, found, seen)

    # ③ confirmed.json에 합치기
    users = {u: day_start_ms(s["first_day"]) for u, s in sorted(suspects.items(), key=lambda x: int(x[0]))}
    current = load_confirmed(CONFIRMED_PATH)
    merged, change = merge_confirmed(current, users, list(found))
    print(f"\n[confirmed.json] {CONFIRMED_PATH}")
    print(f"  새로 영구 차단할 사용자 {len(change['added'])}명 {change['added']}")
    if change["earlier"]:
        print(f"  이미 있던 사용자 중 시작 시각을 앞당길 사용자 {change['earlier']}")
    if change["skipped_released"]:
        print(f"  관리자가 해제한 적이 있어 넣지 않을 사용자 {change['skipped_released']}")
    print(f"  새로 학습에서 뺄 요청 {change['requests']}건 (전체 {len(merged['requests'])}건)")

    if args.dry_run:
        print("\n미리 보기만 했습니다 (--dry-run). confirmed.json에 넣으려면 --dry-run 없이 실행하세요 "
              "(판단 서버가 꺼져 있어야 함, 넣은 사용자는 판단 서버가 켜질 때 영구 차단됨)")
        return
    if not (change["added"] or change["earlier"] or change["requests"]):
        print("\n바뀐 것이 없어 confirmed.json을 그대로 둡니다")
        return
    status = judge_status(cfg)
    if status == "running":
        sys.exit("\n판단 서버가 켜져 있어 confirmed.json에 쓰지 않았습니다. 먼저 멈추세요 "
                 "(WSL /mnt/d/python-rule: docker compose stop judge)\n"
                 "(켜진 판단 서버는 메모리 명단으로 confirmed.json을 덮어써서 넣은 내용이 사라집니다)")
    if status != "stopped":
        sys.exit(f"\n판단 서버가 꺼져 있는지 확인하지 못해 쓰지 않았습니다 ({status[9:]})")
    save_confirmed(CONFIRMED_PATH, merged)
    print(f"\n→ confirmed.json에 씀: 사용자 {len(merged['users'])}명, 요청 {len(merged['requests'])}건")
    print("다음: python ledger_v2.py 로 다시 학습 → 판단 서버 켜기 (docker compose up -d, 켜질 때 영구 차단)")


if __name__ == "__main__":
    main()
