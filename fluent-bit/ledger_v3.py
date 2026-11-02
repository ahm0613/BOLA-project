"""ledger_v3.py: 2단계 장부 학습

ledger_v2.py가 만든 학습 데이터(ledger_days)로 1차 장부를 계산하고, 그 장부로 ledger_days를 다시 훑어
BOLA로 보이는 사용자를 찾은 뒤, 그 사용자를 빼고 다시 학습해 더 깨끗한 장부(2차)를 만든다.

  ledger_days/*.json ─▶ 1차 장부 (ledger_v2.py와 같은 merge, 메모리에서 계산)
          │                  │
          │                  ▼
          ├──────────▶ ① 의심 사용자 찾기 ──▶ confirmed1.json users
          │                  │
  (--log) 원본 로그 ─────▶ ①-1 의심 사용자의 공격 요청 ID 모으기 ──▶ confirmed1.json requests
          │                  │
          └──────────▶ ② 의심 사용자를 빼고 다시 학습 ──▶ ledger_v3.json (--apply면 ledger.json)

  1차 장부를 ledger.json에서 읽지 않는 이유: --apply 뒤에는 ledger.json이 이미 2차 장부라서
  (--ledger 파일을 주면 그 파일을 1차 장부로 씀)

실행 (fluent-bit 폴더 기준이 아니어도 됨, 경로는 이 파일 위치 기준)
  python ledger_v3.py                       찾기 + confirmed1.json + 2차 장부를 ledger_v3.json에 (미리보기)
  python ledger_v3.py --log data\\access_fake.json   원본 로그에서 공격 요청 ID까지 모아 requests를 채움
  python ledger_v3.py --apply               2차 장부를 ledger.json에 씀 (기존 장부는 ledger_v2_backup.json)
  python ledger_v3.py --truth ..\\data\\attacks_truth.csv   정답지와 비교 (--log가 있으면 요청 단위로도)
  python ledger_v3.py --days-dir ..\\data\\ledger_days --min-victims 3

의심 사용자 판정 (사용자별로 30일치를 모아서)
  - URL 번호가 곧 사용자 번호인 API(/members/{id}, /profiles/{id})에서 남의 번호 → 확실한 남의 것 (장부를 보지 않음)
  - 그 밖의 API에서 1차 장부상 주인이 요청자가 아님 → 남의 것 (장부 주인이 null인 객체는 셀 수 없음)
  - 서로 다른 피해자(주인)가 --min-victims명 이상이면 의심 사용자

confirmed1.json
  {"requests": [요청 ID...], "users": {"43": <처음 남의 것을 본 날 00:00 KST, ms>, ...}}
  - ledger_days는 하루치 집계라 요청 ID가 없음 → --log로 원본 로그를 줘야 requests가 채워짐 (없으면 [])
  - requests: 의심 사용자의 요청 중 ① 상태 200이고 남의 것(URL 번호 또는 1차 장부 주인 기준) = BOLA
                                    ② 객체 URL에 403/404 = ATTEMPT (시도)
  - 403/404만 낸 사용자(시도만 함)는 ledger_days에 없어서 의심 사용자로 찾을 수 없음 (상태 200 요청만 집계됨)
  - ⚠️ 판단 서버(judge)의 confirmed.json과 별개 파일이다. confirmed.json에 옮기면 판단 서버가
    그 번호의 실제 계정을 영구 차단하므로 옮기지 말 것 (학습용 가짜 로그 속 공격자일 뿐임)

2차 학습: 의심 사용자의 기록을 모든 날짜에서 빼고 ledger_v2.py와 같은 방법(merge, 상한 cap)으로 다시 합친다.
"""
import argparse
import csv
import glob
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
from common import parse_line  # noqa: E402
from ledger_v2 import merge, object_key  # noqa: E402  (1차 학습과 같은 방법으로 합치기, 같은 객체 키)

KST = timezone(timedelta(hours=9))
LEDGER_PATH = os.path.join(BASE_DIR, "ledger.json")
OUT_LEDGER = os.path.join(BASE_DIR, "ledger_v3.json")
BACKUP_LEDGER = os.path.join(BASE_DIR, "ledger_v2_backup.json")
OUT_CONFIRMED = os.path.join(BASE_DIR, "confirmed1.json")
DAYS_CANDIDATES = [os.path.join(BASE_DIR, "ledger_days"),                    # ledger_v2.py 기본 위치
                   os.path.join(BASE_DIR, "..", "data", "ledger_days")]       # D:\python-rule\data\ledger_days
JUDGE_CONFIG = os.path.join(BASE_DIR, "..", "judge", "config.json")
DEFAULT_PATH_OWNERS = ["/members/{id}", "/profiles/{id}"]
MIN_VICTIMS = 3


def path_owner_prefixes():
    """URL 번호 = 사용자 번호인 경로 (판단 서버 config.json의 path_owners와 같게). 예: ["members", "profiles"]"""
    owners = DEFAULT_PATH_OWNERS
    try:
        with open(JUDGE_CONFIG, encoding="utf-8") as f:
            owners = json.load(f).get("path_owners") or owners
    except (OSError, ValueError):
        pass
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
    sys.exit("ledger_days 폴더를 찾지 못했습니다. --days-dir로 지정하세요")


def load_days(days_dir):
    """[(날짜, {"objects": ...}), ...] 날짜순, 상한(cap)"""
    days = []
    for path in sorted(glob.glob(os.path.join(days_dir, "????-??-??.json"))):
        with open(path, encoding="utf-8") as f:
            days.append((os.path.basename(path)[:10], json.load(f)))
    cap = None
    state = os.path.join(days_dir, "_state.json")
    if os.path.exists(state):
        with open(state, encoding="utf-8") as f:
            cap = json.load(f).get("cap")
    return days, cap or 10


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


def without_users(days, users):
    """의심 사용자의 기록을 모든 날짜에서 뺀 ledger_days (원본은 건드리지 않음)"""
    out = []
    for _, data in days:
        objects = {}
        for api, objs in data["objects"].items():
            kept = {oid: {u: n for u, n in us.items() if u not in users} for oid, us in objs.items()}
            kept = {oid: us for oid, us in kept.items() if us}
            if kept:
                objects[api] = kept
        out.append({"objects": objects})
    return out


def summary(ledger):
    total = sum(len(o) for o in ledger.values())
    shared = sum(1 for o in ledger.values() for v in o.values() if v is None)
    return total, shared


def path_mismatch(ledger, prefixes):
    """URL 번호가 주인인 API인데 장부 주인이 URL 번호와 다른 객체 (장부 오염). [(api, oid, 장부 주인)]"""
    out = []
    for api, objs in ledger.items():
        for oid, owner in objs.items():
            p = path_owner(api, oid, prefixes)
            if p is not None and owner is not None and owner != p:
                out.append((api, oid, owner))
    return out


def collect_requests(log_path, suspects, ledger1, prefixes, day_set, watch_ids=frozenset()):
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
                owner = p if p is not None else ledger1.get(api, {}).get(oid)
                if owner is not None and owner != me:
                    found[e["request_id"]] = ("BOLA", e["uri"])
    return found, lines, seen


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
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="2단계 장부 학습: 의심 사용자를 찾아 빼고 다시 학습")
    p.add_argument("--ledger", help="1차 장부 파일 (기본: ledger_days로 직접 계산 = ledger_v2.py 결과와 같음)")
    p.add_argument("--days-dir", help="ledger_days 폴더 (기본: fluent-bit/ledger_days, 없으면 ../data/ledger_days)")
    p.add_argument("--min-victims", type=int, default=MIN_VICTIMS, help="의심 사용자 기준: 서로 다른 피해자 수")
    p.add_argument("--log", help="원본 로그 (예: data\\access_fake.json). 주면 공격 요청 ID를 모아 requests를 채움")
    p.add_argument("--apply", action="store_true", help="2차 장부를 ledger.json에 씀 (기존은 ledger_v2_backup.json)")
    p.add_argument("--truth", help="정답지 attacks_truth.csv (사용자 단위, --log가 있으면 요청 단위로도 비교)")
    args = p.parse_args()

    days_dir = find_days_dir(args.days_dir)
    days, cap = load_days(days_dir)
    if not days:
        sys.exit(f"{days_dir}에 날짜 파일이 없습니다")
    day_set = {d for d, _ in days}
    prefixes = path_owner_prefixes()
    base = merge([d for _, d in days], cap)              # 1차 장부: ledger_v2.py와 같은 방법으로 계산
    if args.ledger:
        with open(args.ledger, encoding="utf-8") as f:
            ledger1 = json.load(f)
        source = args.ledger
    else:
        ledger1, source = base, "ledger_days로 계산 (ledger_v2.py와 같음)"
    print(f"학습 데이터 {days_dir} ({days[0][0]} ~ {days[-1][0]}, {len(days)}일, 상한 {cap}) | 1차 장부: {source}")

    # ① 의심 사용자 찾기
    stats, suspects = find_suspects(ledger1, days, prefixes, args.min_victims)
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

    # ①-1 원본 로그에서 의심 사용자의 공격 요청 ID 모으기
    found, seen, truth_rows = {}, set(), None
    if args.truth:
        truth_rows = load_truth(args.truth)
    if args.log:
        watch = frozenset(r["request_id"] for r in truth_rows) if truth_rows else frozenset()
        found, n, seen = collect_requests(args.log, set(suspects), ledger1, prefixes, day_set, watch)
        kinds = Counter(k for k, _ in found.values())
        print(f"\n[공격 요청] 원본 로그 {n:,}줄에서 BOLA {kinds['BOLA']}건, ATTEMPT {kinds['ATTEMPT']}건")

    confirmed1 = {"requests": list(found),
                  "users": {u: day_start_ms(s["first_day"]) for u, s in sorted(suspects.items(), key=lambda x: int(x[0]))}}
    with open(OUT_CONFIRMED, "w", encoding="utf-8") as f:
        json.dump(confirmed1, f, ensure_ascii=False, indent=2)
    why = "" if args.log else " (requests 없음: --log로 원본 로그를 주면 채워짐)"
    print(f"\n→ {OUT_CONFIRMED} (users {len(confirmed1['users'])}명, requests {len(found)}건){why}")

    # ② 의심 사용자를 빼고 다시 학습
    ledger2 = merge(without_users(days, set(suspects)), cap)
    differ = sum(1 for api in set(base) | set(ledger1)
                 for oid in set(base.get(api, {})) | set(ledger1.get(api, {}))
                 if base.get(api, {}).get(oid, "없음") != ledger1.get(api, {}).get(oid, "없음"))
    if args.ledger and differ:
        print(f"\n[주의] {args.ledger}는 이 ledger_days로 만든 장부와 객체 {differ}개가 다릅니다 "
              f"(다른 데이터나 다른 시점에 학습됨). 아래 비교는 ledger_days로 다시 계산한 1차 기준입니다")
    t1, s1 = summary(base)
    t2, s2 = summary(ledger2)
    m1, m2 = path_mismatch(base, prefixes), path_mismatch(ledger2, prefixes)
    changed = sum(1 for api, objs in ledger2.items() for oid, o in objs.items()
                  if oid in base.get(api, {}) and base[api][oid] != o)
    dropped = t1 - sum(1 for api, objs in ledger2.items() for oid in objs if oid in base.get(api, {}))
    print("\n[1차 → 2차 장부] (같은 ledger_days 기준)")
    print(f"  객체 {t1} → {t2} (의심 사용자만 보던 객체 {dropped}개 빠짐), 주인이 바뀐 객체 {changed}개")
    print(f"  주인 null(공유) {s1} → {s2}")
    print(f"  URL 번호와 장부 주인이 다른 객체(오염) {len(m1)} → {len(m2)}  {m1[:4] if m1 else ''}")
    for api in sorted(base):
        n1 = sum(1 for v in base[api].values() if v is None)
        n2 = sum(1 for v in ledger2.get(api, {}).values() if v is None)
        if n1 or n2:
            print(f"    {api:34} null {n1} → {n2}")

    if args.apply:
        current = None
        if os.path.exists(LEDGER_PATH):
            with open(LEDGER_PATH, encoding="utf-8") as f:
                current = json.load(f)
        if current == ledger2:
            print(f"\n→ {LEDGER_PATH}는 이미 이 2차 장부입니다. 그대로 둠 (백업 {BACKUP_LEDGER}도 그대로)")
        else:
            if current is not None:                      # 이미 2차 장부를 다시 백업해서 1차 백업을 덮어쓰지 않게
                shutil.copyfile(LEDGER_PATH, BACKUP_LEDGER)
            with open(LEDGER_PATH, "w", encoding="utf-8") as f:
                json.dump(ledger2, f, ensure_ascii=False)
            print(f"\n→ 2차 장부를 {LEDGER_PATH}에 씀 (기존 장부는 {BACKUP_LEDGER}). realtime.py가 다음 요청 때 읽음")
    else:
        with open(OUT_LEDGER, "w", encoding="utf-8") as f:
            json.dump(ledger2, f, ensure_ascii=False)
        print(f"\n→ 2차 장부 미리보기 {OUT_LEDGER} (실제 탐지에 쓰려면 --apply)")

    if truth_rows is not None:
        compare_truth(truth_rows, suspects)
        if args.log:
            compare_requests(truth_rows, found, seen)


if __name__ == "__main__":
    main()
