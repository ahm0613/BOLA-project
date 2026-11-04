import hashlib
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import date, timedelta

LOG_PATH = r"data\access_fake.json"
LEDGER_PATH = "ledger.json"
MIN_SHARE = 0.7
DAYS_DIR = "ledger_days"
CONFIRMED_PATH = "confirmed.json"
STATE_PATH = os.path.join(DAYS_DIR, "_state.json")
WINDOW_DAYS = 30
CAP_MIN, CAP_MAX = 2, 10

def parse_line(line):
    """한 줄 → 딕셔너리. 빈 줄·깨진 줄이면 None"""
    line = line.strip().strip("\x00")
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def api_key(e):
    """GET /orders/7  →  GET /orders/{id}  (realtime.py와 똑같아야 장부를 찾을 수 있음)"""
    path = e["uri"].split("?")[0]
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return f'{e["method"]} {path}'

def object_key(e):
    path = e["uri"].split("?")[0]
    ids = re.findall(r"/(\d+)(?=/|$)", path)
    if not ids:
        return None
    return api_key(e), "/".join(ids)

def is_learnable(e):
    return (
        e.get("status") == 200
        and e.get("role") == "user"
        and e.get("user_id") is not None
        and not e.get("blocked")
    )

def decide_owner(days_per_user):
    user, n = days_per_user.most_common(1)[0]
    return user if n / sum(days_per_user.values()) >= MIN_SHARE else None

def save_ledger(ledger, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False)

def day_of(e):
    return e.get("time", "")[:10]

def viewed_objects(e):
    key = object_key(e)
    if key is not None:
        return [key]
    detail_api = api_key(e) + "/{id}"
    return [(detail_api, str(oid)) for oid in (e.get("resp_ids") or {}).get("[].id", [])]

def build_days(todo, confirmed):
    """로그 파일을 한 줄씩 읽으면서 날짜별 '누가 어떤 객체를 몇 번 봤나'를 바로 셈 (로그를 메모리에 쌓지 않음)"""
    days = {d: defaultdict(lambda: defaultdict(Counter)) for d in todo}
    lines, skipped = Counter(), Counter()
    with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e is None or day_of(e) not in days:
                continue
            d = day_of(e)
            lines[d] += 1
            if not is_learnable(e):
                continue
            if is_excluded(e, confirmed):              # 확정된 요청·확정 사용자의 확정 이후 요청은 학습에서 뺌
                skipped[d] += 1
                continue
            for api, oid in viewed_objects(e):
                days[d][api][oid][str(e["user_id"])] += 1
    return days, lines, skipped

def day_path(d):
    return os.path.join(DAYS_DIR, f"{d}.json")

def save_day(d, day, sig):
    os.makedirs(DAYS_DIR, exist_ok=True)
    with open(day_path(d), "w", encoding="utf-8") as f:
        json.dump({"excluded": sig, "objects": day}, f, ensure_ascii=False)

def load_day(d):
    with open(day_path(d), encoding="utf-8") as f:
        return json.load(f)

def load_confirmed():
    """confirmed.json: {"requests": [요청ID...], "users": {사용자: 확정 시각 ms}, "released": {...}}
    released(관리자 해제 기록)는 판단 서버용이라 읽지 않음"""
    if not os.path.exists(CONFIRMED_PATH):
        return {"requests": set(), "users": {}}
    with open(CONFIRMED_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {"requests": set(data.get("requests") or []),
            "users": {str(u): int(ms) for u, ms in (data.get("users") or {}).items()}}

def confirmed_sig(confirmed):
    """confirmed 내용의 서명. 날짜 파일에 남겨 두고, 바뀌면 그 날짜를 다시 만듦"""
    text = json.dumps([sorted(confirmed["requests"]), sorted(confirmed["users"].items())])
    return hashlib.sha1(text.encode()).hexdigest()

def is_excluded(e, confirmed):
    """확정된 요청이거나, 확정 사용자의 확정 시각 이후 요청이면 학습에서 뺌"""
    if e.get("request_id") in confirmed["requests"]:
        return True
    since = confirmed["users"].get(str(e.get("user_id")))
    if since is None:
        return False
    ts = e.get("started_at")
    return ts is None or int(float(ts)) >= since

def days_to_build(today, sig):
    todo = []
    for i in range(1, WINDOW_DAYS + 1):
        d = (today - timedelta(days=i)).isoformat()
        if not os.path.exists(day_path(d)) or load_day(d).get("excluded") != sig:
            todo.append(d)
    return sorted(todo)

def percentile99(values):
    values = sorted(values)
    return values[max(0, int(len(values) * 0.99) - 1)]

def compute_cap(days, prev_cap):
    per_user = defaultdict(list)
    for day in days:
        for objs in day["objects"].values():
            for users in objs.values():
                for user, n in users.items():
                    per_user[user].append(n)
    p99s = [percentile99(v) for v in per_user.values() if len(v) >= 10]
    wanted = round(statistics.median(p99s)) if p99s else CAP_MIN
    wanted = max(CAP_MIN, min(CAP_MAX, wanted))
    if prev_cap is None:
        return wanted
    if abs(wanted - prev_cap) > 1:
        print(f"[알림] 상한이 {prev_cap} -> {wanted} 로 크게 바뀌려 함. 이번엔 1만 움직임")
    return prev_cap + max(-1, min(1, wanted - prev_cap))

def merge(days, cap):
    scores = defaultdict(lambda: defaultdict(Counter))
    for day in days:
        for api, objs in day["objects"].items():
            for oid, users in objs.items():
                for user, n in users.items():
                    scores[api][oid][user] += min(n, cap)
    return {api: {oid: decide_owner(c) for oid, c in objs.items()} for api, objs in scores.items()}

def load_state():
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"cap": None}

def run(today):
    confirmed = load_confirmed()
    sig = confirmed_sig(confirmed)
    todo = days_to_build(today, sig)
    if todo:
        built, lines, skipped = build_days(todo, confirmed)
        for d in todo:
            if not lines[d]:                    # 로그가 없는 날은 파일을 안 만듦 → 다음 학습 때 다시 시도
                print(f"{d} 로그 0줄 -> 날짜 파일 안 만듦")
                continue
            save_day(d, built[d], sig)
            print(f"{d} 날짜 파일 만듦 (로그 {lines[d]}줄, 제외 {skipped[d]}건)")

    window = [(today - timedelta(days=i)).isoformat() for i in range(1, WINDOW_DAYS + 1)]
    days = [load_day(d) for d in window if os.path.exists(day_path(d))]
    if not days:
        print("학습할 날짜 파일이 없음 -> 장부를 그대로 둠")
        return

    state = load_state()
    cap = compute_cap(days, state["cap"])
    state["cap"] = cap
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f)

    ledger = merge(days, cap)
    save_ledger(ledger, LEDGER_PATH)
    shared = sum(1 for objs in ledger.values() for o in objs.values() if o is None)
    total = sum(len(objs) for objs in ledger.values())
    print(f"합친 날짜 {len(days)}일, 상한 {cap}, 객체 {total}개 (공유 {shared}개) -> {LEDGER_PATH}")


if __name__ == "__main__":
    # python ledger_v2.py              → 오늘 기준 (어제까지 30일)
    # python ledger_v2.py 2026-10-28   → 그 날이 '오늘'인 것처럼 (가짜 로그 실험용)
    today = date.fromisoformat(sys.argv[1]) if len(sys.argv) > 1 else date.today()
    run(today)
