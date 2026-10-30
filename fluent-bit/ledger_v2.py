import hashlib
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta

from common import api_key, load_logs

LOG_PATH = r"data\access_fake.json"
LEDGER_PATH = "ledger.json"
MIN_SHARE = 0.7
DAYS_DIR = "ledger_days"
CONFIRMED_PATH = "confirmed.json"
STATE_PATH = os.path.join(DAYS_DIR, "_state.json")
WINDOW_DAYS = 30
CAP_MIN, CAP_MAX = 2, 10

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

# def build_ledger(logs):
#     seen = defaultdict(lambda: defaultdict(set))
#     for e in logs:
#         if not is_learnable(e):
#             continue
#         key = object_key(e)
#         if key is None:
#             continue
#         api, oid = key
#         day = e.get("time", "")[:10]
#         seen[api][oid].add((str(e["user_id"]), day))

#     ledger = defaultdict(dict)
#     for api, objs in seen.items():
#         for oid, visits in objs.items():
#             days_per_user = Counter(user for user, day in visits)
#             ledger[api][oid] = decide_owner(days_per_user)
#     return ledger

def decide_owner(days_per_user):
    if len(days_per_user) == 1:
        return next(iter(days_per_user))
    user, days = days_per_user.most_common(1)[0]
    total = sum(days_per_user.values())
    if days / total >= MIN_SHARE:
        return user
    return None

def add_from_list(ledger, e):
    if not is_learnable(e) or object_key(e) is not None:
        return 0
    detail_api = api_key(e) + "/{id}"
    if detail_api not in ledger:
        return 0
    added = 0
    for oid in (e.get("resp_ids") or {}).get("[].id", []):
        oid = str(oid)
        if oid not in ledger[detail_api]:
            ledger[detail_api][oid] = str(e["user_id"])
            added += 1
    return added

def save_ledger(ledger, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ledger, f, ensure_ascii=False)


def load_ledger(path):
    with open(path, encoding="utf-8") as f:
        return defaultdict(dict, json.load(f))

def day_of(e):
    return e.get("time", "")[:10]

def viewed_objects(e):
    key = object_key(e)
    if key is not None:
        return [key]
    detail_api = api_key(e) + "/{id}"
    return [(detail_api, str(oid)) for oid in (e.get("resp_ids") or {}).get("[].id", [])]

def ts_of(e):
    # 요청 시각(ms). started_at이 없으면 time 문자열("2026-10-28T09:07:47+09:00")로
    if e.get("started_at") is not None:
        return int(float(e["started_at"]))
    try:
        return int(datetime.fromisoformat(e["time"]).timestamp() * 1000)
    except (KeyError, TypeError, ValueError):
        return None

def is_excluded(e, confirmed):
    # 확정된 공격 요청이거나, 확정된 사용자의 그 시각 이후 요청이면 학습에서 뺌
    if e.get("request_id") in confirmed["requests"]:
        return True
    since = confirmed["users"].get(str(e.get("user_id")))
    if since is None:
        return False
    ts = ts_of(e)
    return ts is None or ts >= since

def build_day(logs, confirmed):
    day = defaultdict(lambda: defaultdict(Counter))
    skipped = 0
    for e in logs:
        if not is_learnable(e):
            continue
        if is_excluded(e, confirmed):
            skipped += 1
            continue
        for api, oid in viewed_objects(e):
            day[api][oid][str(e["user_id"])] += 1
    return day, skipped

def day_path(d):
    return os.path.join(DAYS_DIR, f"{d}.json")

def save_day(d, day, excluded):
    os.makedirs(DAYS_DIR, exist_ok=True)
    with open(day_path(d), "w", encoding="utf-8") as f:
        json.dump({"excluded": excluded, "objects": day}, f, ensure_ascii=False)

def load_day(d):
    with open(day_path(d), encoding="utf-8") as f:
        return json.load(f)

def load_confirmed():
    # 판단 서버가 만든 {"requests": [request_id, ...], "users": {user_id: 이 시각(ms) 이후 제외}}
    if not os.path.exists(CONFIRMED_PATH):
        return {"requests": set(), "users": {}}
    with open(CONFIRMED_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {
        "requests": set(data.get("requests") or []),
        "users": {str(u): int(ms) for u, ms in (data.get("users") or {}).items()},
    }

def confirmed_sig(confirmed):
    # confirmed.json 내용의 지문. 날짜 파일에 저장해 두고, 바뀌면 그 날짜를 다시 만듦
    # requests에 날짜가 없어서 어느 날에 영향을 주는지 모름 → 바뀌면 30일 전부 다시 만듦
    text = json.dumps([sorted(confirmed["requests"]), sorted(confirmed["users"].items())])
    return hashlib.sha1(text.encode()).hexdigest()

def days_to_build(today, sig):
    todo = []
    for i in range(1, WINDOW_DAYS + 1):
        d = (today - timedelta(days=i)).isoformat()
        if not os.path.exists(day_path(d)):
            todo.append(d)
        elif load_day(d).get("excluded") != sig:
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
        by_day = defaultdict(list)
        for e in load_logs(LOG_PATH):
            d = day_of(e)
            if d in todo:
                by_day[d].append(e)
        for d in todo:
            day, skipped = build_day(by_day[d], confirmed)
            save_day(d, day, sig)
            print(f"{d} 날짜 파일 만듦 (로그 {len(by_day[d])}줄, 제외 {skipped}건)")

    window = [(today - timedelta(days=i)).isoformat() for i in range(1, WINDOW_DAYS + 1)]
    days = [load_day(d) for d in window if os.path.exists(day_path(d))]

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
    # python ledger.py              → 오늘 기준 (어제까지 30일)
    # python ledger.py 2026-10-22   → 그 날이 '오늘'인 것처럼 (가짜 로그 실험용)
    today = date.fromisoformat(sys.argv[1]) if len(sys.argv) > 1 else date.today()
    run(today)
