import json
import os
import re
import ssl
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import date, timedelta

import requests
from requests.adapters import HTTPAdapter

LEDGER_PATH = "ledger.json"
MIN_SHARE = 0.7
DAYS_DIR = "ledger_days"
CONFIRMED_PATH = "confirmed.json"
STATE_PATH = os.path.join(DAYS_DIR, "_state.json")
WINDOW_DAYS = 35
CAP_MIN, CAP_MAX = 2, 10

WAZUH_URL = "https://192.168.0.26:9200"
WAZUH_CA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "root-ca.pem")
WAZUH_CERT_NAME = "wazuh.indexer"     # 인덱서 인증서에 적힌 이름
INDEX_PREFIX = "bola-api-"
INDEX_UTC = True                      # 인덱스 이름이 UTC 날짜면 True, 한국 날짜면 False

WAZUH_USER = "read"
WAZUH_PASS = "2whvmfhwprxm"

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

def add_from_list(ledger, e):                    # detect_ledger.py가 씀 (추가한 개수를 돌려줌)
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


def load_ledger(path):                           # detect_ledger.py가 씀
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

def day_path(d):
    return os.path.join(DAYS_DIR, f"{d}.json")

def save_day(d, day, excluded):
    os.makedirs(DAYS_DIR, exist_ok=True)
    with open(day_path(d), "w", encoding="utf-8") as f:
        json.dump({"excluded": sorted(excluded), "objects": day}, f, ensure_ascii=False)

def load_day(d):
    with open(day_path(d), encoding="utf-8") as f:
        return json.load(f)

def load_confirmed():
    if not os.path.exists(CONFIRMED_PATH):
        return {}
    with open(CONFIRMED_PATH, encoding="utf-8") as f:
        data = json.load(f)
    by_day = defaultdict(set)
    for rid, d in data.items():
        by_day[d].add(rid)
    return by_day

def days_to_build(today, confirmed):
    todo = []
    for i in range(1, WINDOW_DAYS + 1):
        d = (today - timedelta(days=i)).isoformat()
        if not os.path.exists(day_path(d)):
            todo.append(d)
        elif set(load_day(d)["excluded"]) != confirmed.get(d, set()):
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

class WazuhAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=WAZUH_CA)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT     # Wazuh CA에 없는 key usage 검사는 끔
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = WAZUH_CERT_NAME     # IP로 접속하되 인증서 이름으로 확인
        super().init_poolmanager(*args, **kwargs)

def wazuh_session():
    s = requests.Session()
    s.mount(WAZUH_URL, WazuhAdapter())
    # s.auth = (os.environ["WAZUH_USER"], os.environ["WAZUH_PASS"])
    s.auth = (WAZUH_USER, WAZUH_PASS)
    s.verify = WAZUH_CA
    return s

def search_all(s, indexes, size=5000):
    r = s.post(f"{WAZUH_URL}/{','.join(indexes)}/_search",
               params={"scroll": "2m", "ignore_unavailable": "true"},
               json={"size": size, "query": {"match_all": {}}, "sort": ["_doc"],
                     "_source": ["full_log"]},          # Kong 원본 한 줄만 받음
               timeout=30)                              # 30초 넘게 응답이 없으면 에러
    r.raise_for_status()
    data = r.json()
    sid = data.get("_scroll_id")
    try:
        while data["hits"]["hits"]:
            for h in data["hits"]["hits"]:
                yield h["_source"]
            r = s.post(f"{WAZUH_URL}/_search/scroll", json={"scroll": "2m", "scroll_id": sid}, timeout=30)
            r.raise_for_status()
            data = r.json()
            sid = data["_scroll_id"]
    finally:
        if sid:
            s.delete(f"{WAZUH_URL}/_search/scroll", json={"scroll_id": sid}, timeout=30)

def to_kong_log(src):
    try:
        return json.loads(src.get("full_log", ""))    # Wazuh가 보관한 Kong 원본 한 줄
    except ValueError:
        return None

def day_indexes(d):
    d = date.fromisoformat(d)
    days = [d - timedelta(days=1), d] if INDEX_UTC else [d]
    return [f"{INDEX_PREFIX}{x:%Y.%m.%d}" for x in days]

def count_day(s, d, excluded):
    """Wazuh에서 받는 대로 바로 셈: 그 날짜의 '누가 어떤 객체를 몇 번 봤나' (로그를 메모리에 쌓지 않음)"""
    day = defaultdict(lambda: defaultdict(Counter))
    lines = 0
    for e in map(to_kong_log, search_all(s, day_indexes(d))):
        if not e or day_of(e) != d:
            continue
        lines += 1
        if not is_learnable(e) or e.get("request_id") in excluded:
            continue
        for api, oid in viewed_objects(e):
            day[api][oid][str(e["user_id"])] += 1
    return day, lines

def build_days(todo, confirmed):
    s = wazuh_session()
    for i, d in enumerate(todo, 1):
        print(f"[{i}/{len(todo)}] {d} 조회 중 ({', '.join(day_indexes(d))}) ...", flush=True)
        started = time.time()
        excluded = confirmed.get(d, set())
        day, lines = count_day(s, d, excluded)
        took = time.time() - started
        if not lines:
            print(f"    로그 0줄 -> 날짜 파일 안 만듦 ({took:.1f}초)", flush=True)
            continue
        save_day(d, day, excluded)
        print(f"    날짜 파일 만듦 (로그 {lines}줄, 제외 {len(excluded)}건, {took:.1f}초)", flush=True)

def run(today, only=None):
    confirmed = load_confirmed()
    todo = [only] if only else days_to_build(today, confirmed)
    if todo:
        build_days(todo, confirmed)

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
    # python ledger.py              → 오늘 기준 (어제까지 35일)
    # python ledger.py 2026-10-22   → 그 날이 '오늘'인 것처럼 (가짜 로그 실험용)
    # python ledger.py --day 2026-10-28 → 그 날짜 하나만 조회해서 날짜 파일을 (다시) 만들고 장부 합치기
    if len(sys.argv) > 2 and sys.argv[1] == "--day":
        run(date.today(), only=sys.argv[2])
    else:
        today = date.fromisoformat(sys.argv[1]) if len(sys.argv) > 1 else date.today()
        run(today)