"""실시간 탐지 엔진: Fluent Bit이 TCP로 보내는 Kong 로그를 한 줄씩 받아 바로 판정

- 장부(ledger.json)로 BOLA / ATTEMPT / UNKNOWN 판정 → Redis Stream bola:events 에 보고 (최종 판단은 판단 서버)
- 10초에 의심 요청(BOLA/ATTEMPT/UNKNOWN)이 10번 넘는 사용자 → 임시 차단 키 blocked:user:<id> (Kong이 403으로 막음) + RATE 보고
  (자기 정보를 아무리 새로고침해도 의심 요청이 아니라서 세지 않음)
- 개인 목록에 나온 객체 · 방금 만든 객체(POST 201 응답)는 장부에 바로 추가
- 같은 객체는 메서드가 달라도 주인이 같다고 봄 (PATCH /members/22 → GET /members/{id} 장부로 판정)
- 매일 학습으로 ledger.json 이 바뀌면 자동으로 다시 읽음 (실시간으로 추가한 객체는 유지)

사용법 (탐지 PC의 engine 폴더에서): python realtime.py
"""
import json
import os
import re
import socketserver
import ssl
import threading
import time
from collections import defaultdict, deque

import redis

LEDGER_PATH = "ledger.json"
PORT = 5170
REDIS_HOST = "192.168.0.39"       # Kong이 차단 키를 읽는 Redis (게이트웨이 PC)
REDIS_PORT = 6379
REDIS_PASS = "redis6379"
STREAM = "bola:events"
STREAM_MAXLEN = 100_000           # 스트림이 끝없이 커지지 않게 최근 10만 건만 유지
RATE_WINDOW_MS = 10_000           # 10초
RATE_LIMIT = 10                   # 10초에 의심 요청 10번 넘으면 (더미 로그: 정상 0번, 빠른 공격자 30~136번)
TEMP_BLOCK_SEC = 600              # 임시 차단 10분 (확정은 판단 서버가)
RELOAD_SEC = 60                   # 장부 파일이 바뀌었는지 1분마다 확인
SUCCESS = (200, 204)              # 데이터를 받아 가거나(200) 지운(204) 요청 → 남의 것이면 BOLA

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS,
                socket_timeout=2, decode_responses=True)
lock = threading.Lock()           # 연결이 여러 개여도 판정은 한 번에 하나씩
recent = defaultdict(deque)       # 사용자 → 최근 10초 의심 요청 시각(ms)
live_added = defaultdict(dict)    # 실시간으로 장부에 추가한 객체 (장부를 다시 읽어도 유지)
ledger, ledger_mtime, last_check = None, 0, 0


# ---------------------------------------------------------------- 장부 판정 (ledger.py, detect_ledger.py와 같은 내용)
def api_key(e):
    """GET /orders/7  →  GET /orders/{id}  (학습 엔진과 똑같아야 장부를 찾을 수 있음)"""
    path = e["uri"].split("?")[0]
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return f'{e["method"]} {path}'


def object_key(e):
    path = e["uri"].split("?")[0]
    ids = re.findall(r"/(\d+)(?=/|$)", path)
    if not ids:
        return None
    return api_key(e), "/".join(ids)


def is_user_request(e):
    return e.get("role") == "user" and e.get("user_id") is not None and not e.get("blocked")


def same_object_apis(api, ledger):
    """같은 객체를 가리키는 장부 키 (정확한 키 → 같은 경로의 다른 메서드 → 마지막 {id}까지 자른 경로
    → 같은 서비스에서 번호 개수가 같은 키)
    /members/22 의 주인은 GET이든 PATCH든 같으므로, 그 메서드로 학습된 기록이 없으면 다른 메서드의 기록을 씀
    예) PATCH /members/{id} → GET /members/{id},  POST /orders/{id}/cancel → GET /orders/{id},
        DELETE /cart/items/{id} → GET /cart/{id} (장바구니 목록 GET /cart 에서 배운 항목)"""
    path = api.split(" ", 1)[1]
    paths = [path]
    cut = path[:path.rfind("{id}") + 4]
    if cut != path:
        paths.append(cut)
    keys = [api] if api in ledger else []
    for p in paths:
        for m in ("GET", "PATCH", "PUT", "DELETE", "POST"):
            k = f"{m} {p}"
            if k in ledger and k not in keys:
                keys.append(k)
    service, n_ids = path.split("/")[1], path.count("{id}")
    for k in sorted(ledger, key=lambda k: not k.startswith("GET ")):
        p = k.split(" ", 1)[1]
        if k not in keys and p.split("/")[1] == service and p.count("{id}") == n_ids:
            keys.append(k)
    return keys


def remember(api, oid, owner):
    """장부에 없는 객체만 추가하고, 다시 읽을 때를 위해 따로 기억"""
    if oid not in ledger[api]:
        ledger[api][oid] = owner
        live_added[api][oid] = owner


def add_from_list(e):
    """GET /orders 같은 개인 목록에 나온 객체 → 요청자 것"""
    if e.get("status") != 200 or not is_user_request(e) or object_key(e) is not None:
        return
    detail_api = api_key(e) + "/{id}"
    if detail_api in ledger:
        for oid in (e.get("resp_ids") or {}).get("[].id", []):
            remember(detail_api, str(oid), str(e["user_id"]))


def add_from_created(e):
    """POST /orders 처럼 방금 만든 객체(201 응답의 id) → 만든 사람 것 (결제 직후 주문 상세가 UNKNOWN이 되지 않게)"""
    if e.get("method") != "POST" or e.get("status") != 201 or not is_user_request(e) or object_key(e) is not None:
        return
    apis = same_object_apis("GET " + e["uri"].split("?")[0].rstrip("/") + "/{id}", ledger)
    if apis:                                        # 예) POST /cart/items → PATCH /cart/items/{id} 장부에 등록
        for oid in (e.get("resp_ids") or {}).get("id", []):
            remember(apis[0], str(oid), str(e["user_id"]))


def load_ledger(path):
    with open(path, encoding="utf-8") as f:
        return defaultdict(dict, json.load(f))


def judge(e, ledger):
    key = object_key(e)
    if key is None:
        return None
    api, oid = key
    apis = same_object_apis(api, ledger)
    if not apis:
        return None

    me = str(e["user_id"])
    status = e.get("status")
    if status in (403, 404):
        return "ATTEMPT", f"요청자 {me} -> {oid} ({status})"

    owner_api = next((a for a in apis if oid in ledger[a]), None)
    if owner_api is None:
        return "UNKNOWN", f"요청자 {me} -> {oid} (장부에 없음)"
    owner = ledger[owner_api][oid]
    if owner is None:
        return None
    if status in SUCCESS and me != owner:
        return "BOLA", f"요청자 {me} -> {oid} (주인 {owner})"
    return None


# ---------------------------------------------------------------- 실시간 처리
def reload_ledger():
    global ledger, ledger_mtime, last_check
    now = time.time()
    if ledger is not None and now - last_check < RELOAD_SEC:
        return
    last_check = now
    mtime = os.path.getmtime(LEDGER_PATH)
    if mtime == ledger_mtime:
        return
    new = load_ledger(LEDGER_PATH)
    kept = 0
    for api, objs in live_added.items():           # 새 장부에 아직 없는 실시간 추가분은 이어서 씀
        if api in new:
            for oid, owner in objs.items():
                if oid not in new[api]:
                    new[api][oid] = owner
                    kept += 1
    ledger, ledger_mtime = new, mtime
    total = sum(len(objs) for objs in ledger.values())
    print(f"[장부] 읽음: API {len(ledger)}개, 객체 {total}개 (실시간 추가분 {kept}개 유지)", flush=True)


def report(kind, e, detail):
    print(f"[{kind:7s}] {api_key(e):35s} {detail} req={e.get('request_id')}", flush=True)
    try:
        r.xadd(STREAM, {
            "kind": kind,
            "user_id": str(e.get("user_id")),
            "api": api_key(e),
            "uri": e.get("uri", ""),
            "status": str(e.get("status")),
            "request_id": e.get("request_id", ""),
            "started_at": str(e.get("started_at", 0)),
            "detail": detail,
        }, maxlen=STREAM_MAXLEN, approximate=True)
    except redis.RedisError as err:
        print(f"[Redis] 보고 실패: {err}", flush=True)


def count_suspicious(e):
    """최근 10초 의심 요청 수 (10초 창 밖의 기록은 버림)"""
    t = e.get("started_at", 0)
    q = recent[str(e["user_id"])]
    q.append(t)
    while q and q[0] <= t - RATE_WINDOW_MS:
        q.popleft()
    return len(q)


def temp_block(e, n):
    """임시 차단: 차단 키가 이미 있으면(임시·확정 모두) 건드리지 않음 → 새로 걸었을 때만 보고"""
    me = str(e["user_id"])
    try:
        if not r.set(f"blocked:user:{me}", "rate", ex=TEMP_BLOCK_SEC, nx=True):
            return
    except redis.RedisError as err:
        print(f"[Redis] 임시 차단 실패: {err}", flush=True)
        return
    report("RATE", e, f"요청자 {me}: 10초에 의심 요청 {n}번 -> {TEMP_BLOCK_SEC}초 임시 차단")


def process(e):
    if not is_user_request(e):
        return
    n = 0
    with lock:                                      # 장부·카운터만 lock 안에서 (Redis 호출은 밖에서)
        reload_ledger()
        add_from_list(e)
        add_from_created(e)
        result = judge(e, ledger)
        if result:
            n = count_suspicious(e)                 # 의심 요청만 셈
    if result:
        report(result[0], e, result[1])
        if n > RATE_LIMIT:
            temp_block(e, n)


TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
TLS_CTX.load_cert_chain("certs/server.crt", "certs/server.key")
TLS_CTX.load_verify_locations("certs/ca.crt")
TLS_CTX.verify_mode = ssl.CERT_REQUIRED          # Fluent Bit 인증서가 없으면 연결 거부


class TLSServer(socketserver.ThreadingTCPServer):
    def get_request(self):
        sock, addr = super().get_request()
        return TLS_CTX.wrap_socket(sock, server_side=True), addr


class Handler(socketserver.StreamRequestHandler):
    """Fluent Bit 연결 하나: 한 줄 = 로그 하나"""
    def handle(self):
        for raw in self.rfile:
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            process(e)


if __name__ == "__main__":
    reload_ledger()
    try:
        r.ping()
        print(f"[Redis] 연결됨 {REDIS_HOST}:{REDIS_PORT}", flush=True)
    except redis.RedisError as err:
        print(f"[Redis] 연결 안 됨 ({err}) -> 판정은 화면에만 출력", flush=True)
    with TLSServer(("0.0.0.0", PORT), Handler) as srv:
        print(f"{PORT} 포트에서 Fluent Bit 로그를 기다리는 중", flush=True)
        srv.serve_forever()
