"""실시간 탐지 엔진: Fluent Bit이 TCP로 보내는 Kong 로그를 한 줄씩 받아 바로 판정

- 장부(ledger.json)로 BOLA / ATTEMPT / UNKNOWN 판정 → Redis Stream bola:events 에 보고 (최종 판단은 판단 서버)
- 10초에 의심 요청(BOLA/ATTEMPT/UNKNOWN)이 10번 넘는 사용자 → 임시 차단 키 blocked:user:<id> (Kong이 403으로 막음) + RATE 보고
  (자기 정보를 아무리 새로고침해도 의심 요청이 아니라서 세지 않음)
- 매일 학습으로 ledger.json 이 바뀌면 자동으로 다시 읽음

사용법 (탐지 PC의 engine 폴더에서): pyt on   realtime.py
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

from common import api_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # 어느 폴더에서 실행해도 이 파일 옆의 장부·인증서를 씀
CERT_DIR = os.path.join(BASE_DIR, "certs")
LEDGER_PATH = os.path.join(BASE_DIR, "ledger.json")
PORT = 5170
REDIS_HOST = "192.168.0.39"       # Kong이 차단 키를 읽는 Redis (게이트웨이 PC)
REDIS_PORT = 6379

def load_env(path):
    """같은 폴더의 .env(KEY=VALUE)를 환경변수로 읽음. 이미 있는 환경변수는 덮어쓰지 않음"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

load_env(os.path.join(BASE_DIR, ".env"))
REDIS_PASS = os.getenv("REDIS_PASSWORD") or None   # 비밀번호는 코드에 두지 않고 .env에서 읽음
STREAM = "bola:events"
STREAM_MAXLEN = 100_000           # 스트림이 끝없이 커지지 않게 최근 10만 건만 유지
RATE_WINDOW_MS = 10_000           # 10초
RATE_LIMIT = 10                   # 10초에 의심 요청 10번 넘으면 (더미 로그: 정상 0번, 빠른 공격자 30~136번)
TEMP_BLOCK_SEC = 600              # 임시 차단 10분 (확정은 판단 서버가)
RELOAD_SEC = 60                   # 장부 파일이 바뀌었는지 1분마다 확인

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASS,
                socket_timeout=2, decode_responses=True)
lock = threading.Lock()           # 연결이 여러 개여도 판정은 한 번에 하나씩
recent = defaultdict(deque)       # 사용자 → 최근 10초 의심 요청 시각(ms)
blocked_until = {}                # 사용자 → 임시 차단이 끝나는 시각(ms), 같은 차단을 반복해서 걸지 않게
ledger, ledger_mtime, last_check = None, 0, 0


# ---------------------------------------------------------------- 장부 판정 (ledger.py, detect_ledger.py와 같은 내용)
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


def load_ledger(path):
    with open(path, encoding="utf-8") as f:
        return defaultdict(dict, json.load(f))


def judge(e, ledger):
    if e.get("user_id") is None or e.get("role") == "admin":
        return None
    key = object_key(e)
    if key is None:
        return None
    api, oid = key
    if api not in ledger:
        return None

    me = str(e["user_id"])
    status = e.get("status")
    if status in (403, 404):
        return "ATTEMPT", f"요청자 {me} -> {oid} ({status})"

    if oid not in ledger[api]:
        return "UNKNOWN", f"요청자 {me} -> {oid} (장부에 없음)"
    owner = ledger[api][oid]
    if owner is None:
        return None
    if status == 200 and me != owner:
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
    if mtime != ledger_mtime:
        ledger, ledger_mtime = load_ledger(LEDGER_PATH), mtime
        total = sum(len(objs) for objs in ledger.values())
        print(f"[장부] 읽음: API {len(ledger)}개, 객체 {total}개", flush=True)


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


def check_rate(e):
    me, t = str(e["user_id"]), e.get("started_at", 0)
    q = recent[me]
    q.append(t)
    while q and q[0] <= t - RATE_WINDOW_MS:
        q.popleft()
    if len(q) <= RATE_LIMIT or blocked_until.get(me, 0) > t:
        return
    blocked_until[me] = t + TEMP_BLOCK_SEC * 1000
    try:
        r.set(f"blocked:user:{me}", "rate", ex=TEMP_BLOCK_SEC)
    except redis.RedisError as err:
        print(f"[Redis] 임시 차단 실패: {err}", flush=True)
    report("RATE", e, f"요청자 {me}: 10초에 의심 요청 {len(q)}번 -> {TEMP_BLOCK_SEC}초 임시 차단")


def process(e):
    if e.get("user_id") is None or e.get("role") == "admin" or e.get("blocked"):
        return
    with lock:
        reload_ledger()
        add_from_list(ledger, e)                # 개인 목록에 나온 새 객체는 장부에 바로 추가
        result = judge(e, ledger)
        if result:
            check_rate(e)                       # 의심 요청만 셈
    if result:
        report(result[0], e, result[1])

TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
TLS_CTX.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
TLS_CTX.load_verify_locations(os.path.join(CERT_DIR, "ca.crt"))
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
