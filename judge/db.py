"""PostgreSQL 기록: 탐지 이벤트(bola_events)와 사용자 현재 상태(user_status)를 백그라운드 스레드가 모아서 씀

역할: 판단 서버의 두 번째 출구 (pc3 Streamlit이 읽음). 판정 루프가 DB 때문에 느려지지 않게 한다.
  - 판정 루프는 put_event()/put_user()로 메모리 큐에 넣고 바로 돌아감
  - 저장 스레드가 flush_sec마다 큐를 비워 한 트랜잭션으로 INSERT/UPSERT
  - 사용자 상태는 사용자마다 마지막 값만 남겨서 씀 (점수가 초당 여러 번 바뀌어도 한 번만)
  - DB가 꺼져 있으면 큐에 쌓아 두고 다시 연결되면 씀 (큐가 너무 커지면 오래된 것부터 버림)
  - sweep_sec마다 만료 시각이 지난 임시 차단(RATE)을 expired로 바꾸고 released_at을 채움
이벤트는 stream_id가 같으면 한 번만 들어가므로, 판단 서버를 다시 시작해 과거 이벤트를 다시 읽어도 중복되지 않는다.

점수 복원 (read_events): 판단 서버가 시작할 때 bola_events를 stream_id 순으로 읽어 Redis 이벤트 모양으로 되돌림.
  Redis 스트림은 최근 10만 건만 남지만(realtime.py STREAM_MAXLEN) DB에는 전부 남으므로 누적 점수를 잃지 않는다.
"""
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:                                     # 패키지가 없으면 DB 기록 없이 동작 (judge.py가 안내)
    psycopg = None

MAX_PENDING = 10000                                     # DB가 오래 꺼져 있을 때 메모리에 쌓아 둘 최대 건수

EVENT_COLUMNS = [
    "stream_id", "event_id", "event_at", "detected_at", "user_id", "action_type", "api_path", "detection_reasons",
    "risk_score", "risk_pct", "assessed_at", "decision", "decision_reason", "user_status", "user_status_updated_at",
    "action_id", "action_reason", "decided_at", "enforcement_status", "enforced_at", "expires_at", "released_at",
]
SQL_EVENT = (f"INSERT INTO bola_events ({', '.join(EVENT_COLUMNS)}) "
             f"VALUES ({', '.join(f'%({c})s' for c in EVENT_COLUMNS)}) ON CONFLICT (stream_id) DO NOTHING")

# 상태 값이 바뀔 때만 user_status_updated_at을 갱신 (점수만 바뀌면 그대로)
SQL_USER = """
INSERT INTO user_status AS u (user_id, user_status, user_status_updated_at, risk_score, risk_pct,
                              last_event_at, last_stream_id)
VALUES (%(user_id)s, %(user_status)s, %(user_status_updated_at)s, %(risk_score)s, %(risk_pct)s,
        %(last_event_at)s, %(last_stream_id)s)
ON CONFLICT (user_id) DO UPDATE SET
  user_status = EXCLUDED.user_status,
  user_status_updated_at = CASE WHEN u.user_status IS DISTINCT FROM EXCLUDED.user_status
                                THEN EXCLUDED.user_status_updated_at ELSE u.user_status_updated_at END,
  risk_score = COALESCE(EXCLUDED.risk_score, u.risk_score),     -- 점수 계산이 없던 이벤트(확정 사용자)는 기존 점수 유지
  risk_pct = COALESCE(EXCLUDED.risk_pct, u.risk_pct),           -- 위험도 0~100 (차단 기준 대비 비율, 차단이면 100). 이 SQL에는 퍼센트 기호를 쓰지 말 것 (psycopg 자리표시로 읽음)
  last_event_at = GREATEST(EXCLUDED.last_event_at, u.last_event_at),
  last_stream_id = EXCLUDED.last_stream_id"""

SQL_SWEEP = """
UPDATE bola_events SET enforcement_status = 'expired', released_at = expires_at
WHERE enforcement_status = 'applied' AND expires_at IS NOT NULL AND expires_at < now()"""


# 점수 복원용: Redis에서 온 이벤트만 (SYNC-… 같은 명단 동기화 행 제외), 스트림 ID 순서 그대로
# stream_id는 TEXT라 "…-10"이 "…-9"보다 앞에 오지 않게 숫자로 나눠 정렬
SQL_REPLAY = """
SELECT stream_id, action_type, user_id, api_path, event_id, event_at, detection_reasons,
       user_status, user_status_updated_at
FROM bola_events
WHERE stream_id ~ '^[0-9]+-[0-9]+$' AND detected_at >= %(since)s
ORDER BY split_part(stream_id, '-', 1)::bigint, split_part(stream_id, '-', 2)::bigint"""
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def row_to_event(row):
    """bola_events 한 행(dict) → (stream_id, Redis 필드 dict, (사용자 상태, 상태 변경 시각))
    Redis 필드는 realtime.py가 보내는 모양(모두 문자열)으로 되돌림. 주인 번호는 detail 문장("주인 N")에 들어 있음"""
    dr = row.get("detection_reasons") or {}
    if isinstance(dr, str):
        dr = json.loads(dr)
    at = row.get("event_at")
    fields = {
        "kind": row.get("action_type") or "",
        "user_id": str(row.get("user_id")),
        "api": row.get("api_path") or "",
        "uri": dr.get("uri") or "",
        "status": str(dr.get("status") or 0),
        "request_id": row.get("event_id") or "",
        "started_at": str(round(at.timestamp() * 1000)) if at else "0",
        "detail": dr.get("detail") or "",
    }
    return row["stream_id"], fields, (row.get("user_status"), row.get("user_status_updated_at"))


def read_events(dsn, since=None, batch=2000):
    """bola_events를 stream_id 순으로 하나씩 돌려줌 (row_to_event 모양). since: 이 시각(탐지 시각) 이후만, None이면 전체
    서버 쪽 커서로 batch건씩 받아서 행이 많아도 메모리를 한꺼번에 쓰지 않음"""
    with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as conn:
        with conn.cursor(name="judge_replay") as cur:
            cur.itersize = batch
            cur.execute(SQL_REPLAY, {"since": since or EPOCH})
            for row in cur:
                yield row_to_event(row)


def dsn_from_env():
    """.env의 PG_*로 psycopg 접속 문자열. psycopg가 없거나 PG_JUDGE_PASSWORD가 없으면 None"""
    if psycopg is None or not os.getenv("PG_JUDGE_PASSWORD"):
        return None
    return psycopg.conninfo.make_conninfo(
        host=os.getenv("PG_HOST", "127.0.0.1"), port=os.getenv("PG_PORT", "5432"),
        dbname=os.getenv("PG_DB", "bola_judge"), user=os.getenv("PG_JUDGE_USER", "judge"),
        password=os.getenv("PG_JUDGE_PASSWORD"))


class DbWriter:
    """메모리 큐 + 저장 스레드. start()로 시작, close()로 남은 것을 쓰고 종료"""
    def __init__(self, dsn, flush_sec=1.0, sweep_sec=10.0):
        """dsn: psycopg 접속 문자열. flush_sec: 몇 초마다 모아서 쓸지. sweep_sec: 만료 처리 주기"""
        self.dsn = dsn
        self.flush_sec = flush_sec
        self.sweep_sec = sweep_sec
        self.events = deque()
        self.users = {}                                 # user_id → 마지막 상태 (사용자마다 한 건만)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.conn = None
        self.last_sweep = 0.0
        self.counts = {"events": 0, "users": 0, "errors": 0, "dropped": 0}
        self.thread = threading.Thread(target=self._run, name="db-writer", daemon=True)

    def start(self):
        """저장 스레드 시작"""
        self.thread.start()

    def put_event(self, row):
        """탐지 이벤트 한 행 (EVENT_COLUMNS, 없는 컬럼은 NULL. detection_reasons는 dict 그대로)"""
        with self.lock:
            self.events.append(row)
            while len(self.events) > MAX_PENDING:       # DB가 오래 꺼져 있을 때 메모리 보호: 오래된 것부터 버림
                self.events.popleft()
                self.counts["dropped"] += 1

    def put_user(self, row):
        """사용자 현재 상태. 같은 사용자의 이전 값은 덮어씀 (risk_pct가 없으면 NULL)"""
        with self.lock:
            self.users[row["user_id"]] = {"risk_pct": None, **row}

    def _run(self):
        """flush_sec마다 큐를 비워 씀. 실패하면 되돌려 놓고 다음에 다시 시도"""
        while not self.stop.wait(self.flush_sec):
            self.flush()

    def flush(self):
        """지금까지 쌓인 것을 한 트랜잭션으로 씀. 성공하면 True"""
        with self.lock:
            events, users = list(self.events), list(self.users.values())
            self.events.clear()
            self.users.clear()
        sweep = time.time() - self.last_sweep >= self.sweep_sec
        if not (events or users or sweep):
            return True
        try:
            if self.conn is None or self.conn.closed:
                self.conn = psycopg.connect(self.dsn, connect_timeout=5)
            with self.conn.transaction(), self.conn.cursor() as cur:
                if events:
                    cur.executemany(SQL_EVENT, [{**{c: None for c in EVENT_COLUMNS}, **r,
                                                 "detection_reasons": json.dumps(r["detection_reasons"],
                                                                                 ensure_ascii=False)}
                                                for r in events])
                if users:
                    cur.executemany(SQL_USER, users)
                if sweep:
                    cur.execute(SQL_SWEEP)
                    self.last_sweep = time.time()
            self.counts["events"] += len(events)
            self.counts["users"] += len(users)
            return True
        except Exception as err:                        # DB가 꺼졌거나 네트워크 문제 → 되돌려 놓고 다음에 다시
            self.counts["errors"] += 1
            if self.counts["errors"] == 1 or self.counts["errors"] % 30 == 0:
                print(f"[DB] 기록 실패 ({self.counts['errors']}번째), 다시 시도함: {err}", flush=True)
            with self.lock:
                self.events.extendleft(reversed(events))
                for r in users:
                    self.users.setdefault(r["user_id"], r)   # 그 사이 들어온 새 상태가 있으면 그쪽을 유지
                while len(self.events) > MAX_PENDING:
                    self.events.popleft()
                    self.counts["dropped"] += 1
            try:
                if self.conn is not None:
                    self.conn.close()
            except Exception:
                pass
            self.conn = None
            return False

    def close(self, timeout=10.0):
        """저장 스레드를 멈추고 남은 것을 씀 (최대 timeout초 동안 다시 시도)"""
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join(timeout=self.flush_sec + 1)
        deadline = time.time() + timeout
        while not self.flush() and time.time() < deadline:
            time.sleep(1)
        if self.conn is not None:
            self.conn.close()

    def check(self):
        """접속 확인 (시작할 때 한 번). 실패하면 오류 메시지, 성공하면 None"""
        try:
            with psycopg.connect(self.dsn, connect_timeout=5) as conn:
                conn.execute("SELECT 1 FROM bola_events LIMIT 1")
            return None
        except Exception as err:
            return str(err)
