"""DB 기록 테스트: python -m unittest discover tests

역할: 실제 PostgreSQL 없이 가짜 연결로 확인한다.
  - DbWriter: 모아서 쓰기, 사용자 상태 합치기, 실패하면 되돌려 놓고 다시 쓰기
  - Server.record_db: Redis 이벤트 한 건 → bola_events 한 행 (Redis 값, 판단, 상태 변경 시각, 조치)
"""
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixed_cfg import pin  # noqa: E402

import db  # noqa: E402
import judge  # noqa: E402


class FakeConn:
    """psycopg 연결 흉내: 실행한 SQL을 기록. fail=True면 실행할 때 예외"""
    def __init__(self, log, fail=False):
        self.log, self.fail, self.closed = log, fail, False

    @contextmanager
    def transaction(self):
        yield

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def executemany(self, sql, rows):
        if self.fail:
            raise RuntimeError("DB 꺼짐")
        self.log.append((sql.split()[2], list(rows)))   # 테이블 이름, 행들

    def execute(self, sql):
        if self.fail:
            raise RuntimeError("DB 꺼짐")
        self.log.append(("SWEEP", []))

    def close(self):
        self.closed = True


class FakePsycopg:
    """psycopg 모듈 흉내: connect()가 FakeConn을 돌려줌"""
    def __init__(self):
        self.log, self.fail = [], False

    def connect(self, dsn, connect_timeout=5):
        return FakeConn(self.log, self.fail)


def user(uid, status, score=None):
    """사용자 상태 한 건"""
    return {"user_id": uid, "user_status": status, "user_status_updated_at": None, "risk_score": score,
            "last_event_at": None, "last_stream_id": None}


class DbWriterTest(unittest.TestCase):
    """DbWriter (스레드는 띄우지 않고 flush를 직접 부름)"""
    def setUp(self):
        """가짜 psycopg로 바꿔 끼움"""
        self.real, self.fake = db.psycopg, FakePsycopg()
        db.psycopg = self.fake
        self.w = db.DbWriter("fake", sweep_sec=3600)
        self.w.last_sweep = 1e18                        # 만료 처리는 이 테스트에서 끔

    def tearDown(self):
        """원래 psycopg로 되돌림"""
        db.psycopg = self.real

    def test_batch_and_user_merge(self):
        """이벤트는 한 번에, 빠진 컬럼은 NULL, 사용자 상태는 사용자마다 마지막 값만"""
        self.w.put_event({"stream_id": "1-0", "user_id": "2", "detection_reasons": {"detail": "요청자 2 -> 3"}})
        self.w.put_user(user("2", "watch", 40))
        self.w.put_user(user("2", "warning", 75))
        self.assertTrue(self.w.flush())
        self.assertEqual([t for t, _ in self.fake.log], ["bola_events", "user_status"])
        row = self.fake.log[0][1][0]
        self.assertEqual(set(row), set(db.EVENT_COLUMNS))
        self.assertIsNone(row["action_id"])
        self.assertEqual(row["detection_reasons"], '{"detail": "요청자 2 -> 3"}')   # JSON 문자열로 바뀜
        self.assertEqual([(r["user_status"], r["risk_score"]) for r in self.fake.log[1][1]], [("warning", 75)])

    def test_retry_after_failure(self):
        """DB가 꺼져 있으면 되돌려 놓고, 다시 켜지면 그대로 씀"""
        self.fake.fail = True
        self.w.put_event({"stream_id": "1-0", "detection_reasons": {}})
        self.w.put_user(user("2", "watch", 40))
        self.assertFalse(self.w.flush())
        self.assertEqual((len(self.w.events), len(self.w.users), self.w.counts["errors"]), (1, 1, 1))
        self.fake.fail = False
        self.assertTrue(self.w.flush())
        self.assertEqual((self.w.counts["events"], self.w.counts["users"], len(self.w.events)), (1, 1, 0))

    def test_newer_user_wins_after_failure(self):
        """실패해서 되돌려 놓는 동안 들어온 새 사용자 상태가 옛 값에 덮이지 않음"""
        self.fake.fail = True
        self.w.put_user(user("2", "watch", 40))
        self.assertFalse(self.w.flush())
        self.w.put_user(user("2", "confirmed", 120))
        self.fake.fail = False
        self.assertTrue(self.w.flush())
        self.assertEqual([(r["user_status"], r["risk_score"]) for r in self.fake.log[-1][1]], [("confirmed", 120)])

    def test_trim(self):
        """큐가 MAX_PENDING을 넘으면 오래된 것부터 버림"""
        old = db.MAX_PENDING
        db.MAX_PENDING = 3
        try:
            for i in range(5):
                self.w.put_event({"stream_id": f"{i}-0", "detection_reasons": {}})
            self.assertEqual([e["stream_id"] for e in self.w.events], ["2-0", "3-0", "4-0"])
            self.assertEqual(self.w.counts["dropped"], 2)
        finally:
            db.MAX_PENDING = old


class RecorderStub:
    """DbWriter 대신 넣어서 record_db가 만든 행을 모음"""
    def __init__(self):
        self.events, self.users = [], []

    def put_event(self, row):
        self.events.append(row)

    def put_user(self, row):
        self.users.append(row)


class RecordDbTest(unittest.TestCase):
    """Server.record_db: Redis 이벤트 → bola_events 행"""
    def setUp(self):
        """Redis·PostgreSQL 없이 Server를 만들고, DB 대신 RecorderStub을 끼움 (파일은 임시 폴더)"""
        judge.load_env()
        cfg = pin(judge.load_config())
        self.tmp = tempfile.mkdtemp()
        cfg["paths"].update({k: os.path.join(self.tmp, f"{k}.out") for k in cfg["paths"]})
        cfg["db"] = {**cfg.get("db", {}), "enabled": False}
        cfg["block"] = {"enabled": False}               # 실제 Redis에 차단 키를 걸지 않게 (차단은 test_block.py)
        self.srv = judge.Server(cfg)
        self.rec = self.srv.db = RecorderStub()
        self.t0 = 1793331593000

    def send(self, kind, uri, owner=None, status=200, s=0, api="GET /members/{id}", user="7"):
        """realtime.py가 Redis에 넣는 모양으로 이벤트 하나를 처리하고 만들어진 bola_events 행을 돌려줌"""
        sid = f"{self.t0 + s * 1000 + 50}-0"
        self.srv.handle(sid, {"kind": kind, "user_id": user, "api": api, "uri": uri, "status": str(status),
                              "request_id": f"rid-{s}", "started_at": str(self.t0 + s * 1000),
                              "detail": f"요청자 {user} -> x (주인 {owner})" if owner else f"요청자 {user} -> x ({status})"})
        return self.rec.events[-1]

    def test_columns_and_levels(self):
        """Redis 값이 그대로 들어가고, 점수가 오르면 decision·user_status가 바뀌며, 상태 변경 시각은 바뀔 때만 갱신"""
        r1 = self.send("BOLA", "/members/3", owner="3")
        self.assertEqual((r1["stream_id"], r1["event_id"], r1["action_type"], r1["api_path"]),
                         (f"{self.t0 + 50}-0", "rid-0", "BOLA", "GET /members/{id}"))
        self.assertEqual(r1["detected_at"].timestamp() * 1000 - r1["event_at"].timestamp() * 1000, 50)
        self.assertEqual((r1["risk_score"], r1["decision"], r1["user_status"]), (40, "watch", "watch"))
        self.assertEqual(r1["detection_reasons"]["detail"], "요청자 7 -> x (주인 3)")
        self.assertNotIn("action_id", r1)
        r2 = self.send("ATTEMPT", "/payments/1", status=403, s=1, api="GET /payments/{id}")
        self.assertEqual((r2["risk_score"], r2["decision"]), (45, "watch"))
        self.assertEqual(r2["user_status_updated_at"], r1["user_status_updated_at"])   # 상태 그대로 → 시각 그대로

    def test_rate_and_confirm_actions(self):
        """RATE 이벤트는 임시 차단(-R, 10분 뒤 만료), 공격 확정 이벤트는 장부 제외(-L)"""
        self.send("BOLA", "/members/3", owner="3")
        r = self.send("RATE", "/members/3", s=1)
        self.assertEqual((r["action_id"][-2:], r["enforcement_status"]), ("-R", "applied"))
        self.assertEqual((r["expires_at"] - r["enforced_at"]).total_seconds(), 600)
        r = self.send("BOLA", "/members/5", owner="5", s=2)                  # 40+20+40 = 100 → 확정
        self.assertEqual((r["decision"], r["user_status"], r["action_id"][-2:]), ("attack", "confirmed", "-L"))
        self.assertEqual(r["enforcement_status"], "applied")
        self.assertIsNone(r["expires_at"])
        r = self.send("BOLA", "/members/9", owner="9", s=3)                  # 확정 뒤: 점수는 마지막 값
        self.assertEqual((r["decision"], r["risk_score"], r["user_status"]), ("attack", 100, "confirmed"))
        self.assertEqual(self.rec.users[-1]["user_status"], "confirmed")

    def test_status_output(self):
        """상태 출력이 사용자 상태 기억(user_state)과 이름이 겹치지 않고 동작"""
        self.send("BOLA", "/members/3", owner="3")
        self.srv.db = None                              # 상태 줄의 DB 건수 부분은 실제 DbWriter에만 있음
        self.srv.status(force=True)

    def test_ignored(self):
        """URL 번호가 본인이면 decision=ignored, 점수 없음"""
        r = self.send("BOLA", "/members/7", owner="43")
        self.assertEqual((r["decision"], r["risk_score"], r["user_status"]), ("ignored", None, "normal"))


if __name__ == "__main__":
    unittest.main()
