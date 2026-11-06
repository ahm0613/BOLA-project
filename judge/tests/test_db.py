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


class FakeRedis:
    """XRANGE만 흉내: 스트림 ID 순서대로, min 이상"""
    def __init__(self, rows):
        self.rows = rows

    def xrange(self, stream, min="-", max="+", count=None):
        lo = (0, 0) if min == "-" else judge.id_key(min)
        out = [(i, f) for i, f in self.rows if judge.id_key(i) >= lo]
        return out[:count] if count else out


class RestoreTest(unittest.TestCase):
    """점수 복원: bola_events 행 → 같은 점수, DB에 다시 쓰지 않음, Redis는 DB 이후만 보충"""
    def make(self, window_sec=0):
        """Redis·PostgreSQL 없이 Server (파일은 임시 폴더, 차단 꺼짐)"""
        judge.load_env()
        cfg = pin(judge.load_config())
        tmp = tempfile.mkdtemp()
        cfg["paths"].update({k: os.path.join(tmp, f"{k}.out") for k in cfg["paths"]})
        cfg["db"] = {**cfg.get("db", {}), "enabled": False, "restore": True}
        cfg["block"] = {"enabled": False}
        cfg["window_sec"] = window_sec
        srv = judge.Server(cfg)
        srv.db = RecorderStub()
        return srv

    def fields(self, s, uri, owner, kind="BOLA", user="7"):
        """realtime.py 모양 이벤트. s일 뒤"""
        t = 1793331593000 + s * 86400 * 1000
        return f"{t + 50}-0", {"kind": kind, "user_id": user, "api": "GET /members/{id}", "uri": uri,
                               "status": "200", "request_id": f"rid-{s}", "started_at": str(t),
                               "detail": f"요청자 {user} -> x (주인 {owner})"}

    def as_db_rows(self, recorded):
        """record_db가 만든 행 → DB에서 읽힌 모양 (detection_reasons는 JSONB라 dict 그대로)"""
        return [dict(r) for r in recorded if r["stream_id"][0].isdigit()]

    def patch_db(self, rows, fail=False):
        """db.read_events·dsn_from_env를 가짜로 바꾸고 테스트 끝나면 되돌림"""
        old = db.read_events, db.dsn_from_env

        def read(dsn, since=None):
            for r in rows:
                if since is None or r["detected_at"] >= since:
                    yield db.row_to_event(r)
            if fail:
                raise RuntimeError("DB 꺼짐")
        db.read_events, db.dsn_from_env = read, lambda: "fake"
        self.addCleanup(lambda: setattr(db, "read_events", old[0]) or setattr(db, "dsn_from_env", old[1]))

    def test_row_to_event_roundtrip(self):
        """record_db가 쓴 행을 되돌리면 Redis 필드와 같음 (started_at ms 그대로)"""
        a = self.make()
        sid, f = self.fields(0, "/members/3", "3")
        a.handle(sid, f)
        sid2, f2, state = db.row_to_event(self.as_db_rows(a.db.events)[0])
        self.assertEqual((sid2, f2), (sid, f))
        self.assertEqual(state[0], "watch")

    def test_restore_from_db_then_redis(self):
        """DB 두 건(30일 간격) + DB에 아직 없는 Redis 한 건 → 누적 100점 확정, DB 복원분은 다시 쓰지 않음"""
        a = self.make()
        ev1, ev2, ev3 = self.fields(0, "/members/3", "3"), self.fields(30, "/members/4", "4"), \
            self.fields(31, "/members/5", "5")
        a.handle(*ev1)
        a.handle(*ev2)
        rows = self.as_db_rows(a.db.events)             # 80점까지 DB에 기록됨, ev3은 DB에 쓰기 전에 꺼졌다고 침

        b = self.make()
        self.patch_db(rows)
        b.r = FakeRedis([ev1, ev2, ev3])                # Redis에는 셋 다 (앞 두 건은 DB와 겹침)
        self.assertEqual(b.rebuild_db(), 2)
        self.assertEqual(b.db.events, [])               # DB에서 읽은 것은 다시 쓰지 않음
        self.assertEqual(b.judge.scores["7"], 80)
        self.assertEqual(b.user_state["7"], (rows[-1]["user_status"], rows[-1]["user_status_updated_at"]))
        self.assertEqual(b.rebuild(), 1)                # Redis에서는 DB 이후 한 건만
        self.assertIn("7", b.store.users)               # 40+40+40 + 피해자 3명 30 → 확정
        self.assertEqual([r["stream_id"] for r in b.db.events], [ev3[0]])   # 보충분만 DB에 씀

    def test_window_limits_db_restore(self):
        """window_sec=86400이면 DB에서도 최근 24시간만 읽음 (여기서는 전부 오래됨 → 0건, Redis도 범위 밖)"""
        a = self.make()
        a.handle(*self.fields(0, "/members/3", "3"))
        b = self.make(window_sec=86400)
        self.patch_db(self.as_db_rows(a.db.events))
        b.r = FakeRedis([])
        self.assertEqual(b.rebuild_db(), 0)
        self.assertEqual(b.rebuild(), 0)

    def test_db_failure_falls_back_to_redis(self):
        """DB를 못 읽으면 None → Redis 전체로 복원"""
        b = self.make()
        self.patch_db([], fail=True)
        ev1 = self.fields(0, "/members/3", "3")
        b.r = FakeRedis([ev1])
        self.assertIsNone(b.rebuild_db())
        self.assertEqual(b.rebuild(), 1)
        self.assertEqual(b.judge.scores["7"], 40)


if __name__ == "__main__":
    unittest.main()
