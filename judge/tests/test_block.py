"""영구 차단 테스트: python -m unittest discover tests

역할: 실제 Redis 없이 가짜 Redis로 확인한다.
  - Blocker: 만료 없는 키, RATE 10분 키 덮어쓰기, 명단 동기화, 해제, Redis 오류 시 멈추지 않음
  - Server: 공격 확정 순간 영구 차단 + DB 조치 기록, 시작 시 기존 확정 사용자 동기화
  - 해제(released): 해제 이전 이벤트로는 다시 확정하지 않음, confirmed.json에 저장·복원
"""
import json
import os
import sys
import tempfile
import unittest

import redis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixed_cfg import pin  # noqa: E402

import judge  # noqa: E402
from blocker import Blocker  # noqa: E402
from scoring import Judge  # noqa: E402
from store import ConfirmedStore  # noqa: E402


class FakeRedis:
    """redis.Redis 흉내: 문자열 키(TTL 포함)와 해시만. down=True면 모든 명령이 ConnectionError"""
    def __init__(self):
        self.kv, self.ttls, self.hashes, self.down = {}, {}, {}, False

    def _check(self):
        if self.down:
            raise redis.ConnectionError("Redis 꺼짐")

    def set(self, k, v, ex=None, nx=False):
        self._check()
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        if ex:
            self.ttls[k] = ex
        else:
            self.ttls.pop(k, None)
        return True

    def hset(self, k, mapping):
        self._check()
        self.hashes.setdefault(k, {}).update({a: str(b) for a, b in mapping.items()})

    def ttl(self, k):
        self._check()
        if k not in self.kv:
            return -2
        return self.ttls.get(k, -1)

    def delete(self, *keys):
        self._check()
        n = 0
        for k in keys:
            if self.kv.pop(k, None) is not None or self.hashes.pop(k, None) is not None:
                n += 1
            self.ttls.pop(k, None)
        return n

    def pipeline(self):
        return FakePipeline(self)


class FakePipeline:
    """명령을 모았다가 execute()에서 한꺼번에 실행"""
    def __init__(self, r):
        self.r, self.calls = r, []

    def __getattr__(self, name):
        return lambda *a, **kw: self.calls.append((name, a, kw))

    def execute(self):
        return [getattr(self.r, n)(*a, **kw) for n, a, kw in self.calls]


class BlockerTest(unittest.TestCase):
    def setUp(self):
        self.r = FakeRedis()
        self.b = Blocker(self.r)

    def test_block_forever(self):
        """만료 없는 키 + 사유 해시"""
        self.assertTrue(self.b.block_forever("7", "점수 120"))
        self.assertEqual((self.r.kv["blocked:user:7"], self.r.ttl("blocked:user:7")), ("confirmed", -1))
        self.assertEqual(self.r.hashes["block:info:7"]["reason"], "점수 120")

    def test_overrides_rate_key(self):
        """RATE의 10분 키가 이미 있어도 영구로 바뀜"""
        self.r.set("blocked:user:7", "rate", ex=600)
        self.b.block_forever("7", "확정")
        self.assertEqual(self.r.ttl("blocked:user:7"), -1)

    def test_rate_does_not_override_forever(self):
        """realtime.py의 nx=True: 영구 키가 있으면 10분 키로 덮어쓰지 않음"""
        self.b.block_forever("7", "확정")
        self.r.set("blocked:user:7", "rate", ex=600, nx=True)
        self.assertEqual((self.r.kv["blocked:user:7"], self.r.ttl("blocked:user:7")), ("confirmed", -1))

    def test_sync(self):
        """명단 중 키가 없거나 만료가 붙은 사용자만 다시 차단"""
        self.b.block_forever("1", "확정")
        self.r.set("blocked:user:2", "rate", ex=600)
        self.assertEqual(self.b.sync({"1": 0, "2": 0, "3": 0}), 2)
        self.assertEqual([self.r.ttl(f"blocked:user:{u}") for u in "123"], [-1, -1, -1])
        self.assertEqual(self.b.sync({"1": 0, "2": 0, "3": 0}), 0)

    def test_unblock(self):
        self.b.block_forever("7", "확정")
        self.assertEqual(self.b.unblock("7"), 2)
        self.assertEqual(self.r.ttl("blocked:user:7"), -2)

    def test_redis_down(self):
        """Redis가 꺼져 있어도 예외 없이 실패만 알림"""
        self.r.down = True
        self.assertFalse(self.b.block_forever("7", "확정"))
        self.assertEqual(self.b.sync({"7": 0}), 0)
        self.assertEqual(self.b.counts["failed"], 1)


class RecorderStub:
    def __init__(self):
        self.events, self.users = [], []

    def put_event(self, row):
        self.events.append(row)

    def put_user(self, row):
        self.users.append(row)


class ServerBlockTest(unittest.TestCase):
    """Server: 확정 → 영구 차단 → DB 조치 기록"""
    def make(self, confirmed=None):
        judge.load_env()
        cfg = pin(judge.load_config())
        tmp = tempfile.mkdtemp()
        cfg["paths"].update({k: os.path.join(tmp, f"{k}.out") for k in cfg["paths"]})
        if confirmed:
            with open(cfg["paths"]["confirmed"], "w", encoding="utf-8") as f:
                json.dump(confirmed, f)
        cfg["db"] = {**cfg.get("db", {}), "enabled": False}
        cfg["block"] = {"enabled": True, "sync_sec": 60}
        srv = judge.Server(cfg)
        srv.r = FakeRedis()
        srv.blocker = Blocker(srv.r)
        srv.db = RecorderStub()
        return srv

    def send(self, srv, s, uri, kind="BOLA", user="7"):
        t0 = 1793331593000
        srv.handle(f"{t0 + s * 1000 + 50}-0", {"kind": kind, "user_id": user, "api": "GET /members/{id}", "uri": uri,
                                              "status": "200", "request_id": f"rid-{s}", "started_at": str(t0 + s * 1000),
                                              "detail": "요청자 7 -> x"})
        return srv.db.events[-1]

    def test_confirm_blocks(self):
        """40+40+40 = 120 → 확정 순간 영구 차단, 조치 applied"""
        srv = self.make()
        self.send(srv, 0, "/members/3")
        self.send(srv, 1, "/members/4")
        self.assertNotIn("blocked:user:7", srv.r.kv)
        r = self.send(srv, 2, "/members/5")
        self.assertEqual(srv.r.ttl("blocked:user:7"), -1)
        self.assertEqual((r["action_id"][-2:], r["enforcement_status"]), ("-L", "applied"))
        self.assertIn("영구 차단 blocked:user:7 (성공)", r["action_reason"])

    def test_confirm_block_fails(self):
        """Redis가 꺼져 있으면 조치 failed, 다음 동기화 때 다시 걸림"""
        srv = self.make()
        srv.r.down = True
        for s, u in enumerate(["3", "4", "5"]):
            r = self.send(srv, s, f"/members/{u}")
        self.assertEqual(r["enforcement_status"], "failed")
        srv.r.down = False
        srv.sync_blocks(force=True)
        self.assertEqual(srv.r.ttl("blocked:user:7"), -1)

    def test_released_events_not_recorded(self):
        """해제 이전 이벤트는 다시 채점하지도, DB에 다시 쓰지도 않음 (정리한 DB 보호)"""
        srv = self.make({"requests": [], "users": {}, "released": {"7": 1793331593000 + 10_000}})
        srv.handle("1793331593050-0", {"kind": "BOLA", "user_id": "7", "api": "GET /members/{id}",
                                       "uri": "/members/3", "status": "200", "started_at": "1793331593000"})
        self.assertEqual((srv.db.events, srv.db.users), ([], []))

    def test_sync_existing_confirmed(self):
        """시작할 때 confirmed.json의 기존 확정 사용자(1, 2)도 영구 차단"""
        srv = self.make({"requests": [], "users": {"1": 1, "2": 2}})
        srv.sync_blocks(force=True)
        self.assertEqual([srv.r.ttl("blocked:user:1"), srv.r.ttl("blocked:user:2")], [-1, -1])

    def test_sync_records_db(self):
        """명단 동기화로 차단한 사용자 → bola_events 조치 행(SYNC) + user_status confirmed, 이미 차단된 사용자는 기록 안 함"""
        srv = self.make({"requests": [], "users": {"21": 1793199600000, "43": 1793113200000}})
        srv.blocker.block_forever("43", "이미 차단됨")
        pushed = []
        srv.notifier = type("N", (), {"push": lambda self, key, ch, kind, text, **kw: pushed.append((key, ch, text))})()
        srv.sync_blocks(force=True)
        self.assertEqual([e["user_id"] for e in srv.db.events], ["21"])
        self.assertEqual([(k, ch) for k, ch, _ in pushed], [("sync:21:1793199600000", "admin")])
        self.assertIn("[명단 차단] 사용자 21 영구 차단 성공", pushed[0][2])
        e = srv.db.events[0]
        self.assertEqual((e["action_type"], e["decision"], e["user_status"], e["enforcement_status"]),
                         ("SYNC", "attack", "confirmed", "applied"))
        self.assertTrue(e["stream_id"].startswith("SYNC-") and e["action_id"].endswith("-21-L"))
        self.assertEqual(e["detection_reasons"]["since"], 1793199600000)
        self.assertEqual([(u["user_id"], u["user_status"]) for u in srv.db.users], [("21", "confirmed")])
        srv.sync_blocks(force=True)                         # 이미 영구 차단 → 다시 기록하지 않음
        self.assertEqual(len(srv.db.events), 1)

    def test_sync_redis_down(self):
        """Redis가 꺼져 있으면 기록 없이 넘어감"""
        srv = self.make({"requests": [], "users": {"21": 1}})
        srv.r.down = True
        srv.sync_blocks(force=True)
        self.assertEqual(srv.db.events, [])


class ReleaseTest(unittest.TestCase):
    """관리자 해제 뒤 다시 확정되지 않음"""
    def test_store_release_roundtrip(self):
        tmp = tempfile.mkdtemp()
        path, log = os.path.join(tmp, "c.json"), os.path.join(tmp, "log.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"requests": ["r1"], "users": {"7": 100}}, f)
        s = ConfirmedStore(path, log)
        self.assertTrue(s.release("7", 5000, "관리자", "오탐"))
        self.assertFalse(s.release("7", 6000, "관리자", "두 번"))
        s.save()
        s2 = ConfirmedStore(path, log)
        self.assertEqual((s2.users, s2.released, s2.requests), ({}, {"7": 5000}, ["r1"]))

    def test_events_before_release_ignored(self):
        cfg = pin(judge.load_config())
        j = Judge(cfg, released={"7": 1000 + 5000})
        for s, u in enumerate(["3", "4", "5"]):     # 해제 이전 이벤트 → 채점 안 함
            out = j.process({"id": None, "kind": "BOLA", "user_id": "7", "api": "GET /members/{id}",
                             "uri": f"/members/{u}", "status": 200, "request_id": f"r{s}", "ts": 1000 + s * 1000,
                             "owner": None, "detail": ""})
            self.assertEqual((out, j.last["result"]), ([], "released"))
        out = j.process({"id": None, "kind": "BOLA", "user_id": "7", "api": "GET /members/{id}", "uri": "/members/9",
                         "status": 200, "request_id": "r9", "ts": 9000, "owner": None, "detail": ""})
        self.assertEqual(j.last["result"], "scored")          # 해제 이후 이벤트는 다시 채점



if __name__ == "__main__":
    unittest.main()
