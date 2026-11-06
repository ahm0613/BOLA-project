"""Slack 알림 테스트: python -m unittest discover tests

역할: 실제 Slack·PostgreSQL 없이 가짜 웹훅·가짜 기록 DB로 확인한다.
  - 관리자: warning / attack(건너뛰면 attack 하나) / RATE(하루 한 번), 재시작해도 같은 알림은 한 번
  - 개발자: 처음 털린 API만, 7일 조용하다가 다시 털리면 재발 알림, 사용자 번호 없음
  - 복원 중(live=False)에는 보내지 않음, 웹훅이 없으면 skipped, 실패하면 5번까지 다시 시도
  - 1시간 요약: 정각 + 30초, 켜진 뒤 끝난 시간대만, 일이 없어도 보냄
  - judge.Server와 연결: 확정 순간 관리자 알림 + 개발자 알림
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixed_cfg import pin  # noqa: E402

import judge  # noqa: E402
import notifier  # noqa: E402
from scoring import Judge, parse_event  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
          encoding="utf-8") as _f:
    CFG = pin(json.load(_f))                            # 운영 설정이 바뀌어도 기준값으로 검증 (fixed_cfg.py)
T0 = 1793331593000                                      # 2026-10-30 (테스트 기준 시각, ms)
DAY = 86400 * 1000
HOOKS = {"admin": "https://hooks/admin", "dev": "https://hooks/dev"}


class FakePost:
    """웹훅 흉내: 보낸 (주소, 글)을 기록. fail=n이면 처음 n번은 예외"""
    def __init__(self, fail=0):
        self.sent, self.fail = [], fail

    def __call__(self, url, text, timeout):
        if self.fail:
            self.fail -= 1
            raise RuntimeError("Slack 응답 없음")
        self.sent.append((url, text))

    def to(self, ch):
        return [t for u, t in self.sent if u == HOOKS[ch]]


class FakeAlertDb:
    """AlertDb 흉내: alerts 테이블을 딕셔너리로. 재시작을 흉내 내려고 여러 Notifier가 같은 것을 씀"""
    def __init__(self):
        self.rows, self.api_hits, self.dev_rows, self.admin_rows = {}, [], [], []

    def claim(self, item):
        if item["key"] in self.rows:
            return False
        self.rows[item["key"]] = "pending"
        return True

    def finish(self, item, status):
        self.rows[item["key"]] = status

    def api_recent(self, api, since_ms, until_ms):
        hits = [ts for a, ts in self.api_hits if a == api and since_ms <= ts < until_ms]
        return True, (max(hits) if hits else None)

    def summary_dev(self, start, end):
        return self.dev_rows

    def summary_admin(self, start, end):
        return self.admin_rows


class Clock:
    """움직일 수 있는 시계 (초)"""
    def __init__(self, ms):
        self.now = ms / 1000

    def __call__(self):
        return self.now


def ev(user, kind, uri, sec=0, status=200, owner=None):
    """realtime.py가 Redis에 넣는 모양의 이벤트"""
    detail = f"요청자 {user} -> x" + (f" (주인 {owner})" if owner else "")
    fields = {"kind": kind, "user_id": str(user), "api": "GET " + "/".join(
        "{id}" if s.isdigit() else s for s in uri.split("/")), "uri": uri, "status": str(status),
        "request_id": f"rid-{user}-{sec}", "started_at": str(T0 + sec * 1000), "detail": detail}
    return parse_event(fields, f"{T0 + sec * 1000}-0")


class NotifierTest(unittest.TestCase):
    def setUp(self):
        self.db = FakeAlertDb()
        self.post = FakePost()
        self.clock = Clock(T0)
        self.n = self.make()

    def make(self, live=True):
        """새 Notifier (재시작 흉내: 같은 FakeAlertDb를 씀)"""
        self.j = Judge(CFG)
        n = notifier.Notifier(CFG, HOOKS, self.db, post=self.post, clock=self.clock)
        n.live = live
        return n

    def feed(self, e, n=None):
        """판단 서버처럼 채점 → on_scored → 보내기"""
        n = n or self.n
        decisions = self.j.process(e)
        n.on_scored(self.j.last, decisions, True, self.j)
        n.run_pending()
        return decisions

    def test_warning_then_attack(self):
        """40 → 80(warning) → 120(attack): 관리자 알림 2건, 개발자 알림은 API 처음 한 번"""
        for i, v in enumerate(["3", "4", "5"]):
            self.feed(ev(7, "BOLA", f"/members/{v}", sec=i))
        admin = self.post.to("admin")
        self.assertEqual(len(admin), 2)
        self.assertIn("사용자 7 warning 단계", admin[0])
        self.assertIn("[공격 확정] 사용자 7 영구 차단함", admin[1])
        self.assertIn("unblock.py 7", admin[1])
        dev = self.post.to("dev")
        self.assertEqual(len(dev), 1)
        self.assertIn("[취약 API] GET /members/{id}", dev[0])
        self.assertNotIn("사용자 7", dev[0])                 # 개발자에게는 사용자 번호를 보내지 않음

    def test_jump_to_attack_only(self):
        """한 이벤트로 warning을 건너뛰고 확정되면 attack 하나만"""
        cfg = dict(CFG, points=dict(CFG["points"], BOLA_PATH=150))
        self.j = Judge(cfg)
        self.feed(ev(7, "BOLA", "/members/3"))
        admin = self.post.to("admin")
        self.assertEqual(len(admin), 1)
        self.assertIn("[공격 확정]", admin[0])

    def test_restart_no_duplicate(self):
        """재시작 후 복원(live=False)도, 복원 뒤 같은 단계 상승도 다시 보내지 않음 (DB 키)"""
        for i, v in enumerate(["3", "4"]):
            self.feed(ev(7, "BOLA", f"/members/{v}", sec=i))
        self.assertEqual(len(self.post.to("admin")), 1)
        n2 = self.make(live=False)                          # 재시작: 복원 중
        for i, v in enumerate(["3", "4"]):
            self.feed(ev(7, "BOLA", f"/members/{v}", sec=i), n2)
        self.assertEqual(len(self.post.sent), 2)            # 처음 보낸 2건 그대로
        n3 = self.make(live=True)                           # 복원이 안 됐다고 치고 실시간으로 다시 올라가도
        for i, v in enumerate(["3", "4"]):
            self.feed(ev(7, "BOLA", f"/members/{v}", sec=i), n3)
        self.assertEqual(len(self.post.to("admin")), 1)
        self.assertGreaterEqual(n3.counts["duplicate"], 1)

    def test_released_user_alerts_again(self):
        """관리자가 해제한 사용자는 해제 시각이 키에 들어가 다시 알림"""
        self.feed(ev(7, "BOLA", "/members/3"))
        self.feed(ev(7, "BOLA", "/members/4", sec=1))
        self.n = self.make()
        self.n.released["7"] = T0 + 5000
        self.j.released["7"] = T0 + 5000
        self.feed(ev(7, "BOLA", "/members/3", sec=10))
        self.feed(ev(7, "BOLA", "/members/4", sec=11))
        self.assertEqual(len([t for t in self.post.to("admin") if "warning" in t]), 2)

    def test_rate_once_per_day(self):
        """RATE는 사용자마다 하루 한 번"""
        self.feed(ev(9, "RATE", "/orders/1"))
        self.feed(ev(9, "RATE", "/orders/2", sec=700))
        self.assertEqual(len([t for t in self.post.to("admin") if "[임시 차단]" in t]), 1)
        self.feed(ev(9, "RATE", "/orders/3", sec=DAY // 1000))
        self.assertEqual(len([t for t in self.post.to("admin") if "[임시 차단]" in t]), 2)

    def test_api_quiet_days(self):
        """같은 API는 7일 안에는 다시 알리지 않고, 7일 조용하다가 털리면 재발 알림"""
        self.feed(ev(7, "BOLA", "/orders/1", owner="2"))
        self.feed(ev(8, "BOLA", "/orders/5", sec=3600, owner="2"))
        self.assertEqual(len(self.post.to("dev")), 1)
        self.feed(ev(8, "BOLA", "/orders/6", sec=3600 + 8 * DAY // 1000, owner="2"))
        dev = self.post.to("dev")
        self.assertEqual(len(dev), 2)
        self.assertIn("[취약 API 재발]", dev[1])
        self.assertIn("장부", dev[1])

    def test_api_db_check_after_restart(self):
        """재시작으로 메모리가 비어도 DB에 7일 안 성공 기록이 있으면 보내지 않음"""
        self.db.api_hits.append(("GET /orders/{id}", T0 - DAY))
        self.feed(ev(7, "BOLA", "/orders/1", owner="2"))
        self.assertEqual(self.post.to("dev"), [])

    def test_live_false_silent(self):
        """복원 중에는 아무것도 보내지 않지만 API 시각은 기억"""
        n = self.make(live=False)
        self.feed(ev(7, "BOLA", "/orders/1", owner="2"), n)
        self.assertEqual(self.post.sent, [])
        self.assertIn("GET /orders/{id}", n.api_last)

    def test_no_webhook_skipped(self):
        """웹훅 주소가 없으면 보내지 않고 skipped로 기록"""
        n = notifier.Notifier(CFG, {}, self.db, post=self.post, clock=self.clock)
        n.live = True
        self.feed(ev(9, "RATE", "/orders/1"), n)
        self.assertEqual(self.post.sent, [])
        self.assertEqual(n.counts["skipped"], 1)
        self.assertIn("skipped", self.db.rows.values())

    def test_retry_then_fail(self):
        """실패하면 2, 4, 8, 16초 뒤 다시, 5번 실패하면 failed"""
        self.post.fail = 99
        self.n.push("k", "admin", "test", "글")
        for _ in range(10):
            self.n.run_pending()
            self.clock.now += 20
        self.assertEqual(self.n.counts["failed"], 1)
        self.assertEqual(self.db.rows["k"], "failed")

    def test_retry_then_success(self):
        self.post.fail = 2
        self.n.push("k", "admin", "test", "글")
        self.n.run_pending()
        self.assertEqual(self.post.sent, [])
        for _ in range(3):
            self.clock.now += 5
            self.n.run_pending()
        self.assertEqual(len(self.post.sent), 1)
        self.assertEqual(self.db.rows["k"], "sent")

    def test_summary_timing(self):
        """켜진 뒤 끝난 시간대만, 정각 + 30초 이후, 시간대마다 한 번"""
        hour = 3600 * 1000
        self.clock.now = (T0 // hour * hour + 10 * 60 * 1000) / 1000   # 정각 10분 뒤 시작
        self.n.started_ms = int(self.clock.now * 1000)
        self.n.maybe_summary()
        self.assertEqual(self.n.queue, [])                  # 켜지기 전에 끝난 시간대 → 안 보냄
        self.clock.now = (T0 // hour * hour + hour + 10_000) / 1000      # 다음 정각 10초 뒤
        self.n.maybe_summary()
        self.assertEqual(self.n.queue, [])                  # 30초 전
        self.clock.now += 30
        self.n.maybe_summary()
        self.n.maybe_summary()
        self.n.run_pending()
        self.assertEqual((len(self.post.to("dev")), len(self.post.to("admin"))), (1, 1))
        self.assertIn("이 시간에 털린 API 없음", self.post.to("dev")[0])
        self.assertIn("주의 사용자 없음 (이상 없음)", self.post.to("admin")[0])

    def test_summary_text(self):
        """요약 글: 확정·warning·RATE 사용자만 한 줄씩, DB 실패 안내"""
        dev = self.n.dev_summary_text("10:00~11:00", [("GET /orders/{id}", 12, 5, 2)])
        self.assertIn("GET /orders/{id}: 성공 12건, 피해자 5명, 공격자 2명", dev)
        admin = self.n.admin_summary_text("10:00~11:00", [
            ("7", 30, 150, 2, True, 3), ("9", 5, 70, 0, False, 2), ("11", 1, 5, 0, False, 0)])
        self.assertIn("확정 1명, 임시 차단 2건", admin)
        self.assertIn("사용자 7: 확정 (최고 150점), 임시 차단 2번", admin)
        self.assertIn("사용자 9: warning (최고 70점)", admin)
        self.assertNotIn("사용자 11", admin)
        self.assertIn("DB 접속 실패", self.n.admin_summary_text("x", None))


class ServerNotifyTest(unittest.TestCase):
    """judge.Server.handle → 알림"""
    def test_confirm_sends_admin_and_dev(self):
        judge.load_env()
        cfg = pin(judge.load_config())
        tmp = tempfile.mkdtemp()
        cfg["paths"].update({k: os.path.join(tmp, f"{k}.out") for k in cfg["paths"]})
        cfg["db"] = {**cfg.get("db", {}), "enabled": False}
        cfg["block"] = {"enabled": False}
        srv = judge.Server(cfg)
        post = FakePost()
        srv.notifier = notifier.Notifier(cfg, HOOKS, FakeAlertDb(), post=post, clock=Clock(T0))
        srv.notifier.live = True
        for i, v in enumerate(["3", "4", "5"]):
            srv.handle(f"{T0 + i * 1000}-0", {"kind": "BOLA", "user_id": "7", "api": "GET /members/{id}",
                                              "uri": f"/members/{v}", "status": "200", "request_id": f"r{i}",
                                              "started_at": str(T0 + i * 1000), "detail": "요청자 7 -> x"})
        srv.notifier.run_pending()
        admin = post.to("admin")
        self.assertEqual(len(admin), 2)
        self.assertIn("영구 차단 기능 꺼짐", admin[1])
        self.assertEqual(len(post.to("dev")), 1)


if __name__ == "__main__":
    unittest.main()
