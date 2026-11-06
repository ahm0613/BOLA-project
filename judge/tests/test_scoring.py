"""점수·확정·confirmed.json 테스트: python -m unittest discover tests

역할: Redis 없이 가짜 이벤트로 점수 계산, 오탐 거르기, 확정, 파일 형식을 확인한다.
"""
import json
import re
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fixed_cfg import pin  # noqa: E402

from scoring import Judge, parse_event  # noqa: E402
from store import ConfirmedStore  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
          encoding="utf-8") as _f:
    CFG = pin(json.load(_f))                            # 운영 설정이 바뀌어도 기준값으로 검증 (fixed_cfg.py)
T0 = 1793331593000


def ev(user, kind, uri, status=200, sec=0, owner=None, rid=None, api=None):
    """realtime.py가 Redis에 넣는 모양(모두 문자열)으로 이벤트를 만들어 parse_event를 거침"""
    detail = f"요청자 {user} -> x" + (f" (주인 {owner})" if owner else f" ({status})")
    api = api or "GET " + re.sub(r"/\d+(?=/|$)", "/{id}", uri)       # realtime.py처럼 템플릿 API 이름
    fields = {"kind": kind, "user_id": str(user), "api": api, "uri": uri, "status": str(status),
              "request_id": rid or f"{user}-{kind}-{uri}-{sec}", "started_at": str(T0 + sec * 1000),
              "detail": detail}
    return parse_event(fields, f"{T0 + sec * 1000}-0")


class JudgeTest(unittest.TestCase):
    """점수와 확정"""
    def setUp(self):
        """테스트마다 새 판단기"""
        self.j = Judge(CFG)

    def test_parse(self):
        """문자열 필드를 숫자로, detail에서 주인 추출, owner 필드가 있으면 우선"""
        e = ev("2", "BOLA", "/orders/5", owner="9")
        self.assertEqual((e["status"], e["ts"], e["owner"]), (200, T0, "9"))
        e = parse_event({"kind": "BOLA", "user_id": "2", "owner": "7", "detail": "(주인 9)"}, "123-0")
        self.assertEqual((e["owner"], e["ts"]), ("7", 123))

    def test_self_path_skipped(self):
        """URL 숫자가 본인이면 BOLA로 보고돼도 점수 없음 (장부 오염 오탐)"""
        self.assertEqual(self.j.process(ev("4", "BOLA", "/members/4", owner="43")), [])
        self.assertEqual(self.j.counts["self_skip"], 1)
        self.assertEqual(self.j.top(), [])

    def test_path_bola_request_confirmed(self):
        """URL로 확인된 BOLA는 사용자 확정 전이라도 그 요청을 확정"""
        out = self.j.process(ev("2", "BOLA", "/members/3", owner="3", rid="r1"))
        self.assertEqual([(d["type"], d["request_ids"]) for d in out], [("request", ["r1"])])

    def test_ledger_bola_not_request_confirmed(self):
        """장부 근거 BOLA 한 건은 요청 확정 안 함 (장부가 틀릴 수 있음)"""
        self.assertEqual(self.j.process(ev("2", "BOLA", "/orders/5", owner="9")), [])

    def test_user_confirmed(self):
        """피해자 3명 BOLA_PATH: 40*3 + 피해자 보너스 30 = 150 → 3번째에 사용자 확정"""
        out = []
        for n, victim in enumerate(["3", "5", "7"]):
            out += self.j.process(ev("2", "BOLA", f"/members/{victim}", owner=victim, sec=n))
        users = [d for d in out if d["type"] == "user"]
        self.assertEqual(len(users), 1)
        u = users[0]
        self.assertEqual((u["user_id"], u["since"], u["victims"]), ("2", T0, ["3", "5", "7"]))
        self.assertEqual(u["breakdown"], {"BOLA_PATH": 120, "+victims": 30})
        self.assertEqual(len(u["request_ids"]), 3)

    def test_write_methods_score_higher(self):
        """PUT/PATCH/DELETE로 남의 객체 수정·삭제는 조회보다 높은 점수 (_WRITE 항목)"""
        out = self.j.process(ev("2", "BOLA", "/members/3", owner="3", sec=0,
                                api="PATCH /members/{id}", rid="w1"))
        self.assertEqual((self.j.last["item"], self.j.last["points"], self.j.last["total"]),
                         ("BOLA_PATH_WRITE", 60, 60))
        self.assertIn(("request", ["w1"]), [(d["type"], d["request_ids"]) for d in out])  # 쓰기도 즉시 요청 확정
        j2 = Judge(CFG)
        j2.process(ev("2", "BOLA", "/orders/5", owner="9", sec=0, api="DELETE /orders/{id}"))
        self.assertEqual((j2.last["item"], j2.last["points"], j2.last["total"]),
                         ("BOLA_LEDGER_WRITE", 40, 40))

    def test_unknown_on_path_becomes_bola_path(self):
        """장부에 없어 UNKNOWN으로 온 /members/4 성공 조회 → URL 번호로 주인을 알아 BOLA_PATH"""
        self.j.process(ev("1", "UNKNOWN", "/members/4", sec=0))
        self.assertEqual((self.j.last["item"], self.j.last["victim"], self.j.last["points"]), ("BOLA_PATH", "4", 40))
        self.j.process(ev("1", "UNKNOWN", "/members/5", sec=1, api="PATCH /members/{id}"))
        self.assertEqual(self.j.last["item"], "BOLA_PATH_WRITE")

    def test_unknown_not_upgraded(self):
        """본인 번호 UNKNOWN은 점수 없음, 성공이 아니거나 path_owners가 아닌 API의 UNKNOWN은 그대로"""
        self.assertEqual(self.j.process(ev("4", "UNKNOWN", "/members/4")), [])
        self.assertEqual(self.j.last["result"], "skip")
        self.j.process(ev("1", "UNKNOWN", "/members/4", status=500, sec=1))
        self.assertEqual(self.j.last["item"], "UNKNOWN")
        self.j.process(ev("1", "UNKNOWN", "/orders/999", sec=2))
        self.assertEqual(self.j.last["item"], "UNKNOWN")

    def test_bonuses(self):
        """ATTEMPT 뒤 BOLA 성공 + 여러 API 보너스"""
        self.j.process(ev("2", "ATTEMPT", "/payments/1", status=403, sec=0))
        self.j.process(ev("2", "BOLA", "/orders/5", owner="9", sec=1, api="GET /orders/{id}"))
        self.j.process(ev("2", "BOLA", "/payments/8", owner="9", sec=2, api="GET /payments/{id}"))
        score, _, breakdown, _ = self.j.top()[0]
        self.assertEqual(breakdown, {"ATTEMPT": 5, "BOLA_LEDGER": 50, "+attempt_then_bola": 20, "+multi_api": 10})
        self.assertEqual(score, 85)

    def test_window(self):
        """window_sec=86400이면 24시간 밖 이벤트는 점수에서 빠짐"""
        j = Judge({**CFG, "window_sec": 86400})
        j.process(ev("2", "BOLA", "/orders/5", owner="9", sec=0))
        j.process(ev("2", "BOLA", "/orders/6", owner="9", sec=90000))
        self.assertEqual(j.top()[0][0], 25)

    def test_permanent(self):
        """window_sec=0이면 기간 제한 없이 누적, 판단 사유는 '누적 점수'"""
        j = Judge({**CFG, "window_sec": 0})
        j.process(ev("2", "BOLA", "/members/3", owner="3", sec=0))
        j.process(ev("2", "BOLA", "/members/4", owner="4", sec=86400 * 30))        # 30일 뒤
        self.assertEqual(j.top()[0][0], 80)
        self.assertEqual(j.last["level_up"]["reason"], "누적 점수 80점 ≥ warning 기준 60점")
        out = j.process(ev("2", "ATTEMPT", "/members/5", status=403, sec=86400 * 365))   # 1년 뒤에도 그대로 +5
        self.assertEqual(j.last["total"], 85)
        self.assertEqual(out, [])

    def test_last_trace(self):
        """이벤트마다 채점 결과(last)가 남음: 무시 / 점수 누적 / 확정"""
        self.j.process(ev("4", "BOLA", "/members/4", owner="43"))
        self.assertEqual(self.j.last["result"], "skip")
        self.j.process(ev("2", "BOLA", "/members/3", owner="3", sec=1))
        self.assertEqual((self.j.last["item"], self.j.last["points"], self.j.last["total"]), ("BOLA_PATH", 40, 40))
        self.j.process(ev("2", "BOLA", "/members/5", owner="5", sec=2))
        self.assertEqual((self.j.last["total"], self.j.last["result"]), (80, "scored"))
        self.j.process(ev("2", "BOLA", "/members/7", owner="7", sec=3))
        self.assertEqual((self.j.last["total"], self.j.last["result"]), (150, "confirmed"))
        self.j.process(ev("2", "ATTEMPT", "/orders/1", status=403, sec=4))
        self.assertEqual(self.j.last["result"], "confirmed_user")

    def test_breached_apis(self):
        """털린 API에는 주인이 아니라 접근한 객체 번호를 기록: BOLA만, 본인 번호·ATTEMPT 제외, 확정 사용자도 계속"""
        self.j.process(ev("2", "BOLA", "/members/4/addresses", owner="4", sec=0))
        self.j.process(ev("2", "BOLA", "/members/3/addresses", owner="3", sec=1))
        self.assertEqual(self.j.last["api_objects"], ["3", "4"])
        self.j.process(ev("2", "ATTEMPT", "/members/9/addresses", status=403, sec=2))
        self.j.process(ev("2", "BOLA", "/members/2", owner="99", sec=3))         # 본인 번호 → 제외
        j2 = Judge(CFG, confirmed_users=["7"])
        j2.process(ev("7", "BOLA", "/orders/57", owner="9", api="GET /orders/{id}"))
        self.assertEqual(self.j.user_hits("2"), {"GET /members/{id}/addresses": ["3", "4"]})
        # orders/57의 주인은 9지만, 털린 API에는 접근한 객체 번호 57이 나와야 함 (주인 9 아님)
        self.assertEqual(j2.user_hits("7"), {"GET /orders/{id}": ["57"]})
        self.j.process(ev("5", "BOLA", "/members/3/addresses", owner="3", sec=4))
        self.assertEqual(self.j.breached()["GET /members/{id}/addresses"],
                         {"victims": ["3", "4"], "attackers": ["2", "5"]})

    def test_levels(self):
        """단계가 올라갈 때만 level_up: 40(watch) → 75(warning) → 80(그대로) → 105(attack)"""
        self.j.process(ev("2", "BOLA", "/members/3", owner="3", sec=0))
        self.assertEqual((self.j.last["total"], self.j.last["level_up"]["decision"]), (40, "watch"))
        self.j.process(ev("2", "BOLA", "/orders/5", owner="9", sec=1, api="GET /orders/{id}"))   # +25, 자원 2종 +10
        self.assertEqual((self.j.last["total"], self.j.last["level_up"]["decision"]), (75, "warning"))
        self.j.process(ev("2", "ATTEMPT", "/payments/1", status=403, sec=2))
        self.assertEqual((self.j.last["total"], self.j.last["level"]), (80, "warning"))
        self.assertNotIn("level_up", self.j.last)                       # 같은 단계 → 사건 없음
        self.j.process(ev("2", "BOLA", "/orders/6", owner="9", sec=3, api="GET /orders/{id}"))   # +25, 시도→성공 +20
        self.assertEqual((self.j.last["total"], self.j.last["level_up"]["decision"], self.j.last["result"]),
                         (125, "attack", "confirmed"))

    def test_level_jump(self):
        """한 번에 여러 단계를 넘으면 가장 높은 단계 하나만 기록"""
        j = Judge({**CFG, "points": {**CFG["points"], "BOLA_PATH": 120}})
        j.process(ev("2", "BOLA", "/members/3", owner="3"))
        self.assertEqual((j.last["level_up"]["decision"], j.last["result"]), ("attack", "confirmed"))

    def test_after_confirmed(self):
        """확정된 사용자의 새 의심 요청은 바로 requests에 추가"""
        j = Judge(CFG, confirmed_users=["2"])
        out = j.process(ev("2", "ATTEMPT", "/orders/1", status=403, rid="r9"))
        self.assertEqual(out[0]["request_ids"], ["r9"])


class StoreTest(unittest.TestCase):
    """confirmed.json 형식"""
    def test_format_and_reload(self):
        """요청은 리스트(중복 없이), 사용자는 {id: ms}, 다시 열면 그대로, 사용자 시각은 더 이른 값 유지"""
        with tempfile.TemporaryDirectory() as d:
            path, log = os.path.join(d, "confirmed.json"), os.path.join(d, "log.jsonl")
            s = ConfirmedStore(path, log)
            changed = s.apply([
                {"type": "request", "user_id": "2", "request_ids": ["a"], "reason": "x"},
                {"type": "user", "user_id": "43", "since": 200, "request_ids": ["a", "b"], "reason": "y"},
            ])
            self.assertTrue(changed)
            s.save()
            with open(path, encoding="utf-8") as f:
                self.assertEqual(json.load(f), {"requests": ["a", "b"], "users": {"43": 200}})
            s2 = ConfirmedStore(path, log)
            self.assertFalse(s2.apply([{"type": "request", "user_id": "2", "request_ids": ["a"], "reason": "x"}]))
            s2.apply([{"type": "user", "user_id": "43", "since": 100, "request_ids": [], "reason": "z"}])
            self.assertEqual(s2.users["43"], 100)
            with open(log, encoding="utf-8") as f:
                self.assertEqual(len(f.readlines()), 3)


if __name__ == "__main__":
    unittest.main()
