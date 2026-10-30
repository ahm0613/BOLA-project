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

from scoring import Judge, parse_event  # noqa: E402
from store import ConfirmedStore  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json"),
          encoding="utf-8") as _f:
    CFG = json.load(_f)
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

    def test_bonuses(self):
        """ATTEMPT 뒤 BOLA 성공 + 여러 API 보너스"""
        self.j.process(ev("2", "ATTEMPT", "/payments/1", status=403, sec=0))
        self.j.process(ev("2", "BOLA", "/orders/5", owner="9", sec=1, api="GET /orders/{id}"))
        self.j.process(ev("2", "BOLA", "/payments/8", owner="9", sec=2, api="GET /payments/{id}"))
        score, _, breakdown, _ = self.j.top()[0]
        self.assertEqual(breakdown, {"ATTEMPT": 5, "BOLA_LEDGER": 50, "+attempt_then_bola": 20, "+multi_api": 10})
        self.assertEqual(score, 85)

    def test_window(self):
        """24시간 밖 이벤트는 점수에서 빠짐"""
        self.j.process(ev("2", "BOLA", "/orders/5", owner="9", sec=0))
        self.j.process(ev("2", "BOLA", "/orders/6", owner="9", sec=90000))
        self.assertEqual(self.j.top()[0][0], 25)

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
        """털린 API별 피해자: BOLA만 기록, 본인 번호·ATTEMPT 제외, 확정된 사용자도 계속 기록"""
        self.j.process(ev("2", "BOLA", "/members/4/addresses", owner="4", sec=0))
        self.j.process(ev("2", "BOLA", "/members/3/addresses", owner="3", sec=1))
        self.assertEqual(self.j.last["api_victims"], ["3", "4"])
        self.j.process(ev("2", "ATTEMPT", "/members/9/addresses", status=403, sec=2))
        self.j.process(ev("2", "BOLA", "/members/2", owner="99", sec=3))         # 본인 번호 → 제외
        j2 = Judge(CFG, confirmed_users=["7"])
        j2.process(ev("7", "BOLA", "/orders/57", owner="9", api="GET /orders/{id}"))
        self.assertEqual(self.j.user_hits("2"), {"GET /members/{id}/addresses": ["3", "4"]})
        self.assertEqual(j2.user_hits("7"), {"GET /orders/{id}": ["9"]})
        self.j.process(ev("5", "BOLA", "/members/3/addresses", owner="3", sec=4))
        self.assertEqual(self.j.breached()["GET /members/{id}/addresses"],
                         {"victims": ["3", "4"], "attackers": ["2", "5"]})

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
