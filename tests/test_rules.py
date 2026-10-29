"""룰 단위 테스트: python -m unittest discover tests

역할: Indexer 없이 짧은 가짜 이벤트로 룰 R1~R6, 장부, 로그 형식 변환이 의도대로 동작하는지 확인한다.
룰이나 설정 동작을 바꾸면 먼저 이 테스트를 돌린다.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bola_engine.event import from_kong, from_wazuh, parse_line, resource_of  # noqa: E402
from bola_engine.ledger import Ledger  # noqa: E402
from bola_engine.rules import Detector  # noqa: E402

CFG = {
  "exclude_roles": ["admin"],
  "rules": {},
  "owner_fields": {"GET /orders/{id}": "user_id", "GET /members/{id}/addresses": "[].user_id"},
  "list_sources": {"GET /orders": {"resource": "/orders/{id}", "id_field": "[].id"}},
  "path_owners": ["/members/{id}", "/profiles/{id}"],
}


def ev(user, method, uri, status=200, resp_ids=None, role="user", day="2026-10-01"):
  return from_kong({"time": f"{day}T10:00:00+09:00", "request_id": f"{user}-{method}-{uri}",
                    "user_id": user, "role": role, "method": method, "uri": uri,
                    "status": status, "resp_ids": resp_ids})


class RuleTest(unittest.TestCase):
  def setUp(self):
    self.det = Detector(CFG, Ledger())

  def test_resource_of(self):
    self.assertEqual(resource_of(ev("1", "POST", "/orders/2/cancel")), ("/orders/{id}", "2"))
    self.assertEqual(resource_of(ev("1", "GET", "/members/1/addresses/5")), ("/members/{id}/addresses/{id}", "1/5"))
    self.assertIsNone(resource_of(ev("1", "GET", "/orders")))

  def test_r1_own_object_is_ok(self):
    self.assertEqual(self.det.process(ev("2", "GET", "/orders/2", resp_ids={"id": ["2"], "user_id": ["2"]})), [])

  def test_r1_other_owner(self):
    v = self.det.process(ev("1", "GET", "/orders/2", resp_ids={"id": ["2"], "user_id": ["2"]}))
    self.assertEqual(v[0]["rule"]["id"], "BOLA-R1")
    self.assertEqual(v[0]["evidence"]["owners"], ["2"])
    self.assertIn("위반했습니다", v[0]["message"])

  def test_403_is_not_python_rule(self):
    self.assertEqual(self.det.process(ev("1", "GET", "/orders/2", status=403)), [])

  def test_admin_excluded(self):
    self.assertEqual(self.det.process(ev("9", "GET", "/orders/2", role="admin", resp_ids={"user_id": ["2"]})), [])

  def test_r2_from_list(self):
    # bob(2)이 내 주문 목록을 보면 주문 7은 bob 것으로 장부에 기록
    self.det.process(ev("2", "GET", "/orders", resp_ids={"[].id": ["7"]}))
    # alice(1)가 응답에 주인 정보가 없는 취소 API로 주문 7을 건드림 → R2
    v = self.det.process(ev("1", "POST", "/orders/7/cancel", resp_ids={"id": ["7"]}))
    self.assertEqual(v[0]["rule"]["id"], "BOLA-R2")
    self.assertEqual(v[0]["evidence"]["owner_source"], "ledger:confirmed")
    # bob 본인이 취소하면 정상
    self.assertEqual(self.det.process(ev("2", "POST", "/orders/7/cancel")), [])

  def test_r2_learns_from_r1_response(self):
    # 공격 응답이라도 응답 속 주인(2)은 사실 → 장부에 기록되어 이후 R2 판정에 쓰임
    self.det.process(ev("1", "GET", "/orders/3", resp_ids={"user_id": ["2"]}))
    v = self.det.process(ev("5", "PATCH", "/orders/3/delivery-memo"))
    self.assertEqual(v[0]["evidence"]["owners"], ["2"])

  def test_r2_unknown_object_not_reported(self):
    # 장부에 없는 객체 조회는 판정 보류 (변경이면 R3, 아래 테스트)
    self.assertEqual(self.det.process(ev("1", "GET", "/orders/99/items")), [])
    self.assertEqual(self.det.counts["unknown_owner"], 1)

  def test_r1_empty_response_falls_back_to_r2(self):
    # path_owners가 없을 때 (있으면 /members는 R5가 먼저 판정)
    det = Detector(dict(CFG, path_owners=[]), Ledger())
    det.process(ev("4", "GET", "/members/4/addresses", resp_ids={"[].id": ["8"], "[].user_id": ["4"]}))
    v = det.process(ev("1", "GET", "/members/4/addresses", resp_ids=None))
    self.assertEqual(v[0]["rule"]["id"], "BOLA-R2")

  def test_r3_unknown_object_write(self):
    # 주인을 모르는 주문 99를, 다뤄 본 적 없는 사용자가 취소 → R3
    v = self.det.process(ev("5", "POST", "/orders/99/cancel"))
    self.assertEqual(v[0]["rule"]["id"], "BOLA-R3")
    self.assertEqual(v[0]["rule"]["severity"], "medium")

  def test_r3_not_for_previously_visited(self):
    # 이전에 정상적으로 다룬 객체(방문 기록 있음)는 주인을 몰라도 R3 아님
    self.det.process(ev("1", "GET", "/orders/99/items"))
    self.assertEqual(self.det.process(ev("1", "PATCH", "/orders/99/delivery-memo")), [])

  def test_r4_multiple_victims(self):
    cfg = dict(CFG, rules={"BOLA-R4": {"windows": [{"name": "급속", "window_sec": 600, "min_victims": 3}]}})
    det = Detector(cfg, Ledger())
    out = []
    for i, owner in enumerate(["2", "3", "4", "5"]):
      e = ev("1", "GET", f"/orders/{10 + i}", resp_ids={"user_id": [owner]})
      e["started_at"] = 1_000_000 + i * 1000
      out += det.process(e)
    r4 = [v for v in out if v["rule"]["id"] == "BOLA-R4"]
    self.assertEqual(len(r4), 1)                                  # 3명째에서 1번만 (cooldown)
    self.assertEqual(r4[0]["evidence"]["owners"], ["2", "3", "4"])
    self.assertEqual(r4[0]["rule"]["severity"], "critical")

  def test_r4_window_expires(self):
    cfg = dict(CFG, rules={"BOLA-R4": {"windows": [{"name": "급속", "window_sec": 60, "min_victims": 2}]}})
    det = Detector(cfg, Ledger())
    e1 = ev("1", "GET", "/orders/10", resp_ids={"user_id": ["2"]})
    e1["started_at"] = 0
    e2 = ev("1", "GET", "/orders/11", resp_ids={"user_id": ["3"]})
    e2["started_at"] = 120_000                                    # 2분 뒤 → 첫 위반은 창 밖
    self.assertFalse([v for v in det.process(e1) + det.process(e2) if v["rule"]["id"] == "BOLA-R4"])

  def test_r5_path_owner(self):
    # 주소가 없는 회원(빈 목록 → resp_ids 없음), 장부도 비어 있음 → R1·R2 불가, 경로의 사용자 번호로 판정
    v = self.det.process(ev("1", "GET", "/members/2/addresses", resp_ids=None))
    self.assertEqual(v[0]["rule"]["id"], "BOLA-R5")
    self.assertEqual(v[0]["evidence"]["owners"], ["2"])
    self.assertEqual(v[0]["evidence"]["owner_source"], "path:/members/{id}")
    # HEAD도 경로로 판정
    self.assertEqual(self.det.process(ev("1", "HEAD", "/profiles/3"))[0]["rule"]["id"], "BOLA-R5")
    # 본인 경로는 정상 (응답 없는 PATCH가 R3로 오탐되지도 않음)
    self.assertEqual(self.det.process(ev("1", "PATCH", "/members/1")), [])

  def test_r5_not_for_other_paths(self):
    # /orders/{id}의 ID는 주문 번호라 R5 대상 아님 → 기존대로 R3
    self.assertEqual(self.det.process(ev("5", "POST", "/orders/99/cancel"))[0]["rule"]["id"], "BOLA-R3")

  def test_r5_response_owner_first(self):
    # 응답에 주인이 있으면 R1이 우선 (한 요청에 한 룰)
    v = self.det.process(ev("1", "GET", "/members/4/addresses", resp_ids={"[].user_id": ["4"]}))
    self.assertEqual([x["rule"]["id"] for x in v], ["BOLA-R1"])

  def _seq(self, det, user, uris_statuses, step_ms=1000):
    out = []
    for i, (uri, status) in enumerate(uris_statuses):
      e = ev(user, "GET", uri, status=status)
      e["request_id"] = f"r{i}"
      e["started_at"] = 1_000_000 + i * step_ms
      out += [v for v in det.process(e) if v["rule"]["id"] == "BOLA-R6"]
    return out

  def test_r6_sequential_scan(self):
    # 남의 주문을 찔러 봄: 404·403·200이 섞여 있어도 연속 ID 5개면 경보 1번 (cooldown)
    det = Detector(CFG, Ledger())
    seq = [(f"/orders/{n}", s) for n, s in zip(range(180, 187), [404, 403, 404, 403, 403, 404, 403])]
    r6 = self._seq(det, "1", seq)
    self.assertEqual(len(r6), 1)
    self.assertEqual(r6[0]["evidence"]["ids"], ["180", "181", "182", "183", "184"])
    self.assertEqual(r6[0]["rule"]["severity"], "medium")

  def test_r6_ignores_own_and_gaps(self):
    det = Detector(CFG, Ledger())
    # 본인 주문 5개를 연달아 보는 것은 정상 (목록으로 본인 것 확인됨)
    det.process(ev("2", "GET", "/orders", resp_ids={"[].id": ["10", "11", "12", "13", "14"]}))
    self.assertEqual(self._seq(det, "2", [(f"/orders/{n}", 200) for n in range(10, 15)]), [])
    # 띄엄띄엄(간격 > max_gap)이면 연속이 아님
    self.assertEqual(self._seq(det, "1", [(f"/orders/{n}", 404) for n in (100, 110, 120, 130, 140)]), [])

  def test_r6_window(self):
    # 창(60초)보다 느리게 훑으면 경보 없음
    det = Detector(CFG, Ledger())
    self.assertEqual(self._seq(det, "1", [(f"/orders/{n}", 404) for n in range(50, 56)], step_ms=20_000), [])

  def test_inferred_owner(self):
    led = Ledger(min_share=0.7)
    for d in ["01", "02", "03"]:
      led.visit("/x/{id}", "1", "3", f"2026-10-{d}")
    self.assertEqual(led.owner("/x/{id}", "1"), ("3", "inferred"))
    led.visit("/x/{id}", "1", "4", "2026-10-04")
    led.visit("/x/{id}", "1", "4", "2026-10-05")
    self.assertEqual(led.owner("/x/{id}", "1"), (None, None))   # 3:2 → 60% < 70%

  def test_kong_default_format(self):
    # custom_fields_by_lua 적용 전 Kong 기본 형식 (request/response 중첩)
    e = from_kong({"started_at": 1793085619745, "user_id": "1", "role": "user",
                   "request": {"method": "GET", "uri": "/orders/2", "headers": {"x-request-id": "abc"}},
                   "response": {"status": 200}, "service": {"name": "orders-service"},
                   "resp_ids": {"user_id": ["2"]}})
    self.assertEqual((e["method"], e["uri"], e["status"], e["request_id"]), ("GET", "/orders/2", 200, "abc"))
    self.assertNotIn("request", e)
    self.assertEqual(self.det.process(e)[0]["rule"]["id"], "BOLA-R1")

  def test_from_wazuh_full_log(self):
    kong = {"method": "GET", "uri": "/orders/2", "status": 200, "user_id": "1", "role": "user",
            "resp_ids": {"[].id": ["1"]}}
    doc = {"id": "1.2", "timestamp": "2026-10-28T12:00:00.000+0000", "location": "/logs/kong/access.json",
           "agent": {"name": "kong-wazuh-agent"}, "full_log": json.dumps(kong),
           "data": {"status": "200"}}
    e = from_wazuh(doc)
    self.assertEqual(e["status"], 200)
    self.assertEqual(e["resp_ids"], {"[].id": ["1"]})
    self.assertEqual(e["_meta"]["agent"], "kong-wazuh-agent")

  def test_parse_bola_api_doc(self):
    # bola-api-* 문서(_source): agent·location이 source 아래에 있음
    kong = {"method": "GET", "uri": "/orders/2", "status": 200, "user_id": "1", "role": "user"}
    doc = {"timestamp": "2026-10-28T00:26:11.739+00:00", "full_log": json.dumps(kong),
           "source": {"location": "/logs/kong/access.json", "agent": {"name": "pc1-bola"}}}
    e = parse_line(json.dumps(doc))
    self.assertEqual((e["uri"], e["_meta"]["agent"], e["_meta"]["location"]),
                     ("/orders/2", "pc1-bola", "/logs/kong/access.json"))


if __name__ == "__main__":
  unittest.main()
