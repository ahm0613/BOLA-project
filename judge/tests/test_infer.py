"""1대1 추론 엔진 테스트: python -m unittest discover tests

역할: 가짜 장부로 api_infer.infer가 "URL 번호 = 사용자 번호"인 자원을 맞게 고르는지,
  판단 서버가 path_owners "auto"일 때 장부로 채우고 장부가 바뀌면 다시 추론하는지 확인한다.
"""
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_infer  # noqa: E402
import judge  # noqa: E402


def same(n, start=1):
    """번호 = 주인인 항목 n개 {"1": "1", ...}"""
    return {str(i): str(i) for i in range(start, start + n)}


def other(n, start=1000):
    """번호 ≠ 주인인 항목 n개 {"1000": "1", ...}"""
    return {str(start + i): str(i + 1) for i in range(n)}


class InferTest(unittest.TestCase):
    """장부 → path_owners"""
    def test_one_to_one_vs_ledger(self):
        """번호=주인 100%인 자원만 1대1, 거의 다른 자원은 장부 사용"""
        owners, stats = api_infer.infer({"GET /members/{id}": same(40), "GET /orders/{id}": other(40)})
        self.assertEqual(owners, ["/members/{id}"])
        self.assertEqual(stats["/members/{id}"]["decision"], "one_to_one")
        self.assertEqual(stats["/orders/{id}"]["decision"], "ledger")

    def test_groups_methods_and_subpaths(self):
        """GET·PATCH·하위 경로를 첫 {id}까지 한 자원으로 묶고, 번호가 여러 개면 첫 번호로 비교"""
        ledger = {"GET /members/{id}": same(20), "PATCH /members/{id}": same(10),
                  "GET /members/{id}/addresses/{id}": {f"{i}/{500 + i}": str(i) for i in range(1, 11)}}
        owners, stats = api_infer.infer(ledger)
        self.assertEqual(owners, ["/members/{id}"])
        self.assertEqual((stats["/members/{id}"]["samples"], stats["/members/{id}"]["match"]), (40, 40))

    def test_shared_not_counted(self):
        """주인이 null인 공유 객체는 표본에서 뺌"""
        owners, stats = api_infer.infer({"GET /members/{id}": {**same(30), **{str(i): None for i in range(900, 950)}}})
        s = stats["/members/{id}"]
        self.assertEqual((s["samples"], s["shared"], owners), (30, 50, ["/members/{id}"]))

    def test_too_few_samples_undecided(self):
        """표본이 min_samples보다 적으면 다 일치해도 보류"""
        owners, stats = api_infer.infer({"GET /members/{id}": same(5)})
        self.assertEqual((owners, stats["/members/{id}"]["decision"]), ([], "undecided"))

    def test_middle_ratio_undecided(self):
        """일치율이 애매하면(50%) 보류"""
        owners, stats = api_infer.infer({"GET /x/{id}": {**same(20), **other(20)}})
        self.assertEqual((owners, stats["/x/{id}"]["decision"]), ([], "undecided"))

    def test_coincidence_not_one_to_one(self):
        """순번 ID라 몇 건이 우연히 일치해도(3%) 1대1이 아님 (/reviews/me/{id} 같은 경우)"""
        owners, stats = api_infer.infer({"GET /reviews/me/{id}": {**same(3), **other(97)}})
        self.assertEqual((owners, stats["/reviews/me/{id}"]["decision"]), ([], "ledger"))

    def test_pollution_tolerated_and_suspects(self):
        """장부가 조금 오염돼도(3%) 1대1 유지, 어긋난 항목의 주인(공격자 후보)을 돌려줌"""
        ledger = {"GET /members/{id}": {**same(97), "200": "3", "201": "3", "202": "3"}}
        owners, stats = api_infer.infer(ledger)
        s = stats["/members/{id}"]
        self.assertEqual(owners, ["/members/{id}"])
        self.assertEqual((s["mismatch"], s["suspects"]), (3, {"3": 3}))

    def test_thresholds_from_args(self):
        """기준값을 바꾸면 판정이 바뀜"""
        self.assertEqual(api_infer.infer({"GET /m/{id}": same(10)}, min_samples=5)[0], ["/m/{id}"])

    def test_resource_of(self):
        """첫 {id}까지 자르기, {id}가 없으면 None"""
        self.assertEqual(api_infer.resource_of("PATCH /members/{id}/addresses/{id}"), "/members/{id}")
        self.assertIsNone(api_infer.resource_of("GET /orders"))


class ServerAutoTest(unittest.TestCase):
    """판단 서버: path_owners "auto" → 장부로 추론해 Judge에 넣고, 장부가 바뀌면 다시 추론"""
    def make(self, ledger):
        cfg = judge.load_config()
        tmp = tempfile.mkdtemp()
        cfg["paths"].update({k: os.path.join(tmp, f"{k}.out") for k in cfg["paths"]})
        cfg["paths"]["ledger"] = os.path.join(tmp, "ledger.json")
        with open(cfg["paths"]["ledger"], "w", encoding="utf-8") as f:
            json.dump(ledger, f)
        cfg["path_owners"] = "auto"
        cfg["path_infer"] = {"min_samples": 30, "min_ratio": 0.95, "max_ratio": 0.05}
        cfg["db"] = {**cfg.get("db", {}), "enabled": False}
        return judge.Server(cfg, dry_run=True), cfg["paths"]["ledger"]

    def test_auto_fills_path_owners(self):
        """시작할 때 장부로 추론 → /members/3을 남이 보면 BOLA_PATH"""
        srv, _ = self.make({"GET /members/{id}": same(40), "GET /orders/{id}": other(40)})
        self.assertEqual(srv.judge.path_owner_list, ["/members/{id}"])
        e = {"kind": "BOLA", "user_id": "2", "api": "GET /members/{id}", "uri": "/members/3",
             "owner": "3", "status": 200, "request_id": "r", "ts": 1, "detail": ""}
        self.assertEqual(srv.judge.classify(e), ("BOLA_PATH", "3"))

    def test_ledger_change_reinfers(self):
        """장부 파일이 바뀌면 다음 확인 때 다시 추론"""
        srv, path = self.make({"GET /members/{id}": same(40)})
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"GET /members/{id}": same(40), "GET /profiles/{id}": same(40)}, f)
        os.utime(path, (time.time() + 5, time.time() + 5))     # 파일 시각을 확실히 바꿈
        srv.last_ledger_check = 0.0
        srv.refresh_path_owners()
        self.assertEqual(srv.judge.path_owner_list, ["/members/{id}", "/profiles/{id}"])

    def test_missing_ledger_keeps_empty(self):
        """장부가 없으면 path_owners 비어 있음 (멈추지 않음)"""
        srv, path = self.make({})
        os.remove(path)
        srv.ledger_mtime = None
        srv.judge.set_path_owners([])
        srv.last_ledger_check = 0.0
        srv.refresh_path_owners()
        self.assertEqual(srv.judge.path_owner_list, [])


if __name__ == "__main__":
    unittest.main()
