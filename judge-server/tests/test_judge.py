"""judge.score_users 테스트

역할: 점수 합산·중복 제거·정렬·시각 계산이 설계대로 되는지 확인.
실행 (judge-server 폴더에서): python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from judge import day_of, read_violations, score_users  # noqa: E402

SCORES = {"BOLA-R1": 30, "BOLA-R4": 100, "BOLA-R6": 20}


def v(rule, user, req, time="2026-10-28T11:00:00+09:00"):
  """테스트용 위반 기록 1건"""
  return {"rule": {"id": rule}, "original": {"user_id": user, "request_id": req, "time": time}}


class ScoreTest(unittest.TestCase):
  """판단 서버 점수 계산 테스트"""
  def test_sum_and_sort(self):
    """룰별 점수를 더하고 점수 높은 순으로 정렬"""
    users = score_users([v("BOLA-R1", "7", "a"), v("BOLA-R1", "7", "b"), v("BOLA-R4", "21", "c")], SCORES)
    self.assertEqual([(u["user_id"], u["score"]) for u in users], [("21", 100), ("7", 60)])
    self.assertEqual(users[1]["rules"], {"BOLA-R1": 2})

  def test_duplicate_rule_request_counted_once(self):
    """같은 (룰, request_id)는 1번만 셈"""
    users = score_users([v("BOLA-R1", "7", "a"), v("BOLA-R1", "7", "a")], SCORES)
    self.assertEqual(users[0]["score"], 30)

  def test_different_rules_same_request_both_count(self):
    """같은 요청이라도 룰이 다르면 각각 셈"""
    users = score_users([v("BOLA-R1", "7", "a"), v("BOLA-R4", "7", "a"), v("BOLA-R6", "7", "a")], SCORES)
    self.assertEqual(users[0]["score"], 150)

  def test_unknown_rule_zero_points_but_counted(self):
    """점수표에 없는 룰은 0점이지만 횟수는 셈"""
    users = score_users([v("BOLA-R9", "7", "a")], SCORES)
    self.assertEqual((users[0]["score"], users[0]["rules"]), (0, {"BOLA-R9": 1}))

  def test_first_last_seen(self):
    """처음·마지막 위반 시각을 요청 시각으로 계산"""
    users = score_users([v("BOLA-R1", "7", "a", "2026-10-28T12:00:00+09:00"),
                         v("BOLA-R1", "7", "b", "2026-10-28T11:00:00+09:00")], SCORES)
    self.assertEqual(users[0]["first_seen"], "2026-10-28T11:00:00+09:00")
    self.assertEqual(users[0]["last_seen"], "2026-10-28T12:00:00+09:00")

  def test_skip_without_user(self):
    """user_id가 없는 위반은 건너뜀"""
    self.assertEqual(score_users([v("BOLA-R1", None, "a")], SCORES), [])

  def test_day_of_uses_original_time(self):
    """날짜는 탐지 시각이 아니라 원본 요청 시각 기준"""
    x = v("BOLA-R1", "7", "a", "2026-10-28T23:59:59+09:00")
    x["detected_at"] = "2026-10-29T00:00:30+09:00"
    self.assertEqual(day_of(x), "2026-10-28")

  def test_read_all_daily_files(self):
    """violations-*.jsonl 날짜별 파일을 모두 읽음"""
    import json
    import tempfile
    with tempfile.TemporaryDirectory() as d:
      for day, req in (("2026-10-28", "a"), ("2026-10-29", "b")):
        with open(os.path.join(d, f"violations-{day}.jsonl"), "w", encoding="utf-8") as f:
          f.write(json.dumps(v("BOLA-R1", "7", req, f"{day}T10:00:00+09:00")) + "\n")
      self.assertEqual(len(read_violations(os.path.join(d, "violations-*.jsonl"))), 2)


if __name__ == "__main__":
  unittest.main()
