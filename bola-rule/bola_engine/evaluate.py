"""리플레이 결과를 정답지(attacks_truth.csv)와 비교
정답지의 ATTEMPT(403/404)는 Wazuh 룰 담당이므로 제외하고 BOLA(200 성공)만 평가

역할: replay 모드 전용 채점기. 탐지에는 관여하지 않고, 결과가 맞았는지만 본다.
  summarize              서비스별 요청·위반 수 표
  evaluate               정답지 CSV로 정탐·미탐·오탐, 시나리오별, R4 공격자 단위 채점
  evaluate_service_logs  API 서버 로그의 owner_id로 채점 (BOLA-APP 로그가 있을 때)
"""
import csv
import json
import os
from collections import Counter, defaultdict

from .event import api_key
from .rules import INCIDENT_RULES


def _split(violations):
  """요청 단위 위반(R1~R3·R5)과 사용자 단위 사건 경보(R4·R6) 분리"""
  per_req = [v for v in violations if v["rule"]["id"] not in INCIDENT_RULES]
  incidents = [v for v in violations if v["rule"]["id"] in INCIDENT_RULES]
  return per_req, incidents


def evaluate(violations, truth_path):
  """위반 결과를 정답지 CSV와 비교해 정탐·미탐·오탐, 정밀도·재현율을 출력하고 돌려줌"""
  violations, incidents = _split(violations)
  with open(truth_path, encoding="utf-8") as f:
    truth = {r["request_id"]: r for r in csv.DictReader(f) if r["label"] == "BOLA"}
  detected = {v["original"]["request_id"]: v for v in violations}

  tp = truth.keys() & detected.keys()
  fn = truth.keys() - detected.keys()
  fp = detected.keys() - truth.keys()
  precision = len(tp) / len(detected) if detected else 0.0
  recall = len(tp) / len(truth) if truth else 0.0

  print("\n=== 평가 (정답지 BOLA 기준) ===")
  print(f"정답 BOLA {len(truth)}건 / 탐지 {len(detected)}건")
  print(f"정탐 {len(tp)}  미탐 {len(fn)}  오탐 {len(fp)}")
  print(f"정밀도 {precision:.3f}  재현율 {recall:.3f}")

  by_rule = Counter(detected[r]["rule"]["id"] for r in tp)
  print("정탐 룰별:", dict(by_rule))
  if fn:
    miss = Counter(api_key({"method": "", "uri": truth[r]["uri"]}).strip() for r in fn)   # 정답지에 method가 없어 경로만
    print("미탐 API별:", dict(miss))
  if fp:
    print("오탐 예시:")
    for r in list(fp)[:5]:
      print("  ", detected[r]["reason"])

  # 정답지에 scenario 열이 있으면 시나리오별 탐지율
  by_scenario = {}
  if any(t.get("scenario") for t in truth.values()):
    print("시나리오별:")
    for sc in sorted({t["scenario"] for t in truth.values()}):
      ids = {r for r, t in truth.items() if t["scenario"] == sc}
      hit = ids & detected.keys()
      rules = dict(Counter(detected[r]["rule"]["id"] for r in hit))
      by_scenario[sc] = {"total": len(ids), "detected": len(hit), "by_rule": rules}
      print(f"  {sc:18s} {len(hit):4d} / {len(ids):4d}  {rules}")
  # R4: 공격자(사용자) 단위 채점
  attackers = Counter(t["attacker_user_id"] for t in truth.values())
  incidents = [v for v in incidents if v["rule"]["id"] == "BOLA-R4"]   # 공격자 단위 채점은 R4만
  flagged = Counter(v["original"]["user_id"] for v in incidents)
  print("\n=== R4 사건 경보 (공격자 단위) ===")
  print(f"정답 공격자 {len(attackers)}명 / R4 경보 {len(incidents)}건, 경보받은 사용자 {len(flagged)}명")
  for user, n in sorted(attackers.items(), key=lambda x: -x[1]):
    print(f"  공격자 {user:>4s}: BOLA {n:4d}건 → R4 경보 {flagged.get(user, 0)}건")
  innocent = set(flagged) - set(attackers)
  if innocent:
    print("  공격자가 아닌데 R4 경보:", sorted(innocent))
  r4 = {"attackers": len(attackers), "flagged": len(set(flagged) & set(attackers)),
        "innocent_flagged": sorted(innocent), "incidents": len(incidents)}
  return {"tp": len(tp), "fn": len(fn), "fp": len(fp), "precision": precision, "recall": recall,
          "by_scenario": by_scenario, "r4": r4}


def summarize(events, violations):
  """서비스별 요약: 판정한 요청 수, 위반 수(룰별), 403/404로 막힌 요청 수(Wazuh 룰 담당)"""
  rows = defaultdict(lambda: {"requests": 0, "success": 0, "blocked_403_404": 0, "violations": 0, "by_rule": Counter()})
  for e in events:
    svc = e.get("api") or "unknown"
    r = rows[svc]
    r["requests"] += 1
    if e.get("status") and 200 <= e["status"] < 300:
      r["success"] += 1
    if e.get("status") in (403, 404) and e.get("user_id"):
      r["blocked_403_404"] += 1
  for v in violations:
    r = rows[v["original"].get("api") or "unknown"]
    if v["rule"]["id"] not in INCIDENT_RULES:           # 위반 칸은 요청 단위만, R4는 룰별에만
      r["violations"] += 1
    r["by_rule"][v["rule"]["id"]] += 1

  print("\n=== 서비스별 요약 ===")
  print(f"{'서비스':20s} {'요청':>6s} {'성공':>6s} {'403/404':>8s} {'BOLA 위반':>9s}  룰별")
  for svc, r in sorted(rows.items()):
    print(f"{svc:20s} {r['requests']:6d} {r['success']:6d} {r['blocked_403_404']:8d} {r['violations']:9d}  {dict(r['by_rule'])}")
  return {svc: {**r, "by_rule": dict(r["by_rule"])} for svc, r in rows.items()}


def load_service_truth(service_log_dir):
  """API 서버 로그(owner_id 포함)에서 정답 만들기: 200 응답인데 user_id ≠ owner_id → 실제 BOLA
  엔진은 이 로그를 판정에 쓰지 않고 채점에만 씀"""
  truth, logged = {}, set()
  for svc in sorted(os.listdir(service_log_dir)):
    path = os.path.join(service_log_dir, svc, "access.json")
    if not os.path.isfile(path):
      continue
    with open(path, encoding="utf-8", errors="replace") as f:
      for line in f:
        try:
          e = json.loads(line.strip().strip("\x00"))
        except json.JSONDecodeError:
          continue
        logged.add(e.get("request_id"))
        if (e.get("status") == 200 and e.get("owner_id") is not None and e.get("user_id") is not None
            and e["owner_id"] != e["user_id"] and e.get("request_id")):
          truth[e["request_id"]] = e
  return truth, logged


def evaluate_service_logs(events, violations, service_log_dir):
  """위반 결과를 API 서버 로그의 owner_id(실제 주인)와 비교해 채점"""
  violations, _ = _split(violations)
  truth_all, logged = load_service_truth(service_log_dir)
  seen = {e.get("request_id") for e in events}
  truth = {k: v for k, v in truth_all.items() if k in seen}     # Kong 로그가 있는 요청만 채점 가능
  detected = {v["original"]["request_id"]: v for v in violations}

  tp = truth.keys() & detected.keys()
  fn = truth.keys() - detected.keys()
  fp = (detected.keys() & logged) - truth_all.keys()             # 서버 로그가 있는데 BOLA가 아닌 요청
  print("\n=== 평가 (API 서버 로그의 owner_id 기준) ===")
  print(f"서버 로그상 BOLA {len(truth_all)}건 중 Kong 로그가 있는 {len(truth)}건을 채점")
  print(f"정탐 {len(tp)}  미탐 {len(fn)}  오탐 {len(fp)}")
  print("정답 서비스별:", dict(Counter(v["service"] for v in truth.values())))
  for r in list(fn)[:5]:
    t = truth[r]
    print(f"  미탐: {t['service']} {t['method']} {t['path']} 요청자 {t['user_id']} 주인 {t['owner_id']}")
  for r in list(fp)[:5]:
    print("  오탐:", detected[r]["reason"])
  return {"graded": len(truth), "tp": len(tp), "fn": len(fn), "fp": len(fp)}
