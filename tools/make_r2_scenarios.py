"""가짜 로그에 R2(장부 주인 불일치) 시나리오를 섞은 새 로그 + 정답지 만들기

응답에 주인(user_id)이 없는 API를 사용:
  POST  /orders/{id}/cancel          → 응답 {id, order_number, status}        → resp_ids {"id": [...]}
  PATCH /orders/{id}/delivery-memo   → 응답 {id, order_number, delivery_memo} → resp_ids {"id": [...]}
(orders 서비스는 BOLA_VULNERABLE=true 이므로 남의 주문이어도 200)

넣는 시나리오 (정답지 scenario 열)
  r2_normal       : 주인이 자기 주문을 취소·메모 변경 (위반 아님 → 오탐이 나면 안 됨)
  r2_attack_known : 공격자가 '이미 장부에 주인이 기록된' 남의 주문을 취소·메모 변경 (R2로 잡혀야 함)
  r2_attack_early : 공격자가 '주인이 로그에 처음 나타나기 전에' 그 주문을 건드림 (장부에 없음 → 엔진 한계, 미탐 예상)

주문의 실제 주인은 가짜 로그의 GET /orders(내 주문 목록) 응답으로 정함 (생성기가 실제 DB로 만든 값)

사용법 (PYTHON-ENGIN 에서):
  python tools/make_r2_scenarios.py
결과:
  data/access_fake_r2.json      원본 가짜 로그 + R2 이벤트 (시간순)
  data/attacks_truth_r2.csv     원본 정답지 + R2 공격 (scenario 열 추가)
"""
import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(BASE, "BOLA-APP", "engine", "data")
SRC_LOG = os.path.join(APP, "access_fake.json")
SRC_TRUTH = os.path.join(APP, "attacks_truth.csv")
OUT_LOG = os.path.join(BASE, "data", "access_fake_r2.json")
OUT_TRUTH = os.path.join(BASE, "data", "attacks_truth_r2.csv")

KST = timezone(timedelta(hours=9))
SEED = 7
N_NORMAL = 300          # 주인 본인의 취소·메모 변경
N_ATTACK_KNOWN = 80     # 장부에 주인이 있는 남의 주문 공격
N_ATTACK_EARLY = 20     # 주인이 나타나기 전 공격 (엔진이 못 잡는 경우)
ATTACKERS = ["31", "58", "77"]

rng = random.Random(SEED)


def load():
  logs = []
  with open(SRC_LOG, encoding="utf-8") as f:
    for line in f:
      line = line.strip()
      if line:
        logs.append(json.loads(line))
  return logs


def order_owners(logs):
  """GET /orders 응답의 [].id → 주문 주인, 주문이 로그에 처음 나타난 시각"""
  owner, first_seen = {}, {}
  for e in logs:
    if e.get("method") == "GET" and e.get("uri") == "/orders" and e.get("status") == 200:
      for oid in (e.get("resp_ids") or {}).get("[].id", []):
        owner.setdefault(oid, e["user_id"])
    if e.get("uri", "").startswith("/orders/") and e.get("status") == 200:
      oid = e["uri"].split("/")[2]
      first_seen[oid] = min(first_seen.get(oid, e["started_at"]), e["started_at"])
    if e.get("uri") == "/orders" and e.get("status") == 200:
      for oid in (e.get("resp_ids") or {}).get("[].id", []):
        first_seen[oid] = min(first_seen.get(oid, e["started_at"]), e["started_at"])
  return owner, first_seen


def event(user, method, oid, ts, status=200):
  action = "cancel" if method == "POST" else "delivery-memo"
  return {
    "time": datetime.fromtimestamp(ts / 1000, KST).isoformat(timespec="seconds"),
    "started_at": ts,
    "request_id": str(uuid.UUID(int=rng.getrandbits(128))),
    "client_ip": "172.20.0.1",
    "method": method,
    "uri": f"/orders/{oid}/{action}",
    "api": "orders-service",
    "status": status,
    "latency_ms": rng.randint(3, 20),
    "user_id": user,
    "role": "user",
    "resp_ids": {"id": [oid]},
  }


def main():
  logs = load()
  start, end = logs[0]["started_at"], logs[-1]["started_at"]
  attack_start = end - 4 * 86400 * 1000                     # 기존 공격과 같은 '마지막 며칠'
  owner, first_seen = order_owners(logs)
  orders = sorted(owner, key=int)
  new, truth = [], []

  # 1) 정상: 주인이 자기 주문을 처음 본 뒤에 취소·메모 변경
  for _ in range(N_NORMAL):
    oid = rng.choice(orders)
    ts = rng.randint(first_seen[oid] + 1000, end)
    new.append(event(owner[oid], rng.choice(["POST", "PATCH"]), oid, ts))

  # 2) 공격(장부에 있음): 공격 기간 이전에 이미 로그에 나타난 남의 주문
  known = [o for o in orders if first_seen[o] < attack_start and owner[o] not in ATTACKERS]
  for _ in range(N_ATTACK_KNOWN):
    oid, who = rng.choice(known), rng.choice(ATTACKERS)
    ts = rng.randint(attack_start, end)
    e = event(who, rng.choice(["POST", "PATCH"]), oid, ts)
    new.append(e)
    truth.append((e, who, "r2_attack_known"))

  # 3) 공격(장부에 없음): 주인이 처음 나타나기 전에 공격 → 엔진은 주인을 모름
  late = [o for o in orders if first_seen[o] > start + 86400 * 1000 and owner[o] not in ATTACKERS]
  for oid in rng.sample(late, min(N_ATTACK_EARLY, len(late))):
    who = rng.choice(ATTACKERS)
    ts = rng.randint(max(start, first_seen[oid] - 6 * 3600 * 1000), first_seen[oid] - 1000)
    e = event(who, rng.choice(["POST", "PATCH"]), oid, ts)
    new.append(e)
    truth.append((e, who, "r2_attack_early"))

  merged = sorted(logs + new, key=lambda e: e["started_at"])
  os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
  with open(OUT_LOG, "w", encoding="utf-8") as f:
    for e in merged:
      f.write(json.dumps(e, ensure_ascii=False) + "\n")

  with open(SRC_TRUTH, encoding="utf-8") as f:
    old = list(csv.DictReader(f))
  with open(OUT_TRUTH, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["request_id", "started_at", "label", "attacker_user_id", "uri", "status", "scenario"])
    for r in old:
      w.writerow([r["request_id"], r["started_at"], r["label"], r["attacker_user_id"], r["uri"], r["status"],
                  "r1_original" if r["label"] == "BOLA" else "attempt_original"])
    for e, who, sc in truth:
      w.writerow([e["request_id"], e["started_at"], "BOLA", who, e["uri"], e["status"], sc])

  print(f"원본 {len(logs)}줄 + R2 이벤트 {len(new)}줄 → {OUT_LOG}")
  print(f"  정상(주인 본인) {N_NORMAL}, 공격(장부 있음) {N_ATTACK_KNOWN}, 공격(장부 없음) {len(truth) - N_ATTACK_KNOWN}")
  print(f"정답지 → {OUT_TRUTH}")


if __name__ == "__main__":
  main()
