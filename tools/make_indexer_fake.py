"""Wazuh Indexer(bola-api-*)에서 가져온 것과 같은 모양의 가짜 BOLA-APP 로그 + 정답지 만들기

역할: 시험 데이터 생성 도구 (엔진 실행에는 필요 없음). 학원 Indexer를 건드리지 않고 R1~R6를 한 번에 시험할 때 씀.

- 문서 한 줄 = bola-api-* 문서의 _source (timestamp, api, identity, source, full_log, raw_event ...)
- API 동작은 BOLA-APP 서버 코드를 흉내냄 (DB 없이 가상 데이터 사용)
    members, orders  : BOLA_VULNERABLE=true → 남의 객체도 200
    payments, profiles: 소유권 검사 → 남의 객체는 403, 없는 객체는 404
- resp_ids는 Kong body_filter 추출 규칙(id, *_id, *Id, *_no)을 그대로 따름

넣는 시나리오 (정답지 scenario 열, 기대 룰)
  r1_enum_fast   : 공격자 7이 회원 10~16 정보·주소를 몰아서 조회       → R1, R4(급속), R6
  r1_slow        : 공격자 13이 남의 주문을 몇 시간 간격으로 조회         → R1, R4(저속)
  r2_known       : 공격자 21이 주인이 목록을 본 주문을 취소·메모 변경    → R2
  r3_unknown     : 공격자 21이 한 번도 로그에 안 나온 주문의 메모 변경   → R3
  r5_path        : 공격자 9가 주소 없는 회원의 주소 목록·HEAD 요청       → R5
  r6_scan_403    : 공격자 25가 결제 ID를 연속으로 찔러 봄 (보안 서비스)   → R6 (BOLA 아님, ATTEMPT)
  r6_scan_404    : 공격자 25가 없는 주문 ID를 연속으로 찔러 봄           → R6 (BOLA 아님, ATTEMPT)
  정상           : 일반 사용자 본인 데이터 조회·본인 주문 취소, 관리자 조회, 토큰 재발급(401)

사용법 (bola-rule 에서):
  python tools/make_indexer_fake.py              # 기본 약 1000건
  python tools/make_indexer_fake.py --count 3000
  python main.py replay data/indexer_fake.jsonl --truth data/indexer_fake_truth.csv
결과:
  data/indexer_fake.jsonl        가짜 Indexer 문서 (timestamp 순)
  data/indexer_fake_truth.csv    공격 요청 정답지 (평가용, 엔진이 읽으면 안 됨)
"""
import argparse
import csv
import json
import os
import random
import re
import string
import uuid
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_LOG = os.path.join(BASE, "data", "indexer_fake.jsonl")
OUT_TRUTH = os.path.join(BASE, "data", "indexer_fake_truth.csv")

KST = timezone(timedelta(hours=9))
UTC = timezone.utc
START = datetime(2026, 10, 27, 9, 0, tzinfo=KST)        # 이틀치 로그
DAY = timedelta(days=1)
VULNERABLE = {"members", "orders"}
AGENT = {"ip": "172.21.0.2", "name": "pc1-bola", "id": "003"}
LOCATION = "/logs/kong/access.json"

ACTIVE = list(range(1, 31))                              # 로그인하는 사용자
INACTIVE = list(range(31, 41))                           # 이틀 동안 접속하지 않는 사용자 (R3 대상 주문의 주인)
ADMIN = 100
ATTACKERS = {"r1_enum_fast": 7, "r5_path": 9, "r1_slow": 13, "r2r3": 21, "r6_scan": 25}

rng = random.Random(42)


# ---------------------------------------------------------------- 가상 DB
def make_db():
  """가상 DB 생성: 사용자(활성·비활성·관리자), 주소, 쿠폰, 주문, 결제"""
  db = {"users": {u: "user" for u in ACTIVE + INACTIVE}, "addresses": {}, "coupons": {},
        "orders": {}, "payments": {}}
  db["users"][ADMIN] = "admin"
  aid = cid = 0
  for u in ACTIVE + INACTIVE:
    db["addresses"][u] = []
    for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
      aid += 1
      db["addresses"][u].append(aid)
    db["coupons"][u] = []
    for _ in range(rng.choice([0, 1, 2])):
      cid += 1
      db["coupons"][u].append(cid)
  pid = 0
  for oid in range(1, 201):
    u = rng.choice(ACTIVE + INACTIVE)
    status = rng.choice(["pending", "paid", "paid", "shipped"])
    coupon = rng.choice(db["coupons"][u]) if db["coupons"][u] and rng.random() < 0.3 else None
    db["orders"][oid] = {"user_id": u, "status": status, "coupon_id": coupon}
    if status != "pending":
      pid += 1
      db["payments"][pid] = {"order_id": oid, "user_id": u, "transaction_id": f"TX{oid:06d}"}
  db["addr_owner"] = {a: u for u, ids in db["addresses"].items() for a in ids}
  db["orders_of"] = {u: sorted(o for o, v in db["orders"].items() if v["user_id"] == u) for u in db["users"]}
  db["payments_of"] = {u: sorted(p for p, v in db["payments"].items() if v["user_id"] == u) for u in db["users"]}
  return db


# ---------------------------------------------------------------- Kong body_filter와 같은 ID 추출
def is_id_key(k):
  """Kong extract_ids와 같은 기준으로 ID 같은 키인지 판단 (id, *_id, *Id, *_no)"""
  low = k.lower()
  return low == "id" or low.endswith("_id") or re.search(r"[a-z]Id$", k) is not None or low.endswith("_no")


def extract_ids(data):
  """응답 본문에서 ID 같은 키의 값을 모아 resp_ids를 만듦 (Kong body_filter Lua 흉내)"""
  out, seen = {}, set()

  def walk(v, path, depth):
    """본문을 깊이 4까지 따라가며 ID 값을 모음 (목록은 앞 20개만)"""
    if not isinstance(v, (dict, list)) or depth > 4 or len(seen) >= 50:
      return
    if isinstance(v, list):
      for item in v[:20]:
        walk(item, path + "[]", depth + 1)
      return
    for k, val in v.items():
      p = k if path == "" else f"{path}.{k}"
      if isinstance(val, (dict, list)):
        walk(val, p, depth + 1)
      elif val is not None and not isinstance(val, bool) and is_id_key(k):
        s = str(val)
        if len(s) <= 64 and (p, s) not in seen:
          seen.add((p, s))
          out.setdefault(p, []).append(s)

  walk(data, "", 0)
  return out


# ---------------------------------------------------------------- API 서버 동작 흉내
def owner_of(db, uri):
  """실제 주인 (정답지용). 목록 API·없는 객체는 None"""
  parts = uri.strip("/").split("/")
  if len(parts) < 2 or not parts[1].isdigit():
    return None
  svc, n = parts[0], int(parts[1])
  if svc in ("members", "profiles"):
    if len(parts) == 4:
      return n if db["addr_owner"].get(int(parts[3])) == n else None
    return n if n in db["users"] else None
  if svc == "orders":
    return (db["orders"].get(n) or {}).get("user_id")
  if svc == "payments":
    return (db["payments"].get(n) or {}).get("user_id")
  return None


def call(db, me, role, method, uri):
  """(서비스 이름, status, 응답 본문 또는 None). HEAD는 GET과 같이 처리하고 본문 없음"""
  parts = uri.strip("/").split("/")
  svc = parts[0]
  owner = owner_of(db, uri)
  if len(parts) >= 2:
    if owner is None:
      return f"{svc}-service", 404, None
    if not (svc in VULNERABLE or role == "admin" or owner == me):
      return f"{svc}-service", 403, None
  body = None
  if svc == "members":
    if len(parts) == 2:
      body = {"user_id": owner, "username": "x", "name": "x", "phone": "x", "email": "x"}
    elif len(parts) == 3:
      body = [{"id": a, "user_id": owner, "label": "집"} for a in db["addresses"][owner]]
    else:
      body = {"id": int(parts[3]), "user_id": owner, "label": "집"}
  elif svc == "profiles":
    if len(parts) == 2:
      body = {"user_id": owner, "name": "x", "grade": "GOLD", "order_status_counts": {"paid": 1}}
    else:
      body = [{"id": c, "name": "쿠폰"} for c in db["coupons"][owner]]
  elif svc == "orders":
    if len(parts) == 1:
      body = [{"id": o, "order_number": f"ORD{o:06d}", "status": "paid"} for o in reversed(db["orders_of"][me])]
    else:
      oid = int(parts[1])
      o = db["orders"][oid]
      if len(parts) == 2:
        body = {"id": oid, "order_number": f"ORD{oid:06d}", "user_id": o["user_id"], "coupon_id": o["coupon_id"],
                "items": [{"product_name": "x", "unit_price": 1000, "quantity": 1}]}
      elif parts[2] == "cancel":
        body = {"id": oid, "order_number": f"ORD{oid:06d}", "status": "cancelled"}
      else:
        body = {"id": oid, "order_number": f"ORD{oid:06d}", "delivery_memo": "문 앞"}
  elif svc == "payments":
    if len(parts) == 1:
      body = [{"id": p, "order_id": db["payments"][p]["order_id"]} for p in reversed(db["payments_of"][me])]
    else:
      pid = int(parts[1])
      body = {"id": pid, **db["payments"][pid], "order_number": "ORD"}
  return f"{svc}-service", 200, (None if method == "HEAD" else body)


# ---------------------------------------------------------------- Kong 로그 → Indexer 문서
def to_indexer(e):
  """Kong 로그 한 줄을 Wazuh를 거쳐 bola-api-*에 저장된 문서 모양으로"""
  ingest = e["started_at"] + rng.randint(200, 4000)      # Filebeat·manager를 거치는 지연
  ts = datetime.fromtimestamp(ingest / 1000, UTC)
  iso = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}"
  full_log = json.dumps(e, ensure_ascii=False, separators=(",", ":"))
  # Wazuh json 디코더: 숫자는 문자열로, "[].id" 같은 키는 점(.)에서 중첩
  data = {k: (str(v) if isinstance(v, int) else v) for k, v in e.items() if k != "resp_ids"}
  data["started_at"] = f"{e['started_at']}.000000"
  if e.get("resp_ids"):
    nested = {}
    for k, v in e["resp_ids"].items():
      head, _, rest = k.partition(".")
      if rest:
        nested.setdefault(head, {})[rest] = v
      else:
        nested[k] = v
    data["resp_ids"] = nested
  path, _, _ = e["uri"].partition("?")
  return {
    "timestamp": iso + "+00:00",
    "api": {"method": e["method"], "path": path, "request_target": e["uri"], "query": {},
            "service": e["api"], "status": e["status"]},
    "request_id": e["request_id"],
    "identity": {"user_id": e.get("user_id"), "role": e.get("role")},
    "source": {"location": LOCATION, "agent": AGENT, "index": f"wazuh-archives-4.x-{ts:%Y.%m.%d}",
               "document_id": "".join(rng.choices(string.ascii_letters + string.digits, k=20))},
    "classification": {"parser": "json", "reason": "explicit_api_field", "version": 1},
    "full_log": full_log,
    "raw_event": {"agent": AGENT, "manager": {"name": "wazuh.manager"}, "data": data, "decoder": {"name": "json"},
                  "full_log": full_log, "input": {"type": "log"}, "@timestamp": iso + "Z", "location": LOCATION,
                  "id": f"{ingest // 1000}.{rng.randint(1000, 999999)}", "timestamp": iso + "+0000"},
  }


class Writer:
  """가짜 요청을 가상 API에 보내 Kong 로그 모양으로 모으고, 공격 요청은 정답지에 기록"""
  def __init__(self, db):
    """db: make_db()로 만든 가상 DB"""
    self.db = db
    self.events = []
    self.truth = []

  def log(self, t, method, uri, me=None, role="user", scenario=None, status=None, api=None):
    """요청 1건을 가상 API로 처리해 Kong 로그 1건을 만들고, scenario가 있으면 정답지에도 추가"""
    body = None
    if me is not None:
      api, status, body = call(self.db, me, role, method, uri)
    e = {
      "request_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
      "latency_ms": rng.randint(3, 40),
      "uri": uri,
      "time": t.astimezone(KST).isoformat(timespec="seconds"),
      "api": api,
      "status": status,
      "method": method,
      "client_ip": "172.20.0.1",
      "started_at": int(t.timestamp() * 1000),
    }
    if me is not None:
      ids = extract_ids(body) if status == 200 and body is not None else {}
      if ids:
        e["resp_ids"] = ids
      e["user_id"] = str(me)
      e["role"] = role
      owner = owner_of(self.db, uri)
      if role != "admin" and str(owner) != str(me):
        if status == 200 and owner is not None:
          self.truth.append((e, "BOLA", me, scenario or "unexpected"))
        elif status in (403, 404) and scenario:
          self.truth.append((e, "ATTEMPT", me, scenario))
    self.events.append(e)
    return status


def step(t, lo=0.3, hi=4.0):
  """t에서 lo~hi초 뒤의 시각 (요청 사이 간격)"""
  return t + timedelta(seconds=rng.uniform(lo, hi))


# ---------------------------------------------------------------- 정상 행동
def normal_visit(w, me, t):
  """웹 화면 흐름: 로그인 → 프로필 → (회원정보/주소) → (주문, 가끔 본인 주문 취소) → (결제) → (쿠폰)"""
  db = w.db
  w.log(t, "POST", "/auth/login", status=200, api="auth-service")
  t = step(t)
  w.log(t, "GET", f"/profiles/{me}", me)
  if rng.random() < 0.6:
    t = step(t)
    w.log(t, "GET", f"/members/{me}", me)
    t = step(t, 0.05, 0.3)
    w.log(t, "GET", f"/members/{me}/addresses", me)
    for a in db["addresses"][me]:
      if rng.random() < 0.3:
        t = step(t)
        w.log(t, "GET", f"/members/{me}/addresses/{a}", me)
  if rng.random() < 0.7:
    t = step(t)
    w.log(t, "GET", "/orders", me)
    for o in db["orders_of"][me]:
      if rng.random() < 0.5:
        t = step(t, 1, 8)
        w.log(t, "GET", f"/orders/{o}", me)
    if db["orders_of"][me] and rng.random() < 0.15:
      t = step(t, 2, 10)
      o = rng.choice(db["orders_of"][me])
      if rng.random() < 0.5:
        w.log(t, "POST", f"/orders/{o}/cancel", me)
      else:
        w.log(t, "PATCH", f"/orders/{o}/delivery-memo", me)
  if rng.random() < 0.5:
    t = step(t)
    w.log(t, "GET", "/payments", me)
    for p in db["payments_of"][me]:
      if rng.random() < 0.5:
        t = step(t, 1, 8)
        w.log(t, "GET", f"/payments/{p}", me)
  if rng.random() < 0.3:
    t = step(t)
    w.log(t, "GET", f"/profiles/{me}/coupons", me)
  if rng.random() < 0.1:                                 # 토큰 만료 → 401 → 재발급
    t = step(t, 60, 900)
    w.log(t, "GET", f"/profiles/{me}", status=401, api="profiles-service")
    t = step(t, 0.05, 0.2)
    w.log(t, "POST", "/auth/refresh", status=200, api="auth-service")
    t = step(t, 0.05, 0.2)
    w.log(t, "GET", f"/profiles/{me}", me)
  if rng.random() < 0.3:
    t = step(t, 5, 60)
    w.log(t, "POST", "/auth/logout", status=204, api="auth-service")


def admin_visit(w, t):
  """관리자가 여러 회원과 주문을 조회하는 세션 (exclude_roles로 판정 제외돼야 함)"""
  w.log(t, "POST", "/auth/login", status=200, api="auth-service")
  for _ in range(rng.randint(3, 8)):
    u = rng.choice(ACTIVE)
    t = step(t, 2, 20)
    w.log(t, "GET", f"/members/{u}", ADMIN, "admin")
    if w.db["orders_of"][u] and rng.random() < 0.5:
      t = step(t)
      w.log(t, "GET", f"/orders/{rng.choice(w.db['orders_of'][u])}", ADMIN, "admin")


# ---------------------------------------------------------------- 공격 시나리오
def attacks(w):
  """공격 시나리오(R1 빠른·느린 열거, R2·R3, R5, R6 403·404 스캔)를 넣음"""
  db = w.db
  day2 = START + DAY

  # R1 + R4(급속) + R6: 회원 10~16 정보·주소를 몰아서 조회
  me, t = ATTACKERS["r1_enum_fast"], day2 + timedelta(hours=2)
  w.log(t, "POST", "/auth/login", status=200, api="auth-service")
  for u in range(10, 17):
    t = step(t, 0.3, 1.0)
    w.log(t, "GET", f"/members/{u}", me, scenario="r1_enum_fast")
    t = step(t, 0.1, 0.4)
    w.log(t, "GET", f"/members/{u}/addresses", me, scenario="r1_enum_fast")

  # R1 + R4(저속): 남의 주문을 1~3시간 간격으로 조회 (ID는 띄엄띄엄 → R6 아님)
  me, t = ATTACKERS["r1_slow"], day2 + timedelta(hours=1)
  owners_used, picks = set(), []
  for o in rng.sample(range(1, 201), 200):
    u = db["orders"][o]["user_id"]
    if u in ACTIVE and u != me and u not in owners_used and all(abs(o - p) > 3 for p in picks):
      owners_used.add(u)
      picks.append(o)
    if len(picks) == 6:
      break
  for o in picks:
    t += timedelta(minutes=rng.randint(60, 180))
    w.log(t, "POST", "/auth/login", status=200, api="auth-service")
    w.log(step(t), "GET", f"/orders/{o}", me, scenario="r1_slow")

  # R2: 주인이 먼저 목록을 본(장부에 주인이 있는) 주문을 취소·메모 변경
  me, t = ATTACKERS["r2r3"], day2 + timedelta(hours=6)
  known = [o for o, v in db["orders"].items() if v["user_id"] in ACTIVE and v["user_id"] != me]
  for o in rng.sample(known, 6):
    owner = db["orders"][o]["user_id"]
    seen_t = t - timedelta(hours=rng.randint(2, 20))
    w.log(seen_t, "POST", "/auth/login", status=200, api="auth-service")
    w.log(step(seen_t), "GET", "/orders", owner)            # 주인이 내 주문 목록을 봄 → 장부에 기록
    t += timedelta(minutes=rng.randint(10, 40))
    if rng.random() < 0.5:
      w.log(t, "POST", f"/orders/{o}/cancel", me, scenario="r2_known")
    else:
      w.log(t, "PATCH", f"/orders/{o}/delivery-memo", me, scenario="r2_known")

  # R3: 접속하지 않는 사용자의 주문(로그에 한 번도 안 나옴)의 메모 변경
  unseen = [o for o, v in db["orders"].items() if v["user_id"] in INACTIVE]
  for o in rng.sample(unseen, 4):
    t += timedelta(minutes=rng.randint(10, 40))
    w.log(t, "PATCH", f"/orders/{o}/delivery-memo", me, scenario="r3_unknown")

  # R5: 주소 없는 회원의 주소 목록(빈 응답 → resp_ids 없음), 본문 없는 HEAD
  me, t = ATTACKERS["r5_path"], day2 + timedelta(hours=10)
  w.log(t, "POST", "/auth/login", status=200, api="auth-service")
  empty = [u for u in ACTIVE if not db["addresses"][u] and u != me]
  for u in rng.sample(empty, min(4, len(empty))):
    t += timedelta(minutes=rng.randint(3, 15))
    w.log(t, "GET", f"/members/{u}/addresses", me, scenario="r5_path")
  for u in rng.sample([u for u in ACTIVE if u != me], 2):
    t += timedelta(minutes=rng.randint(3, 15))
    w.log(t, "HEAD", f"/members/{u}", me, scenario="r5_path")

  # R6: 결제 ID 연속 탐색 (보안 서비스라 403), 없는 주문 ID 연속 탐색 (404)
  me, t = ATTACKERS["r6_scan"], day2 + timedelta(hours=12)
  w.log(t, "POST", "/auth/login", status=200, api="auth-service")
  mine = set(db["payments_of"][me])
  first = next(p for p in range(10, 200) if not mine & set(range(p, p + 8)))
  for p in range(first, first + 8):
    t = step(t, 0.5, 2.0)
    w.log(t, "GET", f"/payments/{p}", me, scenario="r6_scan_403")
  t += timedelta(minutes=5)
  for o in range(901, 908):
    t = step(t, 0.5, 2.0)
    w.log(t, "GET", f"/orders/{o}", me, scenario="r6_scan_404")


def main():
  """가상 DB → 공격 → 정상 세션으로 목표 건수를 채우고 jsonl과 정답지 CSV로 저장"""
  p = argparse.ArgumentParser(description="bola-api-* 모양의 가짜 로그 생성")
  p.add_argument("--count", type=int, default=1000, help="대략적인 문서 수 (기본 1000)")
  args = p.parse_args()

  db = make_db()
  w = Writer(db)
  attacks(w)
  # 정상 세션을 이틀에 고르게 넣어 목표 건수를 채움 (공격자도 평소엔 본인 데이터만 봄)
  while len(w.events) < args.count:
    t = START + timedelta(seconds=rng.uniform(0, 2 * 86400 - 3600))
    if rng.random() < 0.05:
      admin_visit(w, t)
    else:
      normal_visit(w, rng.choice(ACTIVE), t)

  docs = sorted((to_indexer(e) for e in w.events), key=lambda d: d["timestamp"])
  os.makedirs(os.path.dirname(OUT_LOG), exist_ok=True)
  with open(OUT_LOG, "w", encoding="utf-8") as f:
    for d in docs:
      f.write(json.dumps(d, ensure_ascii=False) + "\n")

  with open(OUT_TRUTH, "w", encoding="utf-8", newline="") as f:
    cw = csv.writer(f)
    cw.writerow(["request_id", "started_at", "label", "attacker_user_id", "uri", "status", "scenario"])
    for e, label, who, sc in sorted(w.truth, key=lambda x: x[0]["started_at"]):
      cw.writerow([e["request_id"], e["started_at"], label, who, e["uri"], e["status"], sc])

  counts = {}
  for _, label, _, sc in w.truth:
    counts[(sc, label)] = counts.get((sc, label), 0) + 1
  print(f"문서 {len(docs)}건 → {OUT_LOG}")
  print(f"정답지 {len(w.truth)}건 → {OUT_TRUTH}")
  for (sc, label), n in sorted(counts.items()):
    print(f"  {sc:14s} {label:8s} {n:3d}")


if __name__ == "__main__":
  main()
