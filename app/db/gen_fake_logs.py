"""PostgreSQL의 실제 데이터로 과거 기간의 가짜 Kong 로그를 대량 생성 (쇼핑몰 화면 흐름 기준)

- 비로그인 방문자: 메인 → 상품 목록 → 상품 상세 (공개 API라 로그에 user_id 없음)
- 정상 사용자: 로그인 → 상품 구경 · 장바구니 · 마이페이지 · 주문 상세 (자기 데이터만)
- 주문 · 리뷰: DB에 있는 주문과 리뷰를 그 작성 시각에 실제로 만든 것처럼 기록 (주문서 → POST /orders)
- 시각 순서 유지: 아직 만들어지지 않은 주문·결제·리뷰는 조회 결과에 나오지 않음 (없는 번호는 404)
- 관리자: 여러 사용자의 데이터를 정상적으로 조회
- 공격자: 마지막 며칠에만 BOLA 공격 (열거, 몰래 조회, 막힌 API·남의 장바구니·리뷰 찔러보기)
  (--attack-days 30 --attack-prob 0.1 이면 30일 내내 가끔씩 섞임)
- 응답의 resp_ids는 API 서버 코드의 응답 모양 + Kong body_filter 추출 규칙을 그대로 따라 만듦

사용법 (app 폴더에서, docker compose가 켜져 있어야 함):
  python db\\gen_fake_logs.py                    # 어제까지 30일, 평소의 10배 트래픽
  python db\\gen_fake_logs.py --scale 20         # 더 많이
  python db\\gen_fake_logs.py --end 2026-10-27   # 이 날 0시 직전(그 전날)까지 생성
  python db\\gen_fake_logs.py --scale 2 --attack-days 30 --attack-prob 0.1 --stealth-prob 0.2
                                                    # 30일 내내 공격이 가끔 섞여 있게
결과 (기존 파일은 *_old 로 이름 바꿔 보관):
  ..\\engine\\data\\access_fake.json     가짜 로그 (Kong 압축 로그 형식: 공백 없음, 필드 순서 제각각)
  ..\\engine\\data\\attacks_truth.csv    공격 요청의 정답지 (평가용, 엔진이 읽으면 안 됨)
"""
import argparse
import csv
import json
import os
import random
import re
import subprocess
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_LOG = os.path.join(ROOT, "..", "engine", "data", "access_fake.json")
OUT_TRUTH = os.path.join(ROOT, "..", "engine", "data", "attacks_truth.csv")
KST = timezone(timedelta(hours=9))
VULNERABLE = {"members", "orders"}          # BOLA_VULNERABLE=true 인 서비스
SERVICE = {"members": "members", "profiles": "profiles", "orders": "orders", "payments": "payments",
           "cart": "cart", "reviews": "catalog", "products": "catalog", "categories": "catalog", "auth": "auth"}
SORTS = ["popular", "popular", "new", "price_asc", "price_desc", "rating"]
SEARCH_WORDS = ["키보드", "마우스", "모니터", "헤드폰", "텀블러", "맨투맨", "감귤", "크림", "백팩", "SSD", "케이블"]


# ---------------------------------------------------------------- DB 조회
def query(sql):
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "bola", "-d", "bola",
         "-At", "-F", "|", "-c", sql],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout
    return [line.split("|") for line in out.splitlines() if line]


def ts(v):
    """psql 시각 문자열 → datetime (없으면 None)"""
    return datetime.fromisoformat(v.replace(" ", "T")) if v else None


def load_db():
    db = {
        "users": {int(i): role for i, role in query("SELECT id, role FROM users")},
        "addresses": defaultdict(list),
        "coupons": defaultdict(list),
        "orders": {},
        "payments": {},
        "reviews": {},
        "cart": defaultdict(list),
        "products": [int(i) for (i,) in query("SELECT id FROM products ORDER BY id")],
        "categories": [int(i) for (i,) in query("SELECT id FROM categories ORDER BY sort_order")],
        "items_of": defaultdict(list),
    }
    for i, u in query("SELECT id, user_id FROM addresses ORDER BY id"):
        db["addresses"][int(u)].append(int(i))
    for i, u in query("SELECT id, user_id FROM coupons ORDER BY id"):
        db["coupons"][int(u)].append(int(i))
    for i, u, c, created, status in query("SELECT id, user_id, coupon_id, created_at, status FROM orders"):
        db["orders"][int(i)] = {"user_id": int(u), "coupon_id": int(c) if c else None,
                                "created": ts(created), "status": status}
    for o, p in query("SELECT order_id, COALESCE(product_id, 0) FROM order_items ORDER BY id"):
        db["items_of"][int(o)].append(int(p) or None)
    for i, o, u, t, paid in query("SELECT id, order_id, user_id, COALESCE(transaction_id, ''), paid_at FROM payments"):
        db["payments"][int(i)] = {"order_id": int(o), "user_id": int(u), "transaction_id": t or None,
                                  "paid": ts(paid) or db["orders"][int(o)]["created"]}
    for i, p, u, o, created in query("SELECT id, product_id, user_id, order_id, created_at FROM reviews"):
        db["reviews"][int(i)] = {"product_id": int(p), "user_id": int(u), "order_id": int(o), "created": ts(created)}
    for i, u, p in query("SELECT id, user_id, product_id FROM cart_items ORDER BY id"):
        db["cart"][int(u)].append({"id": int(i), "product_id": int(p)})

    db["addr_owner"] = {a: u for u, ids in db["addresses"].items() for a in ids}
    db["orders_of"] = defaultdict(list)
    for i, o in sorted(db["orders"].items()):
        db["orders_of"][o["user_id"]].append(i)
    db["payments_of"] = defaultdict(list)
    db["payment_of_order"] = {}
    for i, p in sorted(db["payments"].items()):
        db["payments_of"][p["user_id"]].append(i)
        db["payment_of_order"][p["order_id"]] = i
    db["reviews_of"] = defaultdict(list)
    db["reviews_on"] = defaultdict(list)
    for i, r in sorted(db["reviews"].items()):
        db["reviews_of"][r["user_id"]].append(i)
        db["reviews_on"][r["product_id"]].append(i)
    db["cart_owner"] = {it["id"]: u for u, items in db["cart"].items() for it in items}
    db["next_cart_id"] = max(db["cart_owner"], default=0) + 1
    return db


# ---------------------------------------------------------------- Kong body_filter와 같은 ID 추출
def is_id_key(k):
    l = k.lower()
    return l == "id" or l.endswith("_id") or re.search(r"[a-z]Id$", k) is not None or l.endswith("_no")


def extract_ids(data):
    out, seen, count = {}, set(), 0

    def walk(v, path, depth):
        nonlocal count
        if not isinstance(v, (dict, list)) or depth > 4 or count >= 50:
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
                    count += 1

    walk(data, "", 0)
    return out


# ---------------------------------------------------------------- API 서버 동작 흉내 (상태 코드 + 응답 본문)
class Shop:
    """시각 t 기준으로 DB에 '이미 있는' 것만 보이게 응답을 만듦"""

    def __init__(self, db):
        self.db = db

    def order_at(self, oid, t):
        o = self.db["orders"].get(oid)
        return o if o and o["created"] <= t else None

    def orders_of(self, me, t):
        return [o for o in self.db["orders_of"][me] if self.db["orders"][o]["created"] <= t]

    def payment_at(self, pid, t):
        p = self.db["payments"].get(pid)
        return p if p and p["paid"] <= t else None

    def payments_of(self, me, t):
        return [p for p in self.db["payments_of"][me] if self.db["payments"][p]["paid"] <= t]

    def review_at(self, rid, t):
        r = self.db["reviews"].get(rid)
        return r if r and r["created"] <= t else None

    def reviews_of(self, me, t):
        return [r for r in self.db["reviews_of"][me] if self.db["reviews"][r]["created"] <= t]

    def writable(self, me, t):
        done = {(r["order_id"], r["product_id"]) for r in map(self.db["reviews"].get, self.reviews_of(me, t))}
        return [(o, p) for o in self.orders_of(me, t) if self.db["orders"][o]["status"] == "delivered"
                for p in self.db["items_of"][o] if p and (o, p) not in done]

    def call(self, me, role, method, uri, t):
        """(service, status, 응답 본문 또는 None)"""
        db = self.db
        parts = uri.split("?")[0].strip("/").split("/")
        svc = parts[0]

        def owner_check(owner):
            if owner is None:
                return 404
            if svc in VULNERABLE or role == "admin" or owner == me:
                return 200
            return 403

        def result(st, body):
            return svc, st, body if st == 200 else None

        if svc == "members":
            uid = int(parts[1])
            exists = uid in db["users"]
            if len(parts) == 2:
                st = owner_check(uid if exists else None)
                if method == "PATCH":
                    return result(st, {"user_id": uid, "name": "x", "phone": "x", "email": "x"})
                return result(st, {"user_id": uid, "username": "x", "name": "x"})
            if len(parts) == 3:
                st = owner_check(uid if exists else None)
                return result(st, [{"id": a, "user_id": uid, "label": "집"} for a in db["addresses"][uid]])
            aid = int(parts[3])
            owner = uid if db["addr_owner"].get(aid) == uid else None   # WHERE id=$1 AND user_id=$2
            return result(owner_check(owner), {"id": aid, "user_id": uid, "label": "집"})

        if svc == "profiles":
            uid = int(parts[1])
            st = owner_check(uid if uid in db["users"] else None)
            if len(parts) == 2:
                return result(st, {"user_id": uid, "name": "x", "grade": "GOLD", "order_status_counts": {"paid": 1}})
            return result(st, [{"id": c, "name": "쿠폰"} for c in db["coupons"][uid]])

        if svc == "orders":
            if len(parts) == 1:
                if method == "POST":                                # 주문하기 (Nest 기본 201)
                    return svc, 201, None
                return svc, 200, [{"id": o, "order_number": "ORD"} for o in reversed(self.orders_of(me, t))]
            oid = int(parts[1])
            o = self.order_at(oid, t)
            st = owner_check(o["user_id"] if o else None)
            if len(parts) == 3:                                     # 취소 · 배송 메모
                return result(st, {"id": oid, "order_number": "ORD", "status": "x"})
            return result(st, {"id": oid, "order_number": "ORD", "user_id": o and o["user_id"],
                               "coupon_id": o and o["coupon_id"],
                               "items": [{"product_id": p, "product_name": "x"} for p in db["items_of"][oid]]})

        if svc == "payments":
            if len(parts) == 1:
                return svc, 200, [{"id": p, "order_id": db["payments"][p]["order_id"]}
                                  for p in reversed(self.payments_of(me, t))]
            pid = int(parts[1])
            p = self.payment_at(pid, t)
            st = owner_check(p["user_id"] if p else None)
            return result(st, p and {"id": pid, "order_id": p["order_id"], "user_id": p["user_id"],
                                     "transaction_id": p["transaction_id"], "order_number": "ORD"})

        if svc == "cart":
            if len(parts) == 1:
                return svc, 200, [{"id": it["id"], "product_id": it["product_id"]} for it in db["cart"][me]]
            if method == "POST":
                cid = db["next_cart_id"]
                db["next_cart_id"] += 1
                return svc, 201, None
            cid = int(parts[2])
            st = 403 if cid in db["cart_owner"] and db["cart_owner"][cid] != me else \
                (404 if cid not in db["cart_owner"] else 200)        # 장바구니는 안전 모드
            if method == "DELETE":
                return svc, 204 if st == 200 else st, None
            return result(st, {"id": cid, "product_id": 1, "quantity": 1})

        if svc == "reviews":
            if parts[1:] == ["me"]:
                return svc, 200, [{"id": r, "product_id": db["reviews"][r]["product_id"],
                                   "order_id": db["reviews"][r]["order_id"]} for r in reversed(self.reviews_of(me, t))]
            if parts[1:] == ["writable"]:
                return svc, 200, [{"order_id": o, "order_number": "ORD", "product_id": p} for o, p in self.writable(me, t)]
            if len(parts) == 1:                                     # 리뷰 작성 (201)
                return svc, 201, None
            rid = int(parts[1])
            r = self.review_at(rid, t)
            st = 404 if r is None else (200 if r["user_id"] == me else 403)   # 리뷰는 안전 모드
            if method == "DELETE":
                return svc, 204 if st == 200 else st, None
            return result(st, r and {"id": rid, "product_id": r["product_id"], "user_id": r["user_id"],
                                     "order_id": r["order_id"]})

        if svc in ("products", "categories"):                       # 공개 API (토큰 없음 → resp_ids 없음)
            return svc, 200, None

        raise ValueError(uri)


# ---------------------------------------------------------------- 로그 한 줄 만들기
class Writer:
    def __init__(self, db):
        self.shop = Shop(db)
        self.db = db
        self.lines = []
        self.truth = []

    def log(self, t, method, uri, me=None, role=None, label=None, status=None, svc=None):
        if me is None:                                  # 로그인 · 공개 API 등 토큰 없는 요청
            body = None
            if status is None:
                svc, status, _ = self.shop.call(None, None, method, uri, t)
        else:
            svc, status, body = self.shop.call(me, role, method, uri, t)
        e = {
            "time": t.astimezone(KST).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}+09:00",
            "started_at": int(t.timestamp() * 1000),
            "request_id": str(uuid.UUID(int=random.getrandbits(128), version=4)),
            "client_ip": "172.20.0.1",
            "method": method,
            "uri": uri,
            "api": f"{SERVICE[svc]}-service",
            "status": status,
            "latency_ms": random.randint(3, 40) if method == "GET" else random.randint(8, 120),
        }
        if me is not None:
            e["user_id"] = str(me)
            e["role"] = role
            if status == 200 and body is not None:
                ids = extract_ids(body)
                if ids:
                    e["resp_ids"] = ids
        keys = list(e)
        random.shuffle(keys)                            # Kong(Lua) 로그는 필드 순서가 줄마다 다름
        # 딕셔너리 대신 완성된 한 줄(문자열)로 보관 → 로그가 수백만 줄이어도 메모리를 적게 씀
        self.lines.append((e["started_at"], json.dumps({k: e[k] for k in keys}, ensure_ascii=False, separators=(",", ":"))))
        if label:                                       # 공격 요청: 데이터가 나갔으면 BOLA, 막혔으면 ATTEMPT
            kind = "BOLA" if status == 200 else "ATTEMPT"
            self.truth.append((e["request_id"], e["started_at"], kind, me, uri, status, method))
        return status, body


def step(t, lo=0.3, hi=4.0):
    return t + timedelta(seconds=random.uniform(lo, hi))


def burst(t):
    """한 화면이 불러오는 API들은 거의 동시에 나감"""
    return t + timedelta(milliseconds=random.randint(2, 60))


# ---------------------------------------------------------------- 화면 단위 (web/*.html 이 부르는 API 그대로)
class Browser:
    def __init__(self, w, me=None, role="user"):
        self.w, self.me, self.role = w, me, role

    def get(self, t, uri, label=None):
        if uri.startswith(("/products", "/categories")):
            return self.w.log(t, "GET", uri)                # 공개 API는 토큰을 보내지 않음
        return self.w.log(t, "GET", uri, self.me, self.role, label=label)

    def send(self, t, method, uri, label=None):
        return self.w.log(t, method, uri, self.me, self.role, label=label)

    def header(self, t):
        t = burst(t)
        self.get(t, "/categories")
        if self.me:
            t = burst(t)
            self.get(t, "/cart")
        return t

    def home(self, t):
        t = self.header(t)
        for uri in ("/categories", "/products?sort=popular&limit=8", "/products?sort=price_desc&limit=60"):
            t = burst(t)
            self.get(t, uri)
        return t

    def product_list(self, t):
        t = self.header(t)
        r = random.random()
        sort = random.choice(SORTS)
        if r < 0.5:
            uri = f"/products?sort={sort}&category={random.choice(self.w.db['categories'])}"
        elif r < 0.75:
            uri = f"/products?sort={sort}&q={random.choice(SEARCH_WORDS)}"
        else:
            uri = f"/products?sort={sort}"
        t = burst(t)
        self.get(t, uri)
        t = burst(t)
        self.get(t, "/categories")
        return t

    def product(self, t, pid):
        t = self.header(t)
        t = burst(t)
        self.get(t, f"/products/{pid}")
        t = burst(t)
        self.get(t, f"/products/{pid}/reviews")
        return t

    def cart_page(self, t):
        t = self.header(t)
        t = burst(t)
        self.get(t, "/cart")
        return t

    def mypage(self, t, tab="orders"):
        me = self.me
        t = self.header(t)
        t = burst(t)
        self.get(t, f"/profiles/{me}")
        t = burst(t)
        self.get(t, "/orders")
        t = burst(t)
        if tab == "orders":
            self.get(t, "/orders")
        elif tab == "payments":
            self.get(t, "/payments")
        elif tab == "coupons":
            self.get(t, f"/profiles/{me}/coupons")
        elif tab == "points":
            self.get(t, f"/profiles/{me}")
            self.get(burst(t), "/payments")
        elif tab == "addresses":
            self.get(t, f"/members/{me}/addresses")
        elif tab == "reviews":
            self.get(t, "/reviews/writable")
            self.get(burst(t), "/reviews/me")
        elif tab == "info":
            self.get(t, f"/members/{me}")
        return t

    def order_detail(self, t, oid, label=None):
        t = self.header(t)
        t = burst(t)
        st, body = self.get(t, f"/orders/{oid}", label=label)
        if st == 200:
            t = burst(t)
            _, pays = self.get(t, "/payments")
            pid = next((p["id"] for p in pays or [] if p["order_id"] == oid), None)
            if pid:                                         # 남의 주문이면 내 결제 목록에 없어서 조회 안 함
                t = burst(t)
                self.get(t, f"/payments/{pid}")
        return t

    def login(self, t):
        t = self.header(t)                                  # 로그인 화면 (아직 토큰 없음)
        t = step(t, 3, 12)
        self.w.log(t, "POST", "/auth/login", status=200, svc="auth")
        return t


# ---------------------------------------------------------------- 행동 시나리오
def browse_products(b, t, n_lo=1, n_hi=5):
    t = step(t, 1, 6)
    t = b.product_list(t)
    for _ in range(random.randint(n_lo, n_hi)):
        t = step(t, 3, 40)
        t = b.product(t, random.choice(b.w.db["products"]))
    return t


def anonymous_visit(w, t):
    b = Browser(w)
    t = b.home(t)
    browse_products(b, t, 0, 4)


def normal_visit(w, me, t):
    """로그인 사용자: 메인 → (상품 구경) → (마이페이지 · 주문 상세) → (장바구니)"""
    db, shop = w.db, w.shop
    b = Browser(w, me)
    t = b.login(t)
    t = step(t, 0.2, 1)
    t = b.home(t)
    if random.random() < 0.6:
        t = browse_products(b, t)
        if random.random() < 0.3:
            t = step(t, 1, 5)
            b.send(t, "POST", "/cart/items")
    if random.random() < 0.6:
        t = step(t, 2, 10)
        t = b.mypage(t, "orders")
        for o in shop.orders_of(me, t):
            if random.random() < 0.35:
                t = step(t, 2, 15)
                t = b.order_detail(t, o)
        for tab, p in (("payments", 0.2), ("coupons", 0.15), ("points", 0.1), ("addresses", 0.1),
                       ("reviews", 0.12), ("info", 0.1)):
            if random.random() < p:
                t = step(t, 2, 10)
                t = b.mypage(t, tab)
                if tab == "info" and random.random() < 0.05:
                    t = step(t, 5, 30)
                    b.send(t, "PATCH", f"/members/{me}")
    if random.random() < 0.3:
        t = step(t, 2, 10)
        t = b.cart_page(t)
        for it in db["cart"][me]:
            r = random.random()
            if r < 0.15:
                t = step(t, 1, 4)
                b.send(t, "PATCH", f"/cart/items/{it['id']}")
            elif r < 0.2:
                t = step(t, 1, 4)
                b.send(t, "DELETE", f"/cart/items/{it['id']}")
    if random.random() < 0.08:                                  # 토큰 만료 후 재발급
        t = step(t, 900, 1800)
        w.log(t, "GET", f"/profiles/{me}", status=401, svc="profiles")
        t = step(t, 0.05, 0.2)
        w.log(t, "POST", "/auth/refresh", status=200, svc="auth")
        t = step(t, 0.05, 0.2)
        b.get(t, f"/profiles/{me}")


def place_order(w, oid):
    """DB의 주문을 그 시각에 실제로 주문한 것처럼: 상품 → 장바구니 → 주문서 → 결제 → 주문 상세"""
    db = w.db
    o = db["orders"][oid]
    me = o["user_id"]
    b = Browser(w, me)
    items = [p for p in db["items_of"][oid] if p]
    t = o["created"] - timedelta(seconds=random.randint(120, 900))
    t = b.login(t)
    t = step(t, 0.2, 1)
    t = b.home(t)
    for p in items:
        t = step(t, 5, 40)
        t = b.product(t, p)
        t = step(t, 2, 8)
        b.send(t, "POST", "/cart/items")
    t = step(t, 2, 6)
    t = b.cart_page(t)
    t = step(t, 2, 6)
    t = b.header(t)                                             # checkout.html
    for uri in ("/cart", f"/members/{me}/addresses", f"/profiles/{me}/coupons", f"/profiles/{me}"):
        t = burst(t)
        b.get(t, uri)
    t = max(step(t, 10, 40), o["created"])
    b.send(t, "POST", "/orders")
    t = step(t, 0.3, 1.5)
    b.order_detail(t + timedelta(milliseconds=50), oid)


def write_review(w, rid):
    r = w.db["reviews"][rid]
    me = r["user_id"]
    b = Browser(w, me)
    t = r["created"] - timedelta(seconds=random.randint(60, 300))
    t = b.login(t)
    t = step(t, 0.2, 1)
    t = b.mypage(t, "reviews")
    t = max(step(t, 20, 90), r["created"])
    b.send(t, "POST", "/reviews")
    t = step(t, 0.3, 1)
    b.get(t, "/reviews/writable")
    b.get(burst(t), "/reviews/me")


def admin_visit(w, admin, users, t):
    b = Browser(w, admin, "admin")
    t = b.login(t)
    for _ in range(random.randint(3, 10)):
        u = random.choice(users)
        t = step(t, 2, 20)
        b.get(t, f"/members/{u}")
        orders = w.shop.orders_of(u, t)
        if random.random() < 0.5 and orders:
            t = step(t)
            b.get(t, f"/orders/{random.choice(orders)}")
        pays = w.shop.payments_of(u, t)
        if random.random() < 0.3 and pays:
            t = step(t)
            b.get(t, f"/payments/{random.choice(pays)}")


def attack_enumerate_members(w, me, t, max_id):
    """Burp Intruder처럼 /members/1 ~ /members/N 을 빠르게 훑기"""
    b = Browser(w, me)
    t = b.login(t)
    for uid in range(1, max_id + 10):
        t = step(t, 0.02, 0.15)
        st, _ = b.get(t, f"/members/{uid}", label="BOLA" if uid != me else None)
        if st == 200 and uid != me and random.random() < 0.5:
            t = step(t, 0.02, 0.1)
            b.get(t, f"/members/{uid}/addresses", label="BOLA")


def attack_enumerate_orders(w, me, t, max_id):
    b = Browser(w, me)
    t = b.login(t)
    start = random.randint(1, max(1, max_id - 80))
    for oid in range(start, start + 80):
        t = step(t, 0.05, 0.3)
        o = w.shop.order_at(oid, t)
        b.get(t, f"/orders/{oid}", label="BOLA" if not o or o["user_id"] != me else None)


def attack_stealth_orders(w, me, t, others):
    """하루에 걸쳐 평소처럼 쓰다가 주소창의 주문 번호만 바꿔 남의 주문을 몇 건씩 조회 (속도로는 안 잡힘)"""
    b = Browser(w, me)
    for _ in range(random.randint(3, 6)):
        normal_visit(w, me, t)
        orders = w.shop.orders_of(random.choice(others), t)
        if orders:
            t2 = step(t, 30, 120)
            b.order_detail(t2, random.choice(orders), label="BOLA")
        t = t + timedelta(minutes=random.randint(40, 180))


def attack_blocked_apis(w, me, t, users):
    """안전한 API(profiles, payments, 장바구니, 리뷰)를 찔러 봄 → 403"""
    db = w.db
    b = Browser(w, me)
    t = b.login(t)
    others_cart = [c for c, u in db["cart_owner"].items() if u != me]
    for _ in range(30):
        t = step(t, 0.1, 0.5)
        r = random.random()
        if r < 0.35:
            u = random.choice(users)
            if u != me:
                b.get(t, f"/profiles/{u}", label="ATTEMPT")
        elif r < 0.7:
            p = random.randint(1, max(db["payments"]) + 5)
            if db["payments"].get(p, {}).get("user_id") != me:
                b.get(t, f"/payments/{p}", label="ATTEMPT")
        elif r < 0.85 and others_cart:
            b.send(t, random.choice(["PATCH", "DELETE"]), f"/cart/items/{random.choice(others_cart)}", label="ATTEMPT")
        else:
            rid = random.randint(1, max(db["reviews"]) + 5)
            if db["reviews"].get(rid, {}).get("user_id") != me:
                b.send(t, random.choice(["PATCH", "DELETE"]), f"/reviews/{rid}", label="ATTEMPT")


# ---------------------------------------------------------------- 메인
def random_time(day):
    """하루 중 사람이 많이 쓰는 시간대에 몰리도록"""
    hour = random.choices(range(24), weights=[1, 1, 1, 1, 1, 1, 2, 4, 6, 7, 7, 8,
                                              9, 8, 7, 7, 7, 8, 9, 10, 10, 9, 6, 3])[0]
    return day + timedelta(hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59),
                           milliseconds=random.randint(0, 999))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30, help="생성할 기간 (일)")
    ap.add_argument("--attack-days", type=int, default=5, help="마지막 며칠에 공격을 넣을지")
    ap.add_argument("--attack-prob", type=float, default=0.6,
                    help="공격 기간의 하루에 공격자별로 공격할 확률 (열거 · 막힌 API 찌르기)")
    ap.add_argument("--stealth-prob", type=float, default=1.0, help="공격 기간의 하루에 몰래 조회 공격을 할 확률")
    ap.add_argument("--end", default=datetime.now(KST).strftime("%Y-%m-%d"),
                    help="이 날 0시 직전까지 생성 (기본: 오늘 → 어제까지)")
    ap.add_argument("--scale", type=float, default=10, help="정상 트래픽 배수 (1 = 하루 평균 접속 1번)")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)

    db = load_db()
    users = [u for u, r in db["users"].items() if r == "user"]
    admins = [u for u, r in db["users"].items() if r == "admin"]
    attackers = random.sample(users, 4)
    normal_users = [u for u in users if u not in attackers]
    max_uid, max_oid = max(db["users"]), max(db["orders"])

    end = datetime.strptime(args.end, "%Y-%m-%d").replace(tzinfo=KST)
    first_day = end - timedelta(days=args.days)
    attack_from = end - timedelta(days=args.attack_days)
    w = Writer(db)
    # 사람마다 쓰는 양이 다름: 가끔 오는 사람 ~ 매일 자주 오는 사람
    activity = {u: random.choice([0.2, 0.5, 0.8, 1, 1, 1, 1.5, 2, 3]) for u in users}

    for d in range(args.days):
        day = first_day + timedelta(days=d)
        weekend = 1.3 if day.weekday() >= 5 else 1.0     # 주말엔 조금 더 많이
        for _ in range(round(args.scale * 15 * weekend)):  # 로그인 안 하고 구경만 하는 방문자
            anonymous_visit(w, random_time(day))
        for u in users:                                   # 공격자도 평소엔 정상 사용
            base = args.scale * activity[u] * weekend
            for _ in range(max(0, round(random.gauss(base, base * 0.3)))):
                normal_visit(w, u, random_time(day))
        for a in admins:
            for _ in range(max(0, round(random.gauss(args.scale * 0.7, 1)))):
                admin_visit(w, a, users, random_time(day))
        if day >= attack_from:
            a1, a2, a3, a4 = attackers
            if random.random() < args.attack_prob:
                attack_enumerate_members(w, a1, random_time(day), max_uid)
            if random.random() < args.attack_prob:
                attack_enumerate_orders(w, a2, random_time(day), max_oid)
            if random.random() < args.stealth_prob:
                attack_stealth_orders(w, a3, random_time(day), normal_users)
            if random.random() < args.attack_prob:
                attack_blocked_apis(w, a4, random_time(day), users)

    # 이 기간에 만들어진 주문 · 리뷰는 그 시각에 실제로 작성한 기록을 남김
    for oid, o in db["orders"].items():
        if first_day <= o["created"] < end:
            place_order(w, oid)
    for rid, r in db["reviews"].items():
        if first_day <= r["created"] < end:
            write_review(w, rid)

    w.lines = [e for e in w.lines if e[0] < int(end.timestamp() * 1000)]
    w.truth = [r for r in w.truth if r[1] < int(end.timestamp() * 1000)]

    for path in (OUT_LOG, OUT_TRUTH):                     # 기존 파일은 *_old 로 보관
        if os.path.exists(path):
            base, ext = os.path.splitext(path)
            os.replace(path, base + "_old" + ext)

    w.lines.sort(key=lambda e: e[0])
    with open(OUT_LOG, "w", encoding="utf-8", newline="\n") as f:
        for _, line in w.lines:
            f.write(line + "\n")
    with open(OUT_TRUTH, "w", encoding="utf-8", newline="") as f:
        cw = csv.writer(f)
        cw.writerow(["request_id", "started_at", "label", "attacker_user_id", "uri", "status", "method"])
        cw.writerows(sorted(w.truth, key=lambda r: r[1]))

    train_end = int(attack_from.timestamp() * 1000) - 1
    last_day = (end - timedelta(days=1)).strftime("%Y-%m-%d")
    print(f"기간: {first_day:%Y-%m-%d} ~ {last_day} ({args.days}일), 공격: {attack_from:%Y-%m-%d} ~ {last_day}")
    print(f"로그 {len(w.lines):,}줄 → {OUT_LOG}")
    print(f"공격 정답 {len(w.truth):,}건 → {OUT_TRUTH}")
    print(f"공격자 user_id: {attackers}")
    if attack_from > first_day:
        print(f"학습 구간(공격 없음): TRAIN_START={int(first_day.timestamp() * 1000)} TRAIN_END={train_end}")
    else:
        print("공격이 전 기간에 섞여 있음 (학습 구간에도 공격 포함)")


if __name__ == "__main__":
    main()
