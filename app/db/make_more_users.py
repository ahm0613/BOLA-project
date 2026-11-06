"""기존 데이터는 그대로 두고 가짜 사용자를 더 만들어 전체를 TOTAL명으로 맞춤
→ db/init/06_more_users.sql + ../engine/test_users_more.csv

사용법 (app 폴더에서):
  python db\\make_more_users.py          # 기본: 896명 추가 (기존 104명 + 896명 = 1000명)
  python db\\make_more_users.py 400      # 인원 지정

06_more_users.sql은 05_shop.sql 다음에 실행되도록 만들어서
  - DB를 새로 만들 때(docker-entrypoint-initdb.d) 자동으로 들어가고
  - 지금 돌아가는 DB에 psql로 한 번 넣어도 똑같이 동작함 (이미 들어가 있으면 건너뜀)
사용자마다: 회원정보, 배송지 1~3개, 프로필, 쿠폰 0~3개, 주문 0~6개(+주문상품·결제), 리뷰, 장바구니 0~3개
같은 SEED면 항상 같은 계정이 나옴. test_users_more.csv에는 평문 비밀번호가 있으니 Git에 올리지 말 것.
"""
import csv, os, random, sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 896
SEED = 2026
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQL_OUT = os.path.join(ROOT, "db", "init", "06_more_users.sql")
CSV_OUT = os.path.join(ROOT, "..", "engine", "test_users_more.csv")
OLD_SQL = os.path.join(ROOT, "db", "init", "04_bulk_seed.sql")

SURNAMES = [("김", "kim"), ("이", "lee"), ("박", "park"), ("최", "choi"), ("정", "jung"),
            ("강", "kang"), ("조", "cho"), ("윤", "yoon"), ("장", "jang"), ("임", "lim"),
            ("한", "han"), ("오", "oh"), ("서", "seo"), ("신", "shin"), ("권", "kwon"),
            ("황", "hwang"), ("안", "ahn"), ("송", "song"), ("류", "ryu"), ("홍", "hong")]
GIVEN = [("민준", "minjun"), ("서연", "seoyeon"), ("도윤", "doyun"), ("지우", "jiwoo"),
         ("하준", "hajun"), ("서윤", "seoyun"), ("시우", "siwoo"), ("하은", "haeun"),
         ("지호", "jiho"), ("수아", "sua"), ("예준", "yejun"), ("지민", "jimin"),
         ("현우", "hyunwoo"), ("유진", "yujin"), ("준서", "junseo"), ("채원", "chaewon"),
         ("건우", "gunwoo"), ("다은", "daeun"), ("우진", "woojin"), ("소율", "soyul"),
         ("은우", "eunwoo"), ("지유", "jiyu"), ("선우", "sunwoo"), ("윤서", "yunseo"),
         ("연우", "yeonwoo"), ("민서", "minseo"), ("유준", "yujun"), ("하윤", "hayun"),
         ("정우", "jungwoo"), ("서현", "seohyun")]
WORDS = ["happy", "sunny", "blue", "coffee", "cat", "dream", "star", "lucky", "ocean", "moon",
         "mint", "cloud", "pink", "green", "night"]
PW_WORDS = ["Seoul", "Summer", "Coffee", "Happy", "Dragon", "Spring", "Lucky", "Blue", "Winter", "Busan"]
SYMBOLS = "!@#$"

rng = random.Random(SEED)


def existing_usernames():
    """기존 계정 이름과 겹치지 않게 (alice 등 + 04_bulk_seed.sql 의 100명)"""
    used = {"alice", "bob", "carol", "admin"}
    with open(OLD_SQL, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("('") and "@example.com" in line:
                used.add(line[2:line.index("'", 2)])
    return used


def make_user(used):
    sur_ko, sur = rng.choice(SURNAMES)
    giv_ko, giv = rng.choice(GIVEN)
    year = rng.randint(1965, 2006)
    month, day = rng.randint(1, 12), rng.randint(1, 28)
    yy, mmdd = f"{year % 100:02d}", f"{month:02d}{day:02d}"

    while True:
        username = rng.choice([
            f"{giv}{yy}",
            f"{giv}.{sur}",
            f"{sur}{giv}{rng.randint(1, 999)}",
            f"{giv}_{sur}{yy}",
            f"{rng.choice(WORDS)}_{giv}",
            f"{sur[0]}{giv}{mmdd}",
            f"{rng.choice(WORDS)}{giv}{rng.randint(1, 99)}",
        ])
        if username not in used:
            used.add(username)
            break

    password = rng.choice([
        f"{giv.capitalize()}{yy}{rng.choice(SYMBOLS)}",
        f"{sur}{giv}{mmdd}",
        f"{rng.choice(PW_WORDS)}{year}{rng.choice(SYMBOLS)}",
        f"{giv}{year}!",
        f"{sur.capitalize()}{rng.choice(SYMBOLS)}{rng.randint(1000, 9999)}",
    ])
    phone = f"010-{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}"
    return {
        "username": username, "password": password, "name": sur_ko + giv_ko,
        "phone": phone, "email": f"{username.replace('.', '_')}@example.com",
        "birth_date": f"{year}-{month:02d}-{day:02d}",
    }


def q(s):
    return "'" + s.replace("'", "''") + "'"


used = existing_usernames()
users = [make_user(used) for _ in range(N)]

values = ",\n  ".join(
    f"({q(u['username'])}, {q(u['password'])}, {q(u['name'])}, {q(u['phone'])}, {q(u['email'])}, {q(u['birth_date'])})"
    for u in users)

SQL = f"""-- =========================================================
-- 가짜 사용자 추가 (db/make_more_users.py로 생성, 직접 수정하지 말 것)
--   테스트 계정 {N}명, 사용자마다 배송지 1~3개, 쿠폰 0~3개, 주문 0~6개(+주문상품, 결제), 리뷰, 장바구니 0~3개
--   기존 데이터(01~05)는 건드리지 않고 뒤에 이어 붙임. 계정/비밀번호 목록: engine/test_users_more.csv
-- 첫 번째 계정이 이미 있으면 아무것도 하지 않음 (여러 번 실행해도 안전)
-- =========================================================
CREATE FUNCTION pg_temp.pick(a TEXT[]) RETURNS TEXT LANGUAGE sql AS
$f$ SELECT a[1 + floor(random() * array_length(a, 1))::int] $f$;

-- 평문 비밀번호는 이 세션의 임시 테이블에만 있고, users에는 bcrypt 해시만 저장됨
CREATE TEMP TABLE seed_users (username TEXT, password TEXT, name TEXT, phone TEXT, email TEXT, birth_date DATE);
INSERT INTO seed_users VALUES
  {values};

CREATE TEMP TABLE new_users (id INT PRIMARY KEY);

DO $$
DECLARE
  s RECORD; p RECORD;
  j INT;
  uid INT; oid INT;
  zip TEXT; addr1 TEXT; addr2 TEXT;
  total INT; ship INT; qty INT;
  st TEXT; created TIMESTAMPTZ; method TEXT;
BEGIN
  IF EXISTS (SELECT 1 FROM users u JOIN seed_users su USING (username)) THEN
    RAISE NOTICE 'more users already applied, skip';
    RETURN;
  END IF;

  FOR s IN SELECT * FROM seed_users LOOP
    INSERT INTO users (username, password_hash, role, created_at)
    VALUES (s.username, crypt(s.password, gen_salt('bf', 8)), 'user', now() - random() * interval '180 days')
    RETURNING id INTO uid;
    INSERT INTO new_users VALUES (uid);

    INSERT INTO member_info (user_id, name, phone, email, birth_date)
    VALUES (uid, s.name, s.phone, s.email, s.birth_date);

    -- 배송지 1~3개 (첫 번째가 기본 배송지)
    FOR j IN 1..(1 + floor(random() * 3))::int LOOP
      INSERT INTO addresses (user_id, label, recipient_name, recipient_phone, zipcode, address1, address2, is_default)
      VALUES (uid, pg_temp.pick(ARRAY['집','회사','본가']), s.name, s.phone,
              lpad(floor(random() * 63000)::text, 5, '0'),
              pg_temp.pick(ARRAY['서울특별시 강남구 테헤란로','서울특별시 마포구 월드컵북로',
                                 '서울특별시 송파구 올림픽로','경기도 성남시 분당구 판교역로',
                                 '경기도 수원시 영통구 광교로','인천광역시 연수구 송도과학로',
                                 '대전광역시 유성구 대학로','대구광역시 수성구 달구벌대로',
                                 '광주광역시 서구 상무중앙로','부산광역시 해운대구 센텀중앙로'])
                || ' ' || (1 + floor(random() * 300))::int,
              (1 + floor(random() * 20))::int || '층',
              j = 1);
    END LOOP;
    SELECT zipcode, address1, address2 INTO zip, addr1, addr2
      FROM addresses WHERE user_id = uid AND is_default;

    INSERT INTO profiles (user_id, grade, points)
    VALUES (uid, pg_temp.pick(ARRAY['BRONZE','BRONZE','SILVER','GOLD','VIP']),
            floor(random() * 200)::int * 100);

    -- 쿠폰 0~3개
    FOR j IN 1..floor(random() * 4)::int LOOP
      INSERT INTO coupons (user_id, name, discount_type, discount_value, min_order_amount, expires_at)
      VALUES (uid, pg_temp.pick(ARRAY['신규가입 5,000원 할인','무료배송 쿠폰','생일 쿠폰']),
              'fixed', pg_temp.pick(ARRAY['3000','5000'])::int, 0, '2026-12-31');
    END LOOP;

    -- 주문 0~6개: 상품은 products 에서 1~3개 (주문번호는 웹 주문과 같은 ORD-YYYYMMDD-NNNNNN)
    FOR j IN 1..floor(random() * 7)::int LOOP
      oid     := nextval('orders_id_seq');
      st      := pg_temp.pick(ARRAY['pending','paid','preparing','shipped','delivered','delivered','cancelled']);
      created := now() - random() * interval '90 days';

      INSERT INTO orders (id, order_number, user_id, status, total_amount, discount_amount, shipping_fee,
                          final_amount, recipient_name, recipient_phone, zipcode, address1, address2, created_at, updated_at)
      VALUES (oid, 'ORD-' || to_char(created, 'YYYYMMDD') || '-' || lpad(oid::text, 6, '0'), uid, st, 0, 0, 0,
              0, s.name, s.phone, zip, addr1, addr2, created, created);

      total := 0;
      FOR p IN SELECT id, name, COALESCE(sale_price, price) AS price FROM products
                ORDER BY random() LIMIT (1 + floor(random() * 3))::int LOOP
        qty   := 1 + floor(random() * 2)::int;
        total := total + p.price * qty;
        INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity)
        VALUES (oid, p.id, p.name, p.price, qty);
      END LOOP;
      ship := CASE WHEN total < 50000 THEN 3000 ELSE 0 END;
      UPDATE orders SET total_amount = total, shipping_fee = ship, final_amount = total + ship WHERE id = oid;

      IF st <> 'pending' THEN   -- 결제 전 주문은 결제 내역 없음
        method := pg_temp.pick(ARRAY['card','card','bank_transfer']);
        INSERT INTO payments (order_id, user_id, method, amount, status, transaction_id,
                              card_company, card_number_masked, bank_name, account_masked, paid_at, cancelled_at)
        VALUES (oid, uid, method, total + ship,
                CASE WHEN st = 'cancelled' THEN 'refunded' ELSE 'paid' END,
                'TX-' || upper(substr(md5(oid::text || random()::text), 1, 12)),
                CASE WHEN method = 'card' THEN pg_temp.pick(ARRAY['신한카드','현대카드','국민카드','삼성카드']) END,
                CASE WHEN method = 'card' THEN lpad(floor(random() * 10000)::text, 4, '0') || '-****-****-'
                                               || lpad(floor(random() * 10000)::text, 4, '0') END,
                CASE WHEN method = 'bank_transfer' THEN pg_temp.pick(ARRAY['국민은행','우리은행','하나은행','신한은행']) END,
                CASE WHEN method = 'bank_transfer' THEN '123-***-' || lpad(floor(random() * 1000000)::text, 6, '0') END,
                created + interval '1 minute',
                CASE WHEN st = 'cancelled' THEN created + interval '1 day' END);
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- 리뷰: 새 사용자의 배송 완료 주문 상품 중 약 60%에 작성 (05_shop.sql과 같은 방식)
INSERT INTO reviews (product_id, user_id, order_id, rating, content, created_at, updated_at)
SELECT oi.product_id, o.user_id, o.id,
       (ARRAY[5,5,5,4,4,4,3,2])[1 + floor(random() * 8)::int],
       (ARRAY['배송이 빨라서 좋았어요. 포장도 꼼꼼했습니다.',
              '생각보다 품질이 좋아요. 재구매 의사 있습니다.',
              '가격 대비 만족합니다. 매일 잘 쓰고 있어요.',
              '사진이랑 똑같아요. 추천합니다.',
              '무난하게 쓰기 좋아요.',
              '조금 아쉽지만 이 가격이면 괜찮아요.',
              '선물용으로 샀는데 반응이 좋았어요.',
              '두 번째 구매입니다. 역시 좋네요.'])[1 + floor(random() * 8)::int],
       o.created_at + interval '3 days', o.created_at + interval '3 days'
  FROM orders o
  JOIN new_users n ON n.id = o.user_id
  JOIN order_items oi ON oi.order_id = o.id
 WHERE o.status = 'delivered' AND oi.product_id IS NOT NULL AND random() < 0.6
ON CONFLICT (order_id, product_id) DO NOTHING;

-- 장바구니: 새 사용자마다 상품 0~3개
INSERT INTO cart_items (user_id, product_id, quantity)
SELECT n.id, p.id, 1 + floor(random() * 2)::int
  FROM new_users n
 CROSS JOIN LATERAL (
       SELECT id FROM products
        WHERE n.id > 0                      -- 사용자마다 따로 뽑도록 바깥 행을 참조
        ORDER BY random()
        LIMIT floor(random() * 4)::int
       ) p
ON CONFLICT (user_id, product_id) DO NOTHING;

DROP TABLE new_users;
DROP TABLE seed_users;
"""

with open(SQL_OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write(SQL)

with open(CSV_OUT, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.writer(f)
    w.writerow(["username", "password", "name", "phone", "email", "birth_date"])
    for u in users:
        w.writerow([u[k] for k in ("username", "password", "name", "phone", "email", "birth_date")])

print(f"{N}명 -> {os.path.relpath(SQL_OUT, ROOT)}, {os.path.relpath(CSV_OUT, ROOT)}")
