"""현실적인 테스트 계정 N명 생성 → db/init/04_bulk_seed.sql + ../engine/test_users.csv

사용법 (app 폴더에서):
  python db\\make_seed.py          # 기본 100명
  python db\\make_seed.py 300      # 인원 지정

같은 SEED면 항상 같은 계정이 나옴. test_users.csv에는 평문 비밀번호가 있으니 Git에 올리지 말 것.
"""
import csv, os, random, sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
SEED = 42
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQL_OUT = os.path.join(ROOT, "db", "init", "04_bulk_seed.sql")
CSV_OUT = os.path.join(ROOT, "..", "engine", "test_users.csv")

SURNAMES = [("김", "kim"), ("이", "lee"), ("박", "park"), ("최", "choi"), ("정", "jung"),
            ("강", "kang"), ("조", "cho"), ("윤", "yoon"), ("장", "jang"), ("임", "lim"),
            ("한", "han"), ("오", "oh"), ("서", "seo"), ("신", "shin"), ("권", "kwon")]
GIVEN = [("민준", "minjun"), ("서연", "seoyeon"), ("도윤", "doyun"), ("지우", "jiwoo"),
         ("하준", "hajun"), ("서윤", "seoyun"), ("시우", "siwoo"), ("하은", "haeun"),
         ("지호", "jiho"), ("수아", "sua"), ("예준", "yejun"), ("지민", "jimin"),
         ("현우", "hyunwoo"), ("유진", "yujin"), ("준서", "junseo"), ("채원", "chaewon"),
         ("건우", "gunwoo"), ("다은", "daeun"), ("우진", "woojin"), ("소율", "soyul")]
WORDS = ["happy", "sunny", "blue", "coffee", "cat", "dream", "star", "lucky", "ocean", "moon"]
PW_WORDS = ["Seoul", "Summer", "Coffee", "Happy", "Dragon", "Spring", "Lucky", "Blue"]
SYMBOLS = "!@#$"

rng = random.Random(SEED)

def make_user(used):
    sur_ko, sur = rng.choice(SURNAMES)
    giv_ko, giv = rng.choice(GIVEN)
    year = rng.randint(1970, 2005)
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

users, used = [], {"alice", "bob", "carol", "admin"}
for _ in range(N):
    users.append(make_user(used))

values = ",\n  ".join(
    f"({q(u['username'])}, {q(u['password'])}, {q(u['name'])}, {q(u['phone'])}, {q(u['email'])}, {q(u['birth_date'])})"
    for u in users)

SQL = f"""-- =========================================================
-- 트래픽 학습용 대량 더미 데이터 (db/make_seed.py로 생성, 직접 수정하지 말 것)
--   테스트 계정 {N}명, 사용자마다 배송지 1~3개, 쿠폰 0~3개, 주문 0~6개(+주문상품, 결제)
--   계정/비밀번호 목록: engine/test_users.csv
-- 첫 번째 계정이 이미 있으면 아무것도 하지 않음 (여러 번 실행해도 안전)
-- =========================================================
CREATE FUNCTION pg_temp.pick(a TEXT[]) RETURNS TEXT LANGUAGE sql AS
$f$ SELECT a[1 + floor(random() * array_length(a, 1))::int] $f$;

-- 평문 비밀번호는 이 세션의 임시 테이블에만 있고, users에는 bcrypt 해시만 저장됨
CREATE TEMP TABLE seed_users (username TEXT, password TEXT, name TEXT, phone TEXT, email TEXT, birth_date DATE);
INSERT INTO seed_users VALUES
  {values};

DO $$
DECLARE
  s RECORD;
  j INT; k INT;
  uid INT; oid INT;
  zip TEXT; addr1 TEXT; addr2 TEXT;
  n_items INT; total INT; ship INT; price INT; qty INT;
  st TEXT; created TIMESTAMPTZ; onum TEXT; method TEXT;
  prices INT[]; qtys INT[]; names TEXT[];
BEGIN
  IF EXISTS (SELECT 1 FROM users u JOIN seed_users su USING (username)) THEN
    RAISE NOTICE 'bulk seed already applied, skip';
    RETURN;
  END IF;

  FOR s IN SELECT * FROM seed_users LOOP
    INSERT INTO users (username, password_hash, role)
    VALUES (s.username, crypt(s.password, gen_salt('bf', 8)), 'user')
    RETURNING id INTO uid;

    INSERT INTO member_info (user_id, name, phone, email, birth_date)
    VALUES (uid, s.name, s.phone, s.email, s.birth_date);

    -- 배송지 1~3개 (첫 번째가 기본 배송지)
    FOR j IN 1..(1 + floor(random() * 3))::int LOOP
      INSERT INTO addresses (user_id, label, recipient_name, recipient_phone, zipcode, address1, address2, is_default)
      VALUES (uid, pg_temp.pick(ARRAY['집','회사','본가']), s.name, s.phone,
              lpad(floor(random() * 63000)::text, 5, '0'),
              pg_temp.pick(ARRAY['서울특별시 강남구 테헤란로','서울특별시 마포구 월드컵북로',
                                 '경기도 성남시 분당구 판교역로','인천광역시 연수구 송도과학로',
                                 '대전광역시 유성구 대학로','부산광역시 해운대구 센텀중앙로'])
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

    -- 주문 0~6개 (+ 주문상품 1~3개, 결제)
    FOR j IN 1..floor(random() * 7)::int LOOP
      n_items := 1 + floor(random() * 3)::int;
      prices := '{{}}'; qtys := '{{}}'; names := '{{}}'; total := 0;
      FOR k IN 1..n_items LOOP
        price := (1 + floor(random() * 30))::int * 5000;
        qty   := 1 + floor(random() * 2)::int;
        prices := prices || price; qtys := qtys || qty;
        names  := names || pg_temp.pick(ARRAY['기계식 키보드','무선 마우스','27인치 모니터','HDMI 케이블',
                                              '블루투스 헤드셋','USB 허브','웹캠','노트북 거치대','SSD 1TB']);
        total := total + price * qty;
      END LOOP;
      ship    := CASE WHEN total < 50000 THEN 3000 ELSE 0 END;
      st      := pg_temp.pick(ARRAY['pending','paid','preparing','shipped','delivered','delivered','cancelled']);
      created := now() - random() * interval '90 days';
      onum    := 'ORD-' || to_char(created, 'YYYYMMDD') || '-' || lpad(uid::text, 4, '0') || lpad(j::text, 2, '0');

      INSERT INTO orders (order_number, user_id, status, total_amount, discount_amount, shipping_fee,
                          final_amount, recipient_name, recipient_phone, zipcode, address1, address2, created_at)
      VALUES (onum, uid, st, total, 0, ship, total + ship, s.name, s.phone, zip, addr1, addr2, created)
      RETURNING id INTO oid;

      FOR k IN 1..n_items LOOP
        INSERT INTO order_items (order_id, product_name, unit_price, quantity)
        VALUES (oid, names[k], prices[k], qtys[k]);
      END LOOP;

      IF st <> 'pending' THEN   -- 결제 전 주문은 결제 내역 없음
        method := pg_temp.pick(ARRAY['card','card','bank_transfer']);
        INSERT INTO payments (order_id, user_id, method, amount, status, transaction_id,
                              card_company, card_number_masked, bank_name, account_masked, paid_at, cancelled_at)
        VALUES (oid, uid, method, total + ship,
                CASE WHEN st = 'cancelled' THEN 'refunded' ELSE 'paid' END,
                'TX-' || upper(substr(md5(oid::text || random()::text), 1, 12)),
                CASE WHEN method = 'card' THEN pg_temp.pick(ARRAY['신한카드','현대카드','국민카드']) END,
                CASE WHEN method = 'card' THEN lpad(floor(random() * 10000)::text, 4, '0') || '-****-****-'
                                               || lpad(floor(random() * 10000)::text, 4, '0') END,
                CASE WHEN method = 'bank_transfer' THEN pg_temp.pick(ARRAY['국민은행','우리은행','하나은행']) END,
                CASE WHEN method = 'bank_transfer' THEN '123-***-' || lpad(floor(random() * 1000000)::text, 6, '0') END,
                created + interval '1 minute',
                CASE WHEN st = 'cancelled' THEN created + interval '1 day' END);
      END IF;
    END LOOP;
  END LOOP;
END $$;

DROP TABLE seed_users;
"""

with open(SQL_OUT, "w", encoding="utf-8", newline="\n") as f:
    f.write(SQL)
with open(CSV_OUT, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["username", "password"])
    for u in [("alice", "alice123"), ("bob", "bob123"), ("carol", "carol123")]:
        w.writerow(u)
    for u in users:
        w.writerow([u["username"], u["password"]])

print(f"{SQL_OUT} 생성 ({N}명)")
print(f"{CSV_OUT} 생성")
