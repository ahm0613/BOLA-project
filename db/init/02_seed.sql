-- 사용자
INSERT INTO users (username, password_hash, role) VALUES
  ('alice', crypt('alice123', gen_salt('bf')), 'user'),   -- 1
  ('bob',   crypt('bob123',   gen_salt('bf')), 'user'),   -- 2
  ('carol', crypt('carol123', gen_salt('bf')), 'user'),   -- 3
  ('admin', crypt('admin123', gen_salt('bf')), 'admin');  -- 4

-- 개인정보
INSERT INTO member_info (user_id, name, phone, email, birth_date) VALUES
  (1, '김앨리스', '010-1111-1111', 'alice@example.com', '1998-03-14'),
  (2, '박밥',     '010-2222-2222', 'bob@example.com',   '1995-07-02'),
  (3, '이캐롤',   '010-3333-3333', 'carol@example.com', '2000-11-25'),
  (4, '관리자',   '010-0000-0000', 'admin@example.com', NULL);

-- 배송지
INSERT INTO addresses (user_id, label, recipient_name, recipient_phone, zipcode, address1, address2, is_default) VALUES
  (1, '집', '김앨리스', '010-1111-1111', '06236',
   '서울특별시 강남구 테헤란로 123', '101동 1001호', true),          -- 1
  (2, '회사', '박밥', '010-2222-2222', '04524',
   '서울특별시 중구 세종대로 110', '5층', true),                     -- 2
  (1, '회사', '김앨리스', '010-1111-1111', '13529',
   '경기도 성남시 분당구 판교역로 235', '3층', false),               -- 3
  (3, '집', '이캐롤', '010-3333-3333', '48058',
   '부산광역시 해운대구 센텀중앙로 79', '1203호', true);             -- 4

-- 프로필
INSERT INTO profiles (user_id, grade, points) VALUES
  (1, 'GOLD',   12500),
  (2, 'SILVER', 3000),
  (3, 'BRONZE', 0),
  (4, 'BRONZE', 0);

-- 쿠폰
INSERT INTO coupons (user_id, name, discount_type, discount_value, min_order_amount, expires_at, used_at) VALUES
  (1, '신규가입 5,000원 할인', 'fixed',   5000, 30000, '2026-12-31', '2026-10-01'),  -- 1 (주문 1에 사용)
  (1, '10% 할인 쿠폰',        'percent', 10,   50000, '2026-12-31', NULL),          -- 2
  (2, '무료배송 쿠폰',        'fixed',   3000, 0,     '2026-11-30', NULL),          -- 3
  (3, '신규가입 5,000원 할인', 'fixed',   5000, 30000, '2026-12-31', NULL),          -- 4
  (1, '생일 쿠폰',            'fixed',   3000, 0,     '2026-11-15', NULL);          -- 5

-- 주문 (5만 원 미만이면 배송비 3,000원)
INSERT INTO orders (order_number, user_id, status,
                    total_amount, discount_amount, shipping_fee, final_amount, coupon_id,
                    recipient_name, recipient_phone, zipcode, address1, address2,
                    delivery_memo, created_at) VALUES
  ('ORD-20261001-0001', 1, 'delivered', 89000, 5000, 0, 84000, 1,
   '김앨리스', '010-1111-1111', '06236', '서울특별시 강남구 테헤란로 123', '101동 1001호',
   '문 앞에 놓아주세요', '2026-10-01 10:00+09'),
  ('ORD-20261005-0002', 2, 'shipped', 35000, 0, 3000, 38000, NULL,
   '박밥', '010-2222-2222', '04524', '서울특별시 중구 세종대로 110', '5층',
   NULL, '2026-10-05 14:30+09'),
  ('ORD-20261020-0003', 1, 'preparing', 344000, 0, 0, 344000, NULL,
   '김앨리스', '010-1111-1111', '13529', '경기도 성남시 분당구 판교역로 235', '3층',
   '경비실에 맡겨주세요', '2026-10-20 09:15+09'),
  ('ORD-20261021-0004', 3, 'delivered', 120000, 0, 0, 120000, NULL,
   '이캐롤', '010-3333-3333', '48058', '부산광역시 해운대구 센텀중앙로 79', '1203호',
   NULL, '2026-10-21 20:45+09'),
  ('ORD-20261022-0005', 2, 'cancelled', 25000, 0, 3000, 28000, NULL,
   '박밥', '010-2222-2222', '04524', '서울특별시 중구 세종대로 110', '5층',
   NULL, '2026-10-22 11:00+09'),
  ('ORD-20261025-0006', 3, 'pending', 75000, 0, 0, 75000, NULL,
   '이캐롤', '010-3333-3333', '48058', '부산광역시 해운대구 센텀중앙로 79', '1203호',
   NULL, '2026-10-25 16:20+09');

INSERT INTO order_items (order_id, product_name, unit_price, quantity) VALUES
  (1, '기계식 키보드',   89000,  1),
  (2, '무선 마우스',     35000,  1),
  (3, '27인치 모니터',   320000, 1),
  (3, 'HDMI 케이블',     12000,  2),
  (4, '블루투스 헤드셋', 120000, 1),
  (5, 'USB 허브',        25000,  1),
  (6, '웹캠',            75000,  1);

-- 결제 (주문 6은 결제 전이라 결제 내역 없음)
INSERT INTO payments (order_id, user_id, method, amount, points_used, status, transaction_id,
                      card_company, card_number_masked, bank_name, account_masked,
                      paid_at, cancelled_at) VALUES
  (1, 1, 'card', 84000, 0, 'paid', 'TX-20261001-A1B2',
   '신한카드', '1234-****-****-5678', NULL, NULL, '2026-10-01 10:01+09', NULL),
  (2, 2, 'card', 38000, 0, 'paid', 'TX-20261005-C3D4',
   '현대카드', '9876-****-****-4321', NULL, NULL, '2026-10-05 14:31+09', NULL),
  (3, 1, 'card', 340000, 4000, 'paid', 'TX-20261020-E5F6',
   '신한카드', '1234-****-****-5678', NULL, NULL, '2026-10-20 09:16+09', NULL),
  (4, 3, 'bank_transfer', 120000, 0, 'paid', 'TX-20261021-G7H8',
   NULL, NULL, '국민은행', '123-***-456789', '2026-10-21 20:50+09', NULL),
  (5, 2, 'card', 28000, 0, 'refunded', 'TX-20261022-J9K0',
   '현대카드', '9876-****-****-4321', NULL, NULL, '2026-10-22 11:01+09', '2026-10-22 18:00+09');