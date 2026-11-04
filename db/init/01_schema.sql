CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================================
-- 인증
-- =========================================================
CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(50) UNIQUE NOT NULL,      -- 로그인 ID
  password_hash TEXT NOT NULL,
  role          VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id),
  token_hash CHAR(64) UNIQUE NOT NULL,             -- 원문 대신 sha256만 저장
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

-- =========================================================
-- 개인정보 (회원정보)
-- =========================================================
CREATE TABLE member_info (
  user_id    INT PRIMARY KEY REFERENCES users(id),
  name       VARCHAR(50) NOT NULL,
  phone      VARCHAR(20) NOT NULL,
  email      VARCHAR(100) NOT NULL,
  birth_date DATE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE addresses (
  id              SERIAL PRIMARY KEY,
  user_id         INT NOT NULL REFERENCES users(id),   -- 객체 소유권
  label           VARCHAR(20),                         -- 집 / 회사
  recipient_name  VARCHAR(50) NOT NULL,
  recipient_phone VARCHAR(20) NOT NULL,
  zipcode         VARCHAR(10) NOT NULL,
  address1        VARCHAR(200) NOT NULL,               -- 도로명 주소
  address2        VARCHAR(200),                        -- 상세 주소
  is_default      BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_addresses_user ON addresses(user_id);

-- =========================================================
-- 프로필 (등급 · 적립금) + 쿠폰
-- =========================================================
CREATE TABLE profiles (
  user_id    INT PRIMARY KEY REFERENCES users(id),
  grade      VARCHAR(20) NOT NULL DEFAULT 'BRONZE' CHECK (grade IN ('BRONZE', 'SILVER', 'GOLD', 'VIP')),
  points     INT NOT NULL DEFAULT 0 CHECK (points >= 0),   -- 적립금 잔액
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE coupons (
  id               SERIAL PRIMARY KEY,
  user_id          INT NOT NULL REFERENCES users(id),
  name             VARCHAR(100) NOT NULL,
  discount_type    VARCHAR(10) NOT NULL CHECK (discount_type IN ('fixed', 'percent')),
  discount_value   INT NOT NULL,                  -- fixed: 원 / percent: %
  min_order_amount INT NOT NULL DEFAULT 0,
  expires_at       TIMESTAMPTZ NOT NULL,
  used_at          TIMESTAMPTZ,                   -- NULL이면 미사용
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_coupons_user ON coupons(user_id);

-- =========================================================
-- 주문
-- =========================================================
CREATE TABLE orders (
  id              SERIAL PRIMARY KEY,             -- 순차 ID (ID 열거 공격 재현용)
  order_number    VARCHAR(30) UNIQUE NOT NULL,    -- 화면 표시용 주문번호
  user_id         INT NOT NULL REFERENCES users(id),
  status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'paid', 'preparing', 'shipped', 'delivered', 'cancelled')),
  total_amount    INT NOT NULL,                   -- 상품 합계
  discount_amount INT NOT NULL DEFAULT 0,         -- 쿠폰 할인
  shipping_fee    INT NOT NULL DEFAULT 0,
  final_amount    INT NOT NULL,                   -- total - discount + shipping
  coupon_id       INT REFERENCES coupons(id),
  -- 배송지 스냅샷
  recipient_name  VARCHAR(50) NOT NULL,
  recipient_phone VARCHAR(20) NOT NULL,
  zipcode         VARCHAR(10) NOT NULL,
  address1        VARCHAR(200) NOT NULL,
  address2        VARCHAR(200),
  delivery_memo   VARCHAR(200),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_orders_user ON orders(user_id);

CREATE TABLE order_items (
  id           SERIAL PRIMARY KEY,
  order_id     INT NOT NULL REFERENCES orders(id),
  product_name VARCHAR(100) NOT NULL,
  unit_price   INT NOT NULL,
  quantity     INT NOT NULL CHECK (quantity > 0)
);
CREATE INDEX idx_order_items_order ON order_items(order_id);

-- =========================================================
-- 결제
-- =========================================================
CREATE TABLE payments (
  id                 SERIAL PRIMARY KEY,
  order_id           INT NOT NULL REFERENCES orders(id),
  user_id            INT NOT NULL REFERENCES users(id),
  method             VARCHAR(20) NOT NULL
                     CHECK (method IN ('card', 'bank_transfer', 'virtual_account', 'points')),
  amount             INT NOT NULL,                -- 실제 결제 금액 (final_amount - points_used)
  points_used        INT NOT NULL DEFAULT 0,
  status             VARCHAR(20) NOT NULL DEFAULT 'ready'
                     CHECK (status IN ('ready', 'paid', 'cancelled', 'refunded', 'failed')),
  transaction_id     VARCHAR(50) UNIQUE,          -- PG사 거래번호
  card_company       VARCHAR(30),
  card_number_masked VARCHAR(25),                 -- 1234-****-****-5678
  bank_name          VARCHAR(30),
  account_masked     VARCHAR(30),                 -- 123-***-456789
  paid_at            TIMESTAMPTZ,
  cancelled_at       TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_payments_user ON payments(user_id);

-- =========================================================
-- 프로필 조회용 VIEW
-- =========================================================
CREATE VIEW profile_summary AS
SELECT
  p.user_id,
  m.name,
  p.grade,
  p.points,
  (SELECT count(*) FROM coupons c
    WHERE c.user_id = p.user_id AND c.used_at IS NULL AND c.expires_at > now()) AS coupon_count,
  COALESCE((
    SELECT jsonb_object_agg(status, cnt)
      FROM (SELECT status, count(*) AS cnt FROM orders o
             WHERE o.user_id = p.user_id GROUP BY status) s
  ), '{}'::jsonb) AS order_status_counts      -- 예: {"paid": 1, "delivered": 2}
FROM profiles p
JOIN member_info m ON m.user_id = p.user_id;

-- =========================================================
-- 판단 서버 테이블 (컬럼은 판단 서버 담당과 확정)
-- =========================================================
CREATE TABLE risk_scores (
  user_id    INT PRIMARY KEY REFERENCES users(id),
  score      NUMERIC NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE block_history (
  id         SERIAL PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id),
  level      VARCHAR(20) NOT NULL,          -- observe / warn / block / long_block
  reason     TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at   TIMESTAMPTZ
);

CREATE TABLE active_blocks (
  user_id    INT PRIMARY KEY REFERENCES users(id),
  level      VARCHAR(20) NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE vulnerable_apis (
  id           SERIAL PRIMARY KEY,
  method       VARCHAR(10) NOT NULL,
  path_pattern VARCHAR(200) NOT NULL,
  detected_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  note         TEXT
);