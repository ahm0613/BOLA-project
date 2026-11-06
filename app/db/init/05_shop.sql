-- =========================================================
-- 쇼핑몰: 카테고리 · 상품 · 장바구니 · 리뷰
--   기존 주문상품(order_items)은 상품명으로 products와 연결
-- =========================================================
CREATE TABLE categories (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(50) NOT NULL,
  sort_order INT NOT NULL DEFAULT 0
);

CREATE TABLE products (
  id          SERIAL PRIMARY KEY,
  category_id INT NOT NULL REFERENCES categories(id),
  brand       VARCHAR(50) NOT NULL,
  name        VARCHAR(100) UNIQUE NOT NULL,
  price       INT NOT NULL,                       -- 정가
  sale_price  INT,                                -- 할인가 (NULL이면 정가 판매)
  stock       INT NOT NULL DEFAULT 100 CHECK (stock >= 0),
  image       VARCHAR(50) NOT NULL,               -- web/img/<image>.svg
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_products_category ON products(category_id);

ALTER TABLE order_items ADD COLUMN product_id INT REFERENCES products(id);

CREATE TABLE cart_items (
  id         SERIAL PRIMARY KEY,
  user_id    INT NOT NULL REFERENCES users(id),   -- 객체 소유권
  product_id INT NOT NULL REFERENCES products(id),
  quantity   INT NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, product_id)
);
CREATE INDEX idx_cart_items_user ON cart_items(user_id);

CREATE TABLE reviews (
  id         SERIAL PRIMARY KEY,
  product_id INT NOT NULL REFERENCES products(id),
  user_id    INT NOT NULL REFERENCES users(id),   -- 객체 소유권
  order_id   INT NOT NULL REFERENCES orders(id),  -- 구매한 주문에만 작성 가능
  rating     INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
  content    VARCHAR(1000) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (order_id, product_id)
);
CREATE INDEX idx_reviews_product ON reviews(product_id);
CREATE INDEX idx_reviews_user ON reviews(user_id);

INSERT INTO ground_truth_apis VALUES
  ('cart',    '/cart',    false),
  ('reviews', '/reviews', false);

-- ---------------------------------------------------------
-- 카테고리 · 상품
-- ---------------------------------------------------------
INSERT INTO categories (name, sort_order) VALUES
  ('디지털·가전', 1),   -- 1
  ('생활·주방',   2),   -- 2
  ('패션·잡화',   3),   -- 3
  ('식품',        4),   -- 4
  ('뷰티',        5);   -- 5

INSERT INTO products (category_id, brand, name, price, sale_price, stock, image, description) VALUES
  (1, '키크론',     '기계식 키보드',          89000,  79000, 120, 'keyboard',   '저소음 갈축 스위치와 알루미늄 상판으로 오래 써도 손목이 편한 텐키리스 키보드입니다.'),
  (1, '로지텍',     '무선 마우스',            35000,  NULL,  300, 'mouse',      '블루투스와 USB 수신기를 모두 지원하고 AA 건전지 하나로 18개월 사용할 수 있어요.'),
  (1, 'LG전자',     '27인치 모니터',          320000, 289000, 40, 'monitor',    'QHD IPS 패널, 75Hz, 높이·각도 조절 스탠드를 갖춘 사무·디자인용 모니터입니다.'),
  (1, '베이직기어', 'HDMI 케이블',            12000,  NULL,  500, 'cable',      'HDMI 2.1 규격, 8K 60Hz와 4K 120Hz를 지원하는 2m 케이블입니다.'),
  (1, '젠하이저',   '블루투스 헤드셋',        120000, NULL,   80, 'headset',    '양방향 마이크와 멀티포인트 연결로 화상회의에 알맞은 헤드셋입니다.'),
  (1, '베이직기어', 'USB 허브',               25000,  22000, 260, 'hub',        'USB-C 하나로 HDMI, USB-A 3개, SD 카드 리더를 연결하는 7in1 허브입니다.'),
  (1, '로지텍',     '웹캠',                   75000,  NULL,  150, 'webcam',     'Full HD 1080p, 자동 초점과 노이즈 감소 마이크를 갖춘 웹캠입니다.'),
  (1, '하루데스크', '노트북 거치대',          39000,  32000, 200, 'stand',      '알루미늄 소재, 6단계 높이 조절로 거북목을 줄여 주는 거치대입니다.'),
  (1, '삼성전자',   'SSD 1TB',                129000, 115000, 90, 'ssd',        'NVMe M.2, 읽기 7,000MB/s의 고속 SSD입니다.'),
  (1, '소니',       '노이즈캔슬링 헤드폰',    399000, 339000, 60, 'headphones', '업계 최고 수준의 노이즈캔슬링과 30시간 배터리를 갖춘 무선 헤드폰입니다.'),
  (2, '하루키친',   '스테인리스 텀블러',      18900,  NULL,  400, 'tumbler',    '이중 진공 구조로 12시간 보온·보냉되는 500ml 텀블러입니다.'),
  (2, '하루키친',   '무선 전기포트',          49000,  42000, 120, 'kettle',     '1℃ 단위 온도 설정과 보온 기능을 갖춘 1.7L 전기포트입니다.'),
  (2, '코튼데이',   '호텔 수건 5종 세트',     29900,  NULL,  250, 'towel',      '40수 코마사 면으로 만든 흡수력 좋은 호텔식 수건 세트입니다.'),
  (2, '우드랩',     '원목 도마',              24000,  NULL,  180, 'board',      '통원목 아카시아로 만든 칼자국이 잘 남지 않는 도마입니다.'),
  (3, '베이직랩',   '오버핏 맨투맨',          39000,  27300, 300, 'sweatshirt', '쭈리 원단으로 만든 사계절 오버핏 맨투맨입니다.'),
  (3, '어반트립',   '데일리 백팩',            59000,  NULL,  140, 'backpack',   '15.6인치 노트북 수납, 생활 방수 원단의 출퇴근용 백팩입니다.'),
  (3, '베이직랩',   '니트 비니',              19000,  15200, 220, 'beanie',     '부드러운 울 혼방 소재의 기본 비니입니다.'),
  (3, '레더앤코',   '가죽 카드지갑',          35000,  NULL,  160, 'wallet',     '이탈리아 소가죽으로 만든 슬림 카드지갑입니다.'),
  (4, '제주농원',   '제주 감귤 3kg',          21900,  18900, 200, 'tangerine',  '산지에서 바로 보내는 당도 11brix 이상의 제주 감귤입니다.'),
  (4, '하루커피',   '콜드브루 원액 1L',       15900,  NULL,  300, 'coffee',     '18시간 저온 추출한 콜드브루 원액입니다. 물이나 우유에 섞어 드세요.'),
  (4, '너티데이',   '하루견과 30봉',          27900,  23900, 260, 'nuts',       '아몬드, 호두, 캐슈넛, 크랜베리를 하루 한 봉씩 담았어요.'),
  (5, '스킨랩',     '수분 크림 50ml',         32000,  25600, 180, 'cream',      '세라마이드와 히알루론산으로 하루 종일 촉촉한 수분 크림입니다.'),
  (5, '스킨랩',     '데일리 선크림 SPF50+',   18000,  NULL,  320, 'sunscreen',  '백탁 없이 산뜻하게 발리는 데일리 선크림입니다.'),
  (5, '플로라',     '핸드크림 3종 세트',      15000,  12000, 400, 'handcream',  '시어버터 함유, 은은한 향의 핸드크림 3종 세트입니다.');

-- 기존 주문상품을 상품과 연결 (이름이 같은 상품)
UPDATE order_items oi SET product_id = p.id FROM products p WHERE p.name = oi.product_name;

-- ---------------------------------------------------------
-- 리뷰: 배송 완료된 주문의 상품 중 약 60%에 작성
-- ---------------------------------------------------------
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
  JOIN order_items oi ON oi.order_id = o.id
 WHERE o.status = 'delivered' AND oi.product_id IS NOT NULL AND random() < 0.6
ON CONFLICT (order_id, product_id) DO NOTHING;

-- ---------------------------------------------------------
-- 장바구니: alice는 2개 고정, 나머지 일반 사용자는 상품 0~3개
-- ---------------------------------------------------------
INSERT INTO cart_items (user_id, product_id, quantity)
SELECT 1, id, 1 FROM products WHERE name IN ('노이즈캔슬링 헤드폰', '스테인리스 텀블러');

INSERT INTO cart_items (user_id, product_id, quantity)
SELECT u.id, p.id, 1 + floor(random() * 2)::int
  FROM users u
 CROSS JOIN LATERAL (
       SELECT id FROM products
        WHERE u.id > 0                      -- 사용자마다 따로 뽑도록 바깥 행을 참조
        ORDER BY random()
        LIMIT floor(random() * 4)::int
       ) p
 WHERE u.role = 'user'
ON CONFLICT (user_id, product_id) DO NOTHING;
