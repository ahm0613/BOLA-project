-- =========================================================
-- 트래픽 학습용 대량 더미 데이터 (db/make_seed.py로 생성, 직접 수정하지 말 것)
--   테스트 계정 100명, 사용자마다 배송지 1~3개, 쿠폰 0~3개, 주문 0~6개(+주문상품, 결제)
--   계정/비밀번호 목록: engine/test_users.csv
-- 첫 번째 계정이 이미 있으면 아무것도 하지 않음 (여러 번 실행해도 안전)
-- =========================================================
CREATE FUNCTION pg_temp.pick(a TEXT[]) RETURNS TEXT LANGUAGE sql AS
$f$ SELECT a[1 + floor(random() * array_length(a, 1))::int] $f$;

-- 평문 비밀번호는 이 세션의 임시 테이블에만 있고, users에는 bcrypt 해시만 저장됨
CREATE TEMP TABLE seed_users (username TEXT, password TEXT, name TEXT, phone TEXT, email TEXT, birth_date DATE);
INSERT INTO seed_users VALUES
  ('jiwoo.han', 'Jiwoo71!', '한지우', '010-4582-4811', 'jiwoo_han@example.com', '1971-12-09'),
  ('soyul_jang71', 'soyul1971!', '장소율', '010-6574-5552', 'soyul_jang71@example.com', '1971-09-07'),
  ('parksiwoo390', 'Siwoo91#', '박시우', '010-7201-2291', 'parksiwoo390@example.com', '1991-02-03'),
  ('sua93', 'sua1993!', '장수아', '010-5554-8428', 'sua93@example.com', '1993-10-07'),
  ('hjimin0612', 'jimin1980!', '한지민', '010-5422-4598', 'hjimin0612@example.com', '1980-06-12'),
  ('yejun_han73', 'yejun1973!', '한예준', '010-7482-8517', 'yejun_han73@example.com', '1973-04-27'),
  ('parkjiho575', 'Park@3266', '박지호', '010-9085-2489', 'parkjiho575@example.com', '1978-04-24'),
  ('star_seoyeon', 'Lucky1977$', '서서연', '010-1188-2876', 'star_seoyeon@example.com', '1977-03-21'),
  ('daeun_han87', 'handaeun1111', '한다은', '010-9317-2743', 'daeun_han87@example.com', '1987-11-11'),
  ('sua.shin', 'Spring2002$', '신수아', '010-6038-4923', 'sua_shin@example.com', '2002-10-07'),
  ('sunny_haeun', 'Kim@5342', '김하은', '010-7932-4470', 'sunny_haeun@example.com', '1975-02-24'),
  ('daeun_kwon82', 'Summer1982@', '권다은', '010-1344-4770', 'daeun_kwon82@example.com', '1982-12-10'),
  ('haeun.lim', 'limhaeun0223', '임하은', '010-5562-8953', 'haeun_lim@example.com', '1970-02-23'),
  ('daeun.choi', 'daeun1978!', '최다은', '010-6804-7939', 'daeun_choi@example.com', '1978-12-19'),
  ('junseo73', 'chojunseo1121', '조준서', '010-9786-8350', 'junseo73@example.com', '1973-11-21'),
  ('yujin_park81', 'parkyujin0515', '박유진', '010-7658-8956', 'yujin_park81@example.com', '1981-05-15'),
  ('siwoo_yoon95', 'yoonsiwoo0106', '윤시우', '010-4111-5861', 'siwoo_yoon95@example.com', '1995-01-06'),
  ('seoyeon04', 'Seoyeon04$', '최서연', '010-2113-4853', 'seoyeon04@example.com', '2004-01-24'),
  ('jiwoo85', 'chojiwoo1020', '조지우', '010-5351-7484', 'jiwoo85@example.com', '1985-10-20'),
  ('sua99', 'Summer1999!', '박수아', '010-3170-6718', 'sua99@example.com', '1999-06-25'),
  ('lucky_doyun', 'Seoul1985#', '권도윤', '010-2891-2753', 'lucky_doyun@example.com', '1985-06-10'),
  ('odaeun0510', 'Daeun79#', '오다은', '010-2512-7939', 'odaeun0510@example.com', '1979-05-10'),
  ('sjiho0111', 'Jiho72#', '신지호', '010-2232-3442', 'sjiho0111@example.com', '1972-01-11'),
  ('seoyeon.jang', 'jangseoyeon1018', '장서연', '010-5088-2684', 'seoyeon_jang@example.com', '1993-10-18'),
  ('daeun.kang', 'daeun1996!', '강다은', '010-5065-5371', 'daeun_kang@example.com', '1996-10-24'),
  ('jiwoo.park', 'Jiwoo94$', '박지우', '010-4164-7528', 'jiwoo_park@example.com', '1994-01-28'),
  ('jiho_kang74', 'Kang#3925', '강지호', '010-5349-1626', 'jiho_kang74@example.com', '1974-05-12'),
  ('soyul_lee97', 'soyul1997!', '이소율', '010-1027-9518', 'soyul_lee97@example.com', '1997-06-24'),
  ('dream_daeun', 'Summer1982#', '권다은', '010-7592-5844', 'dream_daeun@example.com', '1982-06-14'),
  ('jhajun0722', 'Dragon1982$', '장하준', '010-4443-8043', 'jhajun0722@example.com', '1982-07-22'),
  ('coffee_woojin', 'Seo#9445', '서우진', '010-6491-2530', 'coffee_woojin@example.com', '1990-08-15'),
  ('haeun89', 'haeun1989!', '신하은', '010-4185-7291', 'haeun89@example.com', '1989-04-26'),
  ('hyunwoo85', 'Yoon$1822', '윤현우', '010-5082-2988', 'hyunwoo85@example.com', '1985-03-21'),
  ('yoonhajun573', 'hajun1999!', '윤하준', '010-5246-5050', 'yoonhajun573@example.com', '1999-11-17'),
  ('jiho_shin03', 'Dragon2003@', '신지호', '010-9849-2320', 'jiho_shin03@example.com', '2003-08-21'),
  ('hajun84', 'Hajun84$', '박하준', '010-4388-7883', 'hajun84@example.com', '1984-07-23'),
  ('chowoojin489', 'chowoojin1013', '조우진', '010-5471-8140', 'chowoojin489@example.com', '1971-10-13'),
  ('yminjun0622', 'Yoon!7455', '윤민준', '010-1444-2375', 'yminjun0622@example.com', '1994-06-22'),
  ('yujin_han78', 'yujin1978!', '한유진', '010-5558-7906', 'yujin_han78@example.com', '1978-08-06'),
  ('jungdoyun553', 'jungdoyun0124', '정도윤', '010-1333-3496', 'jungdoyun553@example.com', '2000-01-24'),
  ('hajun_choi00', 'Spring2000@', '최하준', '010-2771-1420', 'hajun_choi00@example.com', '2000-11-04'),
  ('sunny_sua', 'Summer1994#', '권수아', '010-9728-8018', 'sunny_sua@example.com', '1994-07-23'),
  ('jimin_han74', 'hanjimin0921', '한지민', '010-8135-3885', 'jimin_han74@example.com', '1974-09-21'),
  ('gunwoo_oh87', 'Gunwoo87$', '오건우', '010-5569-8385', 'gunwoo_oh87@example.com', '1987-10-26'),
  ('junseo.choi', 'Happy1994#', '최준서', '010-5526-1166', 'junseo_choi@example.com', '1994-06-01'),
  ('lucky_siwoo', 'Siwoo75@', '장시우', '010-5820-4630', 'lucky_siwoo@example.com', '1975-04-24'),
  ('lucky_haeun', 'Lucky1989#', '조하은', '010-6023-5118', 'lucky_haeun@example.com', '1989-11-19'),
  ('cjiwoo0604', 'Choi$5530', '최지우', '010-9595-5636', 'cjiwoo0604@example.com', '1982-06-04'),
  ('siwoo88', 'leesiwoo0412', '이시우', '010-9042-2680', 'siwoo88@example.com', '1988-04-12'),
  ('minjun.shin', 'minjun1988!', '신민준', '010-9056-2213', 'minjun_shin@example.com', '1988-08-16'),
  ('seoyeon79', 'seoyeon1979!', '임서연', '010-8381-8253', 'seoyeon79@example.com', '1979-03-26'),
  ('happy_woojin', 'jungwoojin0519', '정우진', '010-4929-3847', 'happy_woojin@example.com', '1997-05-19'),
  ('doyun_jang80', 'doyun1980!', '장도윤', '010-2166-4824', 'doyun_jang80@example.com', '1980-01-14'),
  ('kjiho0704', 'kwonjiho0704', '권지호', '010-6039-5728', 'kjiho0704@example.com', '1982-07-04'),
  ('yoonjiwoo717', 'Blue1999!', '윤지우', '010-5102-1423', 'yoonjiwoo717@example.com', '1999-12-10'),
  ('haeun71', 'Lee#3973', '이하은', '010-8141-9056', 'haeun71@example.com', '1971-11-27'),
  ('chaewon.lee', 'Lee#7561', '이채원', '010-1601-8451', 'chaewon_lee@example.com', '1992-07-11'),
  ('star_yejun', 'Lee!4073', '이예준', '010-6927-9167', 'star_yejun@example.com', '1986-06-04'),
  ('hanjunseo563', 'hanjunseo0409', '한준서', '010-6091-1224', 'hanjunseo563@example.com', '1973-04-09'),
  ('yujin_jang75', 'Coffee1975$', '장유진', '010-7807-8905', 'yujin_jang75@example.com', '1975-04-27'),
  ('coffee_haeun', 'Yoon$6568', '윤하은', '010-5377-1042', 'coffee_haeun@example.com', '1999-09-05'),
  ('jungsua552', 'jungsua0315', '정수아', '010-7274-4826', 'jungsua552@example.com', '2001-03-15'),
  ('yujin_shin72', 'Shin@9229', '신유진', '010-6439-2644', 'yujin_shin72@example.com', '1972-06-24'),
  ('junseo_shin76', 'Shin#6546', '신준서', '010-7512-2315', 'junseo_shin76@example.com', '1976-09-15'),
  ('lucky_yejun', 'Yejun04!', '신예준', '010-8110-2612', 'lucky_yejun@example.com', '2004-07-11'),
  ('jiwoo98', 'jiwoo1998!', '서지우', '010-3385-5000', 'jiwoo98@example.com', '1998-03-23'),
  ('yujin_jang81', 'Blue1981@', '장유진', '010-8529-5183', 'yujin_jang81@example.com', '1981-03-06'),
  ('minjun99', 'minjun1999!', '한민준', '010-5949-4263', 'minjun99@example.com', '1999-05-22'),
  ('dream_chaewon', 'Chaewon76#', '조채원', '010-1803-9138', 'dream_chaewon@example.com', '1976-04-13'),
  ('ssua1026', 'Dragon1984@', '신수아', '010-8222-1546', 'ssua1026@example.com', '1984-10-26'),
  ('jimin.lim', 'Coffee1978#', '임지민', '010-8894-5835', 'jimin_lim@example.com', '1978-02-10'),
  ('oyejun0803', 'Spring1977!', '오예준', '010-9791-3024', 'oyejun0803@example.com', '1977-08-03'),
  ('jimin86', 'Jimin86@', '윤지민', '010-8606-5951', 'jimin86@example.com', '1986-10-13'),
  ('hanyujin969', 'hanyujin0302', '한유진', '010-7367-8432', 'hanyujin969@example.com', '1977-03-02'),
  ('daeun_kang96', 'Blue1996$', '강다은', '010-4559-8264', 'daeun_kang96@example.com', '1996-10-24'),
  ('yhaeun0222', 'Haeun93#', '윤하은', '010-8450-2501', 'yhaeun0222@example.com', '1993-02-22'),
  ('siwoo.han', 'Summer1971@', '한시우', '010-3417-1046', 'siwoo_han@example.com', '1971-01-26'),
  ('hajun78', 'Jung#4898', '정하준', '010-6304-1258', 'hajun78@example.com', '1978-09-09'),
  ('jiho73', 'Park#9408', '박지호', '010-2786-8405', 'jiho73@example.com', '1973-03-24'),
  ('janghaeun931', 'haeun1972!', '장하은', '010-2768-9032', 'janghaeun931@example.com', '1972-12-26'),
  ('junseo74', 'Dragon1974#', '오준서', '010-8433-9282', 'junseo74@example.com', '1974-02-11'),
  ('lyujin1204', 'Lucky1976$', '임유진', '010-8430-7532', 'lyujin1204@example.com', '1976-12-04'),
  ('chojiwoo682', 'Jiwoo90@', '조지우', '010-8075-2582', 'chojiwoo682@example.com', '1990-07-11'),
  ('ocean_jimin', 'Jimin78#', '오지민', '010-5712-6119', 'ocean_jimin@example.com', '1978-09-02'),
  ('jiwoo.kang', 'Kang!5564', '강지우', '010-4705-8030', 'jiwoo_kang@example.com', '2002-04-05'),
  ('daeun05', 'Daeun05@', '신다은', '010-3972-3347', 'daeun05@example.com', '2005-01-20'),
  ('hyunwoo74', 'limhyunwoo0324', '임현우', '010-7062-6105', 'hyunwoo74@example.com', '1974-03-24'),
  ('yejun75', 'Oh$8957', '오예준', '010-8242-7785', 'yejun75@example.com', '1975-01-05'),
  ('jungsiwoo441', 'Jung@7475', '정시우', '010-1897-1125', 'jungsiwoo441@example.com', '2002-02-12'),
  ('choisua262', 'choisua0325', '최수아', '010-7229-9725', 'choisua262@example.com', '1983-03-25'),
  ('haeun02', 'Haeun02$', '오하은', '010-6129-8033', 'haeun02@example.com', '2002-09-27'),
  ('limhyunwoo415', 'Hyunwoo96@', '임현우', '010-4986-8138', 'limhyunwoo415@example.com', '1996-05-04'),
  ('lhyunwoo0213', 'Lim@2251', '임현우', '010-2868-9693', 'lhyunwoo0213@example.com', '2003-02-13'),
  ('siwoo.jang', 'Jang@3842', '장시우', '010-3504-2234', 'siwoo_jang@example.com', '1992-06-24'),
  ('pchaewon1025', 'chaewon1999!', '박채원', '010-8245-5961', 'pchaewon1025@example.com', '1999-10-25'),
  ('jiho_seo73', 'Jiho73$', '서지호', '010-2479-9307', 'jiho_seo73@example.com', '1973-06-17'),
  ('cjunseo1202', 'junseo2005!', '조준서', '010-2695-6626', 'cjunseo1202@example.com', '2005-12-02'),
  ('odoyun1106', 'Blue2002@', '오도윤', '010-7347-7697', 'odoyun1106@example.com', '2002-11-06'),
  ('seoyejun343', 'Lucky1973#', '서예준', '010-2335-3317', 'seoyejun343@example.com', '1973-11-21'),
  ('jimin.kwon', 'Kwon#3093', '권지민', '010-2531-7937', 'jimin_kwon@example.com', '1989-11-23');

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
      prices := '{}'; qtys := '{}'; names := '{}'; total := 0;
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
