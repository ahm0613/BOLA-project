-- 이미 쓰고 있는 DB에 위험도(risk_pct) 열 추가, 예전 단계 이름(watch / warning)을 새 이름으로 바꿈
-- 새로 만드는 DB는 db/init/01-schema.sql에 이미 들어 있으므로 실행하지 않아도 됨. 여러 번 실행해도 안전함
-- 권한: 테이블 단위로 준 권한(judge 읽기·쓰기, dashboard 읽기)은 새 열에도 그대로 적용되므로 GRANT는 필요 없음
-- 실행 (WSL, /mnt/d/python-rule에서):
--   docker compose exec -T postgres psql -U postgres -d bola_judge < judge/db/migrate/04-risk.sql
\set ON_ERROR_STOP on

BEGIN;

ALTER TABLE bola_events ADD COLUMN IF NOT EXISTS risk_pct INT;   -- 위험도(%) 0~100, 차단이면 100
ALTER TABLE user_status ADD COLUMN IF NOT EXISTS risk_pct INT;

-- 예전 단계 이름 → 새 이름 (경계 점수가 같음: watch 30~59 = danger, warning 60~99 = high)
UPDATE bola_events SET decision = 'danger' WHERE decision = 'watch';
UPDATE bola_events SET decision = 'high'   WHERE decision = 'warning';
UPDATE bola_events SET user_status = 'danger' WHERE user_status = 'watch';
UPDATE bola_events SET user_status = 'high'   WHERE user_status = 'warning';
UPDATE user_status SET user_status = 'danger' WHERE user_status = 'watch';
UPDATE user_status SET user_status = 'high'   WHERE user_status = 'warning';

-- 이미 있는 행의 위험도 채우기 (차단 기준 100점 기준)
UPDATE bola_events SET risk_pct = CASE WHEN user_status = 'confirmed' THEN 100
                                       ELSE LEAST(GREATEST(risk_score, 0), 100) END
WHERE risk_pct IS NULL AND (risk_score IS NOT NULL OR user_status = 'confirmed');
UPDATE user_status SET risk_pct = CASE WHEN user_status = 'confirmed' THEN 100
                                       ELSE LEAST(GREATEST(risk_score, 0), 100) END
WHERE risk_pct IS NULL AND (risk_score IS NOT NULL OR user_status = 'confirmed');

COMMIT;
