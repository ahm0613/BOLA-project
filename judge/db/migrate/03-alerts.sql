-- 이미 쓰고 있는 DB에 alerts 테이블 추가 (Slack 알림 기록, notifier.py)
-- 새로 만드는 DB는 db/init/01-schema.sql에 이미 들어 있으므로 실행하지 않아도 됨. 여러 번 실행해도 안전함
-- 실행 (WSL, /mnt/d/python-rule에서. 계정 이름이 .env의 PG_JUDGE_USER, PG_DASHBOARD_USER와 다르면 바꿀 것):
--   docker compose exec -T postgres psql -U postgres -d bola_judge -v judge_user=judge -v dash_user=dashboard < judge/db/migrate/03-alerts.sql
\set ON_ERROR_STOP on

CREATE TABLE IF NOT EXISTS alerts (
  alert_key              TEXT PRIMARY KEY,
  channel                TEXT NOT NULL,
  kind                   TEXT NOT NULL,
  user_id                TEXT,
  api_path               TEXT,
  message                TEXT NOT NULL,
  status                 TEXT NOT NULL,
  attempts               INT NOT NULL DEFAULT 0,
  created_at             TIMESTAMPTZ NOT NULL,
  sent_at                TIMESTAMPTZ,
  last_error             TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created_at_idx ON alerts (created_at DESC);

GRANT SELECT, INSERT, UPDATE ON alerts TO :"judge_user";
GRANT SELECT ON alerts TO :"dash_user";
