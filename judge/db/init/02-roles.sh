#!/bin/sh
# 계정 만들기 (PostgreSQL 컨테이너가 처음 뜰 때 01-schema.sql 다음에 한 번 실행됨)
#   judge     : 판단 서버. 읽기·쓰기 (삭제는 안 함)
#   dashboard : pc3 Streamlit. 읽기만
# 비밀번호는 judge/.env의 PG_JUDGE_PASSWORD, PG_DASHBOARD_PASSWORD (docker-compose.yml이 넘겨 줌)
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v judge_user="$PG_JUDGE_USER" -v judge_pw="$PG_JUDGE_PASSWORD" \
  -v dash_user="$PG_DASHBOARD_USER" -v dash_pw="$PG_DASHBOARD_PASSWORD" <<'EOSQL'
CREATE ROLE :"judge_user" LOGIN PASSWORD :'judge_pw';
CREATE ROLE :"dash_user" LOGIN PASSWORD :'dash_pw';
GRANT CONNECT ON DATABASE bola_judge TO :"judge_user", :"dash_user";
GRANT USAGE ON SCHEMA public TO :"judge_user", :"dash_user";
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO :"judge_user";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO :"dash_user";
EOSQL
