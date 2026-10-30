-- 판단 서버 DB 스키마 (PostgreSQL 컨테이너가 처음 뜰 때 한 번 실행됨)
-- 역할: pc3 Streamlit이 읽을 데이터. 판단 서버(judge)만 쓰고, 대시보드(dashboard)는 읽기만 한다.
-- 시간은 모두 TIMESTAMPTZ (Streamlit에서 한국 시간으로 보여 줌)

-- 탐지 이벤트: Redis bola:events 한 건 = 한 행. Redis 값 + 그 시점의 판단 결과 + (있으면) 조치
CREATE TABLE bola_events (
  stream_id              TEXT PRIMARY KEY,     -- Redis 스트림 ID (행의 고유 키. event_id는 겹칠 수 있음)

  -- Redis 로그에서 그대로
  event_id               TEXT,                 -- BOLA 탐지 사건 ID = request_id (RATE는 계기가 된 요청과 같은 값)
  event_at               TIMESTAMPTZ,          -- BOLA 탐지 시각 = started_at (Kong이 요청을 받은 시각)
  detected_at            TIMESTAMPTZ NOT NULL, -- 탐지 발생 시각 = 스트림 ID의 시각 (탐지 엔진이 Redis에 올린 시각)
  user_id                TEXT NOT NULL,        -- 공격 의심 사용자 ID
  action_type            TEXT NOT NULL,        -- kind: BOLA / ATTEMPT / UNKNOWN / RATE
  api_path               TEXT,                 -- 탐지 대상 API (예: GET /members/{id})
  detection_reasons      JSONB NOT NULL,       -- 탐지 근거: detail(장부 비교 결과) + 판단 서버 분류·점수·피해자

  -- 판단 서버 (이 이벤트까지 반영한 그 시점의 값)
  risk_score             INT,                  -- 위험도 점수 (24시간 합계). 판단 서버 시작 전에 확정된 사용자는 NULL
  assessed_at            TIMESTAMPTZ NOT NULL, -- 위험도 산정 시각
  decision               TEXT NOT NULL,        -- normal / watch / warning / attack / ignored(본인 번호 오탐)
  decision_reason        TEXT NOT NULL,        -- 최종 판단 근거
  user_status            TEXT NOT NULL,        -- 사용자 현재 상태: normal / watch / warning / confirmed
  user_status_updated_at TIMESTAMPTZ,          -- 사용자 상태가 마지막으로 바뀐 시각

  -- 조치 (있을 때만, 없으면 NULL)
  --   AC-<스트림ID>-R : RATE = 탐지 엔진(realtime.py)의 임시 차단 (판단 서버는 기록만)
  --   AC-<스트림ID>-L : 공격 확정 → confirmed.json 등록 (장부 학습에서 제외, 만료 없음)
  action_id              TEXT,                 -- 제한·차단 조치 ID
  action_reason          TEXT,                 -- 제한·차단 사유
  decided_at             TIMESTAMPTZ,          -- 조치 결정 시각
  enforcement_status     TEXT,                 -- applied / failed / expired
  enforced_at            TIMESTAMPTZ,          -- 실제 조치 적용 시각
  expires_at             TIMESTAMPTZ,          -- 임시 제한 만료 시각 (RATE)
  released_at            TIMESTAMPTZ           -- 실제 제한 해제 시각 (만료되면 판단 서버가 채움)
);
CREATE INDEX ON bola_events (user_id, detected_at DESC);
CREATE INDEX ON bola_events (detected_at DESC);
CREATE INDEX ON bola_events (event_id);
CREATE INDEX ON bola_events (enforcement_status) WHERE enforcement_status IS NOT NULL;

-- 사용자 현재 상태: 사용자당 1행, 바뀔 때마다 덮어씀 (대시보드의 "지금 위험한 사용자")
CREATE TABLE user_status (
  user_id                TEXT PRIMARY KEY,
  user_status            TEXT NOT NULL,        -- normal / watch / warning / confirmed
  user_status_updated_at TIMESTAMPTZ NOT NULL, -- 상태 값이 마지막으로 바뀐 시각 (점수만 바뀌면 그대로)
  risk_score             INT,                  -- 마지막 위험도 점수
  last_event_at          TIMESTAMPTZ,          -- 마지막 의심 요청 시각
  last_stream_id         TEXT                  -- 마지막 이벤트 (bola_events.stream_id)
);
