# BOLA-project
API 인가 우회(BOLA, Broken Object Level Authorization) 취약점을 **실시간으로 탐지하고 차단**하는 시스템이다.

API 게이트웨이(Kong) 로그만 보고, 정상 트래픽에서 "어떤 객체의 주인이 누구인지"를 학습한 장부(ledger)로 남의 객체에 접근하는 요청을 찾아낸다. 탐지 결과는 사용자별 점수로 쌓여, 공격자로 확정되면 게이트웨이에서 차단된다.

> ⚠️ **주의: 이 저장소에는 일부러 취약하게 만든 API가 들어 있다.**
> `app/`의 `members`, `orders` 서비스는 탐지 실험을 위해 BOLA 취약점을 그대로 두었다 (`BOLA_VULNERABLE=true`).
> 폐쇄망·실험 환경에서만 실행하고, 인터넷에 공개된 서버에 띄우지 않는다.

## 구성

| PC | 역할 | 폴더 |
|---|---|---|
| 게이트웨이 (pc2, 192.168.0.39) | WAF → Kong → API 서비스, DB, Redis, 로그 수집 | [`app/`](app/README.md) |
| 탐지·판단 (pc1, 192.168.0.40) | 실시간 BOLA 판정, 점수 계산, 공격자 확정 | [`engine/`](engine/README.md), [`judge/`](judge/README.md) |
| 로그 저장 (192.168.0.26) | Wazuh 인덱서 | [`wazuh/`](wazuh/README.md) |

## 폴더

| 폴더 | 내용 |
|---|---|
| [`app/`](app/README.md) | 게이트웨이 PC 전체: WAF(ModSecurity CRS), Kong, NestJS API 서비스 7개, 쇼핑몰 웹, PostgreSQL, Redis, Fluent Bit, Wazuh agent |
| [`engine/`](engine/README.md) | 탐지 엔진: 장부 학습(`ledger_v2.py`, Wazuh 버전 `ledger.py`), 설치 전 공격자 찾기(`ledger_v3.py`), 실시간 판정(`realtime.py`) |
| [`judge/`](judge/README.md) | 판단 엔진: 탐지 이벤트로 사용자별 점수 → 공격자 확정 → 영구 차단, PostgreSQL 기록, Slack 알림 |
| [`attack/`](attack/README.md) | 공격 시뮬레이터(`simulate.py`): burst / steady / slow / rotate 시나리오 |
| [`wazuh/`](wazuh/README.md) | Wazuh 인덱서 설정 |

## 동작 흐름

1. 사용자 요청 → **WAF** → **Kong** (JWT 검증, Redis 차단 키 확인, 초당 요청 제한) → API 서비스
2. Kong 접근 로그 → **Fluent Bit** → (mTLS) → **탐지 엔진** `engine/realtime.py`
3. 탐지 엔진이 장부로 판정: BOLA / ATTEMPT / UNKNOWN → Redis Stream `bola:events`, 10초에 의심 요청 10번 초과 시 임시 차단
4. **판단 엔진** `judge/judge.py`가 이벤트로 사용자별 점수 계산 → 기준을 넘으면 공격자로 확정하고 영구 차단
5. 장부는 지난 30일 로그로 다시 학습한다 (확정된 공격자·요청은 제외)

## 시작하기

1. 키와 인증서를 준비한다 (저장소에 없음): [`app/README.md`](app/README.md)
2. 게이트웨이 PC: `app` 폴더에서 `docker compose up -d --build`
3. 탐지 PC
   - `engine` 폴더: `.env`(Redis 비밀번호)와 `certs/`를 준비하고 `docker compose up -d --build`
   - `judge` 폴더: `.env`(Redis·PostgreSQL 비밀번호, Slack 웹훅)를 준비하고 `docker compose up -d --build`
   - 자세한 내용은 [`engine/README.md`](engine/README.md), [`judge/README.md`](judge/README.md)
4. 공격 시험: [`attack/README.md`](attack/README.md)
