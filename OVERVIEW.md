# BOLA 탐지·판단 시스템 전체 동작과 로그 보는 곳

pc2 Kong의 API 로그를 실시간으로 받아 **BOLA(객체 수준 인가 우회, Broken Object Level Authorization)** 를 판정하고(`fluent-bit`),
사용자별 누적 점수가 100점에 이르면 공격자로 확정해 **영구 차단**하며 PostgreSQL에 기록하고 Slack으로 알립니다(`judge`).
pc3 Streamlit은 `bola_db.py`로 그 DB를 읽어 보여 줍니다 (사본: `archive/dashboard/`).

> 마지막 정리: 2026-11-09. 점수는 기간 제한 없이 **영구 누적**(`window_sec: 0`)하고, 판단 서버를 다시 시작하면 DB `bola_events`로 점수를 복원합니다. 조회/쓰기 구분, 1대1 자동 추론(`path_owners: "auto"`), Slack 알림(`notifier.py`)이 반영돼 있습니다. 11/06에 DB·Redis·확정 명단·점수 로그를 모두 비웠고 처음부터 쌓는 중입니다 (8장).

목차

1. 한눈에 보기
2. 요청 하나가 지나가는 길 (단계마다 남는 로그)
3. **로그 어디서 보나**
4. **상황별로 볼 곳**
5. 단계별 동작 자세히
6. 영구 차단 관리 (해제, 설치 전 이력 가져오기)
7. Docker 명령어
8. 현재 상태
9. 처음 준비와 포트
10. 폴더
11. 알려진 문제와 남은 과제

---

## 1. 한눈에 보기

```
[장부 학습, 수동]  pc1
  access_fake.json ─ledger_v2.py─▶ ledger_days + 1차 장부 ─ledger_v3.py─▶ confirmed.json (설치 전 BOLA 사용자)
                                                          ─ledger_v2.py─▶ ledger.json (그 사용자를 뺀 깨끗한 장부)
                   판단 서버를 그 뒤에 켜면 confirmed.json 명단을 영구 차단

[실시간 탐지·차단, Docker]
pc2 (게이트웨이)                      pc1 (이 PC, WSL Docker)                              pc3
┌───────────────────┐
│ Kong              │ ① 로그 (mTLS 5170)
│  └ Fluent Bit ────┼───────────▶ bola-realtime   fluent-bit/realtime.py
│                   │                ledger.json으로 BOLA / ATTEMPT / UNKNOWN 판정
│                   │                10초에 의심 요청 10번 초과 → 10분 임시 차단
│ Redis             │ ② 이벤트, 임시 차단 키
│  ├ bola:events ◀──┼────────────────┘
│  └ blocked:user:N ◀───────────┐ ⑤ 영구 차단 키 (만료 없음)
│        │          │ ③ 새 이벤트 │
│        └──────────┼───────────▶ bola-judge      judge/judge.py
│                   │                사용자별 누적 점수 → 위험도 % → 100%(100점)면 확정
│ Kong: 요청마다     │                ├─▶ fluent-bit/confirmed.json (영구 차단 명단, 학습 제외)
│ blocked:user:N 조회│                ├─▶ ④ judge-postgres (5432)
│ 있으면 403         │                │      bola_events, user_status, alerts ──portproxy──▶ Streamlit
└───────────────────┘                │                                                 └ bola_db.py
                                     └─▶ Slack 웹훅 (관리자: 고위험·차단·RATE·요약 / 개발자: 털린 API)
```

| 순서 | 파일 | 실행 | 역할 |
|---|---|---|---|
| 1 | `fluent-bit/ledger_v2.py` | 수동 | 학습 로그로 1차 장부 |
| 2 | `fluent-bit/ledger_v3.py` | 수동 (설치할 때) | 1차 장부로 설치 전 로그의 BOLA 사용자·요청을 찾아 `confirmed.json`에 합침 (판단 서버가 꺼져 있을 때만, `--dry-run`은 미리 보기). 그 뒤 `ledger_v2.py`를 다시 돌려 깨끗한 장부 |
| 3 | `fluent-bit/realtime.py` | Docker `bola-realtime` | 장부로 BOLA 판정, 10분 임시 차단 |
| 4 | `judge/judge.py` | Docker `bola-judge` | 점수(조회·쓰기 구분, 영구 누적), 확정, **영구 차단**, DB 기록, 재시작 때 DB로 점수 복원. 1대1 API 자동 추론(`api_infer.py`), Slack 알림(`notifier.py`) |
| 5 | `judge/unblock.py` | 관리자 수동 | 영구 차단 해제 (오탐일 때) |
| 6 | `dashboard/bola_db.py` | pc3 | DB 읽기 (pc1에는 `archive/dashboard/`에 사본만 있음) |
| — | `attack/simulate.py` | 수동 (검증용) | 본인 시스템에 BOLA 공격을 보내 탐지·차단을 검증 (burst/steady/slow/rotate, 무작위 순서). 상세는 `attack/README.md` |

---

## 2. 요청 하나가 지나가는 길 (단계마다 남는 로그)

사용자 7이 남의 회원 정보 `/members/3`, `/members/4`, `/members/5`를 차례로 조회했을 때입니다.

```
① pc2 Kong                       요청 처리 → /logs/kong/access.json 에 한 줄
   {"request_id":"a1…","user_id":"7","uri":"/members/3","status":200,…}

② pc2 Fluent Bit                 access.json 을 tail → pc1:5170 으로 전송 (mTLS)

③ pc1 bola-realtime              docker compose logs realtime
   [BOLA   ] GET /members/{id}   요청자 7 -> 3 (주인 3) req=a1…
                                 + Redis bola:events 에 이벤트 1건 (XADD)

④ pc1 bola-judge                 docker compose logs judge
   [점수] 15:10:02 사용자 7 BOLA 200 /members/3 → BOLA_PATH +40 = 40/100점 (위험도 40% 위험) {…} 피해자 ['3']
   [점수] 15:10:05 사용자 7 BOLA 200 /members/4 → BOLA_PATH +40 = 80/100점 (위험도 80% 고위험) …
   [점수] 15:10:09 사용자 7 BOLA 200 /members/5 → BOLA_PATH +40 = 150/100점 (위험도 100% 차단) …  ★ 확정
   [확정] 사용자 7 점수 150 {'BOLA_PATH': 120, '+victims': 30} 피해자 ['3','4','5'] 요청 3건
   [차단] 사용자 7 영구 차단 (blocked:user:7) 공격 확정: …
                                 + judge/output/score_log.jsonl      점수 줄 3개 (JSON)
                                 + judge/output/confirmed_log.jsonl  확정 근거 1줄 (type user)
                                 + fluent-bit/confirmed.json         users 에 "7" 추가
                                 + Redis blocked:user:7 = "confirmed" (TTL 없음)

⑤ pc1 judge-postgres             1초 안에
   bola_events  3행 (마지막 행에 action_id AC-…-L, enforcement_status applied)
   user_status  사용자 7 = confirmed, risk_pct 100 (위험도), risk_score 150 (차단 근거)

⑥ pc2 Kong                       사용자 7의 다음 요청부터 403 "blocked by security policy"
                                 access.json 에 "blocked": true, "status": 403
                                 (realtime 은 Kong이 막은 요청은 판정하지 않음 → 로그 없음)

⑦ pc3 대시보드                   5초 안에 사용자 7이 확정·조치 목록에 표시
```

---

## 3. 로그 어디서 보나

### 3-1. 한 장 요약

| 알고 싶은 것 | 어디서 | 명령 / 위치 | 오래 남나 |
|---|---|---|---|
| 로그가 pc1에 들어오나, 무엇이 의심으로 판정됐나 | 탐지 엔진 화면 출력 | `docker compose logs -f realtime` | 컨테이너를 다시 만들면 사라짐 |
| 점수가 어떻게 쌓였나, 누가 확정·차단됐나 | 판단 서버 화면 출력 | `docker compose logs -f judge` | 컨테이너를 다시 만들면 사라짐 |
| 점수 기록을 파일로 | 점수 로그 | `judge/output/score_log.jsonl` | ✅ |
| 확정·해제의 근거와 승인자 | 감사 기록 | `judge/output/confirmed_log.jsonl` | ✅ |
| 어떤 API에서 누가 털렸나 | 요약 파일 | `judge/output/breached_apis.json` | ✅ (최신 상태로 덮어씀) |
| 지금 영구 차단 명단 | 명단 파일 | `fluent-bit/confirmed.json` | ✅ |
| 지금 Kong이 막고 있는 사용자 | Redis 차단 키 | `docker compose exec judge python unblock.py --list` | Redis |
| 탐지·판단·조치 전체 이력 | DB | `bola_events`, `user_status` (psql, DBeaver, pc3 대시보드) | ✅ |
| Slack 알림을 보냈나, 실패했나 | DB | `alerts` (`status`: sent / failed / skipped) | ✅ |
| 장부 학습 결과 | 학습 스크립트 화면 출력 | `python ledger_v2.py`, `python ledger_v3.py` 실행 화면 | 화면만 (결과 파일은 `ledger.json`, `confirmed.json`) |
| 컨테이너 자동 시작, 포트 전달 | 스크립트 로그 | `judge/output/startup.log`, `portproxy.log` | ✅ |
| 요청 원본 | pc2 Kong 로그 | pc2 `/logs/kong/access.json` (kong-logs 볼륨) | pc2 |
| pc2 → pc1 전송 오류 (연결, TLS) | pc2 Fluent Bit | pc2에서 `docker logs <fluent-bit 컨테이너>` | pc2 |

모든 `docker compose` 명령은 WSL에서 `cd /mnt/d/python-rule` 한 뒤에 실행합니다 (7장).

### 3-2. 탐지 엔진 로그: `docker compose logs -f realtime`

**정상 요청은 출력하지 않습니다.** 아무것도 안 뜨면 의심 요청이 없는 것입니다.

| 줄 | 뜻 | 언제 |
|---|---|---|
| `[장부] 읽음: API 10개, 객체 1359개` | 장부를 읽음 | 시작할 때, `ledger.json`이 바뀐 뒤 첫 요청 때 |
| `[Redis] 연결됨 192.168.0.39:6379` | pc2 Redis 접속 성공 | 시작할 때 |
| `5170 포트에서 Fluent Bit 로그를 기다리는 중` | 준비 완료 | 시작할 때 |
| `[BOLA   ] GET /members/{id}  요청자 7 -> 3 (주인 3) req=…` | 남의 객체 조회 성공 | 상태 200, 요청자 ≠ 주인 |
| `[ATTEMPT] GET /orders/{id}  요청자 7 -> 5 (403) req=…` | 시도했다가 막힘 | 403/404 |
| `[UNKNOWN] GET /orders/{id}  요청자 7 -> 999 (장부에 없음)` | 주인을 모르는 객체 | 장부에 없음 |
| `[RATE   ] …  10초에 의심 요청 11번 -> 600초 임시 차단` | 10분 임시 차단 | 의심 요청이 몰림 |
| `[Redis] 보고 실패` / `[Redis] 임시 차단 실패` | Redis에 못 씀 | Redis 꺼짐, 비밀번호 오류 |

```bash
docker compose logs -f realtime | grep -E 'BOLA|ATTEMPT|RATE'     # 의심 판정만
docker compose logs --since 1h realtime | grep -c BOLA             # 최근 1시간 BOLA 건수
docker compose logs -f realtime | grep '요청자 7 '                  # 특정 사용자만
```

### 3-3. 판단 서버 로그: `docker compose logs -f judge`

| 줄 | 뜻 |
|---|---|
| `[DB] postgres:5432/bola_judge 접속됨` | DB 연결 |
| `[1대1 추론] /members/{id} 표본 N건, 일치 N건 (100.0%) → 1대1` | 장부로 URL 번호 = 주인인 API를 찾음. 마지막 줄 `path_owners = [...]`가 결과 |
| `[시작] Redis … → /fluent-bit/confirmed.json \| 영구 차단 켜짐` | 시작. `꺼짐`이면 `config.json`의 `block.enabled` 확인 |
| `[알림] 켜짐 \| 관리자 웹훅 있음, 개발자 웹훅 있음 \| …` | Slack 알림 설정. 웹훅 `없음`이면 보내지 않고 `skipped`로만 기록 |
| `[Redis] 연결 안 됨, 3초 뒤 다시 시도: …` | 시작할 때 pc2 Redis에 못 붙음 (연결 거부·`Timeout connecting to server`). 붙을 때까지 기다림 |
| `[복원] 전체 이벤트: DB N건 + Redis 보충 N건 채점` | 시작할 때 DB `bola_events` 전체로 점수 복원, DB에 아직 안 쓴 것만 Redis에서 보충. DB를 못 읽으면 `Redis N건 채점 (DB 복원 안 함)` |
| `[차단] 명단 동기화: 확정 사용자 N명 중 M명 새로 영구 차단` | `confirmed.json`과 Redis 차단 키 맞춤 (시작할 때, 새로 건 게 있을 때) |
| `[대기] 새 이벤트를 기다리는 중` | 준비 완료 |
| `[점수] 시각 사용자 7 BOLA 200 /members/3 → BOLA_PATH +40 = 40/100점 (위험도 40% 위험) {내역} 피해자 [...]` | 이벤트 하나 채점 |
| `… → 무시: URL 번호가 본인 (장부 오탐)` | 본인 번호라 점수 없음 |
| `… → 이미 확정된 사용자 → 요청만 confirmed.json에 추가` | 확정된 뒤 들어온 이벤트 |
| `… ★ 확정` | 이 이벤트로 100점 넘음 |
| `[확정] 사용자 7 점수 150 {…} 피해자 [...] 요청 N건` + `털린 API: …` | 공격자 확정 |
| `[차단] 사용자 7 영구 차단 (blocked:user:7) …` | Redis 영구 차단 성공 |
| `[차단] 사용자 7 영구 차단 실패: … → 다음 동기화 때 다시 시도` | Redis 문제. 60초마다 재시도 |
| `[상태] 이벤트 N (채점 N, 본인 번호 제외 N) 확정 사용자 N … \| 점수 상위 7:150` | 60초마다 요약 |
| `[털린 API] GET /members/{id} 털린 객체 {3,4,5} ← 공격자 {7}` | 60초마다 요약 (숫자는 주인이 아니라 접근한 객체 번호) |
| `[DB] 기록 이벤트 N 사용자 상태 N (실패 0, 버림 0)` | 60초마다. 실패·버림이 늘면 DB 문제 |
| `[알림] 보냄 N 실패 N 웹훅 없어 건너뜀 N 중복 N 대기 N` | 60초마다 Slack 알림 요약 |
| `[Redis] 연결 끊김, 3초 뒤 다시 시도` | Redis 재시작, 네트워크 |
| `[오류] … 처리 실패` | 이상한 이벤트 하나 (서버는 계속 돎) |

```bash
docker compose logs -f judge | grep -E '확정|차단'        # 확정, 영구 차단만
docker compose logs -f judge | grep '사용자 7 '           # 특정 사용자
docker compose logs --since 1h judge | grep -E '오류|실패|끊김'   # 문제만
```

### 3-4. 파일로 남는 로그 (`judge/output/`)

| 파일 | 한 줄 / 내용 | 언제 쓰나 |
|---|---|---|
| `score_log.jsonl` | 이벤트 하나의 채점 결과 (JSON). `user_id`, `kind`, `uri`, `item`, `points`, `total`, `breakdown`, `result` | 실시간 모드에서 이벤트마다 |
| `confirmed_log.jsonl` | 확정·해제 근거 (감사 기록). `type`: `user`(사용자 확정), `request`(요청 확정), `release`(해제) | 확정·해제·가져오기 때 |
| `breached_apis.json` | API별 털린 객체 번호·공격자, 공격자별 API (`_by_user`) | 새로 털린 게 생길 때 덮어씀 |
| `startup.log`, `portproxy.log` | 로그온 자동 시작, 포트 전달 결과 | 스크립트 실행 때 |

```powershell
# PowerShell에서 실시간으로 (한글이 깨지지 않게 -Encoding utf8)
Get-Content D:\python-rule\judge\output\score_log.jsonl -Wait -Encoding utf8
# 확정·해제 줄만
Get-Content D:\python-rule\judge\output\confirmed_log.jsonl -Encoding utf8 | Select-String '"type": "(user|release)"'
```

### 3-5. DB에서 보기 (가장 오래, 가장 자세히 남음)

```bash
docker compose exec postgres psql -U postgres -d bola_judge      # 접속 (\q 종료)
```

```sql
-- 최근 탐지 이벤트
SELECT detected_at, user_id, action_type, api_path, risk_pct, risk_score, decision, action_id
FROM bola_events ORDER BY detected_at DESC LIMIT 20;

-- 지금 위험한 사용자
SELECT user_id, user_status, risk_pct, risk_score, last_event_at FROM user_status
ORDER BY risk_pct DESC NULLS LAST, risk_score DESC NULLS LAST;

-- 조치 이력 (임시 차단 R, 확정·영구 차단 L, 설치 전 이력 가져오기 IMPORT)
SELECT decided_at, user_id, action_id, enforcement_status, expires_at, released_at, action_reason
FROM bola_events WHERE action_id IS NOT NULL ORDER BY decided_at DESC;

-- 특정 사용자의 모든 기록
SELECT detected_at, action_type, api_path, decision, decision_reason, detection_reasons->>'detail' AS detail
FROM bola_events WHERE user_id = '7' ORDER BY detected_at;
```

화면으로 보려면 DBeaver에서 `192.168.0.40:5432`, DB `bola_judge`, 사용자 `dashboard`(읽기 전용)로 접속합니다.

### 3-6. Redis에서 보기 (지금 상태)

```bash
docker compose exec judge python unblock.py --list      # 차단된 사용자, 영구/임시, 사유
docker compose exec -T judge python -c "
import judge, redis
judge.load_env(); rc = judge.load_config()['redis']
r = redis.Redis(host=rc['host'], port=rc['port'], password=rc['password'], decode_responses=True)
print('이벤트 수', r.xlen('bola:events'))
print('그룹', [(g['name'], g['pending']) for g in r.xinfo_groups('bola:events')])
for i, f in r.xrevrange('bola:events', count=5): print(i, f['kind'], f['user_id'], f['uri'], f.get('detail'))
"
```

| 키 | 내용 |
|---|---|
| `bola:events` | 탐지 이벤트 스트림 (최대 10만 건). 그룹 `judges`의 `pending`이 계속 늘면 판단 서버가 못 읽는 중 |
| `blocked:user:N` | 차단 키. TTL `-1` = 영구, 양수 = 임시(남은 초) |
| `block:info:N` | 영구 차단 사유, 시각, 처리자 |

### 3-7. pc2에서 보기

| 알고 싶은 것 | pc2에서 |
|---|---|
| 요청 원본, Kong이 막았는지 | Kong 로그 `/logs/kong/access.json`의 `"blocked": true`, `"status": 403` |
| pc1으로 로그가 가는지, TLS 오류 | `docker logs <fluent-bit 컨테이너>` |
| Kong이 Redis를 못 읽는지 | `docker logs <kong 컨테이너> 2>&1 \| grep -i redis` |

---

## 4. 상황별로 볼 곳

| 상황 | 먼저 볼 곳 | 확인할 것 |
|---|---|---|
| 공격을 했는데 아무 반응이 없음 | `logs realtime` | `[BOLA]`가 뜨나? 안 뜨면 ↓ |
| └ realtime에 아무 줄도 안 뜸 | pc2 Fluent Bit 로그, pc1 portproxy | 5170 전송·TLS 오류, `wsl-portproxy.ps1 -Port 5170` 다시 실행 |
| └ `[UNKNOWN]`만 뜸 | `ledger.json` | 장부에 그 객체가 없음 (새 객체, 2차 학습에서 빠진 객체) |
| └ 본인 번호인데 `[BOLA]` | `ledger.json` | 장부 오염. 판단 서버가 `무시`로 걸러서 차단은 안 됨 |
| realtime에는 뜨는데 점수가 안 오름 | `logs judge` | `[점수]` 줄이 있나, `무시:`인가, `[Redis] 연결 끊김`인가 |
| 100점 넘었는데 안 막힘 | `logs judge`의 `[차단]` → `unblock.py --list` → pc2 Kong 로그 | 키가 있는데도 200이면 pc2 Kong의 Redis 인증(`red:auth`) 문제 |
| 정상 사용자가 막힘 | `unblock.py --list`의 사유 → `confirmed_log.jsonl` → DB 해당 사용자 기록 | 근거가 `BOLA_LEDGER`·`UNKNOWN` 위주면 장부 오류 의심 → `unblock.py` |
| 대시보드에 안 보임 | DB 직접 조회 → `logs judge`의 `[DB]` 줄 | DB에 있는데 안 보이면 pc3 연결(5432 portproxy, 방화벽) |
| 판단 서버가 계속 재시작됨 | `logs judge`의 마지막 줄 | `NOGROUP`(Redis 초기화), 인증 실패(`.env`) |
| 판단 서버가 `[Redis] 연결 안 됨`만 반복 | pc2 Redis, pc1 → pc2 6379 | pc2 Redis 컨테이너가 떠 있나, pc2 방화벽·IP(`config.json` `redis.host`). 붙으면 저절로 이어서 처리 |
| 정상 사용자 점수가 계속 올라감 | DB `user_status`, `bola_events` | 영구 누적이라 점수가 줄지 않음. `ATTEMPT`·`RATE`가 오래 쌓인 것이면 오탐 의심 |
| Slack 알림이 안 옴 | `logs judge`의 `[알림]` 줄 → DB `alerts` | 웹훅 `없음`(`.env`), `failed`의 `last_error`. 시험: `docker compose run --rm judge python notifier.py --test` |
| 장부를 바꿨는데 반영 안 됨 | `logs realtime`의 `[장부] 읽음` | 요청이 없으면 아직 안 읽음 → `docker compose restart realtime` |

---

## 5. 단계별 동작 자세히

### 5-1. 탐지: `fluent-bit/realtime.py` (컨테이너 `bola-realtime`)

로그 한 줄을 장부(`ledger.json`: API별 `{객체 ID: 주인 user_id}`)와 비교합니다. 위에서부터 검사해 처음 걸리는 결과를 냅니다.

| 순서 | 조건 | 결과 |
|---|---|---|
| 1 | 비로그인, admin, Kong이 이미 차단한 요청, 숫자 ID 없음, 장부에 없는 API | 판정 안 함 |
| 2 | 상태 403/404 | `ATTEMPT` |
| 3 | 장부에 그 객체 ID가 없음 | `UNKNOWN` |
| 4 | 장부의 주인이 `null` (공유 객체) | 판정 안 함 |
| 5 | 상태 200이고 요청자 ≠ 장부상 주인 | `BOLA` |
| 6 | 그 밖 (본인 객체 등) | 정상 (출력 안 함) |

- **임시 차단:** 의심 요청이 사용자별로 10초에 10번을 넘으면 `SET blocked:user:<id> "rate" EX 600 NX` + `RATE` 보고. `NX`라서 영구 차단 키를 덮어쓰지 않습니다.
- **목록으로 장부 채우기:** 목록 응답의 `resp_ids`로 새 객체를 메모리 장부에 추가합니다 (파일에는 저장 안 함).
- **장부 다시 읽기:** 로그가 들어올 때 `ledger.json`이 바뀌었는지 확인합니다 (최대 60초마다).

### 5-2. 판단: `judge/judge.py` (컨테이너 `bola-judge`)

Redis `bola:events`를 소비자 그룹 `judges`로 읽어 사용자별 점수를 **기간 제한 없이 누적**합니다 (`config.json` `window_sec: 0`. 86400으로 바꾸면 최근 24시간만 합산).

| 항목 | 점수 | 조건 |
|---|---|---|
| `BOLA_PATH` / `BOLA_PATH_WRITE` | 40 / 60 | `/members/{id}`, `/profiles/{id}`에서 남의 번호 조회 / 수정·삭제(PUT·PATCH·DELETE) (URL로 확실) |
| `BOLA_LEDGER` / `BOLA_LEDGER_WRITE` | 30 / 50 | 그 밖의 BOLA 조회 / 수정·삭제 (장부 근거) |
| `UNKNOWN` | 20 | 장부에 없는 객체를 성공 조회 |
| `ATTEMPT` | 5 | 403/404 |
| `RATE` | 10 | 임시 차단 발생 |
| `+victims` | 30 | 서로 다른 피해자 3명 이상 |
| `+attempt_then_bola` | 20 | ATTEMPT 뒤 BOLA 성공 |
| `+multi_api` | 10 | 2개 이상 자원 종류에서 BOLA |

- 100점은 최대가 아니라 **차단 기준선**입니다. 마지막 요청 점수와 보너스가 한 번에 더해져 확정 순간 150점처럼 넘을 수 있고, 확정 뒤에는 더 채점하지 않습니다. 넘은 점수는 차단 근거(`risk_score`)로만 남깁니다.
- **위험도(`risk_pct`) = min(점수 ÷ 100, 1) × 100%.** 화면에는 이 값을 보여 줍니다. 차단된 사용자는 100%.
- 단계: 정상 `normal` → 주의 `caution`(10) → 위험 `danger`(30) → 고위험 `high`(60) → **차단 `attack`/`confirmed`(100, 확정 + 영구 차단)**. 경계는 `config.json` `levels`. 상세는 `judge/README.md` "위험도와 단계"
- 쓰기(PUT·PATCH·DELETE)는 남의 객체 수정·삭제라 조회보다 높은 `_WRITE` 점수.
- `path_owners`(URL 번호=사용자 번호 API)는 `config.json`에서 `"auto"`면 학습 장부로 자동 추론(`api_infer.py`), `[]`면 끔, 직접 목록 지정도 가능.
- `path_owners` API에서 장부에 없어 `UNKNOWN`으로 온 성공 요청은 `BOLA_PATH`로 올려 채점.
- URL 번호가 본인인 BOLA·ATTEMPT·UNKNOWN은 점수 없음 (`decision = ignored`).
- `confirmed.json`의 `released`(관리자 해제) 시각 이전 이벤트는 채점·DB 기록 안 함.
- 영구 누적이라 점수가 줄지 않습니다. 점수를 처음부터 다시 쌓으려면 DB `bola_events`를 비웁니다 (재시작할 때 이 테이블로 복원하므로).
- 시작할 때 점수 복원 → 이후 새 이벤트만 받음 (처리 후 ACK).
  1. PostgreSQL `bola_events`에서 먼저 복원 (`db.restore`, 기본 켜짐). Redis 스트림은 최근 10만 건만 남지만 DB에는 전부 남음. 복원한 행은 DB에 다시 쓰지 않음.
  2. Redis 스트림에서 ①의 마지막 이벤트 이후만 보충. DB를 못 읽으면 Redis만으로 복원.
  - 복원하는 동안은 Slack 알림을 보내지 않음.

### 5-2-1. 알림: `judge/notifier.py`

| 채널 (`judge/.env`) | 알림 | 횟수 |
|---|---|---|
| 관리자 `SLACK_ADMIN_WEBHOOK` | 사용자 단계가 고위험(`high`)·차단(`attack`)으로 오름 | 사용자·단계마다 한 번 (해제되면 다시 셈) |
| | `RATE` 임시 차단 | 사용자마다 하루 한 번 |
| | `unblock.py` 해제 기록 | 실행할 때마다 |
| | 직전 1시간 요약 | 매시 정각 + 30초 (일이 없어도 보냄 = 판단 서버 생존 신호) |
| 개발자 `SLACK_DEV_WEBHOOK` | API에서 BOLA가 처음 성공 (또는 7일 조용하다가 다시) | 사용자 번호는 넣지 않음 |
| | 직전 1시간 털린 API 요약 | 매시 |

- 보낸 알림은 DB `alerts`에 키로 남겨 같은 알림을 두 번 보내지 않습니다. 실패하면 2, 4, 8, 16초 간격으로 5번까지 다시 시도하고, 판단·차단에는 영향이 없습니다.
- 웹훅 주소가 없으면 보내지 않고 `skipped`로 기록합니다. 끄려면 `config.json` `"notify": {"enabled": false}`.

### 5-3. 영구 차단: `judge/blocker.py`

```
100점 확정 ─┬─▶ Redis SET blocked:user:<id> "confirmed"  (TTL 없음) + block:info:<id> 사유
           ├─▶ confirmed.json users 에 추가
           └─▶ DB: AC-<스트림ID>-L  applied / failed
60초마다 ─▶ confirmed.json users 중 영구 키가 없거나 만료가 붙은 사용자를 다시 영구 차단
pc2 Kong ─▶ 요청마다 GET blocked:user:<id>, 있으면 403
```

| 차단 | 거는 곳 | 기간 | 푸는 방법 |
|---|---|---|---|
| 임시 (RATE) | `realtime.py` | 10분 | 자동 만료, DB `expired` |
| 영구 | `judge.py` (설치 전 이력은 `ledger_v3.py` → confirmed.json → judge 시작 때 차단) | 없음 | `unblock.py` (6장) |

끄려면 `judge/config.json`의 `"block": {"enabled": false}` → `docker compose restart judge`.

### 5-4. 기록: PostgreSQL (컨테이너 `judge-postgres`, DB `bola_judge`)

| 테이블 | 한 행 | 주요 컬럼 |
|---|---|---|
| `bola_events` | Redis 이벤트 1건 (또는 가져오기 조치 1건) | 탐지(`event_id`, `event_at`, `detected_at`, `user_id`, `action_type`, `api_path`, `detection_reasons`) + 판단(`risk_score` 차단 근거 점수, `risk_pct` 위험도, `decision`, `decision_reason`, `user_status`) + 조치(`action_id`, `action_reason`, `decided_at`, `enforcement_status`, `enforced_at`, `expires_at`, `released_at`) |
| `user_status` | 사용자 1명 | `user_status`(normal/caution/danger/high/confirmed), `risk_pct`, `risk_score`, `last_event_at`, `user_status_updated_at` |
| `alerts` | Slack 알림 1건 | `alert_key`, `channel`, `kind`, `user_id`, `api_path`, `status`(sent/failed/skipped), `attempts`, `last_error` |

예전부터 쓰던 DB에 `alerts`가 없으면 `judge/db/migrate/03-alerts.sql`, `risk_pct`가 없으면 `04-risk.sql`로 추가합니다 (파일 머리말에 실행 명령). pc1 DB에는 둘 다 적용돼 있습니다.

조치 컬럼은 조치가 있는 행에만 채워집니다 (나머지는 NULL이 정상).

| `action_id` | 언제 | `enforcement_status` |
|---|---|---|
| `AC-<스트림ID>-R` | RATE (10분 임시 차단) | `applied` → `expired` + `released_at` |
| `AC-<스트림ID>-L` | 실시간 확정 (영구 차단) | `applied` / `failed`, 해제 시 `released` |
| `AC-IMPORT-<시각>-<사용자>-L` | 설치 전 이력 가져오기 (`action_type = IMPORT`) | `applied` / `failed`, 해제 시 `released` |

계정: `judge`(읽기·쓰기), `dashboard`(읽기 전용, pc3).

### 5-5. 조회: `dashboard/bola_db.py` (pc3)

pc3 Streamlit 앱이 `import bola_db`로 씁니다. 읽기 전용 계정 + 읽기 전용 세션, 한국 시간. (대시보드는 pc3에서 도는 별도 컴포넌트입니다. 이 저장소에는 git에 올리지 않는 `archive/dashboard/`에 사본만 있습니다.)

| 함수 | 가져오는 것 |
|---|---|
| `read_all(cfg)` | DB의 모든 테이블 |
| `all_events` / `all_user_status` / `all_actions` | 테이블별 전체 |
| `recent_events` / `risky_users` / `active_actions` | 실시간 화면용 |
| `status_counts` / `event_counts` / `events_per_minute` | 집계 |

### 5-6. 장부 학습 (수동, 설치할 때)

학습 로그는 `fluent-bit/data/access_fake.json`입니다. 실제 설치에서는 **솔루션 설치 전 고객사의 접근 로그**를 같은 형식으로 만든 것이고, 지금은 pc2에서 `gen_fake_logs.py --days 30`으로 만듭니다. 학습(장부 만들기) 상세는 `fluent-bit/README.md`를 보세요.

```powershell
# 판단 서버가 꺼져 있어야 함 (WSL: docker compose stop judge)
cd D:\python-rule\fluent-bit                       # 상대 경로라 이 폴더 안에서
python ledger_v2.py                                # ① 1차: ledger_days + ledger.json
python ledger_v3.py --dry-run                      # ② BOLA 사용자 찾기 (미리 보기)
python ledger_v3.py                                # ② confirmed.json에 합침
python ledger_v2.py                                # ③ confirmed.json을 빼고 다시 학습 → 깨끗한 ledger.json
# WSL: docker compose up -d                        # ④ 판단 서버가 켜지면서 명단을 영구 차단
```

학습 결과는 **실행 화면에만** 출력됩니다 (날짜별 로그 수, 의심 사용자 표, 합칠 내용).

**학습 `ledger_v2.py`** (①, ③)
1. 어제부터 30일치를 날짜별로 집계 (`ledger_days/`, 이미 만든 날짜는 재사용. `confirmed.json`이 바뀌면 다시 만듦).
2. `confirmed.json`의 확정 요청과 확정 사용자의 확정 시각 이후 요청은 뺌.
3. 하루에 같은 객체를 여러 번 봐도 상한(cap)까지만 셈.
4. 한 사용자의 몫이 70% 이상이면 주인, 아니면 `null`.

**BOLA 사용자 찾기 `ledger_v3.py`** (②)
```
ledger_days (30일 집계) + ledger.json (1차 장부 주인)
   ├─ 사용자별 "남의 것" 피해자 3명 이상 = BOLA 사용자 ─▶ confirmed.json users (처음 공격한 날 00:00)
   └─ 원본 로그에서 그 사용자의 공격 요청 ID ───────────▶ confirmed.json requests
```

| 옵션 | 하는 일 |
|---|---|
| (없음) | `confirmed.json`에 합침. **판단 서버가 켜져 있으면 거부** (켜진 판단 서버가 덮어써서 사라지므로) |
| `--dry-run` | 찾기만, 결과 출력 (파일 안 바꿈) |
| `--log 원본 로그` | 기본 `data\access_fake.json` |
| `--truth 정답지` | 정답과 비교 |

- `ledger_v3.py`가 넣은 사용자는 판단 서버가 켜질 때 Redis에 영구 차단됩니다. DB·Slack에는 기록되지 않습니다.
- 403/404만 낸 사용자는 찾지 못합니다 (`ledger_days`에 상태 200 요청만 집계됨).
- 관리자가 해제한 사용자(`released`)는 다시 넣지 않습니다.

- `ledger_v3.py`도 판단 서버와 같은 `api_infer.infer`로 1대1 API를 추론해, `/members/{id}`처럼 URL 번호가 남의 것이면 장부와 상관없이 "남의 번호(URL)"로 셉니다.

**현재 파일** (2026-11-09)

| 파일 | 내용 |
|---|---|
| `data/access_fake.json` | 학습 로그 2,196,826줄 |
| `ledger_days/` | 2026-10-04 ~ 2026-11-02 (30일) 집계, 하루 상한 `cap` 10 |
| `ledger.json` | 탐지에 사용 중인 장부. API 10개, 객체 13,247개, 주인 `null` 0 (11/05 학습) |
| `confirmed.json` | 비어 있음. `ledger_v3.py --dry-run` 결과 설치 전 BOLA 사용자 0명 (전체 999명 중 남의 것을 본 사용자 없음) |

---

## 6. 영구 차단 관리

두 스크립트 모두(`ledger_v3.py`도 같음) **판단 서버를 멈춘 뒤** 실행합니다 (켜져 있으면 거부). 판단 서버는 확정 명단을 메모리에 들고 있다가 `confirmed.json`을 다시 쓰고 60초마다 차단 키를 다시 걸기 때문입니다. 멈추는 동안에도 탐지 엔진과 Kong 차단은 계속 동작하고, 쌓인 이벤트는 다시 켜면 이어서 처리됩니다.

### 6-1. 차단 목록 보기, 해제: `judge/unblock.py`

```bash
docker compose exec judge python unblock.py --list          # 켜져 있어도 됨

docker compose stop judge
docker compose run --rm judge python unblock.py 7 --by 관리자이름 --note "장부 오류, 본인 주문"
docker compose start judge
```

Redis 키 삭제, `confirmed.json`에서 제거 + `released` 기록, `confirmed_log.jsonl`에 `release`, DB 조치 `released` + `user_status = normal`.

> 설치 전 이력의 BOLA 사용자는 `fluent-bit/ledger_v3.py`가 직접 `confirmed.json`에 넣고(5-6), 판단 서버가 켜질 때 영구 차단됩니다. 별도 가져오기 도구는 없습니다.

---

## 7. Docker 명령어

모든 명령은 **WSL에서 저장소 폴더로 이동한 뒤** 실행합니다 (다른 폴더에서 하면 `no configuration file provided: not found`).

```bash
cd /mnt/d/python-rule
```
```powershell
wsl -e sh -c "cd /mnt/d/python-rule && docker compose ps"     # Windows PowerShell에서
```

| 서비스 이름 | 컨테이너 이름 | 역할 |
|---|---|---|
| `realtime` | `bola-realtime` | 탐지 엔진 |
| `judge` | `bola-judge` | 판단 서버 + 영구 차단 |
| `postgres` | `judge-postgres` | DB |

### 7-1. 켜기, 끄기, 상태

```bash
docker compose up -d --build        # 세 개 모두 실행 (처음, 또는 코드 수정 후)
docker compose ps                   # 상태
docker compose stop / start         # 모두 멈춤 / 다시 시작
docker compose stop judge           # 하나만
docker compose down                 # 컨테이너 삭제 (DB 데이터는 judge_pgdata 볼륨에 남음)
```
> `docker compose down -v`는 **DB 볼륨까지 지웁니다.** 쓰지 마세요.

### 7-2. 무엇을 바꿨을 때 어떤 명령을 쓰나

| 바꾼 것 | 명령 | 이유 |
|---|---|---|
| `judge/*.py` | `docker compose up -d --build judge` | 코드를 이미지에 복사함 → 다시 빌드 |
| `judge/config.json` | `docker compose restart judge` | 파일을 붙여 씀 |
| `judge/.env` | `docker compose up -d judge` | 환경 변수는 새로 만들 때 읽음 |
| `fluent-bit/realtime.py`, `.env`, 인증서 | `docker compose restart realtime` | 폴더를 붙여 씀 |
| `fluent-bit/ledger.json` | 없음 (다음 요청 때 읽음). 바로: `docker compose restart realtime` | |
| `fluent-bit/confirmed.json` | `stop judge` → 수정(또는 6장 스크립트) → `start judge` | 켜져 있으면 덮어씀 |

`volume "judge_pgdata" already exists but was created for project "judge"` 경고는 무시해도 됩니다 (볼륨 이름 고정 때문).

### 7-3. 로그 명령 모음

```bash
docker compose logs -f realtime               # 탐지 (Ctrl+C로 빠져나옴)
docker compose logs -f judge                  # 판단
docker compose logs -f realtime judge         # 둘 다
docker compose logs --tail 100 judge          # 마지막 100줄
docker compose logs --since 10m judge         # 최근 10분
docker compose logs -t realtime               # 시각 표시
```

### 7-4. DB 백업

```bash
docker compose exec -T postgres pg_dump -U postgres -d bola_judge --data-only > judge/output/backup.sql
docker compose exec -T postgres psql -U postgres -d bola_judge < judge/output/backup.sql      # 되돌리기
```

---

## 8. 현재 상태 (2026-11-09)

| 대상 | 상태 |
|---|---|
| 컨테이너 | `bola-realtime`, `bola-judge`, `judge-postgres` 실행 중 (로그온 자동 시작, 09:18 포트 전달 완료) |
| pc2 Redis 연결 | **안 됨.** 판단 서버가 `[Redis] 연결 안 됨 … Timeout connecting to server`를 반복하며 기다리는 중 (pc2 Redis 192.168.0.39:6379 확인 필요) |
| 판단 설정 | 영구 누적(`window_sec: 0`), 기준 100점, 단계 주의 10 / 위험 30 / 고위험 60, DB 복원 켜짐, 영구 차단 켜짐, 알림 켜짐 (고위험·차단) |
| 위험도 | 11/09 적용 (`risk_pct` 열, 단계 이름 변경). pc3 대시보드는 `archive/dashboard/bola_db.py` 사본을 넘겨 맞춰야 함 |
| 1대1 추론 결과 | `path_owners = ['/members/{id}', '/profiles/{id}']` |
| 장부 | `ledger.json` API 10개, 객체 13,247개, `null` 0 (5-6) |
| 설치 전 BOLA 사용자 | 0명 (`ledger_v3.py --dry-run`) |
| `confirmed.json` | 빈 명단 |
| DB | 11/06 초기화 후 `bola_events` 0행, `user_status` 0행 (`alerts` 22행은 알림 시험 기록) |
| `judge/output/` | `score_log.jsonl`, `confirmed_log.jsonl` 비어 있음, `breached_apis.json` `{}` (11/06 초기화) |
| 예전 기록 | 따로 보관하지 않음 (11/06 초기화는 백업 없이 삭제) |

---

## 9. 처음 준비와 포트

**pc1에서 처음 한 번**
- `fluent-bit/.env`: `REDIS_PASSWORD`
- `judge/.env`: `REDIS_PASSWORD`, `PG_SUPERUSER_PASSWORD`, `PG_JUDGE_PASSWORD`, `PG_DASHBOARD_PASSWORD`
  - Slack 알림을 쓰려면 `SLACK_ADMIN_WEBHOOK`, `SLACK_DEV_WEBHOOK`도 넣음 (비우면 알림만 안 보냄). 넣은 뒤 `docker compose up -d judge`
- `fluent-bit/certs/server.key` (mTLS 서버 개인키, git에 없음)

**포트 전달** (관리자 PowerShell, 재부팅·`wsl --shutdown` 뒤 다시). Docker가 WSL(NAT) 안에 있어서 필요합니다.

```powershell
powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\wsl-portproxy.ps1 -Remote <pc3 IP>                  # 5432: DB
powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\wsl-portproxy.ps1 -Port 5170 -Name "bola realtime"  # 5170: 로그 수신
```

로그온할 때 자동으로 하려면 `judge\scripts\register-startup-task.ps1`을 관리자로 한 번 실행합니다 (결과는 `judge/output/startup.log`).

| 연결 | 포트 | 보안 |
|---|---|---|
| pc2 Fluent Bit → realtime | pc1 5170 | mTLS |
| realtime, judge → Redis | pc2 6379 | 비밀번호 (`.env`) |
| pc3 → PostgreSQL | pc1 5432 | `dashboard` 읽기 전용, 방화벽은 pc3 IP만 |

---

## 10. 폴더

```
D:\python-rule
├─ fluent-bit/   pc1 운영 (탐지 + 장부 학습)
│   ├─ realtime.py            실시간 탐지 (컨테이너 bola-realtime)
│   ├─ ledger_v2.py           장부 학습        ledger_v3.py   설치 전 BOLA 사용자 찾기 → confirmed.json
│   ├─ ledger.json            탐지 장부
│   ├─ ledger_days/           날짜별 집계 (학습 데이터)
│   ├─ data/access_fake.json  학습 로그
│   ├─ confirmed.json         영구 차단 명단 + 학습 제외 (판단 서버, ledger_v3.py가 씀)
│   └─ certs/                 mTLS 인증서
├─ judge/        pc1 운영 (판단 + 영구 차단 + DB + 알림)
│   ├─ judge.py, scoring.py, api_infer.py, blocker.py, store.py, db.py, notifier.py, config.json
│   ├─ unblock.py      관리자용 (영구 차단 해제)
│   ├─ db/init/        DB 테이블·계정 (처음 한 번)   db/migrate/  기존 DB에 alerts 추가
│   ├─ scripts/        포트 전달, 자동 시작
│   ├─ tests/          python -m unittest discover tests
│   └─ output/         score_log.jsonl, confirmed_log.jsonl, breached_apis.json, startup.log, portproxy.log
├─ attack/       BOLA 공격 시뮬레이터 (simulate.py, 검증용)
├─ docker-compose.yml   fluent-bit + judge compose 포함
├─ README.md, OVERVIEW.md
├─ 동작시나리오_20261106.html, 문제해결_기록_20261105.html   동작 설명, 문제 해결 기록
└─ archive/      사용하지 않는 것 보관 (git에 올리지 않음)
```

| `archive/` 안 | 내용 |
|---|---|
| `BOLA-APP/` | pc2 대상 앱 사본 (10/29 시점), `engine/test/gen_fake_logs.py` |
| `BOLA_Insight_v2_Docker/`, `bola_streamlit/` | pc3 Streamlit 앱 사본 (실제 비밀번호가 든 파일 있음, 전달 금지) |
| `dashboard/` | pc3에 넘기는 DB 조회 모듈 `bola_db.py` 사본 |
| `bola-rule/`, `judge-server/` | 예전 Wazuh Indexer 방식 |
| `bola-rule-rule/` | 행동 룰 실험 (R6 순차 ID, R7 403 다발, R12 거부 뒤 변경) |
| `bola-architecture.png`, `판단서버 to streamlit.txt` | 예전 구조도, DB 컬럼 메모 |

---

## 11. 알려진 문제와 남은 과제

| 내용 | 영향 |
|---|---|
| **pc2 Kong의 Redis 인증 미확인** | `archive/BOLA-APP/kong/kong.yml` 사본에는 `red:auth`가 없음. 실제 pc2에서도 없으면 차단 키를 걸어도 막히지 않음. 첫 영구 차단 때 403이 나오는지 확인 필요 |
| pc2 Redis 연결 시간 초과 (11/09) | 판단 서버가 이벤트를 받지 못하고 기다리는 중. 탐지 엔진도 보고·임시 차단을 못 함. pc2 Redis·방화벽 확인 필요 |
| 장부에 없는 객체 | `/members/{id}`, `/profiles/{id}`는 판단 서버가 `UNKNOWN`을 `BOLA_PATH`로 올려 해결. 그 밖 API는 `UNKNOWN`(20점)으로만 채점 |
| 자동 영구 차단은 오탐에 취약 | 잘못 확정되면 정상 사용자가 계속 막힘. `unblock.py`로 해제 |
| 영구 누적이라 점수가 줄지 않음 | 정상 사용자의 `ATTEMPT`(5점)·`RATE`(10점)도 오래 쌓이면 100점에 닿을 수 있음. 점수 상위 사용자를 가끔 확인 || 차단 해제·가져오기 때 판단 서버를 잠깐 멈춰야 함 | 판단 서버가 관리 명령을 받는 기능을 만들면 멈추지 않아도 됨 |
| 탐지 엔진 로그가 파일로 남지 않음 | `docker compose logs`로만 볼 수 있고 컨테이너를 다시 만들면 사라짐. 이벤트 자체는 DB에 남음 |
| 장부를 다시 읽으면 목록으로 추가한 객체가 사라짐 | 새 객체가 다시 UNKNOWN |
| UNKNOWN도 RATE 횟수에 셈 | 새 객체를 빠르게 보는 정상 사용자가 임시 차단될 수 있음 |
| Redis를 통째로 지우면 `judges` 그룹도 사라짐 | 판단 서버가 `NOGROUP`으로 한 번 종료된 뒤 Docker가 다시 띄우며 복구 |
| WSL IP가 재부팅마다 바뀜 | portproxy 다시 실행. WSL 미러 네트워킹(`networkingMode=mirrored`)으로 바꾸면 해결 |
| 새 테이블을 추가하면 `dashboard` 계정 권한이 없음 | 추가할 때 `GRANT SELECT` 필요 |
