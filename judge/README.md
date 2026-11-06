# judge: BOLA 판단 서버 (Redis → 점수 → confirmed.json)

`realtime.py`(로그 룰 탐지 서버)가 Redis `bola:events`에 보낸 의심 이벤트를 읽어서 **사용자별 점수**를 매기고,
진짜 공격자와 공격 요청을 **`confirmed.json`** 으로 남깁니다.
`ledger_v2.py`는 장부를 학습할 때 이 파일의 요청·사용자를 빼서, 공격 요청이 장부를 오염시키지 않게 합니다.

```
pc2: Kong ─Fluent Bit─▶ pc1: realtime.py + ledger.json ──의심 이벤트──▶ pc2: Redis bola:events
                                  ▲                                          │ judges 그룹
                                  │ 장부 재학습 (확정분 제외)                  ▼
                         pc1: ledger_v2.py ◀──── confirmed.json ◀──── pc1: judge.py (이 폴더)
```

판단 서버는 공격자를 확정하는 순간 **영구 차단**합니다 (아래 "영구 차단"). `realtime.py`의 RATE 10분 임시 차단은 그대로입니다.
판단·조치·사용자 상태는 **PostgreSQL**에 기록해서 pc3 Streamlit이 읽습니다 (아래 "DB 연동").

## 영구 차단

pc2 Kong은 요청마다 Redis `blocked:user:<id>`를 조회해서 **키가 있으면 403**으로 막습니다 (`kong.yml` post-function, 값·만료는 보지 않음).
판단 서버는 100점을 넘어 확정되는 순간 이 키를 **만료 없이** 겁니다 (`blocker.py`, pc2 담당자가 정한 방식).

```
judge.py 확정 ─┬─▶ Redis SET blocked:user:<id> "confirmed"  (TTL 없음 = 영구)
              │         HSET block:info:<id> reason, blocked_at, by
              ├─▶ confirmed.json users (= 영구 차단 명단, 장부 학습 제외)
              └─▶ DB bola_events: AC-<스트림ID>-L  applied(차단·저장 성공) / failed
pc2 Kong ── 요청마다 GET blocked:user:<id> ──▶ 있으면 403 "blocked by security policy"
```

- **명단 동기화:** 실시간 모드에서 시작할 때와 60초마다(`block.sync_sec`) `confirmed.json`의 확정 사용자 중 영구 키가 없거나 만료가 붙은 사용자를 다시 겁니다. Redis가 초기화되거나 차단에 실패했을 때 복구됩니다. **시작하면 기존 확정 사용자(1, 2)도 이때 차단됩니다.**
- `realtime.py`의 RATE는 `nx=True`로 걸어서 영구 키를 10분짜리로 덮어쓰지 않습니다.
- Redis가 꺼져 있어도 판단은 멈추지 않습니다. 조치가 `failed`로 기록되고 다음 동기화 때 다시 겁니다.
- 끄려면 `config.json`의 `"block": {"enabled": false}`. `--dry-run`이면 차단하지 않습니다.
- 지금 차단된 사용자 보기: `python unblock.py --list` (컨테이너: `docker compose run --rm judge python unblock.py --list`)

### 해제 (오탐일 때)

판단 서버가 켜져 있으면 메모리의 명단으로 `confirmed.json`을 덮어쓰고 다시 차단하므로 **멈춘 뒤** 해제합니다. 켜져 있으면 스크립트가 거부합니다.

```bash
cd /mnt/d/python-rule
docker compose stop judge
docker compose run --rm judge python unblock.py 7 --by 관리자이름 --note "장부 오류, 본인 주문"
docker compose start judge
```

| 하는 일 | 결과 |
|---|---|
| Redis `blocked:user:7`, `block:info:7` 삭제 | 다음 요청부터 Kong 통과 |
| `confirmed.json` `users`에서 빼고 `released`에 해제 시각 기록 | 판단 서버가 **해제 이전 이벤트로는 다시 확정하지 않음** (해제 이후 새 공격은 다시 채점) |
| `output/confirmed_log.jsonl`에 `type: release` 한 줄 | 누가·언제·왜 해제했는지 |
| DB: 확정 조치 `enforcement_status = released`, `released_at`, `user_status = normal` | 대시보드에 해제 반영 |

`requests`의 요청 ID는 그대로 두므로 장부 학습에서는 계속 빠집니다.

## DB 연동 (pc3 Streamlit용)

```
pc1  judge.py ──(저장 스레드가 1초마다 모아서)──▶ PostgreSQL 컨테이너 (pc1:5432, DB bola_judge)
                                                        ▲ dashboard 계정 (읽기 전용)
pc3  Streamlit ──────────── 몇 초마다 SELECT ─────────────┘   (판단 서버를 거치지 않음)
```

테이블은 두 개입니다.

| 테이블 | 한 행 | 용도 |
|---|---|---|
| `bola_events` | **Redis 이벤트 1건** (Redis 값 + 그 시점의 판단 + 있으면 조치) | 탐지 이력 |
| `user_status` | 사용자 1명 (바뀔 때마다 덮어씀) | 지금 위험한 사용자 |

`bola_events` 컬럼:

| 컬럼 | 뜻 | 출처 |
|---|---|---|
| `stream_id` | 행의 고유 키 (Redis 스트림 ID) | Redis |
| `event_id` | BOLA 탐지 사건 ID = `request_id` (RATE는 계기가 된 요청과 같은 값이라 겹칠 수 있음) | Redis |
| `event_at` | 요청 시각 = `started_at` | Redis |
| `detected_at` | 탐지 엔진이 Redis에 올린 시각 = 스트림 ID의 시각 | Redis |
| `user_id`, `action_type`, `api_path` | 의심 사용자, `kind`(BOLA/ATTEMPT/UNKNOWN/RATE), `api` | Redis |
| `detection_reasons` (JSON) | `detail`(장부 비교 결과) + 판단 서버 분류(BOLA_PATH 등)·점수·피해자 | Redis + 판단 서버 |
| `risk_score`, `assessed_at` | 이 이벤트까지 반영한 24시간 점수, 계산 시각 | 판단 서버 |
| `decision`, `decision_reason` | normal / watch(30) / warning(60) / attack(100) / ignored(본인 번호 오탐), 근거 | 판단 서버 |
| `user_status`, `user_status_updated_at` | 그 시점 사용자 상태(normal/watch/warning/confirmed), 상태가 바뀐 시각 | 판단 서버 |
| `action_id`, `action_reason`, `decided_at`, `enforcement_status`, `enforced_at`, `expires_at`, `released_at` | 조치가 있는 이벤트에만 (없으면 NULL) | 판단 서버 |

조치는 실제로 일어나는 두 가지만 기록합니다:

| `action_id` | 언제 | 상태 |
|---|---|---|
| `AC-<스트림ID>-R` | RATE 이벤트 = realtime.py의 10분 임시 차단 | `applied` → `expires_at`이 지나면 판단 서버가 `expired` + `released_at` |
| `AC-<스트림ID>-L` | 공격 확정 → **영구 차단** + `confirmed.json` 등록 (장부 학습에서 제외) | 차단·저장 둘 다 성공 `applied`, 하나라도 실패 `failed`. 만료 없음. 관리자 해제 시 `released` + `released_at` |

- 판정 루프는 큐에 넣기만 하고, 쓰기는 저장 스레드가 합니다. DB가 꺼져 있어도 판단은 계속되고, 다시 연결되면 밀린 것을 씁니다.
- `stream_id`가 같으면 한 번만 들어가므로, 판단 서버를 다시 시작해 과거 이벤트를 다시 읽어도 중복되지 않습니다.
- 판단 서버를 켜기 전에 이미 확정된 사용자(`confirmed.json`에 있음)는 점수를 다시 계산하지 않으므로 `risk_score`가 비어 있습니다.
- `--dry-run`이면 DB에도 쓰지 않습니다. 단계 기준은 `config.json`의 `levels`, DB 설정은 `db`.

### 실행 (Docker)

pc1에서는 탐지 엔진(`engine/`)과 판단 서버(`judge/`)를 각 폴더의 compose로 띄웁니다. 각 폴더의 `.env`를 씁니다.

```bash
cd judge                             # 저장소의 judge 폴더에서
docker compose up -d --build         # bola-judge + judge-postgres (탐지 엔진은 engine 폴더에서 따로)
docker compose ps
docker compose logs -f judge         # 실시간 점수 로그
docker compose up -d postgres        # DB만 띄우고 판단 서버는 로컬(python judge.py)로 돌릴 때
```

- 처음이면 `copy .env.example .env`로 `REDIS_PASSWORD`, `PG_*` 비밀번호를 채웁니다.
- 판단 서버 코드를 고치면 `docker compose up -d --build judge`로 다시 빌드합니다 (`config.json`만 바꿨으면 `restart judge`).
- DB 볼륨 이름은 `judge_pgdata`로 고정되어 있어서, 어느 폴더에서 띄워도 같은 데이터를 씁니다.

- 테이블과 계정(`judge` 쓰기, `dashboard` 읽기)은 **DB 볼륨이 비어 있을 때 처음 한 번** `db/init/`으로 만들어집니다.
  비밀번호를 바꾸려면 `docker compose down -v`로 볼륨을 지우고 다시 만들거나 `ALTER ROLE`을 씁니다 (볼륨을 지우면 기록도 지워짐).
- 컨테이너 판단 서버는 `../engine`을 붙여서 `confirmed.json`을 그대로 그 폴더에 씁니다.

### pc3에서 접속

Docker가 **WSL(NAT 모드) 안**에 있어서, LAN에서 오는 연결을 WSL로 넘겨 주는 포트 전달이 필요합니다.

```
pc3 ──▶ pc1 192.168.0.40:5432 ──portproxy──▶ WSL 172.22.x.x:5432 ──▶ judge-postgres
```

1. **포트 전달 + 방화벽** (관리자 PowerShell, `scripts/wsl-portproxy.ps1`):
   `powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\wsl-portproxy.ps1`
   - WSL IP는 **재부팅이나 `wsl --shutdown` 때마다 바뀌므로 그때마다 다시 실행**합니다. 결과는 `output/portproxy.log`.
   - 방화벽은 같은 LAN(`LocalSubnet`)에서만 허용합니다. pc3만 허용하려면 `-Remote 192.168.0.X`를 붙입니다.
2. pc3 Streamlit 접속 정보: `host=192.168.0.40 port=5432 dbname=bola_judge user=dashboard password=<PG_DASHBOARD_PASSWORD>`
   ```python
   conn = psycopg.connect(host="<pc1 IP>", dbname="bola_judge", user="dashboard", password="...")
   pd.read_sql("SELECT * FROM user_status ORDER BY risk_score DESC", conn)
   ```

## Slack 알림 (`notifier.py`)

판단 서버가 채점할 때 알림이 필요한지 보고 큐에 넣고, 알림 스레드가 Slack 웹훅으로 글자 메시지를 보냅니다. 웹훅이 느리거나 실패해도 판단·차단은 멈추지 않습니다.

| 채널 (.env) | 알림 | 언제 | 한 번만 보내는 기준 |
|---|---|---|---|
| 관리자 `SLACK_ADMIN_WEBHOOK` | warning | 60점을 넘어 단계가 올라갈 때 | 사용자마다 (해제되면 다시) |
| | attack | 공격 확정·영구 차단 순간 (warning을 건너뛰면 이것만) | 사용자마다 (해제되면 다시) |
| | RATE | 탐지 엔진의 10분 임시 차단 | 사용자마다 하루 한 번 |
| | 해제 | `unblock.py` 실행 | 실행할 때마다 |
| | 1시간 요약 | 매시 정각 + 30초 (일이 없어도 보냄 = 생존 신호) | 시간대마다 |
| 개발자 `SLACK_DEV_WEBHOOK` | 취약 API | API에서 BOLA가 처음 성공, 또는 7일 조용하다가 다시 성공 (사용자 번호 없음) | API마다 |
| | 1시간 요약 | 매시 정각 + 30초 | 시간대마다 |

- 보낸 알림은 DB `alerts` 테이블에 남깁니다 (`pending` / `sent` / `failed` / `skipped`=웹훅 없음). 같은 키는 다시 보내지 않으므로 재시작해도 중복되지 않습니다.
- 재시작할 때 과거 이벤트를 다시 채점하는 동안, `--once`, `--dry-run`에서는 보내지 않습니다.
- 실패하면 2·4·8·16초 뒤 다시, 5번 실패하면 `failed`. 설정은 `config.json`의 `notify`.

```bash
# 웹훅 넣기: judge/.env 의 SLACK_ADMIN_WEBHOOK=, SLACK_DEV_WEBHOOK= 에 주소를 적고 (WSL, /mnt/d/python-rule)
docker compose up -d judge                                   # env_file은 컨테이너를 다시 만들어야 반영
docker compose run --rm judge python notifier.py --test      # 두 채널에 시험 메시지
docker compose exec postgres psql -U postgres -d bola_judge -c "SELECT created_at, channel, kind, status FROM alerts ORDER BY created_at DESC LIMIT 20"
```

이미 쓰고 있는 DB에 `alerts` 테이블 추가 (새 DB는 `db/init/01-schema.sql`에 들어 있음, 2026-11-03 pc1에 적용함):

```bash
docker compose exec -T postgres psql -U postgres -d bola_judge -v judge_user=judge -v dash_user=dashboard < judge/db/migrate/03-alerts.sql
```

## confirmed.json

```json
{
  "requests": ["979917aa-...", "4ca321f0-..."],
  "users": {"2": 1793266756647, "1": 1793266895188},
  "released": {"7": 1793400000000}
}
```

| 키 | 들어가는 것 |
|---|---|
| `requests` | URL로 확인된 BOLA 요청 (사용자 확정 전이라도), 확정된 사용자의 의심 요청 전부 (확정 전·후) |
| `users` | 점수가 기준(100점)을 넘은 사용자 → 값은 **그 사용자의 첫 의심 이벤트 시각(ms)**. 이 시각 이후 요청은 학습에서 제외. **영구 차단 명단**이기도 함 |
| `released` | `unblock.py`로 해제한 사용자 → 해제 시각(ms). 이 시각 이전 이벤트는 채점하지 않음 (해제한 사용자가 재시작 때 다시 확정되지 않게). `ledger_v2.py`는 읽지 않음 |

- 판단 서버는 한 번 들어간 값을 지우지 않습니다. **잘못 확정되면 `unblock.py`로 해제합니다** (파일을 직접 고치지 않음).
- 확정할 때마다 근거(점수 내역, 피해자, 자원 종류, 이벤트 수)가 `output/confirmed_log.jsonl`에 한 줄씩 남습니다.
- 임시 파일에 쓴 뒤 바꿔치기하므로, 다른 프로그램이 쓰다 만 파일을 읽지 않습니다.

## 점수 (최근 24시간, `config.json`에서 조정)

| 항목 | 점수 | 조건 |
|---|---|---|
| `BOLA_PATH` | 40 | `/members/{id}`, `/profiles/{id}`처럼 URL 숫자가 곧 사용자 번호인 API에서 남의 번호 → 확실 |
| `BOLA_PATH_WRITE` | 60 | 위 `BOLA_PATH`를 PUT/PATCH/DELETE로 (남의 객체 수정·삭제 → 조회보다 위험) |
| `BOLA_LEDGER` | 30 | 그 밖의 BOLA (realtime.py 장부 근거) |
| `BOLA_LEDGER_WRITE` | 50 | 위 `BOLA_LEDGER`를 PUT/PATCH/DELETE로 (남의 객체 수정·삭제) |
| `ATTEMPT` | 5 | 403/404 |
| `UNKNOWN` | 20 | 장부에 없는 객체를 성공 조회 (주인을 몰라 BOLA로 단정 못 함) |
| `RATE` | 10 | 10초에 의심 요청 10번 초과 |
| `+victims` | 30 | 서로 다른 피해자 3명 이상 |
| `+attempt_then_bola` | 20 | ATTEMPT 뒤 BOLA 성공 (우회 경로를 찾음) |
| `+multi_api` | 10 | 2개 이상 자원 종류(members, orders, payments…)에서 BOLA |

- **합계 100점 이상이면 사용자 확정** (점수 값은 `config.json`의 `points`에서 조정)
- **UNKNOWN → BOLA_PATH 승격:** `path_owners` API(/members/{id} 등)에서 장부에 없어 UNKNOWN으로 온 **성공(200/204)** 요청은, URL 번호로 주인을 알 수 있으므로 `BOLA_PATH`(쓰기는 `BOLA_PATH_WRITE`)로 올려 채점합니다.
- **오탐 거르기:** URL 숫자가 요청자 본인인 BOLA·ATTEMPT·UNKNOWN은 점수를 주지 않습니다. 장부 오염(예: `/members/4`의 주인이 `43`)이나 장부 미학습으로 잘못 보고된 경우를 거릅니다.
- 피해자(주인)는 이벤트의 `owner` 필드를 쓰고, 없으면 `detail`의 `주인 N`에서 뽑습니다. 그래서 `realtime.py`를 고치지 않아도 됩니다. **단 "털린 API" 표시는 주인이 아니라 실제로 접근한 객체 번호(URL의 숫자)를 보여 줍니다** (예: `GET /orders/{id}` 주인 41이어도 접근한 주문 번호 99로 표시).

### 1대1 추론 (`path_owners`, `api_infer.py`)

`BOLA_PATH`와 본인 번호 오탐 거르기는 "URL 번호 = 사용자 번호"인 API 목록(`path_owners`)이 있어야 동작합니다.
`config.json`에서 세 가지로 정합니다.

| 값 | 동작 |
|---|---|
| `"auto"` (기본) | 학습 장부(`paths.ledger`)로 추론. BOLA-APP 코드·DB는 보지 않음 |
| `[]` | 끔. 모든 BOLA를 `BOLA_LEDGER`로 (장부만으로 검증할 때) |
| `["/members/{id}", ...]` | 사람이 직접 지정 |

추론 방법: 장부의 API 키를 첫 `{id}`까지 잘라 자원별로 묶고(`GET`·`PATCH`·하위 경로를 하나로), "객체 번호 = 학습된 주인"인 비율을 셉니다.
정상 사용자는 자기 것만 보므로 `/members/{id}`는 100%, `/orders/{id}`는 거의 0%가 나옵니다.

| 조건 (`path_infer`) | 판정 |
|---|---|
| 표본 `min_samples`(30)개 이상 + 일치율 `min_ratio`(95%) 이상 | 1대1 → `path_owners`에 넣음 |
| 표본 30개 이상 + 일치율 `max_ratio`(5%) 이하 | 장부 사용 |
| 그 사이 또는 표본 부족 | 판단 보류 (쓰지 않음) |

- 시작할 때 추론하고, 60초마다 장부 파일이 바뀌었는지 확인해 바뀌었으면 다시 추론합니다.
- 1대1 자원인데 번호 ≠ 주인인 항목은 장부 오염(공격 흔적)일 가능성이 높아 주인으로 적힌 사용자를 로그에 함께 보여 줍니다.
- 직접 확인: `python api_infer.py` (judge 폴더에서)

## 실행 (pc1)

```powershell
pip install redis
copy .env.example .env          # REDIS_PASSWORD 채우기 (Redis에 비밀번호가 걸려 있음)

python judge.py                 # 계속 실행 (judges 그룹으로 새 이벤트를 받음, Ctrl+C 종료)
python judge.py --once          # 최근 24시간 이벤트로 한 번 계산 후 종료 (그룹·ACK 안 건드림)
python judge.py --once --all    # 스트림 전체로 한 번 계산
python judge.py --once --all --dry-run   # 결과만 보고 파일은 쓰지 않음

python -m unittest discover tests
```

- 시작하면 최근 24시간 이벤트를 다시 읽어 점수를 복원하고, 그 다음 이벤트부터 그룹으로 받습니다. 복원에서 이미 본 이벤트가 그룹으로 다시 오면 점수에 두 번 넣지 않고 ACK만 합니다.
- Redis가 꺼져 있으면 3초마다 다시 연결을 시도합니다. 비밀번호가 틀리면 바로 안내하고 종료합니다.
- 60초마다 `[상태] 이벤트 N … 확정 사용자 N … 점수 상위 …`를 출력합니다.

### 실시간 점수 로그

실시간 모드(`python judge.py`)에서는 새 이벤트가 올 때마다 점수가 어떻게 쌓이는지 한 줄씩 보여 줍니다.

```
[점수] 18:39:16 사용자 2 BOLA 200 /members/24 → BOLA_PATH +40 = 40/100점 {'BOLA_PATH': 40} 피해자 ['24']
[점수] 18:39:16 사용자 2 BOLA 200 /members/24/addresses → BOLA_PATH +40 = 80/100점 {'BOLA_PATH': 80} 피해자 ['24']
[점수] 18:39:22 사용자 2 BOLA 200 /members/3 → BOLA_PATH +40 = 120/100점 {'BOLA_PATH': 120} 피해자 ['24', '3']  ★ 확정
[점수] 18:39:22 사용자 2 BOLA 200 /members/3/addresses → 이미 확정된 사용자 → 요청만 confirmed.json에 추가
[점수] 10:29:10 사용자 4 BOLA 200 /members/4 → 무시: URL 번호가 본인 (장부 오탐)
```

- BOLA(실제로 털린 요청)이면 줄 끝에 `| GET /members/{id}/addresses {3,4}`처럼 **그 사용자가 이 API에서 지금까지 턴 객체 번호 전체**가 붙습니다.
- `[확정]` 아래에 `털린 API: GET /members/{id} {3,24}`, 60초마다 `[털린 API] GET /orders/{id} 털린 객체 {...} ← 공격자 {...}` 요약이 나옵니다. 숫자는 주인이 아니라 접근한 객체 번호입니다.
- 털린 API 요약은 `output/breached_apis.json`에도 저장됩니다 (API별 털린 객체 번호·공격자, `_by_user`: 공격자별 API·객체). 새로 털린 것이 생길 때마다 갱신.
- 같은 내용이 `output/score_log.jsonl`에 JSON 한 줄씩 남습니다. 다른 창에서 실시간으로 보려면:
  `Get-Content output\score_log.jsonl -Wait -Encoding utf8`
- 점수 줄을 끄려면 `python judge.py --quiet`
- 과거 이벤트가 어떻게 채점됐는지 보려면 `python judge.py --once --all --dry-run --trace`
  (이미 `confirmed.json`에 있는 사용자는 처음부터 "이미 확정된 사용자"로 나옵니다)
- `confirmed.json`은 `ledger_v2.py`가 있는 `../engine/confirmed.json`에 씁니다 (`config.json`의 `paths.confirmed`).
- 같은 그룹·이름(`judges`/`judge-1`)으로 Redis를 읽는 다른 프로그램과 **동시에 실행하지 마세요** (이벤트가 둘로 나뉨).

## 핵심 .py 쉽게 보기

판단 서버는 역할이 다른 작은 파일 여러 개로 나뉘어 있습니다. 한 이벤트가 들어오면 아래 순서로 지나갑니다.

```
Redis 이벤트 1건
   │
judge.py (총괄)  ── 이벤트를 받아 아래 담당들에게 넘기고 결과를 모음
   ├─▶ scoring.py    점수를 매기고 "확정?"을 판단          (api_infer.py가 미리 "어떤 API가 1대1인지" 알려 줌)
   ├─▶ store.py      확정되면 confirmed.json에 명단 기록
   ├─▶ blocker.py    확정된 공격자를 Redis에 영구 차단
   ├─▶ db.py         모든 결과를 PostgreSQL에 기록
   └─▶ notifier.py   주의·확정·요약을 Slack으로 알림
```

| 파일 | 쉽게 말하면 | 하는 일 |
|---|---|---|
| **`judge.py`** | 총괄 지휘자 | Redis에서 이벤트를 꺼내 나머지 담당들에게 넘기고, 시작할 때 최근 24시간을 복원하며, 60초마다 상태를 출력합니다. 다른 파일들을 **불러 쓰는 중심**입니다. |
| **`scoring.py`** | 점수 매기는 머리 | 이벤트 하나를 보고 "이건 BOLA_PATH 40점" 식으로 분류·채점하고, 24시간 합계가 100점을 넘으면 **확정**이라고 알려 줍니다. Redis·파일을 전혀 몰라서 **테스트하기 쉽습니다**. |
| **`api_infer.py`** | 장부로 배우는 선생 | 학습 장부만 보고 "`/members/{id}`는 URL 번호 = 주인(1대1)"인 API를 **자동으로 찾아** `scoring.py`에 알려 줍니다. 앱 코드는 보지 않습니다. (`config.json`이 `"auto"`일 때) |
| **`store.py`** | 확정 명단 담당 | 공격자로 확정된 사용자·요청을 `confirmed.json`에 쓰고 읽습니다. 관리자 해제(`released`)도 여기서 관리합니다. 이 파일 덕에 장부 학습이 공격 기록을 빼고 할 수 있습니다. |
| **`blocker.py`** | 차단 집행관 | 확정된 공격자를 Redis `blocked:user:<id>`에 **만료 없이** 걸어 pc2 Kong이 403으로 막게 합니다. 명단과 Redis가 어긋나면 다시 맞춥니다(동기화). |
| **`db.py`** | 기록 보관 담당 | 모든 이벤트·상태·조치를 PostgreSQL에 저장합니다. 느린 DB가 판단을 막지 않게 **모아서 비동기로 쓰고**, 실패하면 다시 시도합니다. pc3 대시보드가 이 기록을 읽습니다. |
| **`notifier.py`** | 연락 담당 | 주의 사용자(관리자 채널), 취약 API(개발자 채널), 매시 1시간 요약을 Slack으로 보냅니다. Slack이 느려도 판단을 막지 않게 **큐에 넣고 따로 보냅니다**. |

> 설계 포인트: `scoring.py`는 "판단 규칙"만, `judge.py`는 "입출력·연결"만 담당하도록 나눠 두었습니다. 그래서 규칙을 바꿔도 Redis/DB 코드를 건드릴 필요가 없고, 규칙만 따로 테스트할 수 있습니다.

## 파일

아래는 위 7개를 포함한 **전체 파일** 목록입니다.

| 파일 | 역할 |
|---|---|
| `judge.py` | 실행: Redis 읽기, 복원, 그룹 소비, 상태 출력, DB에 보낼 내용 만들기 |
| `db.py` | PostgreSQL 저장 스레드 (모아서 쓰기, 재시도, 임시 차단 만료 처리) |
| `db/init/` | DB 컨테이너 첫 실행 때 테이블(`01-schema.sql`)과 계정(`02-roles.sh`) 생성 |
| `docker-compose.yml`, `Dockerfile`, `requirements.txt` | PostgreSQL + 판단 서버 컨테이너 |
| `scripts/bola-startup.ps1`, `scripts/register-startup-task.ps1` | 로그온 시 자동 시작 (컨테이너 `up -d` + 포트 전달 5432·5170). 등록은 관리자로 한 번, 결과는 `output/startup.log` |
| `scripts/wsl-portproxy.ps1` | LAN → pc1 → WSL 포트 전달 + 방화벽 (관리자, WSL IP가 바뀌면 다시 실행). 5432(DB, `-Remote 192.168.0.26`), 5170(로그 수신, `-Port 5170 -Name "bola realtime"`) |
| `scoring.py` | 점수·확정 로직 (Redis를 몰라서 테스트하기 쉬움) |
| `api_infer.py` | 1대1 추론: 학습 장부로 `path_owners`를 만듦 (`"auto"`일 때) |
| `store.py` | `confirmed.json` 읽기·쓰기(해제 포함), 확정 근거 기록 |
| `blocker.py` | Redis 영구 차단 키 걸기·명단 동기화·해제 |
| `notifier.py` | Slack 알림: 관리자(주의 사용자), 개발자(취약 API), 1시간 요약, 시험(`--test`) |
| `db/migrate/03-alerts.sql` | 이미 쓰는 DB에 `alerts` 테이블 추가 |
| `unblock.py` | 관리자용: 차단 목록 보기(`--list`), 영구 차단 해제 (판단 서버를 멈춘 뒤) |
| `config.json` | Redis 주소, 점수, 기준, 시간 창, 경로, 영구 차단(`block`) |
| `.env` | Redis·DB 비밀번호, Slack 웹훅 주소 (git 제외) |
| `tests/test_scoring.py` | 점수, 오탐 거르기, 보너스, 시간 창, 파일 형식 테스트 |
| `tests/test_block.py` | 영구 차단, RATE 덮어쓰기 방지, 명단 동기화, Redis 장애, 해제 테스트 |
| `tests/test_notify.py` | 알림 기준, 중복 방지, 재시도, 1시간 요약 테스트 (가짜 웹훅) |

## 남은 일

- pc2 실제 Kong이 Redis 비밀번호로 `auth`하는지 확인 (`archive/BOLA-APP/kong/kong.yml` 사본에는 `red:auth`가 없음. 없으면 키를 걸어도 막히지 않음)
- 자동 영구 차단 대신 "자동 장기 차단 + 관리자 확정"이 필요해지면 `block` 설정에 기간 추가
