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

판단 서버는 **차단하지 않습니다** (`blocked:user:N`을 건드리지 않음). `realtime.py`의 RATE 임시 차단은 그대로이고, 판단 서버는 그 보고를 받아 기록만 합니다.
판단·조치·사용자 상태는 **PostgreSQL**에 기록해서 pc3 Streamlit이 읽습니다 (아래 "DB 연동").

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

조치는 실제로 일어나는 두 가지만 기록합니다 (판단 서버는 차단하지 않음):

| `action_id` | 언제 | 상태 |
|---|---|---|
| `AC-<스트림ID>-R` | RATE 이벤트 = realtime.py의 10분 임시 차단 | `applied` → `expires_at`이 지나면 판단 서버가 `expired` + `released_at` |
| `AC-<스트림ID>-L` | 공격 확정 → `confirmed.json` 등록 (장부 학습에서 제외) | 저장 성공 `applied`, 실패 `failed`. 만료 없음 |

- 판정 루프는 큐에 넣기만 하고, 쓰기는 저장 스레드가 합니다. DB가 꺼져 있어도 판단은 계속되고, 다시 연결되면 밀린 것을 씁니다.
- `stream_id`가 같으면 한 번만 들어가므로, 판단 서버를 다시 시작해 과거 이벤트를 다시 읽어도 중복되지 않습니다.
- 판단 서버를 켜기 전에 이미 확정된 사용자(`confirmed.json`에 있음)는 점수를 다시 계산하지 않으므로 `risk_score`가 비어 있습니다.
- `--dry-run`이면 DB에도 쓰지 않습니다. 단계 기준은 `config.json`의 `levels`, DB 설정은 `db`.

### 실행 (Docker)

pc1 전체(탐지 엔진 + 판단 서버 + DB)는 **루트 `D:\python-rule\docker-compose.yml`** 로 한꺼번에 띄웁니다 (프로젝트 이름 `bola`).
루트 compose는 `fluent-bit/`와 `judge/`의 compose를 포함(include)하므로, 각 폴더의 `.env`를 그대로 씁니다.

```bash
cd /mnt/d/python-rule                # WSL에서
docker compose up -d --build         # bola-realtime + bola-judge + judge-postgres
docker compose ps
docker compose logs -f judge         # 실시간 점수 로그
docker compose up -d postgres        # DB만 띄우고 판단 서버는 로컬(python judge.py)로 돌릴 때
```

- 처음이면 `copy .env.example .env`로 `REDIS_PASSWORD`, `PG_*` 비밀번호를 채웁니다.
- 판단 서버 코드를 고치면 `docker compose up -d --build judge`로 다시 빌드합니다 (`config.json`만 바꿨으면 `restart judge`).
- DB 볼륨 이름은 `judge_pgdata`로 고정되어 있어서, 어느 폴더에서 띄워도 같은 데이터를 씁니다.

- 테이블과 계정(`judge` 쓰기, `dashboard` 읽기)은 **DB 볼륨이 비어 있을 때 처음 한 번** `db/init/`으로 만들어집니다.
  비밀번호를 바꾸려면 `docker compose down -v`로 볼륨을 지우고 다시 만들거나 `ALTER ROLE`을 씁니다 (볼륨을 지우면 기록도 지워짐).
- 컨테이너 판단 서버는 `../fluent-bit`을 붙여서 `confirmed.json`을 그대로 그 폴더에 씁니다.

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

## confirmed.json

```json
{
  "requests": ["979917aa-...", "4ca321f0-..."],
  "users": {"2": 1793266756647, "1": 1793266895188}
}
```

| 키 | 들어가는 것 |
|---|---|
| `requests` | URL로 확인된 BOLA 요청 (사용자 확정 전이라도), 확정된 사용자의 의심 요청 전부 (확정 전·후) |
| `users` | 점수가 기준(100점)을 넘은 사용자 → 값은 **그 사용자의 첫 의심 이벤트 시각(ms)**. 이 시각 이후 요청은 학습에서 제외 |

- 한 번 들어간 값은 판단 서버가 지우지 않습니다. **잘못 확정되면 사람이 파일에서 직접 지웁니다.**
- 확정할 때마다 근거(점수 내역, 피해자, 자원 종류, 이벤트 수)가 `output/confirmed_log.jsonl`에 한 줄씩 남습니다.
- 임시 파일에 쓴 뒤 바꿔치기하므로, 다른 프로그램이 쓰다 만 파일을 읽지 않습니다.

## 점수 (최근 24시간, `config.json`에서 조정)

| 항목 | 점수 | 조건 |
|---|---|---|
| `BOLA_PATH` | 40 | `/members/{id}`, `/profiles/{id}`처럼 URL 숫자가 곧 사용자 번호인 API에서 남의 번호 → 확실 |
| `BOLA_LEDGER` | 25 | 그 밖의 BOLA (realtime.py 장부 근거) |
| `ATTEMPT` | 5 | 403/404 |
| `UNKNOWN` | 2 | 장부에 없는 객체 |
| `RATE` | 20 | 10초에 의심 요청 10번 초과 |
| `+victims` | 30 | 서로 다른 피해자 3명 이상 |
| `+attempt_then_bola` | 20 | ATTEMPT 뒤 BOLA 성공 (우회 경로를 찾음) |
| `+multi_api` | 10 | 2개 이상 자원 종류(members, orders, payments…)에서 BOLA |

- **합계 100점 이상이면 사용자 확정**
- **오탐 거르기:** URL 숫자가 요청자 본인인 BOLA·ATTEMPT는 점수를 주지 않습니다. 장부 오염(예: `/members/4`의 주인이 `43`)으로 잘못 보고된 경우를 거릅니다.
- 피해자(주인)는 이벤트의 `owner` 필드를 쓰고, 없으면 `detail`의 `주인 N`에서 뽑습니다. 그래서 `realtime.py`를 고치지 않아도 됩니다.

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

- BOLA(실제로 털린 요청)이면 줄 끝에 `| GET /members/{id}/addresses {3,4}`처럼 **그 사용자가 이 API에서 지금까지 턴 피해자 전체**가 붙습니다.
- `[확정]` 아래에 `털린 API: GET /members/{id} {3,24}`, 60초마다 `[털린 API] GET /orders/{id} 피해자 {...} ← 공격자 {...}` 요약이 나옵니다.
- 털린 API 요약은 `output/breached_apis.json`에도 저장됩니다 (API별 피해자·공격자, `_by_user`: 공격자별 API·피해자). 새로 털린 것이 생길 때마다 갱신.
- 같은 내용이 `output/score_log.jsonl`에 JSON 한 줄씩 남습니다. 다른 창에서 실시간으로 보려면:
  `Get-Content output\score_log.jsonl -Wait -Encoding utf8`
- 점수 줄을 끄려면 `python judge.py --quiet`
- 과거 이벤트가 어떻게 채점됐는지 보려면 `python judge.py --once --all --dry-run --trace`
  (이미 `confirmed.json`에 있는 사용자는 처음부터 "이미 확정된 사용자"로 나옵니다)
- `confirmed.json`은 `ledger_v2.py`가 있는 `../fluent-bit/confirmed.json`에 씁니다 (`config.json`의 `paths.confirmed`).
- 같은 그룹·이름(`judges`/`judge-1`)으로 Redis를 읽는 다른 프로그램과 **동시에 실행하지 마세요** (이벤트가 둘로 나뉨).

## 파일

| 파일 | 역할 |
|---|---|
| `judge.py` | 실행: Redis 읽기, 복원, 그룹 소비, 상태 출력, DB에 보낼 내용 만들기 |
| `db.py` | PostgreSQL 저장 스레드 (모아서 쓰기, 재시도, 임시 차단 만료 처리) |
| `db/init/` | DB 컨테이너 첫 실행 때 테이블(`01-schema.sql`)과 계정(`02-roles.sh`) 생성 |
| `docker-compose.yml`, `Dockerfile`, `requirements.txt` | PostgreSQL + 판단 서버 컨테이너 |
| `scripts/bola-startup.ps1`, `scripts/register-startup-task.ps1` | 로그온 시 자동 시작 (컨테이너 `up -d` + 포트 전달 5432·5170). 등록은 관리자로 한 번, 결과는 `output/startup.log` |
| `scripts/wsl-portproxy.ps1` | LAN → pc1 → WSL 포트 전달 + 방화벽 (관리자, WSL IP가 바뀌면 다시 실행). 5432(DB, `-Remote 192.168.0.26`), 5170(로그 수신, `-Port 5170 -Name "bola realtime"`) |
| `scoring.py` | 점수·확정 로직 (Redis를 몰라서 테스트하기 쉬움) |
| `store.py` | `confirmed.json` 읽기·쓰기, 확정 근거 기록 |
| `config.json` | Redis 주소, 점수, 기준, 시간 창, 경로 |
| `.env` | Redis 비밀번호 (git 제외) |
| `tests/test_scoring.py` | 점수, 오탐 거르기, 보너스, 시간 창, 파일 형식 테스트 |

## 남은 일

- 차단을 판단 서버로 옮기기 (`blocked:user:N`)
