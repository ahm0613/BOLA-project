# BOLA 공격 탐지·자동 차단 엔진

> **남의 데이터를 몰래 보는 사용자를 API 로그만 보고 찾아내 자동으로 차단합니다.**

**BOLA(Broken Object Level Authorization, 객체 수준 인가 우회)** 는 API에서 가장 흔한 취약점입니다.
예를 들어 7번 사용자가 URL 번호만 바꿔 `/members/3`, `/members/4`처럼 **다른 사람의 정보**를 조회하는 공격입니다.

이 엔진은 앱 코드를 고치지 않고 **API 게이트웨이(Kong) 로그만** 봅니다.
요청마다 점수를 매기고, 점수가 쌓여 100점이 되면 공격자로 확정해 바로 차단합니다.

## 한눈에 보기

```
 사용자 ──요청──▶ Kong ──로그──▶ ① 탐지 엔진 ──의심 요청──▶ ② 판단 엔진 ──▶ 차단 / 알림 / 기록
                   ▲            (fluent-bit/)               (judge/)          │
                   │            "이 요청은 남의 것?"          "이 사람은 공격자?" │
                   └───────────────────── 차단된 사용자는 403 ◀────────────────┘
```

엔진은 **둘로 나뉘어 있습니다.**

| | ① 탐지 엔진 `fluent-bit/` | ② 판단 엔진 `judge/` |
|---|---|---|
| 보는 단위 | 요청 **한 건** | 사용자 **한 명** (요청을 모아서) |
| 묻는 것 | 이 요청이 남의 데이터를 건드렸나? | 이 사람을 차단해야 하나? |
| 결과 | 이름표 (`BOLA`, `ATTEMPT` …)를 붙여 Redis에 넘김 | 점수, 위험도, 단계 → 100점이면 영구 차단 |
| 속도 | 아주 빠름 (장부를 찾아보기만 함) | 점수 누적, DB 기록, 알림까지 |

이렇게 나눈 이유는 판정 규칙(점수, 단계)을 바꿀 때 로그를 받는 쪽을 건드리지 않기 위해서입니다.

---

## 요청 한 건이 차단되기까지

사용자 7이 남의 회원 정보 `/members/3`을 조회했을 때 엔진 안에서 일어나는 일을 순서대로 따라가 봅니다.

### ① 로그가 들어온다

pc2의 Kong이 요청을 처리하면 Fluent Bit가 로그 한 줄을 pc1로 보냅니다 (mTLS 암호화, 5170 포트).

```json
{"user_id": "7", "uri": "/members/3", "method": "GET", "status": 200, "request_id": "a1…"}
```

누가(`7`), 무엇을(`/members/3`), 결과(`200` 성공)가 들어 있습니다.

### ② 탐지 엔진이 이름표를 붙인다 (`fluent-bit/realtime.py`)

미리 학습한 **장부**(`ledger.json`, "어떤 번호의 데이터가 누구 것인지" 적은 표)를 찾아봅니다.
`/members/3`의 주인은 3인데 요청자는 7입니다. 그래서 `BOLA` 이름표를 붙입니다.

| 이름표 | 뜻 | 예 |
|---|---|---|
| `BOLA` | 남의 데이터를 **보는 데 성공** | 7이 `/members/3` → 200 |
| `ATTEMPT` | 남의 데이터를 **시도했다가 막힘** | 7이 `/orders/502` → 403 |
| `UNKNOWN` | 장부에 없어서 주인을 모름 | 학습 뒤 새로 생긴 주문 번호 |
| `RATE` | 의심 요청이 **10초에 10번 넘게** 몰림 | 번호를 빠르게 바꿔 가며 조회 → **10분 임시 차단** |

자기 데이터를 보는 정상 요청에는 이름표가 붙지 않고 그냥 지나갑니다.
이름표가 붙은 요청만 Redis 스트림 `bola:events`에 넣습니다.

### ③ 판단 엔진이 점수를 매긴다 (`judge/scoring.py`)

판단 엔진은 Redis에서 이벤트를 꺼내 이름표를 더 자세히 나누고 점수를 더합니다.

| 행동 | 점수 |
|---|---|
| 남의 데이터 조회 성공: URL로 확인 `BOLA_PATH` / 장부로 확인 `BOLA_LEDGER` | 40 / 30 |
| 남의 데이터 **수정·삭제** 성공: URL로 확인 / 장부로 확인 (`_WRITE`) | 60 / 50 |
| 주인을 모르는 데이터 조회 `UNKNOWN` | 20 |
| 너무 많이 요청함 `RATE` | 10 |
| 남의 데이터를 시도했다가 막힘 `ATTEMPT` | 5 |
| **보너스:** 피해자 3명 이상 / 막힌 뒤 다른 길로 성공 / 여러 종류 API를 노림 | +30 / +20 / +10 |

- **URL로 확인**은 `/members/{id}`처럼 **URL 번호가 곧 사용자 번호**인 API입니다. 7이 `/members/3`을 봤다면 장부 없이도 남의 것이 확실해서 점수가 더 높습니다. 이런 API는 판단 엔진이 장부를 분석해 **자동으로 찾아 둡니다** (`api_infer.py`).
- **장부로 확인**은 `/orders/{id}`처럼 번호만으로는 주인을 알 수 없는 API입니다. 장부의 주인 기록과 비교합니다.
- 본인 번호를 조회한 경우는 점수를 주지 않습니다.

사용자 7의 `/members/3`은 URL로 확인된 조회라서 **`BOLA_PATH` +40점**입니다.
점수는 사용자별로 **기간 제한 없이 누적**됩니다.

### ④ 위험도와 단계가 정해진다

누적 점수를 **위험도(0~100%)** 로 바꿔 단계를 정합니다. 100점이 곧 100%입니다.

```
위험도  0% ──── 10% ──── 30% ──── 60% ──── 100%
단계    정상  │  주의  │  위험  │ 고위험 │  차단
```

사용자 7은 40점이라 **위험도 40%, 위험** 단계입니다. 단계는 올라가기만 합니다.

### ⑤ 기록하고 알린다 (`judge/db.py`, `judge/notifier.py`)

- **DB:** 모든 이벤트의 판정, 점수, 위험도를 PostgreSQL에 저장합니다. pc3 Streamlit 대시보드가 이 DB를 읽습니다.
- **Slack:** 상황에 따라 알림을 보냅니다.

| 받는 사람 | 언제 |
|---|---|
| 관리자 | 사용자가 **고위험**이나 **차단** 단계에 이름, 임시 차단(RATE), 차단 해제 |
| 개발자 | 어떤 API에서 BOLA가 **처음 성공**함 → "이 API를 고쳐야 함" (사용자 번호는 넣지 않음) |
| 둘 다 | 매시 정각에 직전 1시간 요약 |

사용자 7의 첫 BOLA로 `GET /members/{id}`가 처음 뚫렸으므로 개발자 채널에 "취약 API" 알림이 갑니다.

### ⑥ 점수가 쌓여 100점이 되면 차단한다 (`judge/store.py`, `judge/blocker.py`)

사용자 7이 계속 남의 정보를 조회하면 이렇게 됩니다.

```
요청          점수                     위험도  단계     일어나는 일
/members/3 →   40점                    40%    위험     개발자 Slack: "GET /members/{id} 취약"
/members/4 →   80점                    80%    고위험   관리자 Slack: 사용자 7 고위험
/members/5 →  150점 (피해자 3명 +30)    100%   차단     공격자 확정 → 영구 차단
```

100점이 넘으면 **공격자로 확정**하고 세 가지를 합니다.

1. **영구 차단:** Redis에 `blocked:user:7`을 만료 없이 등록합니다. pc2 Kong이 요청마다 이 키를 확인해서 **다음 요청부터 403**을 돌려줍니다.
2. **명단 기록:** `confirmed.json`에 공격자와 근거를 남깁니다. 다음 장부 학습 때 이 사람의 요청을 빼서, 공격 기록이 "주인"으로 잘못 학습되는 것을 막습니다.
3. **관리자 알림:** 확정과 차단 결과를 관리자 Slack으로 보냅니다.

확정된 뒤에는 더 채점하지 않습니다. 그래서 점수는 150처럼 100을 넘은 채로 멈추고, 이 값은 "차단 근거"로만 남습니다.
잘못 막았다면 관리자가 `judge/unblock.py`로 해제합니다. 해제하면 위험도가 0%로 돌아갑니다.

> **차단은 두 종류입니다.** 짧은 시간에 몰리면 탐지 엔진이 **10분 임시 차단**(RATE)을 겁니다. 그 사이 100점이 되면 판단 엔진이 같은 키를 **영구 차단**으로 바꿉니다.

---

## 판단 엔진이 계속 돌아가는 방식

| 언제 | 하는 일 |
|---|---|
| **켜질 때** | ① 장부를 분석해 URL로 확인할 수 있는 API를 찾음 ② PostgreSQL에 저장된 이벤트를 다시 채점해 **사용자별 점수를 복원** ③ DB에 아직 못 쓴 이벤트는 Redis에서 이어서 읽음 |
| **실행 중** | Redis에서 이벤트를 받아 처리하고 "처리 완료(ACK)" 표시. 꺼졌다 켜져도 표시 안 된 이벤트부터 다시 받아서 **빠뜨리지 않음** |
| **60초마다** | `confirmed.json` 명단과 Redis 차단 키를 비교해 빠진 키를 다시 검 (Redis가 초기화돼도 차단 유지). 상태 한 줄 출력 |
| **장부가 바뀌면** | URL로 확인할 API를 다시 찾음 |
| **오류가 나면** | 이벤트 하나, Slack, DB 문제로 판단이 멈추지 않게 오류만 기록하고 계속함 |

### 판단 엔진 파일 구성

`judge.py`가 이벤트를 받아 담당 파일에 차례로 넘깁니다.

```
Redis bola:events
      │ 이벤트 하나
      ▼
  judge.py ─────────────▶ scoring.py    점수, 위험도, 단계, "확정?" 판단
  (총괄)   ◀── 결과 ──────     ▲
      │                       │ URL로 확인할 API 목록
      │                  api_infer.py   장부를 보고 "URL 번호 = 사용자 번호"인 API를 찾음
      │
      ├─ 확정이면 ──▶ store.py      confirmed.json에 공격자 명단 기록
      │            ▶ blocker.py    Redis에 영구 차단 키 등록
      ├─ 항상 ─────▶ db.py         PostgreSQL에 기록 (따로 도는 스레드가 모아서 씀)
      └─ 필요하면 ──▶ notifier.py   Slack 알림 (큐에 넣고 따로 보냄)
```

| 파일 | 종류 | 한 줄 역할 |
|---|---|---|
| `judge.py` | **계속 실행** (컨테이너) | 총괄. 이벤트를 받아 나머지에 넘기고, 시작할 때 점수를 복원함 |
| `scoring.py` | 모듈 | 점수 규칙 |
| `api_infer.py` | 모듈 + 단독 실행 | URL만으로 판정할 수 있는 API를 장부에서 찾음 |
| `store.py` | 모듈 | 확정 명단 `confirmed.json` |
| `blocker.py` | 모듈 | Redis 영구 차단 키 |
| `db.py` | 모듈 | PostgreSQL 기록 |
| `notifier.py` | 모듈 + 단독 실행 | Slack 알림 |
| `unblock.py` | **관리자가 실행** | 차단 해제 |

평소에는 `judge.py` 하나만 컨테이너로 계속 돌고, 나머지는 그 안에서 불립니다. 사람이 직접 실행하는 것은 주로 `unblock.py`입니다.

### `judge.py`: 판단 서버 본체

Redis에서 이벤트를 받아 `scoring.py`로 채점하고, 결과에 따라 `store`/`blocker`/`db`/`notifier`를 부릅니다.

- **켜질 때:** 설정 읽기 → 1대1 API 추론 → DB와 Redis로 점수 복원 → 차단 명단 맞추기 → 실시간 수신 시작
- **실행 중:** 이벤트마다 채점하고 ACK, 60초마다 상태 출력, 명단 동기화, 장부 변경 확인
- **남기는 것:** 화면 로그(`[점수]`, `[확정]`, `[차단]`, `[상태]`), `output/score_log.jsonl`(이벤트별 점수), `output/breached_apis.json`(털린 API 요약)

| 명령 | 용도 |
|---|---|
| `python judge.py` | 계속 실행. 컨테이너가 이 명령으로 띄움 |
| `python judge.py --quiet` | 이벤트마다 찍히는 점수 줄 끄기 |
| `python judge.py --once --all --dry-run --trace` | 과거 이벤트 전체가 어떻게 채점되는지 한 줄씩 보기. 파일, DB, 차단, 알림을 건드리지 않아 **설정을 바꿔 시험할 때** 씀 |

### `scoring.py`: 점수 규칙

판단의 두뇌입니다. Redis나 파일을 모르고 이벤트만 받아 계산하기 때문에 테스트하기 쉽습니다.

- **나누기:** 이벤트를 `BOLA_PATH` / `BOLA_LEDGER` / `_WRITE` / `ATTEMPT` / `UNKNOWN` / `RATE`로 나눕니다. 본인 번호면 0점입니다. 1대1 API에서 `UNKNOWN`으로 온 성공 요청은 `BOLA_PATH`로 올립니다.
- **합산:** 사용자별로 합계와 보너스를 계산합니다.
- **판정:** 위험도와 단계를 정하고, 100점이면 확정 결과를 `judge.py`에 돌려줍니다. 확정 뒤에는 더 채점하지 않습니다.
- **설정:** `judge/config.json`의 `points`(배점), `bonus`, `threshold`(100), `levels`(10/30/60), `window_sec`(0 = 영구 누적)

### `api_infer.py`: URL로 확인할 API 찾기

장부에서 같은 자원(`/members/{id}` 등)의 **번호와 주인이 95% 이상 같으면** "URL 번호 = 사용자 번호"인 API로 판단합니다.
번호와 주인이 다른 몇 안 되는 항목은 장부 오염(공격 흔적)일 가능성이 높아서 따로 알려 줍니다.

- **판단 서버 안에서:** `config.json`의 `"path_owners": "auto"`이면 시작할 때와 장부가 바뀔 때 자동으로 실행됩니다. 현재 결과는 `/members/{id}`, `/profiles/{id}`입니다.
- **단독 실행:** 추론 결과만 보고 싶을 때 `python api_infer.py`를 실행합니다.

### `store.py`: 확정 명단

공격자로 확정된 사용자와 요청을 `fluent-bit/confirmed.json`에 쓰고, 근거는 `output/confirmed_log.jsonl`에 한 줄씩 남깁니다.

| 이 파일을 쓰는 곳 | 용도 |
|---|---|
| `ledger_v2.py` (장부 학습) | 여기 있는 요청과 사용자를 학습에서 빼서 장부 오염을 막음 |
| `blocker.py` | 차단의 기준 명단 |
| `unblock.py` | 해제한 사용자를 `users`에서 빼고 `released`에 해제 시각을 남김. 해제 이전 이벤트로는 다시 확정하지 않음 |

### `blocker.py`: 영구 차단

Redis에 `blocked:user:<id>`를 **만료 없이** 등록합니다. pc2 Kong이 이 키를 보고 403을 돌려줍니다. 사람이 확인하는 용도로 `block:info:<id>`에 사유와 시각을 함께 남깁니다.

- **확정 순간:** 영구 키를 겁니다. RATE의 10분 임시 키가 있으면 영구로 덮어씁니다.
- **60초마다:** `confirmed.json` 명단과 비교해 빠진 키를 다시 겁니다. Redis가 초기화돼도 차단이 유지됩니다.
- **Redis 오류가 나면:** 판단을 멈추지 않고 다음 동기화 때 다시 시도합니다.

### `db.py`: PostgreSQL 기록

`bola_events`(이벤트 1건 = 1행)와 `user_status`(사용자별 현재 상태)에 씁니다.

- **판단을 막지 않음:** 판단은 큐에 넣기만 하고, 저장 스레드가 모아서 씁니다. DB가 꺼져 있으면 쌓아 뒀다가 다시 연결되면 씁니다.
- **중복 없음:** 같은 이벤트(`stream_id`)는 한 번만 들어갑니다.
- **점수 복원:** 판단 서버가 켜질 때 과거 이벤트를 되돌려 줍니다. Redis에는 최근 10만 건만 남지만 DB에는 전부 남습니다.
- **설정:** 접속 정보는 `judge/.env`의 `PG_*`입니다.

### `notifier.py`: Slack 알림

판단은 알림을 큐에 넣기만 하고, 알림 스레드가 보냅니다. 언제 무엇을 보내는지는 위 ⑤의 표를 참고하세요.

- **중복 방지:** 보낸 알림은 DB `alerts`에 키로 남겨 재시작해도 다시 보내지 않습니다. 점수를 복원하는 동안에는 보내지 않습니다.
- **실패하면:** 2, 4, 8, 16초 간격으로 최대 5번 다시 시도합니다.
- **웹훅 설정:** 주소는 `judge/.env`의 `SLACK_ADMIN_WEBHOOK`, `SLACK_DEV_WEBHOOK`입니다. 비어 있으면 보내지 않고 기록만 합니다.
- **시험 전송:** `python notifier.py --test`를 실행하면 두 채널에 시험 메시지를 보냅니다.

### `unblock.py`: 차단 해제 (관리자용)

오탐으로 막힌 사용자를 풀어 줍니다. **판단 서버를 먼저 멈춰야 합니다.** 켜져 있으면 메모리의 명단으로 1분 안에 다시 차단하기 때문에, 이 스크립트가 실행을 거부합니다.

```bash
# WSL, /mnt/d/python-rule 에서
docker compose stop judge
docker compose run --rm judge python unblock.py 7 --by 홍길동 --note "장부 오류, 본인 주문"
docker compose start judge

docker compose run --rm judge python unblock.py --list    # 차단 목록 보기 (서버가 켜져 있어도 됨)
```

해제하면 다섯 군데가 바뀝니다.

| 대상 | 바뀌는 것 |
|---|---|
| Redis | 차단 키 삭제 → Kong 통과 |
| `confirmed.json` | 명단에서 빼고 해제 시각 기록 |
| `confirmed_log.jsonl` | 누가, 언제, 왜 해제했는지 |
| DB | 조치를 `released`로, 사용자를 `normal`, 위험도 0%로 |
| 관리자 Slack | 해제 알림 |

`--by`(해제한 사람)와 `--note`(이유)는 필수입니다.

### 그 밖의 `judge/` 내용

| 위치 | 내용 |
|---|---|
| `config.json` | 배점, 기준, 단계, 차단, 알림, DB 설정 |
| `tests/` | 테스트 74개. `judge` 폴더에서 `python -m unittest discover tests` |
| `scripts/` | 포트 전달(`wsl-portproxy.ps1`), 로그온 자동 시작 등록(`register-startup-task.ps1`) |
| `db/init/`, `db/migrate/` | DB 구조. `init`은 DB를 새로 만들 때 자동으로, `migrate`는 기존 DB를 고칠 때 직접 실행 |

---

## 빠른 시작

pc1의 WSL에서 Docker로 실행합니다. 컨테이너 3개가 함께 뜹니다.

```bash
cd /mnt/d/python-rule
docker compose up -d --build     # bola-realtime(탐지) + bola-judge(판단) + judge-postgres(DB)
docker compose logs -f judge     # [점수] 사용자 7 … = 80/100점 (위험도 80% 고위험)
```

처음 한 번은 git에 없는 파일을 준비해야 합니다.

1. **비밀번호:** `fluent-bit/.env.example`, `judge/.env.example`을 `.env`로 복사해 채웁니다. Slack 웹훅은 비워 두면 알림만 빠집니다.
2. **인증서 키:** `fluent-bit/certs/server.key`를 따로 받아 넣습니다 (로그 수신 mTLS용).
3. **포트 전달:** 관리자 PowerShell에서 실행합니다. 재부팅하거나 `wsl --shutdown`을 한 뒤에는 다시 실행해야 합니다.
   ```powershell
   powershell -ExecutionPolicy Bypass -File judge\scripts\wsl-portproxy.ps1 -Remote 192.168.0.26              # 5432 DB (pc3만)
   powershell -ExecutionPolicy Bypass -File judge\scripts\wsl-portproxy.ps1 -Port 5170 -Name "bola realtime"  # 5170 로그 수신
   ```
   `judge\scripts\register-startup-task.ps1`을 한 번 실행해 두면 로그온할 때 위 작업과 컨테이너 시작을 자동으로 합니다.

## 구성

```
pc2 (Kong, Redis)             pc1 (이 저장소, Docker)                  pc3
Fluent Bit ── 로그 5170 ──▶   bola-realtime ──▶ Redis bola:events
Redis      ◀── 이벤트 ─────   bola-judge    ──▶ Slack
Kong 403   ◀── 차단 키 ────        │
                                   ▼
                              judge-postgres ── 5432 ──────────────▶ Streamlit 대시보드
```

| DB 테이블 | 내용 |
|---|---|
| `bola_events` | 탐지된 요청 1건과 그에 대한 판단(점수, 위험도, 단계)과 조치 |
| `user_status` | 사용자별 현재 단계와 위험도 |
| `alerts` | 보낸 Slack 알림 기록 |

대시보드는 `dashboard` 계정으로 읽기 전용으로 접속합니다. 비밀번호는 `judge/.env`의 `PG_DASHBOARD_PASSWORD`입니다.

## 더 보기

| 문서 | 내용 |
|---|---|
| [`judge/README.md`](judge/README.md) | 판단 엔진 자세히: 점수 규칙, 위험도, 차단과 해제, DB 열, Slack 알림, 설정 |
| [`fluent-bit/README.md`](fluent-bit/README.md) | 탐지 엔진 자세히: 판정 규칙, 장부 학습 |
| [`attack/README.md`](attack/README.md) | 공격 시뮬레이터로 탐지·차단 시험하기 |
| [`OVERVIEW.md`](OVERVIEW.md) | 전체 동작, 로그 보는 법, 현재 운영 상태 |
| `동작시나리오_20261106.html`, `위험도_정리_20261109.html` | 그림으로 보는 동작과 위험도 설명 |
