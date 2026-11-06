# engine: BOLA 실시간 탐지 엔진 (장부 기반)

pc1의 Fluent Bit가 보내는 Kong 로그를 **mTLS로 받아**, 미리 학습한 **장부(`ledger.json`)** 와 비교해 의심 요청을 판정합니다.
결과는 Redis Stream `bola:events`로 보고하고, 의심 요청이 몰리는 사용자는 Redis 차단 키로 **임시 차단**합니다.
최종 판단(점수·장기 차단·알림)은 판단 서버가 합니다.

> **두 단계 설계.** 이 엔진은 장부로 **원본 분류**(`BOLA`/`ATTEMPT`/`UNKNOWN`/`RATE`)만 붙여 Redis로 보냅니다.
> 점수 계산과 **최종 분류**(조회/쓰기 구분 `BOLA_PATH`·`BOLA_LEDGER`·`_WRITE`, 장부에 없던 요청의 `UNKNOWN → BOLA_PATH` 승격 등)는
> 판단 서버가 합니다. 전체 흐름은 [`../README.md`](../README.md), 점수·확정은 [`../judge/README.md`](../judge/README.md)를 보세요.

> Wazuh(Indexer)를 거치는 기존 경로는 수 초에서 수십 초씩 늦습니다. 이 엔진은 그 경로를 건너뛰는 실시간 경로입니다.
> Wazuh는 보관·대시보드 용도로 그대로 남겨 둡니다.

---

## 1. 전체 구조

```
게이트웨이 PC (192.168.0.39)                                  탐지 PC (realtime.py)
┌────────────────────────────────────────┐                 ┌───────────────────────────────┐
│ Kong ─file-log─▶ /logs/kong/access.json │                 │                               │
│   ▲                     │ tail          │                 │  ① 5170 포트에서 기다림 (서버)  │
│   │               Fluent Bit ───────────┼──mTLS TCP 5170─▶│  ② 한 줄 = Kong 로그 JSON      │
│   │ 요청마다 확인                         │  (Fluent Bit가  │  ③ 장부로 판정                  │
│   │ GET blocked:user:N                  │   먼저 연결)     │  ④ 의심 요청 횟수 세기          │
│ Redis :6379 ◀───────────────────────────┼─────────────────┤  ⑤ 보고·차단 (클라이언트)       │
│   ├ bola:events   (탐지 이벤트 Stream)    │  XADD / SET     └───────────────────────────────┘
│   └ blocked:user:N (임시 차단 키, 10분)   │
│        │                                │
│        ▼ 소비자 그룹 judges              │
│   판단 서버 (점수·장기 차단·알림)          │
└────────────────────────────────────────┘
```

| 연결 | 누가 먼저 연결하나 | 포트 | 보안 |
|---|---|---|---|
| Fluent Bit → realtime.py | Fluent Bit (클라이언트) | 탐지 PC **5170** (방화벽 인바운드 허용 필요) | mTLS (서로 인증서 검사) |
| realtime.py → Redis | realtime.py (클라이언트) | 게이트웨이 PC **6379** | 비밀번호 없음 (`REDIS_PASS = None`) |

realtime.py는 Redis를 **실행하지 않습니다.** 0.39에서 도는 Redis에 접속해서 쓰기만 합니다.

---

## 2. 파일

```
engine/
├─ realtime.py     실시간 탐지 엔진 (수신·판정·보고·차단). 이 폴더의 본체
├─ ledger_v2.py    장부 학습: 30일치 로그로 ledger.json을 만듦 (confirmed.json의 요청·사용자는 빼고 학습)
├─ common.py       공용 함수: api_key(), JSON 줄 읽기, tail -f 흉내(follow)
├─ ledger.json     장부: API별 {객체 ID: 주인}. ledger_v2.py가 만들고, realtime.py는 읽기만 함
├─ confirmed.json  확정된 공격 요청·사용자. ../judge/judge.py(판단 서버)가 씀
├─ ledger_days/    ledger_v2.py가 만드는 날짜별 집계 (자동 생성)
├─ data/           학습할 Kong 로그 (ledger_v2.py의 LOG_PATH)
└─ certs/
   ├─ ca.crt       자체 CA (CN=bola-log-ca). Fluent Bit 클라이언트 인증서 검사에 사용
   ├─ server.crt   탐지 서버 인증서 (CN=bola-detector, SAN=IP 192.168.0.39)
   └─ server.key   탐지 서버 개인키 ⚠️ git에 올리지 말 것
```

| 파일 | realtime.py가 쓰나 | 설명 |
|---|---|---|
| `common.py`의 `api_key` | ✅ | `GET /orders/7` → `GET /orders/{id}` |
| `common.py`의 `parse_line`, `load_logs`, `follow` | ❌ | 파일로 학습·검사할 때 쓰는 함수 |
| `common.py`의 `load_logs` | — | `ledger_v2.py`가 학습 로그를 읽을 때 씀 |

**장부 학습:** 이 폴더 안에서 `python ledger_v2.py`를 실행합니다 (상대 경로라 폴더 안에서 실행해야 함).
어제부터 30일치 로그로 `ledger.json`을 다시 만들고, `realtime.py`는 60초 안에 새 장부를 자동으로 읽습니다.
`confirmed.json`의 `requests`에 있는 요청과 `users`의 시각 이후 그 사용자의 요청은 학습에서 뺍니다.

---

## 3. 장부 (`ledger.json`)

**"이 API의 이 객체 주인은 누구인가"** 를 담은 표입니다. 바깥 키는 API 템플릿, 안쪽은 `{객체 ID: 주인 user_id}`입니다.

```json
{
  "GET /orders/{id}":                 { "298": "102", "297": "102", ... },
  "GET /members/{id}/addresses/{id}": { "27/55": "27", ... },
  "GET /members/{id}":                { "27": "27", ... }
}
```

- URL에 ID가 여러 개 있으면 `/`로 이어 붙입니다. 예: `/members/27/addresses/55` → `"27/55"`
- 현재 장부: **API 7개, 객체 1,174개**

| API | 객체 수 |
|---|---|
| `GET /orders/{id}` | 302 |
| `GET /payments/{id}` | 249 |
| `GET /members/{id}/addresses/{id}` | 209 |
| `GET /members/{id}` | 104 |
| `GET /members/{id}/addresses` | 104 |
| `GET /profiles/{id}` | 103 |
| `GET /profiles/{id}/coupons` | 103 |

- 실행 중에 `ledger.json`이 바뀌면 **60초 안에 자동으로 다시 읽습니다** (`RELOAD_SEC`). 파일 수정 시각으로 확인합니다.
- 실행 중에 목록 응답으로 객체를 추가하기도 합니다 (아래 `add_from_list`). 이 추가분은 메모리에만 있고 파일에는 저장하지 않습니다.

---

## 4. 로그 한 건이 처리되는 순서

```
Fluent Bit 한 줄 ─▶ Handler.handle()  json.loads (깨진 줄은 건너뜀)
                      │
                      ▼
                   process(e)
                      ├ 비로그인 / admin / Kong이 이미 차단한 요청(blocked) → 무시
                      └ lock (연결이 여러 개여도 판정은 한 번에 하나씩)
                          ├ reload_ledger()   장부 파일이 바뀌었으면 다시 읽기
                          ├ add_from_list()   목록 응답 객체를 장부에 추가
                          ├ judge()           BOLA / ATTEMPT / UNKNOWN / 없음
                          └ 의심이면 check_rate()  → 기준 넘으면 임시 차단 + RATE 보고
                      │
                      ▼ (의심일 때만)
                   report()  콘솔 한 줄 + Redis XADD bola:events
```

### 4-1. 판정 `judge()`

위에서부터 차례로 검사하고, 처음 걸리는 결과를 냅니다.

| 순서 | 조건 | 결과 |
|---|---|---|
| 1 | 비로그인, admin, URL에 숫자 ID 없음, **장부에 없는 API** | 판정 안 함 |
| 2 | 상태 **403/404** | **ATTEMPT** (남의 객체를 시도했다가 막힘) |
| 3 | 장부에 그 **객체 ID가 없음** | **UNKNOWN** (주인을 모르는 객체) |
| 4 | 상태 **200** 이고 요청자 ≠ 장부상 주인 | **BOLA** (남의 객체 조회 성공) |
| 5 | 그 밖 (본인 객체 등) | 정상 |

### 4-2. 목록으로 장부 채우기 `add_from_list()`

- 대상: `GET /orders`처럼 **ID 없는 목록 API**이면서, 같은 경로의 상세 API(`GET /orders/{id}`)가 장부에 있는 경우
- 조건: 상태 200, role이 `user`, 차단되지 않은 요청
- 동작: 응답의 `resp_ids["[].id"]`에 나온 객체를 **요청자를 주인으로** 장부에 추가합니다. 이미 장부에 있는 객체는 덮어쓰지 않습니다.
- 목적: 학습 이후에 새로 생긴 객체(새 주문 등)가 UNKNOWN으로 잡히지 않게 하기 위함입니다.

### 4-3. 임시 차단 `check_rate()`

- **의심 요청(BOLA, ATTEMPT, UNKNOWN)만** 셉니다. 자기 정보를 아무리 새로고침해도 세지 않습니다.
- 사용자별로 **10초에 10번을 넘으면**:
  - Redis `SET blocked:user:<id> "rate" EX 600` → Kong이 요청마다 이 키를 확인해서 **10분 동안 403**으로 막습니다.
  - `RATE` 이벤트를 보고합니다.
- 같은 사용자를 차단 중에는 다시 걸지 않습니다 (`blocked_until`).

### 4-4. 보고 `report()`

콘솔 출력 예:
```
[BOLA   ] GET /members/{id}                   요청자 2 -> 9 (주인 9) req=...
```

Redis `bola:events`에 넣는 필드 (최근 10만 건만 유지):

| 필드 | 예 |
|---|---|
| `kind` | `BOLA` / `ATTEMPT` / `UNKNOWN` / `RATE` (원본 분류. 최종 점수·분류는 판단 서버가 함) |
| `user_id`, `api`, `uri`, `status` | `2`, `GET /members/{id}`, `/members/9`, `200` |
| `request_id`, `started_at` | Kong 요청 ID, 요청 시각(ms) |
| `detail` | `요청자 2 -> 9 (주인 9)` |

> `api`에는 **HTTP 메서드가 포함**됩니다(`PATCH /members/{id}`). 판단 서버는 이 메서드를 보고 남의 객체 **수정·삭제(PUT·PATCH·DELETE)** 를
> 조회보다 높은 `_WRITE` 점수로 매깁니다. 그래서 쓰기 공격을 구분하려고 `realtime.py`를 고칠 필요가 없습니다.

Redis가 꺼져 있어도 엔진은 멈추지 않습니다. 판정은 계속하고 `[Redis] 보고 실패` 메시지만 남깁니다.

---

## 5. 설정값 (`realtime.py` 맨 위)

| 이름 | 값 | 의미 |
|---|---|---|
| `PORT` | 5170 | Fluent Bit 연결을 받을 포트 |
| `REDIS_HOST` / `REDIS_PORT` | 192.168.0.39 / 6379 | Kong이 차단 키를 읽는 Redis |
| `REDIS_PASS` | `.env`의 `REDIS_PASSWORD` | 비밀번호는 코드에 두지 않음 (`.env.example`을 `.env`로 복사해서 채움) |
| `STREAM` / `STREAM_MAXLEN` | `bola:events` / 100,000 | 보고 Stream, 최대 길이 |
| `RATE_WINDOW_MS` / `RATE_LIMIT` | 10,000 / 10 | 10초에 의심 요청 10번 초과 시 임시 차단 |
| `TEMP_BLOCK_SEC` | 600 | 임시 차단 10분 |
| `RELOAD_SEC` | 60 | 장부 파일 변경 확인 주기 |
| `BASE_DIR`, `CERT_DIR`, `LEDGER_PATH` | 이 파일이 있는 폴더 기준 | 어느 폴더에서 실행해도 장부와 인증서를 찾음 |

---

## 6. mTLS (인증서)

```
Fluent Bit (클라이언트 인증서, bola-log-ca가 서명) ──▶ realtime.py (server.crt / server.key)
        서버 인증서를 ca.crt로 검사                        클라이언트 인증서를 ca.crt로 검사 (CERT_REQUIRED)
```

- realtime.py는 **클라이언트 인증서가 없거나 다른 CA가 서명한 연결은 거부**합니다.
- `server.crt`의 SAN은 **IP 192.168.0.39**입니다. 탐지 PC의 IP가 이와 다르고 Fluent Bit에서 `tls.verify_hostname on`을 쓰면 연결에 실패합니다. 이때는 탐지 PC IP로 인증서를 다시 발급하거나 `tls.verify_hostname off`로 둡니다.
- Fluent Bit 쪽 `[OUTPUT]`에 필요한 설정 (참고):
  ```
  tls          on
  tls.verify   on
  tls.ca_file  /certs/ca.crt
  tls.crt_file /certs/client.crt
  tls.key_file /certs/client.key
  ```

---

## 7. 실행

### Docker (pc1 WSL, 추천)

```bash
cd engine                      # 저장소의 engine 폴더에서
docker compose up -d --build   # bola-realtime (판단 서버는 judge 폴더에서 따로)
docker compose logs -f realtime
```

- 이 폴더를 컨테이너 `/app`에 **읽기 전용으로 붙여서** 실행합니다 (`docker-compose.yml`). 장부를 다시 학습하면 60초 안에 반영되고, 코드를 고치면 `docker compose restart realtime`만 하면 됩니다.
- Docker가 WSL(NAT) 안에 있으므로 pc2 → pc1:5170을 WSL로 넘기는 포트 전달이 필요합니다 (관리자 PowerShell):
  `powershell -ExecutionPolicy Bypass -File D:\python-rule\judge\scripts\wsl-portproxy.ps1 -Port 5170 -Name "bola realtime"`
  재부팅하면 WSL IP가 바뀌므로 다시 실행합니다 (5432도 함께).

### 로컬 Python

```powershell
pip install redis                      # 필요한 외부 패키지는 redis 하나
copy engine\.env.example engine\.env   # REDIS_PASSWORD 채우기
# certs\server.key는 git에 없음 → 따로 받아서 certs\에 넣기
python engine\realtime.py          # 어느 폴더에서 실행해도 됨
```

정상이면 다음과 같이 뜹니다.
```
[장부] 읽음: API 7개, 객체 1174개
[Redis] 연결됨 192.168.0.39:6379
5170 포트에서 Fluent Bit 로그를 기다리는 중
```

**사전 준비**
- 탐지 PC 방화벽에서 TCP 5170 인바운드 허용
- pc1 Fluent Bit의 `Host`가 탐지 PC IP, `Port`가 5170
- 게이트웨이 PC의 Redis 6379가 탐지 PC에서 접속 가능해야 함

---

## 8. Redis 데이터 확인

```python
import redis
r = redis.Redis(host="192.168.0.39", port=6379, decode_responses=True)
print(r.xlen("bola:events"))                              # 이벤트 수
for mid, f in r.xrevrange("bola:events", count=10):        # 최근 10건
    print(mid, f["kind"], f["user_id"], f["uri"], f["detail"])
print(list(r.scan_iter("blocked:*")))                     # 지금 차단 중인 사용자
print(r.xinfo_groups("bola:events"))                      # 판단 서버(judges 그룹)가 어디까지 읽었나
```

2026-10-30 확인 결과: 이벤트 288건 (BOLA 275, ATTEMPT 9, RATE 4), 차단 키 0개.
`judges` 그룹은 consumers 0명, 10:29 이후 이벤트가 전달되지 않음 → 판단 서버가 꺼져 있었음.

---

## 9. 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| `FileNotFoundError` (`load_cert_chain`) | 예전 코드는 인증서를 **실행한 폴더 기준** 상대 경로로 찾았음 | 지금은 `BASE_DIR` 기준이라 해결됨. `certs/`에 파일 3개가 있는지 확인 |
| 대기 중인데 화면에 아무것도 안 뜸 | ① 정상 로그는 출력하지 않음 ② TLS 실패도 출력하지 않음 (`SSLError`를 socketserver가 조용히 버림) ③ 연결 로그가 없음 | pc1에서 `docker logs <fluent-bit>`로 연결·TLS 오류 확인, `nc -vz <탐지PC> 5170`, Kong에 요청을 보내 새 로그를 만들어 봄 |
| 연결이 안 됨 | Fluent Bit `Host`가 다른 PC를 가리킴, 방화벽 막힘, 인증서 SAN 불일치 | 6장, 7장 참고 |
| `[Redis] 연결 안 됨` | 0.39 Redis가 꺼졌거나, 127.0.0.1에만 바인딩됨 | 게이트웨이 PC의 Redis 포트 설정 확인. 판정은 계속되고 보고·차단만 안 됨 |
| 정상 사용자가 BOLA로 잡힘 | 장부의 주인이 잘못됨 (예: `/members/4`의 주인이 `43`) | 10장 1번 참고 |

---

## 10. 알려진 문제와 개선 후보

| # | 내용 | 영향 / 현황 |
|---|---|---|
| 1 | 장부에 잘못된 주인: `GET /members/{id}`, `GET /members/{id}/addresses`의 `"4": "43"` | 회원 4가 자기 정보를 봐도 BOLA. **→ 판단 서버가 보완**: ID가 곧 사용자인 API를 `path_owners`로 **경로 판정**(1대1 자동 추론 `api_infer.py`)해 장부 오염에 면역. 본인 번호면 점수 0 |
| 2 | 장부 키가 **GET API**뿐 | `PATCH`/`PUT`/`DELETE`도 `same_object_apis`가 같은 객체의 GET 장부로 매핑해 **판정은 됨**. **→ 판단 서버가** 이 수정·삭제를 `_WRITE`로 조회보다 **높게 채점** |
| 3 | `add_from_list`가 `resp_ids`를 씀 | "응답 본문을 안 쓴다"는 방향과 맞지 않음. resp_ids가 없으면 새 객체가 계속 UNKNOWN |
| 4 | 장부를 다시 읽으면 실행 중 추가분이 사라짐 | 새 객체가 다시 UNKNOWN이 됨. `path_owners` API라면 판단 서버가 `UNKNOWN → BOLA_PATH`로 올려 덜 치명적 |
| 5 | UNKNOWN도 차단 횟수에 셈 | 새 객체를 빠르게 조회하는 정상 사용자가 차단될 수 있음 |
| 6 | 403/404면 본인 객체여도 ATTEMPT | 가벼운 오탐 (판단 서버에서 본인 번호면 점수 0) |
| 7 | BOLA를 상태 **200·204**일 때만 봄(`SUCCESS`) | 201 등 그 밖의 성공은 놓침 |
| 8 | 연결, TLS 실패, 수신 건수를 출력하지 않음 | 문제가 생겼을 때 진단이 어려움 |
| 9 | TLS 핸드셰이크를 연결을 받는 메인 스레드에서 함 | 멈춘 클라이언트 하나가 다른 연결까지 막을 수 있음 |
| 10 | 설정이 코드에 하드코딩됨 | 기준값을 바꿀 때마다 코드 수정 필요 |

- **1·2·4번은 판단 서버(`judge/`) 쪽에서 보완**했습니다. `realtime.py`는 원본 분류만 하고, 경로 판정·쓰기 채점·UNKNOWN 승격은 판단 서버가 합니다. 상세는 [`../judge/README.md`](../judge/README.md).
- 행동 룰을 함께 쓰는 엔진은 `../archive/bola-rule-rule`에 보관되어 있습니다. 순차 ID 탐색(R6), 403/404 다발(R7) 같은 룰을 합치면 5·6번을 더 보완할 수 있습니다.
