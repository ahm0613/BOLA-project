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

이번 범위는 `confirmed.json` 생성까지입니다. 차단(`blocked:user:N`)은 하지 않습니다. `realtime.py`의 RATE 임시 차단은 그대로입니다.

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
| `judge.py` | 실행: Redis 읽기, 복원, 그룹 소비, 상태 출력 |
| `scoring.py` | 점수·확정 로직 (Redis를 몰라서 테스트하기 쉬움) |
| `store.py` | `confirmed.json` 읽기·쓰기, 확정 근거 기록 |
| `config.json` | Redis 주소, 점수, 기준, 시간 창, 경로 |
| `.env` | Redis 비밀번호 (git 제외) |
| `tests/test_scoring.py` | 점수, 오탐 거르기, 보너스, 시간 창, 파일 형식 테스트 |

## 남은 일

- 차단을 판단 서버로 옮기기 (`blocked:user:N`)
