# bola-rule — Wazuh Indexer 기반 BOLA 탐지 엔진

Wazuh 룰로는 잡을 수 없는 **"성공한 BOLA"**(남의 객체를 조회·변경해 200을 받은 요청)를 Python 룰로 판정하고,
**"이 로그는 이 룰을 위반했습니다"** 형식의 위반 로그를 만듭니다.
위반 로그는 판단 서버(`../judge-server`)가 읽어 사용자별 점수를 매깁니다.

## 전체 흐름

```
APP PC (pc1-bola)   Kong access.json
                       └─ Wazuh agent ─▶ Wazuh manager ─▶ Indexer bola-api-YYYY.MM.DD
                                                            (https://192.168.0.26:9200)
                                                                    │ 1초마다 새 로그 조회
이 PC   bola-rule: python main.py run ◀─────────────────────────────┘
          ├─ 읽은 로그 전체   → output/api_logs/api-YYYY-MM-DD.jsonl
          └─ 룰 R1~R6 판정   → output/violations-YYYY-MM-DD.jsonl  (요청 날짜별)
                                    │
        judge-server: python judge.py --watch 1
                                    └─ 사용자별 점수 → judge-server/output/scores.json, daily/
```

## 역할 분담

| 구분 | 담당 | 예 |
|---|---|---|
| 한 줄·횟수로 잡히는 것 | **Wazuh 룰** (다음 단계) | 401 반복, 1분에 403/404 N번 (ID 찔러보기) |
| 기억이 필요한 것 | **Python 룰 (이 엔진)** | alice(1)가 `GET /orders/2` → **200**, 그런데 주문 2의 주인은 bob(2) |
| 점수·차단 결정 | **판단 서버** (`../judge-server`) | 사용자별 룰 위반 점수 합산 (차단 연동은 다음 단계) |

## Python 룰

> 룰별 자세한 설명은 [docs/RULES.md](docs/RULES.md), 내부 동작 순서는 [docs/RULE_FLOW.md](docs/RULE_FLOW.md)를 참고하세요.

| 룰 | 이름 | 심각도 | 판정 |
|---|---|---|---|
| `BOLA-R1` | 응답 주인 불일치 | high | 2xx 응답의 주인 필드(`config.yaml`의 `owner_fields`)에 요청자가 아닌 사용자가 있음 |
| `BOLA-R5` | 경로 주인 불일치 | high | `/members/{id}`처럼 경로의 번호가 곧 사용자 번호인 API에서, 그 번호가 요청자와 다름 (`path_owners`) |
| `BOLA-R2` | 장부 주인 불일치 | high | 응답에 주인 정보가 없으면(예: `POST /orders/{id}/cancel`) **장부**의 주인과 요청자를 비교 |
| `BOLA-R3` | 목록 밖 객체 변경 | medium | 장부에도 주인이 없는 객체를, 요청자가 이전에 다룬 적 없이 **변경**(POST/PUT/PATCH/DELETE)함. 확정이 아닌 의심 |
| `BOLA-R4` | 다수 소유자 접근 | critical | R1·R2·R3·R5 위반을 사용자별로 묶어, 창 안에서 서로 다른 피해 대상이 기준 이상이면 **사건 경보** |
| `BOLA-R6` | 순차 ID 탐색 | medium | 짧은 시간에 자기 것이 아닌 ID를 연속으로 요청 (403·404로 막힌 요청도 셈) |

판정 순서: **R1**(응답에 주인 있음) → **R5**(경로가 사용자 번호) → **R2**(장부에 주인 있음) → **R3**(변경 요청일 때만).
위반이 나면 **R4**로 집계하고, **R6**은 위반 여부와 관계없이 연속 ID 요청을 따로 셉니다.

R4의 창(window)은 두 개입니다(`config.yaml`의 `rules.BOLA-R4.windows`).
- **급속:** 10분 안에 5명. 몰아서 수집하는 공격
- **저속:** 24시간 안에 5명. 천천히 수집하는 공격

**장부(ledger)** 는 "객체 → 주인" 표입니다(`state/ledger.json`). 아래 방법으로 채웁니다.
1. **응답으로 확인:** 응답에 주인이 하나로 나오면 그 객체의 주인으로 확정합니다. 공격 응답이라도 응답 속 주인은 사실이므로 기록합니다.
2. **목록 응답:** `GET /orders`처럼 내 목록에 나온 객체는 내 것으로 기록합니다 (`list_sources`).
3. **방문 기록:** 확인된 주인이 없는 객체만, 여러 날 중 70% 이상 한 사용자가 조회했으면 그 사람을 주인으로 추정합니다.

처음 보는 객체(장부에 없음)는 위반으로 판정하지 않고 `unknown_owner`로 개수만 셉니다.

## 출력 파일

| 파일 | 내용 |
|---|---|
| `output/api_logs/api-YYYY-MM-DD.jsonl` | `run`이 읽은 **전체 API 로그** (Indexer 문서 `_source` 그대로). `main.py replay`로 다시 돌릴 수 있음 |
| `output/violations-YYYY-MM-DD.jsonl` | `run`의 **룰 위반 로그** |
| `output/<이름>.jsonl`, `<이름>_summary.json` | `replay` 결과 (위반 로그, 서비스별 요약·채점) |
| `state/checkpoint.json` | 어디까지 읽었는지. 재시작해도 중복·누락이 없음. 지우면 "지금부터" 다시 읽음 |
| `state/ledger.json` | 장부. 실행 중에도 계속 갱신됨 |

날짜는 엔진이 찾은 시각이 아니라 **요청이 일어난 시각** 기준입니다.

### 위반 로그 형식 (한 줄에 하나)

`event_time`은 요청이 실제로 일어난 시각(Kong 로그), `detected_at`은 엔진이 위반을 찾아낸 시각입니다.

```json
{
  "event_time": "2026-10-28T13:36:08+09:00",
  "detected_at": "2026-10-28T13:36:18+09:00",
  "message": "이 로그는 BOLA-R1(응답 주인 불일치) 룰을 위반했습니다.",
  "rule": {"id": "BOLA-R1", "name": "응답 주인 불일치", "severity": "high", "description": "..."},
  "reason": "요청자 1이(가) 주인 2의 객체(GET /members/2)를 조회·변경해 200 응답을 받음 (응답 필드 user_id)",
  "evidence": {"api": "GET /members/{id}", "resource": "/members/{id}", "object_id": "2",
               "requester": "1", "owners": ["2"], "owner_source": "response:user_id"},
  "original": {"request_id": "...", "time": "...", "user_id": "1", "method": "GET", "uri": "/members/2", "status": 200, "...": "..."},
  "source": {"index": "bola-api-2026.10.28", "doc_id": "...", "wazuh_id": "...", "timestamp": "...",
             "agent": "pc1-bola", "location": "/logs/kong/access.json"}
}
```

## 설치 (Windows)

```
cd D:\python-rule\bola-rule
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .env.example .env        # Indexer 주소·계정·CA 경로 수정
```

- `.env`의 비밀번호에 특수문자가 있으면 작은따옴표로 감쌉니다.
- Indexer 인증서 이름이 `wazuh.indexer`뿐이라, IP로 접속할 때는 `INDEXER_TLS_HOSTNAME=wazuh.indexer`를 씁니다.
- CA 파일(`root-ca.pem`)과 `.env`는 Git에 올리지 않습니다.

## 사용법

```
.venv\Scripts\python main.py check              # Indexer 연결 + bola-api-* 문서 수 확인
.venv\Scripts\python main.py run                # 실시간 탐지 (장부가 없으면 최근 7일 로그로 먼저 학습)
.venv\Scripts\python main.py run --relearn      # 장부를 버리고 다시 학습한 뒤 탐지
.venv\Scripts\python main.py learn              # 장부만 다시 만들기

# 쌓아 둔 전체 API 로그로 다시 탐지 (Indexer 없이)
.venv\Scripts\python main.py replay output\api_logs\api-2026-10-28.jsonl --out replay_1028.jsonl

# Indexer 모양 가짜 로그를 만들어 정답지 CSV로 채점 (data/는 비어 있으므로 먼저 생성)
.venv\Scripts\python tools\make_indexer_fake.py
.venv\Scripts\python main.py replay data\indexer_fake.jsonl --truth data\indexer_fake_truth.csv --out indexer_fake.jsonl

.venv\Scripts\python -m unittest discover tests    # 룰 단위 테스트
.venv\Scripts\python smoke_attack.py               # 실환경 공격 (KONG_URL 설정 후, 엔진 run 중에 실행)
```

### Docker로 실행

```
cd D:\python-rule\bola-rule
docker compose up -d --build     # main.py run 을 컨테이너로 실행
docker compose logs -f           # 탐지 출력 보기
docker compose down              # 멈춤
```

- `.env`, `root-ca.pem`, `config.yaml`은 이미지에 넣지 않고 실행할 때 읽기 전용으로 붙입니다. 비밀번호가 이미지에 남지 않습니다.
- `state/`, `output/`은 로컬 폴더를 그대로 씁니다. 판단 서버(`../judge-server`)도 이 `output/`을 읽습니다.
- 로컬 `main.py run`과 컨테이너를 **동시에 돌리지 마세요**. 같은 체크포인트·장부를 두 곳에서 덮어씁니다.

## 설정 (`config.yaml`)

| 키 | 설명 |
|---|---|
| `indexer.index` | 조회할 인덱스 (`bola-api-*`, 시간 필드는 `timestamp`) |
| `indexer.poll_interval_sec` | 조회 주기 (현재 1초, 소수 가능) |
| `indexer.overlap_sec` | 늦게 들어오는 로그를 위해 겹쳐 읽는 구간 (기본 30초, 이미 본 문서는 건너뜀) |
| `learning.days` / `min_share` | 장부 학습 기간(7일) / 방문 기록으로 주인을 추정하는 기준(0.7) |
| `paths.*` | 장부·체크포인트·위반 로그·전체 API 로그 위치 |
| `owner_fields` | R1: API별 응답의 주인 필드. **새 API를 추가하면 여기에 한 줄 추가** |
| `list_sources` | 목록 API → 장부에 추가할 객체 |
| `path_owners` | R5: 경로의 번호가 곧 사용자 번호인 API |
| `rules.*` | 룰 켜기/끄기, 심각도, R4 창·R6 기준값 |

## 파일 구성

```
bola-rule/
├─ main.py                CLI (check / learn / run / replay)
├─ config.yaml            룰·동작 설정
├─ requirements.txt       필요한 라이브러리
├─ .env.example           접속 정보 견본 (.env로 복사해 사용)
├─ smoke_attack.py        실환경 공격 스크립트
├─ Dockerfile, docker-compose.yml, .dockerignore   Docker 이미지·실행 설정
├─ bola_engine/
│  ├─ config.py           config.yaml + .env 읽기
│  ├─ sources.py          Indexer 조회(search_after 페이지, TLS 이름 지정), 체크포인트, 파일 읽기
│  ├─ event.py            Kong·Wazuh 문서 → 이벤트, API/객체 키 추출
│  ├─ ledger.py           장부 (확인된 주인 + 방문 기록)
│  ├─ rules.py            BOLA-R1~R6 판정 + 위반 로그 생성
│  ├─ output.py           콘솔 + 날짜별 JSONL 출력
│  └─ evaluate.py         정답지 비교 (정밀도/재현율)
├─ tests/test_rules.py    단위 테스트
├─ tools/                 시험 데이터 생성 도구
├─ docs/
│  ├─ RULES.md            룰 설명서
│  └─ RULE_FLOW.md        룰 내부 동작 순서
├─ data/                  시험용 가짜 로그 (README.md 참고, 지금은 비어 있음)
├─ output/                실행 결과 (Git 제외)
└─ state/                 장부·체크포인트 (Git 제외)
```

## 알려진 한계

- **처음 보는 객체는 판단하지 못합니다.** 장부에 없는 객체에 대한 R2 접근은 판정하지 않습니다.
- **방문 기록 추정의 한계:** 주인이 한 번도 조회하지 않은 객체를 공격자가 먼저 조회하면, 공격자가 주인으로 추정될 수 있습니다. 그래서 응답·목록으로 확인된 주인을 우선합니다.
- **출력 파일 정리:** 날짜별 파일은 지우지 않고 계속 쌓입니다. 오래된 파일은 직접 정리해야 합니다.
