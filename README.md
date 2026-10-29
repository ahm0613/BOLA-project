# PYTHON-ENGIN — Wazuh Indexer 기반 BOLA 탐지 엔진

Wazuh 룰로는 잡을 수 없는 **"성공한 BOLA"**를 Python 룰로 판정하고, **"이 로그는 이 룰을 위반했습니다"** 형식의 위반 로그를 만듭니다.
(분석 엔진 전송은 다음 단계이며, 지금은 콘솔과 JSONL 파일로 출력합니다.)

## 전체 흐름

```
BOLA-APP          Kong access.json
   └─ wazuh-agent (kong-wazuh-agent) ──[docker 네트워크 wazuh-net]──▶ wazuh.manager
         archives.json (logall_json=yes)
           ├─ Filebeat (wazuh 모듈) ───────────────────────────▶ wazuh-archives-4.x-YYYY.MM.DD  (전체)
           └─ api-tee: Kong 로그만 api.json에 복사 ─ Filebeat ─▶ wazuh-api-YYYY.MM.DD            (API만)
                                                                     │
PC: python main.py run  ◀── 10초마다 검색 API로 새 로그 조회 ────────┘
      └─ BOLA-R1 / BOLA-R2 판정 → 콘솔 + output/violations.jsonl
```

## 역할 분담

| 구분 | 담당 | 예 |
|---|---|---|
| 한 줄·횟수로 잡히는 것 | **Wazuh 룰** (다음 단계) | 401 반복, 1분에 403/404 N번 (ID 찔러보기) |
| 기억이 필요한 것 | **Python 룰 (이 엔진)** | alice(1)가 `GET /orders/2` → **200**, 그런데 주문 2의 주인은 bob(2) |

## Python 룰

> 룰별 자세한 설명은 [RULES.md](RULES.md)를 참고하세요.

| 룰 | 이름 | 심각도 | 판정 |
|---|---|---|---|
| `BOLA-R1` | 응답 주인 불일치 | high | 2xx 응답의 주인 필드(`config.yaml`의 `owner_fields`)에 요청자가 아닌 사용자가 있음 |
| `BOLA-R2` | 장부 주인 불일치 | high | 응답에 주인 정보가 없으면(예: `POST /orders/{id}/cancel`) **장부**의 주인과 요청자를 비교 |
| `BOLA-R3` | 목록 밖 객체 변경 | medium | 장부에도 주인이 없는 객체를, 요청자가 이전에 다룬 적 없이 **변경**(POST/PUT/PATCH/DELETE)함. 확정이 아닌 의심 |
| `BOLA-R4` | 다수 소유자 접근 | critical | R1~R3 위반을 사용자별로 묶어, 창 안에서 서로 다른 피해 대상이 기준 이상이면 **사건 경보** |

R4의 창(window)은 두 개입니다(`config.yaml`의 `rules.BOLA-R4.windows`).
- **급속:** 10분 안에 5명. 몰아서 수집하는 공격
- **저속:** 24시간 안에 5명. 천천히 수집하는 공격

같은 사용자에게는 창 길이만큼 다시 경보하지 않고, 짧은 창 경보가 나면 긴 창도 함께 대기합니다.

판정 순서: **R1**(응답에 주인 있음) → 없으면 **R2**(장부에 주인 있음) → 그것도 없으면 **R3**(변경 요청일 때만) → 위반이 나면 **R4**로 집계.

**장부(ledger)** 는 "객체 → 주인" 표입니다. 아래 방법으로 채웁니다.
1. **응답으로 확인:** 응답에 주인이 하나로 나오면 그 객체의 주인으로 확정합니다. 공격 응답이라도 응답 속 주인은 사실이므로 기록합니다.
2. **목록 응답:** `GET /orders`처럼 내 목록에 나온 객체는 내 것으로 기록합니다 (`list_sources`).
3. **방문 기록:** 확인된 주인이 없는 객체만, 여러 날 중 70% 이상 한 사용자가 조회했으면 그 사람을 주인으로 추정합니다.

처음 보는 객체(장부에 없음)는 위반으로 판정하지 않고 `unknown_owner`로 개수만 셉니다.

## 위반 로그 형식 (`output/violations.jsonl`, 한 줄에 하나)

```json
{
  "detected_at": "2026-10-28T21:40:12+09:00",
  "message": "이 로그는 BOLA-R1(응답 주인 불일치) 룰을 위반했습니다.",
  "rule": {"id": "BOLA-R1", "name": "응답 주인 불일치", "severity": "high", "description": "..."},
  "reason": "요청자 1이(가) 주인 2의 객체(GET /orders/2)를 조회·변경해 200 응답을 받음 (응답 필드 user_id)",
  "evidence": {"api": "GET /orders/{id}", "resource": "/orders/{id}", "object_id": "2",
               "requester": "1", "owners": ["2"], "owner_source": "response:user_id"},
  "original": {"request_id": "...", "time": "...", "user_id": "1", "method": "GET", "uri": "/orders/2", "status": 200, "...": "..."},
  "source": {"index": "wazuh-api-2026.10.28", "doc_id": "...", "wazuh_id": "...", "agent": "kong-wazuh-agent"}
}
```

## 설치

```bash
cd PYTHON-ENGIN
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Indexer 주소·계정 수정
```

## 사용법

```bash
python main.py check                 # Indexer 연결 + wazuh-api-* 문서 수 확인
python main.py run                   # 실시간 탐지 (장부가 없으면 최근 7일 로그로 먼저 학습)
python main.py run --relearn         # 장부를 버리고 다시 학습한 뒤 탐지
python main.py learn                 # 장부만 다시 만들기

# Wazuh 없이 파일로 같은 로직 검증 (여러 파일은 시간순으로 합침) + 서비스별 요약
# 가짜 로그 → 정답지 CSV로 채점
python main.py replay BOLA-APP/engine/data/access_fake.json \
  --truth BOLA-APP/engine/data/attacks_truth.csv --out fake_violations.jsonl --quiet
# 실제 Kong 로그 → API 서버 로그의 owner_id로 채점
#   BOLA-APP/logs/는 실행 중 생기는 로그라 저장소에 없습니다. BOLA-APP을 docker로 띄워 로그를 쌓은 뒤 실행하세요.
python main.py replay BOLA-APP/engine/data/access.json BOLA-APP/logs/kong/access.json \
  --service-logs BOLA-APP/logs --out real_violations.jsonl
#   결과: output/<이름>.jsonl (위반 로그) + output/<이름>_summary.json (서비스별 요약·채점)

# R2 시나리오(주문 취소·배송 메모 변경)를 가짜 로그에 섞어 시험
python tools/make_r2_scenarios.py            # → data/access_fake_r2.json, data/attacks_truth_r2.csv
python main.py replay data/access_fake_r2.json --truth data/attacks_truth_r2.csv --out r2_violations.jsonl --quiet

python -m unittest discover tests    # 룰 단위 테스트
python smoke_attack.py               # 실환경 공격 (엔진 run 중에 실행)
```

- `state/checkpoint.json`: 어디까지 읽었는지 저장합니다. 재시작해도 중복·누락이 없습니다. 지우면 "지금부터" 다시 읽습니다.
- `state/ledger.json`: 장부입니다. 실행 중에도 계속 갱신됩니다.

## 설정 (`config.yaml`)

| 키 | 설명 |
|---|---|
| `indexer.poll_interval_sec` | 조회 주기 (기본 10초) |
| `indexer.overlap_sec` | Filebeat가 늦게 넣는 로그를 위해 겹쳐 읽는 구간 (기본 30초, 이미 본 문서는 건너뜀) |
| `learning.days` / `min_share` | 장부 학습 기간(7일) / 방문 기록으로 주인을 추정하는 기준(0.7) |
| `owner_fields` | R1: API별 응답의 주인 필드. **새 API를 추가하면 여기에 한 줄 추가** |
| `list_sources` | 목록 API → 장부에 추가할 객체 |
| `rules.*.enabled/severity` | 룰 켜기/끄기, 심각도 |

## 파일 구성

```
main.py                 CLI (check / learn / run / replay)
config.yaml             룰·동작 설정
bola_engine/
  event.py              Kong·Wazuh 문서 → 이벤트, API/객체 키 추출
  sources.py            Indexer 조회(search_after 페이지), 체크포인트, 파일 읽기
  ledger.py             장부 (확인된 주인 + 방문 기록)
  rules.py              BOLA-R1, BOLA-R2 판정 + 위반 로그 생성
  output.py             콘솔 + JSONL 출력
  evaluate.py           정답지 비교 (정밀도/재현율)
tests/test_rules.py     단위 테스트
smoke_attack.py         실환경 공격 스크립트
```

## 알려진 한계

- **처음 보는 객체는 판단하지 못합니다.** 장부에 없는 객체에 대한 R2 접근은 판정하지 않습니다.
- **방문 기록 추정의 한계:** 주인이 한 번도 조회하지 않은 객체를 공격자가 먼저 조회하면, 공격자가 주인으로 추정될 수 있습니다. 그래서 응답·목록으로 확인된 주인을 우선합니다.
- **Wazuh 쪽 개발용 설정:** `api.json`은 정리(rotate)되지 않고 계속 커집니다. 운영 환경에서는 logrotate가 필요합니다.
