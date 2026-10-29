# data/ — 시험용 로그와 정답지

역할: 엔진을 Indexer 없이 `replay` 모드로 시험할 때 쓰는 가짜 로그와 정답지를 두는 곳입니다.
JSON·CSV 형식이라 파일 안에 주석을 넣을 수 없어서, 각 파일의 역할을 여기에 적습니다.
**정답지(`*_truth*.csv`)는 채점에만 쓰고, 엔진 판정에는 쓰지 않습니다.**

> 지금은 비어 있습니다. 가짜 데이터는 지웠고, 필요할 때 아래 도구로 다시 만듭니다.

| 파일 | 형식 | 만드는 도구 | 내용 |
|---|---|---|---|
| `indexer_fake.jsonl` | `bola-api-*` 문서(`_source`) 한 줄씩 | `tools/make_indexer_fake.py` | 학원 Indexer에서 가져온 것과 같은 모양의 가짜 로그 약 1000건. R1~R6 시나리오 포함 |
| `indexer_fake_truth.csv` | CSV | `tools/make_indexer_fake.py` | 위 로그의 정답지. `label`이 `BOLA`(데이터 유출)·`ATTEMPT`(403/404로 막힘), `scenario`가 시나리오 이름 |

정답지 열: `request_id, started_at, label, attacker_user_id, uri, status, scenario`

`tools/make_r2_scenarios.py`(BOLA-APP 가짜 로그 + R2 시나리오)는 BOLA-APP 원본 데이터가 레포 밖에 있어 지금은 실행할 수 없습니다.

## 사용법

```
.venv\Scripts\python tools\make_indexer_fake.py
.venv\Scripts\python main.py replay data\indexer_fake.jsonl --truth data\indexer_fake_truth.csv
```
