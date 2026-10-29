# BOLA Python 탐지 엔진 (python-engin)

| 폴더 | 역할 |
|---|---|
| [`bola-rule/`](bola-rule/README.md) | Wazuh Indexer(`bola-api-*`)의 Kong 로그를 읽어 BOLA 룰(R1~R6)을 판정하고 위반 로그를 날짜별로 남김 |
| [`judge-server/`](judge-server/README.md) | `bola-rule/output`의 위반 로그를 읽어 사용자별 룰 점수 JSON(`scores.json`)을 만듦 |

```
Wazuh Indexer ─▶ bola-rule (main.py run) ─▶ bola-rule/output/violations-YYYY-MM-DD.jsonl
                                                        │
                              judge-server (judge.py) ◀─┘ ─▶ judge-server/output/scores.json
```

두 폴더는 나란히 있어야 합니다. 판단 서버가 `../bola-rule/output`을 읽습니다.

```
cd bola-rule;    docker compose up -d --build
cd judge-server; docker compose up -d --build
```
