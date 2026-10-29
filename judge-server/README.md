# judge-server — BOLA 판단 서버

역할: bola-rule 탐지 엔진이 남긴 위반 기록을 읽어 **사용자별 점수**를 json 파일로 만듭니다.
지금은 점수 계산까지만 합니다. 차단(Redis), 기록(PostgreSQL), 학습 제외는 다음 단계입니다.

```
bola-rule (탐지 엔진) ──▶ ../bola-rule/output/violations.jsonl
                                   │ 읽기
                                   ▼
                          judge.py (판단 서버)
                                   │ 룰별 점수 합산
                                   ▼
                          output/scores.json
```

## 파일

| 파일 | 역할 |
|---|---|
| `judge.py` | 판단 서버 본체 (Python 표준 라이브러리만 사용, 설치할 것 없음) |
| `config.json` | 입력·출력 경로, 룰별 점수 |
| `tests/test_judge.py` | 점수 계산 테스트 |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | Docker 이미지·실행 설정 |
| `output/scores.json` | 결과 (Git에 올리지 않음) |

## 실행

```
cd D:\python-rule\judge-server
python judge.py                  # 한 번 계산하고 종료
python judge.py --watch 10       # 10초마다 다시 계산 (Ctrl+C로 종료)
python judge.py --input ..\bola-rule\output\indexer_replay.jsonl --output output\scores_replay.json
python -m unittest discover -s tests
```

### Docker로 실행

```
cd D:\python-rule\judge-server
docker compose up -d --build     # 1초마다 다시 계산
docker compose logs -f           # 점수 출력 보기
docker compose down              # 멈춤
```

- `../bola-rule/output`을 읽기 전용으로 붙여 위반 기록을 읽습니다. 결과는 로컬 `output/`에 그대로 쌓입니다.
- `config.json`도 붙여 두었으므로 점수를 바꾼 뒤 `docker compose restart`만 하면 됩니다.

## 점수 규칙

| 룰 | 점수 | 근거 |
|---|---|---|
| BOLA-R1 응답 주인 불일치 | 30 | 서버 응답으로 확인된 위반 |
| BOLA-R2 장부 주인 불일치 | 30 | 장부와 다름 |
| BOLA-R3 주인 모르는 객체 변경 | 10 | 의심 수준 |
| BOLA-R4 다수 소유자 접근 | 100 | 여러 피해자, 사건 단위 |
| BOLA-R5 경로 주인 불일치 | 30 | 경로의 사용자 번호와 다름 |
| BOLA-R6 순차 ID 탐색 | 20 | 막혀도 탐색 의도가 분명함 |

- 점수는 `config.json`의 `scores`에서 바꿉니다. 목록에 없는 룰은 0점이고 횟수만 셉니다.
- **합산 기간**: 입력 파일 전체.
- **중복**: 같은 `(룰, request_id)`는 1번만 셉니다. R1과 R4처럼 다른 룰이 같은 요청에서 나오면 각각 셉니다.

## 출력 모양 (`output/scores.json`, 점수 높은 순)

```json
{
  "generated_at": "2026-10-29T14:00:33+09:00",
  "source": "D:\\python-rule\\bola-rule\\output\\violations.jsonl",
  "users": [
    {
      "user_id": "7",
      "score": 540,
      "rules": {"BOLA-R1": 12, "BOLA-R4": 1, "BOLA-R5": 2, "BOLA-R6": 1},
      "first_seen": "2026-10-28T11:00:00+09:00",
      "last_seen": "2026-10-28T11:00:06+09:00"
    }
  ]
}
```

`first_seen`, `last_seen`은 원본 로그 시각(`original.time`)입니다. 파일은 임시 파일에 쓴 뒤 바꿔치기하므로, 다른 프로그램이 반쯤 쓴 파일을 읽지 않습니다.
