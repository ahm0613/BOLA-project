# BOLA Python 탐지·판단 엔진 (python-engin)

Kong API 로그를 실시간으로 받아 **BOLA(객체 수준 인가 우회)** 를 판정하고, 사용자별 점수로 공격자를 확정해 **PostgreSQL**에 쌓습니다.
pc1에서 **Docker로만** 실행하며, pc3 Streamlit 대시보드가 DB를 읽습니다.

```
pc2 (Kong·Redis)                    pc1 (WSL Docker, 이 저장소)                              pc3
┌────────────────┐                 ┌───────────────────────────────────────────────┐
│ Kong            │                 │ bola-realtime  로그 수신(5170, mTLS) + 장부 판정 │
│ Fluent Bit ─────┼── 5170 ────────▶│        │ XADD bola:events                       │
│ Redis ◀─────────┼─────────────────┼────────┘                                       │
│   └─────────────┼── XREADGROUP ──▶│ bola-judge     점수 → 공격자 확정               │
└────────────────┘                 │        │ confirmed.json (장부 학습에서 제외)      │
                                   │        ▼                                       │
                                   │ judge-postgres bola_events, user_status ───────┼── 5432 ──▶ Streamlit
                                   └───────────────────────────────────────────────┘
```

## 폴더

| 폴더 | 컨테이너 | 역할 |
|---|---|---|
| [`fluent-bit/`](fluent-bit/README.md) | `bola-realtime` | Fluent Bit이 보내는 Kong 로그를 받아 장부(`ledger.json`)로 BOLA/ATTEMPT/UNKNOWN 판정 → Redis `bola:events`. 장부 학습(`ledger_v2.py`) |
| [`judge/`](judge/README.md) | `bola-judge`, `judge-postgres` | Redis 이벤트로 사용자별 점수(조회·쓰기 구분) → 공격자 확정 → `confirmed.json` + PostgreSQL 기록. 1대1 API 자동 추론(`api_infer.py`) |
| [`attack/`](attack/README.md) | — | BOLA 공격 시뮬레이터(`simulate.py`). 탐지·차단을 검증 (burst/steady/slow/rotate, 무작위 순서) |
| `docker-compose.yml` | — | 위 두 폴더의 compose를 포함(include)해서 세 컨테이너를 한꺼번에 실행 (프로젝트 이름 `bola`) |

## 처음 준비 (pc1)

git에 없는 파일 세 가지를 먼저 준비합니다.

1. **비밀번호:** 두 폴더에서 `.env.example`을 `.env`로 복사해 채움
   - `fluent-bit/.env`: `REDIS_PASSWORD`
   - `judge/.env`: `REDIS_PASSWORD`, `PG_SUPERUSER_PASSWORD`, `PG_JUDGE_PASSWORD`, `PG_DASHBOARD_PASSWORD` 등
2. **개인키:** `fluent-bit/certs/server.key`를 따로 받아서 넣음 (mTLS 서버 키)
3. **포트 전달:** Docker가 WSL(NAT) 안에 있으므로 LAN → pc1 → WSL 포트 전달이 필요 (관리자 PowerShell)
   ```powershell
   powershell -ExecutionPolicy Bypass -File judge\scripts\wsl-portproxy.ps1 -Remote 192.168.0.26              # 5432: pc3만 허용
   powershell -ExecutionPolicy Bypass -File judge\scripts\wsl-portproxy.ps1 -Port 5170 -Name "bola realtime"  # 5170: Fluent Bit 로그 수신
   ```
   **재부팅이나 `wsl --shutdown` 뒤에는 WSL IP가 바뀌므로 다시 실행합니다.**
4. **자동 시작 (선택):** 관리자 PowerShell에서 `judge\scripts\register-startup-task.ps1`을 한 번 실행하면,
   로그온할 때마다 30초 뒤 작업 스케줄러 "BOLA 자동 시작"이 컨테이너 시작(`docker compose up -d`)과 포트 전달 두 개를 대신 해 줍니다.
   결과는 `judge/output/startup.log`. 로그인 전(부팅 직후)에는 WSL이 동작하지 않아 실행되지 않습니다.

## 실행

```bash
cd /mnt/d/python-rule            # WSL에서 (저장소 위치)
docker compose up -d --build     # bola-realtime + bola-judge + judge-postgres
docker compose ps
docker compose logs -f realtime  # 탐지: [BOLA   ] GET /members/{id} 요청자 2 -> 3 (주인 3)
docker compose logs -f judge     # 판단: [점수] … BOLA_PATH +40 = 80/100점
```

| 컨테이너 | 포트 | 데이터 |
|---|---|---|
| `bola-realtime` | 5170 | `fluent-bit/` 폴더를 읽기 전용으로 붙임 (코드·장부·인증서·`.env`) |
| `bola-judge` | — | `judge/output/`(점수 로그), `fluent-bit/confirmed.json` |
| `judge-postgres` | 5432 | Docker 볼륨 `judge_pgdata` (컨테이너를 지워도 남음, `down -v`로만 지워짐) |

## DB (pc3 Streamlit용)

| 테이블 | 한 행 |
|---|---|
| `bola_events` | Redis 이벤트 1건: Redis 값(`event_id`, `event_at`, `detected_at`, `user_id`, `action_type`, `api_path`, `detection_reasons`) + 판단(`risk_score`, `decision`, `user_status` …) + 조치(`action_id`, `enforcement_status`, `expires_at` …) |
| `user_status` | 사용자 1명의 현재 상태 |

접속: `host=<pc1 IP> port=5432 dbname=bola_judge user=dashboard` (읽기 전용, 비밀번호는 `judge/.env`의 `PG_DASHBOARD_PASSWORD`)

## 알아 둘 점

- 차단은 두 가지입니다. 탐지 엔진의 RATE 임시 차단(10초에 의심 요청 10번 초과 → 10분)과, 판단 서버의 **영구 차단**(100점 확정 → Redis `blocked:user:<id>`를 만료 없이, pc2 Kong이 403). 해제는 `judge/unblock.py` ([`judge/README.md`](judge/README.md) "영구 차단").
- 공격자로 확정되면 `fluent-bit/confirmed.json`에 올라가고, `ledger_v2.py`가 장부를 학습할 때 그 요청·사용자를 뺍니다 (장부 오염 방지).
- 자세한 내용은 [`fluent-bit/README.md`](fluent-bit/README.md), [`judge/README.md`](judge/README.md)
