# BOLA 공격 시뮬레이터 (`simulate.py`)

본인 BOLA-APP에 공격 요청을 보내 **내가 만든 탐지·판단·차단 시스템이 동작하는지 검증**하는 도구입니다.
공격자 계정으로 로그인한 뒤 남의 객체를 조회해서, 어디까지 성공(200)하고 어디서 막혔는지(403)를 CSV로 남기고 끝에 요약합니다. 읽기 조회(GET)만 보냅니다.

## 준비

```powershell
pip install httpx
```

전제: BOLA-APP(Kong 8000), 탐지 엔진(`engine`), 판단 서버(`judge`)가 켜져 있어야 공격→탐지→차단 흐름이 보입니다.

## 실행

```powershell
cd D:\python-rule\attack
python simulate.py --pattern burst                                   # 1초 1000번
python simulate.py --pattern steady --target members,orders          # 10초 30번
python simulate.py --pattern slow --victims 1-20 --stop-on-block     # 5분 3번
python simulate.py --pattern rotate --target members --victims 7     # 계정 교대 (차단되면 다음 계정)
```

## 네 패턴

| `--pattern` | 전송 | 확인하는 것 |
|---|---|---|
| `burst` | 1초에 1000번 (httpx 비동기) | 10초 10회 초과 → rate 임시 차단(403)이 몇 번째에 걸리나 |
| `steady` | 10초에 30번 | 임시 차단 경계(10초 10회) |
| `slow` | 5분에 3번 | rate엔 안 걸리지만 점수가 쌓여 100점 확정·영구 차단되나 |
| `rotate` | 피해자마다 담당 계정이 돌아감(alice→bob→carol→…), 차단되면 다음 계정이 이어받음 | 계정 단위 차단이 분산 공격을 막는지 (한 계정 막혀도 다른 계정은 뚫리나) |

### rotate (계정 교대)

피해자마다 담당 계정이 `--attacker` 순서대로 돌아갑니다. 담당 계정이 Kong 차단(`403-blocked`)되면 **그 피해자를 다음 계정**이 이어받고,
한번 막힌 계정은 이후 피해자에서 건너뜁니다.

```
피해자 1 → alice
피해자 2 → bob
피해자 3 → carol
피해자 4 → alice … 가다가 4에서 alice가 막히면 → bob이 4를 이어받음
```

- 확인 포인트: 차단은 **계정(사용자) 단위**이므로, alice가 막혀도 아직 확정 안 된 bob·carol은 같은 피해자를 뚫습니다.
  이 결과로 "계정별 차단만으로는 여러 계정을 쓰는 분산 공격을 못 막는다"는 한계를 눈으로 확인할 수 있습니다.
- 끝에 **계정별 성공/차단 건수**와 **여러 계정이 노린 피해자의 교대 사슬**(alice(막힘) → bob(막힘) → carol(성공))을 요약합니다.
- `--gap` 으로 요청 간격(기본 0.5초)을 조절합니다. 간격이 너무 짧으면 rate 임시 차단이 먼저 걸릴 수 있습니다.

## 인자

| 인자 | 뜻 | 기본 |
|---|---|---|
| `--pattern` | `burst` / `steady` / `slow` / `rotate` | 필수 |
| `--url` | Kong 주소 | `https://192.168.0.39/api` |
| `--attacker user:pass` | 공격자 계정, 여러 번 가능 | alice/bob/carol |
| `--target` | `members,orders,profiles,payments` 중 쉼표로 | 네 개 모두 |
| `--victims` | 피해자 범위 `1-104` 또는 `3,4,5` (자기 번호 자동 제외) | `1-104` |
| `--count` | 요청 수 | burst 1000, steady 30, slow 3 |
| `--stop-on-block` | 첫 Kong 차단에서 멈춤 | 끔 |
| `--concurrency` | burst 동시 연결 수 | 200 |
| `--gap` | rotate 요청 사이 간격 (초) | 0.5 |
| `--random` | 피해자 번호를 무작위 순서로 (순차 열거 대신) | 끔 |
| `--seed` | `--random` 순서를 재현 (같은 seed = 같은 순서) | 매번 다름 |

로그인 가능한 계정은 `alice/bob/carol` 셋뿐입니다(시드 계정). 대량 계정(5~104)은 비밀번호 파일이 없습니다.

## 대상 API

| 대상 | 경로 | 남의 것 조회 시 |
|---|---|---|
| `members` | `GET /members/{id}` | 200 (취약, BOLA 성공) |
| `orders` | `GET /orders/{id}` | 200 (취약, BOLA 성공) |
| `profiles` | `GET /profiles/{id}` | 403 (안전, ATTEMPT) |
| `payments` | `GET /payments/{id}` | 403 (안전, ATTEMPT) |

## 결과

**CSV** (`results/<패턴>_<시각>.csv`): 요청마다 한 줄
`ts_ms, pattern, attacker, uri, target_id, status, got_data, elapsed_ms, request_id, label`

`request_id`는 Kong의 `X-Request-ID`입니다. 판단 서버 DB `bola_events.event_id`와 같은 값이라, 공격 CSV와 DB를 같은 요청으로 맞춰 볼 수 있습니다.

**`label`** (차단 종류)

| label | 뜻 |
|---|---|
| `200-bola` | 취약 API에서 남의 데이터를 받음 (공격 성공) |
| `200-own` | 안전 API의 200 (본인 것) |
| `403-blocked` | Kong이 차단 정책으로 막음 (`blocked by security policy`) ← rate 임시 또는 영구 차단 |
| `403-attempt` | 앱이 소유권으로 거부 (profiles/payments) |
| `error:<종류>` | 네트워크 오류 |

**터미널 요약**: 상태코드별 건수, 첫 차단이 몇 번째·몇 초에 나왔는지, 이후 차단이 유지되는지.

> 이 시스템에는 **429가 없습니다.** 속도 초과도 403으로 막습니다. "어디서 막혔나"는 `403-blocked`로 구분합니다.

## 주의

- 공격자가 확정(100점)되면 영구 차단되어 `confirmed.json`에 들어갑니다. 테스트 뒤 풀려면
  판단 서버를 멈추고 `judge/unblock.py`로 해제하세요.
- 임시 차단(rate)은 10분 뒤 자동으로 풀립니다.
