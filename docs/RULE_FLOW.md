# BOLA 룰 동작 방식

이 문서는 엔진이 로그 한 건을 받아서 위반을 내기까지의 **내부 동작**을 단계별로 설명합니다.
룰의 목적과 시험 결과는 `RULES.md`, 설정 값은 `config.yaml`, 코드는 `bola_engine/`에 있습니다.

---

## 1. 전체 흐름

```
Wazuh Indexer (bola-api-*)
   │  sources.py  IndexerSource.iter_range()   timestamp 순으로 500건씩 (search_after)
   ▼
문서 _source
   │  event.py    from_wazuh() → full_log(Kong 원문 JSON) 파싱 → from_kong()
   ▼
이벤트 e = {user_id, role, method, uri, status, resp_ids, started_at, time, _meta ...}
   │  rules.py    Detector.process(e)
   │     ① 판정 대상 거르기 (대상이 아니어도 403/404는 ⑥으로)
   │     ② API·객체 뽑기 (api_key, resource_of, _path_owner)
   │     ③ R1 → R5 → R2 → R3 중 하나로 판정
   │     ④ 장부 갱신 (_learn)
   │     ⑤ R4 집계 (_r4)
   │     ⑥ R6 순차 ID 탐색 (_r6)
   ▼
위반 목록
   │  output.py   ViolationWriter  → 콘솔 한 줄 + output/*.jsonl
   ▼
state/ledger.json (장부), state/checkpoint.json (어디까지 읽었나)
```

---

## 2. 로그 → 이벤트 변환 (`event.py`)

Indexer 문서에는 같은 내용이 여러 모양으로 들어 있습니다. 엔진은 **`full_log`(Kong이 쓴 원문 JSON)를 우선** 씁니다.
Wazuh 디코더를 거친 `raw_event.data`에서는 `resp_ids`의 `"[].id"` 같은 키가 `{"[]": {"id": [...]}}`로 바뀌어 버리기 때문입니다.

```
_source.full_log  ──json.loads──▶  from_kong()   ← 우선
_source.data      ─────────────▶  from_kong()   ← full_log가 없거나 깨졌을 때
```

`from_kong()`이 하는 일:
- `method`, `uri`가 없으면 버림 (`None`)
- `status`를 정수로, `user_id`를 문자열로 맞춤
- Kong 기본 형식(`request`/`response`가 중첩된 형식)이면 짧은 형식으로 바꿈
- `_meta`에 Indexer 문서 정보(index, doc_id, agent, location, timestamp)를 붙임

판정에 쓰는 Kong 로그 필드:

| 필드 | 예 | 용도 |
|---|---|---|
| `user_id`, `role` | `"1"`, `"user"` | 요청자, admin 제외 |
| `method`, `uri` | `GET`, `/orders/184` | API·객체 뽑기 |
| `status` | `200` | 성공 여부 |
| `resp_ids` | `{"id": ["184"], "user_id": ["70"]}` | 응답 속 ID·주인 (Kong이 응답 본문에서 추출) |
| `started_at` / `time` | `1793147171503` | R4 시간 창, 방문 날짜 |
| `blocked` | `true` | Kong에서 차단된 요청 제외 |

---

## 3. 판정 단계 (`Detector.process`)

### ① 판정 대상 거르기 (`_judgeable`)

아래를 **모두** 만족해야 R1~R5로 판정합니다. 하나라도 아니면 `events`만 세고, ⑥ R6로만 넘어갑니다.

```
user_id 있음  AND  role ∉ exclude_roles(admin)  AND  blocked 아님  AND  200 ≤ status < 300
```

403/404 같은 실패 요청은 R1~R5에서 빠집니다. 실패 횟수는 Wazuh 룰이 세고, 실패가 **연속된 ID**로 이어지는지는 R6가 봅니다.

### ② API와 객체 뽑기

| 함수 | 하는 일 | 예 |
|---|---|---|
| `api_key(e)` | 숫자 경로를 `{id}`로 바꿈 → `owner_fields`, `list_sources`를 찾는 키 | `GET /orders/7/cancel` → `GET /orders/{id}/cancel` |
| `resource_of(e)` | **마지막 숫자 ID까지**를 객체로 봄 → 장부의 키 | 아래 표 |
| `pick(e, 필드)` | `resp_ids`에서 값 목록을 꺼냄 | `pick(e, "[].user_id")` → `["7", "7"]` |
| `_path_owner(e)` | `path_owners`에 맞는 경로면 그 경로 속 **사용자 번호** | `/members/2/addresses` → `("/members/{id}", "2")` |

| URL | resource | key |
|---|---|---|
| `/orders/2` | `/orders/{id}` | `2` |
| `/orders/2/cancel` | `/orders/{id}` | `2` |
| `/members/1/addresses` | `/members/{id}` | `1` |
| `/members/1/addresses/5` | `/members/{id}/addresses/{id}` | `1/5` |
| `/orders` | (없음, 목록) | — |

`/orders/2`와 `/orders/2/cancel`이 같은 객체로 묶이기 때문에, 조회로 알게 된 주인을 변경 요청 판정에 그대로 쓸 수 있습니다.

### ③ R1 / R5 / R2 / R3 중 하나로 판정

한 요청에는 **넷 중 하나만** 적용됩니다. 위에서부터 조건이 맞는 첫 번째 룰로 갑니다.

```
resp_owners = pick(e, owner_fields[api_key])     # 응답 속 주인 목록
path_owner  = _path_owner(e)                     # 경로 속 사용자 번호

resp_owners 있음?
 ├─ 예  → [R1] resp_owners 중 요청자가 아닌 값이 있으면 위반
 │        (모두 요청자 본인이면 정상. 나머지는 보지 않음)
 │
 └─ 아니오 → path_owner 있음?
       ├─ 예 → [R5] 경로 사용자 ≠ 요청자 이면 위반 (같으면 정상. 장부는 보지 않음)
       │
       └─ 아니오 → 객체(resource)가 있나?
             ├─ 없음 (목록 API 등) → 판정 없음
             └─ 있음 → ledger.owner(resource, key)
                   ├─ 주인 있음, ≠ 요청자 → [R2] 위반
                   ├─ 주인 있음, = 요청자 → 정상
                   └─ 주인 없음 → unknown_owner +1
                         └─ 변경 메서드(POST/PUT/PATCH/DELETE) AND 요청자가 방문한 적 없음 → [R3] 위반
```

| 룰 | 주인 출처 (`evidence.owner_source`) | 심각도 |
|---|---|---|
| R1 | `response:<필드>` 예: `response:user_id` | high |
| R2 | `ledger:confirmed` 또는 `ledger:inferred` | high |
| R3 | `unknown` (주인 모름) | medium |
| R5 | `path:<경로>` 예: `path:/members/{id}` | high |

**순서가 R1 → R5 → R2인 이유:** 응답은 서버가 그 순간 알려 준 사실이고, 경로의 사용자 번호는 요청 자체에 있는 사실이며, 장부는 과거 기록이기 때문입니다.
`owner_fields`에 없는 API이거나 응답에 주인 필드가 비어 있으면(빈 목록, 64KB 초과, gzip 응답, `HEAD`) R5, 그다음 R2로 넘어갑니다.

### ④ 장부 갱신 (`_learn`)

판정이 끝난 뒤, **위반 여부와 관계없이** 아래 순서로 장부를 채웁니다.

| 순서 | 조건 | 장부에 쓰는 것 |
|---|---|---|
| 1 | 객체가 있고 응답 주인이 **딱 한 명** | `confirmed[resource][key] = 그 주인` (덮어씀) |
| 2 | `list_sources`에 있는 목록 API | 응답의 각 ID → `confirmed`. 주인은 아래 규칙 |
| 3 | 객체가 있고 **위반이 아님** | `visits[resource][key][요청자]`에 날짜 추가 |

목록 API의 주인 규칙:
- `owner_field`가 설정되어 있고 응답 주인이 한 명 → 그 주인
- `owner_field`가 없고 위반이 아님 → 요청자 본인 ("내 목록" API이므로)
- 그 밖에는 기록하지 않음

```
요청자 36  GET /orders → resp_ids {"[].id": ["91", "90"]}
  list_sources["GET /orders"] = {resource: /orders/{id}, id_field: [].id}  (owner_field 없음)
  → confirmed["/orders/{id}"]["91"] = 36,  ["90"] = 36
```

**공격 요청의 응답도 장부에 씁니다.** 응답 속 주인은 서버가 준 사실이기 때문입니다.
반면 **위반이 난 요청은 방문 기록(3번)에 넣지 않습니다.** 공격자가 방문 기록으로 주인으로 추정되는 것을 막기 위해서입니다.

### 장부에서 주인 찾기 (`ledger.owner`)

```
confirmed에 있음?  ─예─▶ (주인, "confirmed")
       │아니오
visits에 있음?     ─아니오─▶ (None, None)  → unknown_owner
       │예
사용자별 방문 '날짜 수'를 셈
  방문자가 1명 이거나, 1등 날짜 수 / 전체 날짜 수 ≥ min_share(0.7)
       ─예─▶ (1등, "inferred")
       ─아니오─▶ (None, None)  → 여러 사람이 쓰는 공유 객체로 보고 판단 보류
```

요청 횟수가 아니라 **날짜 수**로 셉니다. 하루에 많이 조회해서 주인 추정을 뒤집는 것을 막기 위해서입니다.

### ⑤ R4 집계 (`_r4`)

③에서 위반이 하나라도 났을 때만 동작합니다.

```
recent[요청자] (deque)  ← (시각, 피해대상, request_id, 룰) 추가
   피해대상 = evidence.owners  (R3처럼 주인을 모르면 "unknown:<resource>/<key>")
   24시간(가장 긴 창)보다 오래된 항목은 버림

짧은 창부터 차례로:
   창 안의 서로 다른 피해대상 수 ≥ min_victims
   AND 이 (요청자, 창)의 마지막 경보로부터 창 길이가 지났음
      → R4 경보
      → 이 창과 그보다 긴 창 모두 cooldown 시작 (같은 사건을 두 번 보고하지 않음)
```

| 창 | `window_sec` | `min_victims` |
|---|---|---|
| 급속 | 600 (10분) | 5 |
| 저속 | 86400 (24시간) | 5 |

시각은 `started_at`(ms)을 쓰고, 없으면 `time`을 씁니다. 실제 요청 시각 기준이므로 리플레이에서도 실시간과 같은 결과가 나옵니다.

### ⑥ R6 순차 ID 탐색 (`_r6`)

R1~R5 판정 여부와 관계없이, 아래 요청을 모두 봅니다.

```
대상: user_id 있음, admin 아님, blocked 아님, status ∈ 2xx ∪ statuses(403, 404), 객체(resource) 있음
제외: 본인 객체 (③에서 응답·경로·장부로 본인 것이 확인됐거나, 이전에 정상적으로 다룬 객체)

r6_recent[(요청자, resource, 상위 ID)] (deque) ← (시각, 마지막 ID, status, request_id)
   window_sec(60초)보다 오래된 항목은 버림

창 안의 서로 다른 ID를 정렬 → 간격이 max_gap(1) 이하로 이어지는 가장 긴 구간
   길이 ≥ min_run(5)  AND  이 키의 마지막 경보로부터 창 길이가 지났음
      → R6 경보 (evidence.ids = 그 구간, statuses = 상태 코드별 건수)
```

| 예 | 결과 |
|---|---|
| `/orders/180`~`184` (404, 403, 200 섞임), 10초 동안 | R6 (ID 180~184) |
| 본인 주문 `/orders/10`~`14` (목록으로 본인 것 확인됨) | 정상 (본인 객체 제외) |
| `/orders/100, 110, 120, 130, 140` | 정상 (간격 > 1) |
| `/orders/50`~`55`를 20초 간격으로 | 정상 (60초 창 안에 5개가 안 됨) |

R6는 R4와 마찬가지로 사용자 단위 경보(`INCIDENT_RULES`)라서, 요청 단위 위반 수와 R4의 피해자 수에는 들어가지 않습니다.

---

## 4. 실제 Indexer 로그로 따라가기

`bola-api-*` 로그 158건을 리플레이한 결과 중 일부입니다 (2026-10-28, 요청자 1).

```
① GET /members/2           resp_ids {user_id: [2]}
     owner_fields[GET /members/{id}] = user_id → resp_owners [2] ≠ 1     → R1
     장부: confirmed[/members/{id}][2] = 2   (응답 주인 1명)

② GET /members/4           resp_ids {user_id: [4]}                       → R1
     장부: confirmed[/members/{id}][4] = 4

③ GET /members/4/addresses resp_ids 에 [].user_id 없음 → R1 불가
     path_owners "/members/{id}" → 경로 사용자 4 ≠ 1                     → R5
     (R5가 없었다면 장부 주인 4 (confirmed)로 R2)

④ 13:36:08 ~ 13:36:17 동안 피해 대상 {2,3,4,5,6} = 5명 ≥ 5             → R4 [급속]
     이후 10분(급속)·24시간(저속) 동안 요청자 1의 R4는 다시 나지 않음

⑤ 같은 9초 동안 /members/{id} 의 ID 2,3,4,5,6 (본인 아님) 5개 연속      → R6
```

결과 요약: 이벤트 158건, 판정 대상 128건, 위반 30건 (R1 27, R5 1, R4 1, R6 1), `unknown_owner` 0건.

---

## 5. 실행 모드별 차이 (`main.py`)

| 모드 | 장부 | 읽는 범위 | 위반 출력 |
|---|---|---|---|
| `learn` | 새로 만듦 | 최근 `learning.days`(7)일 | 하지 않음 (학습만) |
| `run` | 파일이 없거나 `--relearn`이면 먼저 `learn` | 체크포인트 이후 새 로그, `poll_interval_sec`(10초)마다 | `output/violations-YYYY-MM-DD.jsonl` + 전체 API 로그 `output/api_logs/api-YYYY-MM-DD.jsonl` (요청 날짜별) |
| `replay` | 빈 장부에서 시작해 읽으면서 채움 | 지정한 파일 전체 (요청 시각순, `request_id` 중복 제거) | `output/replay_violations.jsonl` + 요약 |

`run`의 체크포인트 동작:

```
매 주기:  iter_range(last_ms - overlap_sec(30초))
            ├─ 이미 본 _id → 건너뜀
            └─ 새 _id → 판정, seen에 기록, last_ms 갱신
          checkpoint.json 저장 (overlap 구간의 _id만 보관)
```

Filebeat가 로그를 조금 늦게 넣어도 30초를 겹쳐 읽기 때문에 놓치지 않고, 이미 본 문서는 `_id`로 걸러서 두 번 판정하지 않습니다.
처음 `run`할 때는 학습에 쓴 로그까지 읽은 것으로 처리하므로, **학습 이후에 들어온 로그만** 탐지합니다.

---

## 6. 설정이 동작에 미치는 영향

| 설정 (`config.yaml`) | 바꾸면 |
|---|---|
| `rules.<룰>.enabled` | `false`면 그 룰은 위반을 내지 않음 (장부 갱신은 계속함) |
| `rules.<룰>.severity` | 위반 로그의 `severity`만 바뀜 |
| `rules.BOLA-R3.methods` | R3를 적용할 변경 메서드 |
| `rules.BOLA-R4.windows` | 창 개수·길이·피해자 기준 |
| `rules.BOLA-R6.window_sec`, `min_run`, `max_gap`, `statuses` | R6의 창 길이, 연속 ID 기준 개수, 허용 간격, 2xx 외에 셀 상태 코드 |
| `owner_fields` | R1을 적용할 API와 응답 속 주인 필드 |
| `path_owners` | R5를 적용할 API (경로 ID가 사용자 번호인 것만) |
| `list_sources` | 장부를 채울 목록 API |
| `exclude_roles` | 판정에서 뺄 역할 |
| `learning.min_share` | 방문 기록으로 주인을 추정하는 기준 비율 |
| `learning.days` | `learn`이 읽는 과거 기간 |
| `indexer.poll_interval_sec`, `overlap_sec`, `batch_size` | `run`의 조회 주기, 겹쳐 읽는 구간, 한 번에 가져올 문서 수 |
