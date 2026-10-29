"""Python BOLA 룰 (Wazuh 룰로는 못 잡는, 기억이 필요한 판정)

역할: 엔진의 핵심. Detector.process(이벤트)가 판정 → 장부 갱신 → 위반 목록 반환을 한 번에 한다.
learn·run·replay 모드 모두 같은 Detector를 쓰므로 판정 결과가 모드와 관계없이 같다. 동작 설명은 docs/RULE_FLOW.md.

BOLA-R1 응답 주인 불일치: 성공 응답에 담긴 객체 주인(owner_fields)이 요청자와 다름
BOLA-R2 장부 주인 불일치: 응답에 주인 정보가 없으면 장부의 주인과 요청자를 비교
BOLA-R3 목록 밖 객체 변경: 주인을 모르는 객체를, 요청자가 다뤄 본 적도 없는데 변경함 (의심)
BOLA-R4 다수 소유자 접근: 한 사용자가 짧은 시간에 여러 피해자의 객체에 접근 (R1~R3·R5 묶음, 사건 경보)
BOLA-R5 경로 주인 불일치: URL의 ID가 곧 사용자 번호인 API(path_owners)에서 그 번호가 요청자와 다름
BOLA-R6 순차 ID 탐색: 한 사용자가 짧은 시간에 남의(또는 주인 모를) 객체 ID를 연속으로 훑음 (403/404 포함, 사건 경보)
"""
from collections import deque
from datetime import datetime, timedelta, timezone

from .event import NUM, api_key, day_of, path_of, pick, resource_of, summary

KST = timezone(timedelta(hours=9))

RULES = {
  "BOLA-R1": {
    "name": "응답 주인 불일치",
    "description": "성공(2xx) 응답에 담긴 객체 주인이 요청자와 다름",
    "severity": "high",
  },
  "BOLA-R2": {
    "name": "장부 주인 불일치",
    "description": "응답에 주인 정보가 없는 요청에서, 장부에 기록된 객체 주인이 요청자와 다름",
    "severity": "high",
  },
  "BOLA-R3": {
    "name": "목록 밖 객체 변경",
    "description": "주인을 알 수 없는 객체를, 요청자가 이전에 정상적으로 다룬 적 없이 변경함",
    "severity": "medium",
  },
  "BOLA-R4": {
    "name": "다수 소유자 접근",
    "description": "한 사용자가 짧은 시간 안에 여러 피해자의 객체에 접근함 (R1~R3·R5 위반 묶음)",
    "severity": "critical",
  },
  "BOLA-R5": {
    "name": "경로 주인 불일치",
    "description": "URL의 ID가 사용자 번호인 API에서, 그 번호가 요청자와 다름 (응답·장부 없이 판정)",
    "severity": "high",
  },
  "BOLA-R6": {
    "name": "순차 ID 탐색",
    "description": "한 사용자가 짧은 시간 안에 자기 것이 아닌 객체 ID를 연속으로 요청함 (성공·403·404 포함)",
    "severity": "medium",
  },
}

INCIDENT_RULES = {"BOLA-R4", "BOLA-R6"}   # 요청 한 건이 아니라 사용자 단위로 묶은 경보


class Detector:
  """BOLA 판정기: 로그 1건씩 받아 R1~R6 룰로 판정하고, 판정하면서 장부도 채움"""
  def __init__(self, config, ledger):
    """config의 룰 설정·주인 필드·목록 API·경로 주인을 읽어 판정 준비"""
    self.cfg = config
    self.ledger = ledger
    self.owner_fields = config.get("owner_fields") or {}
    self.list_sources = config.get("list_sources") or {}
    self.exclude_roles = set(config.get("exclude_roles") or [])
    self.rule_cfg = config.get("rules") or {}
    self.counts = {"events": 0, "judged": 0, "unknown_owner": 0}
    r3 = self.rule_cfg.get("BOLA-R3") or {}
    self.write_methods = set(r3.get("methods") or ["POST", "PUT", "PATCH", "DELETE"])
    r4 = self.rule_cfg.get("BOLA-R4") or {}
    # 창(window) 여러 개: 짧은 창은 몰아치는 공격, 긴 창은 천천히 하는 공격
    self.r4_windows = [
      {"name": w.get("name", f"{w['window_sec']}s"), "ms": int(w["window_sec"]) * 1000,
       "min_victims": int(w.get("min_victims", 5))}
      for w in (r4.get("windows") or [{"name": "급속", "window_sec": 600, "min_victims": 5}])
    ]
    self.r4_keep_ms = max(w["ms"] for w in self.r4_windows)
    self.recent = {}                                      # 요청자 → deque[(시각ms, 피해대상, request_id, rule)]
    self.r4_last = {}                                     # (요청자, 창 이름) → 마지막 경보 시각ms (cooldown)
    # R5: "/members/{id}" 처럼 경로 앞부분의 마지막 {id}가 사용자 번호인 API
    self.path_owners = [[s for s in t.split("/") if s] for t in (config.get("path_owners") or [])]
    r6 = self.rule_cfg.get("BOLA-R6") or {}
    self.r6_ms = int(r6.get("window_sec", 60)) * 1000
    self.r6_min_run = int(r6.get("min_run", 5))
    self.r6_max_gap = int(r6.get("max_gap", 1))
    self.r6_statuses = set(r6.get("statuses") or [403, 404])   # 2xx 외에 R6에 넣을 상태 코드
    self.r6_recent = {}                                   # (요청자, resource, 상위 ID) → deque[(시각ms, ID, status, request_id)]
    self.r6_last = {}                                     # 같은 키 → 마지막 경보 시각ms (cooldown)

  def _enabled(self, rule_id):
    """config.yaml에서 이 룰이 켜져 있는지 (기본은 켜짐)"""
    return (self.rule_cfg.get(rule_id) or {}).get("enabled", True)

  def _judgeable(self, e):
    """판정 대상: 로그인한 일반 사용자의 성공 요청 (Kong에서 차단된 요청 제외)"""
    return (
      e.get("user_id") is not None
      and e.get("role") not in self.exclude_roles
      and not e.get("blocked")
      and e.get("status") is not None
      and 200 <= e["status"] < 300
    )

  def _path_owner(self, e):
    """path_owners에 맞는 경로면 (템플릿, 경로 속 사용자 번호), 아니면 None
    /members/2/addresses 와 "/members/{id}" → ("/members/{id}", "2")"""
    segs = [s for s in path_of(e).split("/") if s]
    for t in self.path_owners:
      if len(segs) < len(t):
        continue
      if all((NUM.match(s) if p == "{id}" else s == p) for p, s in zip(t, segs)):
        last = max(i for i, p in enumerate(t) if p == "{id}")
        return "/" + "/".join(t), segs[last]
    return None

  def process(self, e):
    """이벤트 하나를 판정하고 장부를 갱신. 위반 목록을 반환 (장부 학습만 할 때는 결과를 버리면 됨)"""
    self.counts["events"] += 1
    if not self._judgeable(e):
      return self._r6(e, own=False)                       # 403/404도 순차 탐색에는 포함
    self.counts["judged"] += 1

    me = e["user_id"]
    api = api_key(e)
    res = resource_of(e)
    owner_field = self.owner_fields.get(api)
    resp_owners = sorted(set(pick(e, owner_field)))
    path_owner = self._path_owner(e)
    violations = []
    own = False                                           # 요청자 본인 객체인지 (R6에서 제외용)

    if resp_owners:
      others = [o for o in resp_owners if o != me]
      own = not others
      if others and self._enabled("BOLA-R1"):
        violations.append(self._violation("BOLA-R1", e, (
          f"요청자 {me}이(가) 주인 {', '.join(others)}의 객체({e['method']} {e['uri']})를 "
          f"조회·변경해 {e['status']} 응답을 받음 (응답 필드 {owner_field})"
        ), {
          "api": api,
          "resource": res[0] if res else None,
          "object_id": res[1] if res else None,
          "requester": me,
          "owners": others,
          "owner_source": f"response:{owner_field}",
        }))
    elif path_owner:
      # R5: 응답에 주인이 없어도, 경로의 사용자 번호로 바로 판정 (장부 불필요, HEAD 등도 포함)
      template, owner = path_owner
      own = owner == me
      if not own and self._enabled("BOLA-R5"):
        violations.append(self._violation("BOLA-R5", e, (
          f"요청자 {me}이(가) 경로상 사용자 {owner}의 객체({e['method']} {e['uri']})에 접근해 "
          f"{e['status']} 응답을 받음 (경로 {template})"
        ), {
          "api": api,
          "resource": res[0] if res else None,
          "object_id": res[1] if res else None,
          "requester": me,
          "owners": [owner],
          "owner_source": f"path:{template}",
        }))
    elif res:
      owner, source = self.ledger.owner(*res)
      own = owner == me
      if owner is None:
        own = self.ledger.visited_by(res[0], res[1], me)
        self.counts["unknown_owner"] += 1
        # R3: 주인을 모르는 객체를, 다뤄 본 적도 없이 변경 (조회는 정상 사용에서도 흔하므로 변경만)
        if (e["method"] in self.write_methods and self._enabled("BOLA-R3")
            and not self.ledger.visited_by(res[0], res[1], me)):
          violations.append(self._violation("BOLA-R3", e, (
            f"요청자 {me}이(가) 주인을 확인할 수 없는 객체({e['method']} {e['uri']})를 "
            f"이전에 다룬 기록 없이 변경해 {e['status']} 응답을 받음"
          ), {
            "api": api,
            "resource": res[0],
            "object_id": res[1],
            "requester": me,
            "owners": [],
            "owner_source": "unknown",
          }))
      elif owner != me and self._enabled("BOLA-R2"):
        violations.append(self._violation("BOLA-R2", e, (
          f"요청자 {me}이(가) 장부상 주인 {owner}의 객체({e['method']} {e['uri']})에 접근해 "
          f"{e['status']} 응답을 받음 (장부 근거: {source})"
        ), {
          "api": api,
          "resource": res[0],
          "object_id": res[1],
          "requester": me,
          "owners": [owner],
          "owner_source": f"ledger:{source}",
        }))

    self._learn(e, api, res, resp_owners, violated=bool(violations))
    violations += self._r4(e, violations)
    violations += self._r6(e, own=own)
    return violations

  def _r6(self, e, own):
    """같은 객체 종류에서 자기 것이 아닌 ID를 창(window_sec) 안에 연속으로 min_run개 이상 요청하면 경보
    대상: 로그인한 일반 사용자의 2xx·403·404 요청 (Kong 차단 제외). 본인 객체는 세지 않음"""
    if own or not self._enabled("BOLA-R6"):
      return []
    status = e.get("status")
    if (e.get("user_id") is None or e.get("role") in self.exclude_roles or e.get("blocked")
        or status is None or not (200 <= status < 300 or status in self.r6_statuses)):
      return []
    res = resource_of(e)
    if not res:
      return []
    me = e["user_id"]
    *parent, oid = res[1].split("/")                      # /members/1/addresses/5 → 상위 "1", ID 5
    key = (me, res[0], "/".join(parent))
    now = _ts_ms(e)
    q = self.r6_recent.setdefault(key, deque())
    q.append((now, int(oid), status, e.get("request_id")))
    while q and q[0][0] < now - self.r6_ms:
      q.popleft()

    # 서로 다른 ID를 정렬해 간격이 max_gap 이하로 이어지는 가장 긴 구간을 찾음
    ids = sorted({x[1] for x in q})
    best = run = [ids[0]]
    for a, b in zip(ids, ids[1:]):
      run = run + [b] if b - a <= self.r6_max_gap else [b]
      if len(run) > len(best):
        best = run
    last = self.r6_last.get(key)
    if len(best) < self.r6_min_run or (last is not None and now - last < self.r6_ms):
      return []
    self.r6_last[key] = now
    inside = [x for x in q if best[0] <= x[1] <= best[-1]]
    statuses = {}
    for x in inside:
      statuses[str(x[2])] = statuses.get(str(x[2]), 0) + 1
    return [self._violation("BOLA-R6", e, (
      f"요청자 {me}이(가) 최근 {_dur(self.r6_ms)} 동안 {res[0]}의 ID {best[0]}~{best[-1]} "
      f"{len(best)}개를 연속으로 요청함 (기준 {self.r6_min_run}, 상태 {statuses})"
    ), {
      "api": api_key(e),
      "resource": res[0],
      "object_id": None,
      "requester": me,
      "owners": [],
      "owner_source": "sequence",
      "ids": [str(i) for i in best],
      "statuses": statuses,
      "window_sec": self.r6_ms // 1000,
      "request_ids": [x[3] for x in inside][:50],
      "first_time": _iso(min(x[0] for x in inside)),
      "last_time": _iso(now),
    })]

  def _r4(self, e, violations):
    """R1~R3 위반을 요청자별로 모아, 창(window) 안에 서로 다른 피해 대상이 기준 이상이면 사건 경보
    같은 사용자·같은 창에 대해서는 창 길이만큼 다시 경보하지 않음 (cooldown)"""
    if not violations or not self._enabled("BOLA-R4"):
      return []
    me = e["user_id"]
    now = _ts_ms(e)
    q = self.recent.setdefault(me, deque())
    for v in violations:
      ev = v["evidence"]
      # 주인을 알면 주인, 모르면(R3) 객체 자체를 피해 대상으로 셈
      targets = ev["owners"] or [f"unknown:{ev['resource']}/{ev['object_id']}"]
      for t in targets:
        q.append((now, t, e.get("request_id"), v["rule"]["id"]))
    while q and q[0][0] < now - self.r4_keep_ms:
      q.popleft()

    alerts = []
    for w in sorted(self.r4_windows, key=lambda w: w["ms"]):
      inside = [x for x in q if x[0] >= now - w["ms"]]
      victims = sorted({t for _, t, _, _ in inside})
      last = self.r4_last.get((me, w["name"]))
      if len(victims) < w["min_victims"] or (last is not None and now - last < w["ms"]):
        continue
      # 같은 사건이 긴 창에서 또 보고되지 않도록, 이 창 이상 길이의 창도 함께 대기(cooldown)
      for other in self.r4_windows:
        if other["ms"] >= w["ms"]:
          self.r4_last[(me, other["name"])] = now
      alerts.append(self._violation("BOLA-R4", e, (
        f"[{w['name']}] 요청자 {me}이(가) 최근 {_dur(w['ms'])} 동안 피해 대상 {len(victims)}명/개의 객체에 "
        f"접근해 위반 {len(inside)}건을 냄 (기준 {w['min_victims']})"
      ), {
        "api": api_key(e),
        "resource": None,
        "object_id": None,
        "requester": me,
        "owners": victims,
        "owner_source": "aggregate",
        "window": w["name"],
        "window_sec": w["ms"] // 1000,
        "violation_count": len(inside),
        "rules": sorted({r for _, _, _, r in inside}),
        "request_ids": [rid for _, _, rid, _ in inside][:50],
        "first_time": _iso(inside[0][0]),
        "last_time": _iso(now),
      }))
    return alerts

  def _learn(self, e, api, res, resp_owners, violated):
    """판정이 끝난 요청에서 장부를 채움: 응답 속 주인 확정, 목록 응답 객체 추가, 방문 기록"""
    me = e["user_id"]
    # 1) 응답에 주인이 하나로 나오면 그 객체의 주인으로 확정 (공격 요청이라도 응답 속 주인은 사실)
    if res and len(resp_owners) == 1:
      self.ledger.confirm(res[0], res[1], resp_owners[0])

    # 2) 목록 응답에 나온 객체들을 장부에 추가 (예: GET /orders → 내 주문 ID들)
    src = self.list_sources.get(api)
    if src:
      owners = sorted(set(pick(e, src.get("owner_field"))))
      if len(owners) == 1:
        owner = owners[0]
      elif not src.get("owner_field") and not violated:
        owner = me                                        # 요청자 본인 것만 돌려주는 목록 API
      else:
        owner = None
      if owner is not None:
        prefix = res[1].split("/") if res else []
        for oid in pick(e, src["id_field"]):
          self.ledger.confirm(src["resource"], "/".join(prefix + [oid]), owner)

    # 3) 위반이 아닌 성공 요청은 방문 기록으로 남김 (확인된 주인이 없는 객체의 주인 추정용)
    if res and not violated:
      self.ledger.visit(res[0], res[1], me, day_of(e))

  def _violation(self, rule_id, e, reason, evidence):
    """위반 기록 1건(json)을 만듦: 요청 시각, 탐지 시각, 룰, 이유, 근거, 원본 요약, 출처"""
    rule = RULES[rule_id]
    severity = (self.rule_cfg.get(rule_id) or {}).get("severity", rule["severity"])
    return {
      "event_time": e.get("time"),                                      # 요청이 실제로 일어난 시각 (Kong 로그)
      "detected_at": datetime.now(KST).isoformat(timespec="seconds"),   # 엔진이 위반을 찾아낸 시각
      "message": f"이 로그는 {rule_id}({rule['name']}) 룰을 위반했습니다.",
      "rule": {"id": rule_id, "name": rule["name"], "severity": severity, "description": rule["description"]},
      "reason": reason,
      "evidence": evidence,
      "original": summary(e),
      "source": e.get("_meta") or {},
    }


def _ts_ms(e):
  """이벤트 시각(ms). started_at이 없으면 time 문자열로"""
  if e.get("started_at") is not None:
    return int(e["started_at"])
  try:
    return int(datetime.fromisoformat(e["time"]).timestamp() * 1000)
  except (KeyError, TypeError, ValueError):
    return int(datetime.now(KST).timestamp() * 1000)


def _iso(ms):
  """ms 시각 → 한국 시간 ISO 문자열"""
  return datetime.fromtimestamp(ms / 1000, KST).isoformat(timespec="seconds")


def _dur(ms):
  """ms 길이 → '10분', '24시간' 같은 사람이 읽는 문자열"""
  sec = ms // 1000
  return f"{sec // 3600}시간" if sec >= 3600 and sec % 3600 == 0 else f"{sec // 60}분"
