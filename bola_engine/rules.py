"""Python BOLA 룰 (Wazuh 룰로는 못 잡는, 기억이 필요한 판정)

BOLA-R1 응답 주인 불일치: 성공 응답에 담긴 객체 주인(owner_fields)이 요청자와 다름
BOLA-R2 장부 주인 불일치: 응답에 주인 정보가 없으면 장부의 주인과 요청자를 비교
BOLA-R3 목록 밖 객체 변경: 주인을 모르는 객체를, 요청자가 다뤄 본 적도 없는데 변경함 (의심)
BOLA-R4 다수 소유자 접근: 한 사용자가 짧은 시간에 여러 피해자의 객체에 접근 (R1~R3 묶음, 사건 경보)
"""
from collections import deque
from datetime import datetime, timedelta, timezone

from .event import api_key, day_of, pick, resource_of, summary

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
    "description": "한 사용자가 짧은 시간 안에 여러 피해자의 객체에 접근함 (R1~R3 위반 묶음)",
    "severity": "critical",
  },
}

INCIDENT_RULES = {"BOLA-R4"}       # 요청 한 건이 아니라 사용자 단위로 묶은 경보


class Detector:
  def __init__(self, config, ledger):
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

  def _enabled(self, rule_id):
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

  def process(self, e):
    """이벤트 하나를 판정하고 장부를 갱신. 위반 목록을 반환 (장부 학습만 할 때는 결과를 버리면 됨)"""
    self.counts["events"] += 1
    if not self._judgeable(e):
      return []
    self.counts["judged"] += 1

    me = e["user_id"]
    api = api_key(e)
    res = resource_of(e)
    owner_field = self.owner_fields.get(api)
    resp_owners = sorted(set(pick(e, owner_field)))
    violations = []

    if resp_owners:
      others = [o for o in resp_owners if o != me]
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
    elif res:
      owner, source = self.ledger.owner(*res)
      if owner is None:
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
    return violations

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
    rule = RULES[rule_id]
    severity = (self.rule_cfg.get(rule_id) or {}).get("severity", rule["severity"])
    return {
      "detected_at": datetime.now(KST).isoformat(timespec="seconds"),
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
  return datetime.fromtimestamp(ms / 1000, KST).isoformat(timespec="seconds")


def _dur(ms):
  sec = ms // 1000
  return f"{sec // 3600}시간" if sec >= 3600 and sec % 3600 == 0 else f"{sec // 60}분"
