"""Kong 로그 한 건(이벤트)을 엔진이 쓰는 모양으로 정리하고, URL에서 API·객체 정보를 뽑는 함수 모음

역할: 로그 형식 차이를 여기서 흡수한다. 다른 파일은 형식을 몰라도 같은 이벤트 dict만 다루면 된다.
  from_wazuh / from_kong / parse_line  Indexer 문서·archives·Kong 원본 → 이벤트 (full_log 우선)
  api_key / resource_of / pick         룰이 쓰는 도구: "GET /orders/{id}", 객체(resource, key), resp_ids 값
  summary                              위반 로그에 넣을 원본 요약
"""
import json
import re
from datetime import datetime, timedelta, timezone

NUM = re.compile(r"^\d+$")
KST = timezone(timedelta(hours=9))


def _from_default_format(obj):
  """Kong 기본 file-log 형식(request/response 중첩) → 짧은 형식으로 변환
  kong.yml의 custom_fields_by_lua 적용 전 로그도 읽기 위함"""
  req = obj.get("request") or {}
  resp = obj.get("response") or {}
  started = obj.get("started_at")
  e = dict(obj)
  e["method"] = req.get("method")
  e["uri"] = req.get("uri")
  e["status"] = resp.get("status")
  e["request_id"] = (req.get("headers") or {}).get("x-request-id") or obj.get("correlation_id")
  e["api"] = (obj.get("service") or {}).get("name")
  if started and not e.get("time"):
    e["time"] = datetime.fromtimestamp(started / 1000, KST).isoformat(timespec="seconds")
  for k in ("request", "response", "service", "route", "consumer", "authenticated_entity"):
    e.pop(k, None)                                      # 헤더·토큰 등 큰 값은 버림
  return e


def from_kong(obj, meta=None):
  """Kong file-log 한 줄(dict) → 이벤트. 판정에 꼭 필요한 값이 없으면 None"""
  if not isinstance(obj, dict):
    return None
  if "method" not in obj and isinstance(obj.get("request"), dict):
    obj = _from_default_format(obj)
  if not obj.get("method") or not obj.get("uri"):
    return None
  e = dict(obj)
  try:
    e["status"] = int(e.get("status"))
  except (TypeError, ValueError):
    e["status"] = None
  if e.get("user_id") is not None:
    e["user_id"] = str(e["user_id"])
  e["_meta"] = meta or {}
  return e


def from_wazuh(doc, meta=None):
  """Wazuh archives 문서(_source 또는 archives.json 한 줄) → 이벤트
  full_log(Kong 원문 JSON)를 우선 사용. resp_ids의 "[].id" 같은 키가 디코더·인덱서를 거치며
  모양이 바뀔 수 있기 때문. full_log가 없거나 깨졌으면 디코딩된 data를 대신 사용"""
  meta = dict(meta or {})
  src = doc.get("source") or {}                         # bola-api-* 문서는 agent·location이 source 아래에 있음
  meta.update({
    "wazuh_id": doc.get("id") or (doc.get("raw_event") or {}).get("id"),
    "timestamp": doc.get("timestamp"),
    "agent": (doc.get("agent") or src.get("agent") or {}).get("name"),
    "location": doc.get("location") or src.get("location"),
  })
  raw = doc.get("full_log")
  if raw:
    try:
      return from_kong(json.loads(raw), meta)
    except json.JSONDecodeError:
      pass
  return from_kong(doc.get("data"), meta)


def parse_line(line):
  """파일의 한 줄 → 이벤트. Kong 원본 형식과 Wazuh archives 형식을 모두 받음"""
  line = line.strip().strip("\x00")
  if not line:
    return None
  try:
    obj = json.loads(line)
  except json.JSONDecodeError:
    return None
  if "full_log" in obj and ("location" in obj or "source" in obj):   # archives 또는 bola-api-* 문서
    return from_wazuh(obj)
  return from_kong(obj)


def path_of(e):
  """URI에서 쿼리 문자열(?...)을 뗀 경로"""
  return e["uri"].split("?")[0]


def api_key(e):
  """GET /orders/7/cancel → GET /orders/{id}/cancel"""
  path = re.sub(r"/\d+(?=/|$)", "/{id}", path_of(e))
  return f'{e["method"]} {path}'


def resource_of(e):
  """URL에서 '어떤 객체를 건드렸나'를 뽑음. 마지막 숫자 ID까지를 객체로 봄
  /orders/2/cancel         → ("/orders/{id}", "2")
  /members/1/addresses     → ("/members/{id}", "1")
  /members/1/addresses/5   → ("/members/{id}/addresses/{id}", "1/5")
  숫자 ID가 없으면(/orders 같은 목록) None"""
  segs = [s for s in path_of(e).split("/") if s]
  idx = [i for i, s in enumerate(segs) if NUM.match(s)]
  if not idx:
    return None
  segs = segs[: idx[-1] + 1]
  resource = "/" + "/".join("{id}" if NUM.match(s) else s for s in segs)
  key = "/".join(s for s in segs if NUM.match(s))
  return resource, key


def pick(e, field):
  """resp_ids에서 필드 값 목록(문자열)을 꺼냄. 예: pick(e, "[].user_id") → ["7", "7"]"""
  if not field:
    return []
  values = (e.get("resp_ids") or {}).get(field) or []
  if not isinstance(values, list):
    values = [values]
  return [str(v) for v in values]


def day_of(e):
  """이벤트가 일어난 날짜 (YYYY-MM-DD). 장부의 방문 날짜로 씀"""
  return str(e.get("time") or (e["_meta"].get("timestamp") or ""))[:10]


def summary(e):
  """위반 로그에 넣을 원본 로그 요약"""
  return {
    "request_id": e.get("request_id"),
    "time": e.get("time"),
    "user_id": e.get("user_id"),
    "role": e.get("role"),
    "method": e.get("method"),
    "uri": e.get("uri"),
    "status": e.get("status"),
    "api": e.get("api"),
    "client_ip": e.get("client_ip"),
    "resp_ids": e.get("resp_ids"),
  }
