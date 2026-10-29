"""로그 입력: Wazuh Indexer(bola-api-*) 조회, 파일 리플레이

역할: 엔진에 로그를 넣어 주는 입구. 판정은 하지 않고 이벤트를 시간순으로 넘겨주기만 한다.
  IndexerSource  learn·run 모드: Indexer 검색 API로 timestamp 순으로 읽음 (CA 검증, 인증서 이름 지정)
  Checkpoint     run 모드: 어디까지 읽었는지 state/checkpoint.json에 저장 (재시작해도 중복·누락 없음)
  read_files     replay 모드: Kong 로그·archives·bola-api-* 문서 파일을 읽음
"""
import json
import os
import time

import requests
import urllib3

from requests.adapters import HTTPAdapter

from .event import from_wazuh, parse_line


class _TLSHostnameAdapter(HTTPAdapter):
  """IP로 접속하되 인증서는 지정한 이름으로 검사 (인증서 SAN에 IP가 없을 때)"""

  def __init__(self, hostname, **kwargs):
    self.hostname = hostname
    super().__init__(**kwargs)

  def init_poolmanager(self, *args, **kwargs):
    kwargs["assert_hostname"] = self.hostname
    kwargs["server_hostname"] = self.hostname
    super().init_poolmanager(*args, **kwargs)


class IndexerSource:
  """Wazuh Indexer(OpenSearch) 검색 API로 API 로그를 시간순으로 가져옴"""

  def __init__(self, url, user, password, index, verify=False, batch_size=500, tls_hostname=None):
    self.url = url.rstrip("/")
    self.index = index
    self.batch_size = batch_size
    self.session = requests.Session()
    self.session.auth = (user, password)
    self.session.verify = verify
    if tls_hostname:
      self.session.mount("https://", _TLSHostnameAdapter(tls_hostname))
    if verify is False:
      urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # 자체 서명 인증서(개발용)

  def _search(self, body):
    r = self.session.post(
      f"{self.url}/{self.index}/_search",
      params={"ignore_unavailable": "true", "allow_no_indices": "true"},
      json=body, timeout=30,
    )
    r.raise_for_status()
    return r.json()["hits"]["hits"]

  def count(self):
    r = self.session.get(f"{self.url}/{self.index}/_count",
                         params={"ignore_unavailable": "true", "allow_no_indices": "true"}, timeout=10)
    r.raise_for_status()
    return r.json()["count"]

  def iter_range(self, gte_ms, lte_ms=None):
    """timestamp가 [gte_ms, lte_ms] 안인 문서를 (_id, 시각ms, 이벤트) 로 시간순 반환
    search_after로 페이지를 넘기므로 1만 건이 넘어도 끝까지 읽음"""
    rng = {"gte": gte_ms, "format": "epoch_millis"}
    if lte_ms is not None:
      rng["lte"] = lte_ms
    body = {
      "size": self.batch_size,
      "query": {"range": {"timestamp": rng}},             # bola-api-* 에는 @timestamp 없음
      "sort": [
        {"timestamp": "asc"},
        {"request_id": {"order": "asc", "unmapped_type": "keyword", "missing": "_last"}},
      ],
    }
    while True:
      hits = self._search(body)
      for h in hits:
        meta = {"index": h["_index"], "doc_id": h["_id"]}
        yield h["_id"], h["sort"][0], from_wazuh(h["_source"], meta)
      if len(hits) < self.batch_size:
        return
      body["search_after"] = hits[-1]["sort"]


class Checkpoint:
  """어디까지 읽었는지 저장 → 재시작해도 중복·누락 없음
  Filebeat가 조금 늦게 넣는 문서를 놓치지 않도록 overlap만큼 겹쳐 읽고, 이미 본 _id는 건너뜀"""

  def __init__(self, path, overlap_ms):
    self.path = path
    self.overlap_ms = overlap_ms
    self.last_ms = None
    self.seen = {}                                        # _id → 시각ms (overlap 구간만 보관)

  def load(self):
    if os.path.exists(self.path):
      with open(self.path, encoding="utf-8") as f:
        data = json.load(f)
      self.last_ms = data.get("last_ms")
      self.seen = data.get("seen", {})
    return self

  def exists(self):
    return self.last_ms is not None

  def since_ms(self):
    return self.last_ms - self.overlap_ms

  def is_new(self, doc_id):
    return doc_id not in self.seen

  def mark(self, doc_id, ts_ms):
    self.seen[doc_id] = ts_ms
    if self.last_ms is None or ts_ms > self.last_ms:
      self.last_ms = ts_ms

  def save(self):
    if self.last_ms is not None:
      cutoff = self.last_ms - self.overlap_ms
      self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
    os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
    tmp = self.path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
      json.dump({"last_ms": self.last_ms, "seen": self.seen}, f)
    os.replace(tmp, self.path)


def read_file(path):
  """Kong access.json 또는 Wazuh archives/api.json 파일을 처음부터 끝까지 읽음 (리플레이용)"""
  with open(path, encoding="utf-8", errors="replace") as f:
    for line in f:
      e = parse_line(line)
      if e is not None:
        yield e


def read_files(paths):
  """여러 파일을 합쳐 요청 시각(started_at) 순으로 반환. 같은 request_id는 한 번만"""
  events, seen = [], set()
  for path in paths:
    for e in read_file(path):
      rid = e.get("request_id")
      if rid and rid in seen:
        continue
      seen.add(rid)
      events.append(e)
  events.sort(key=lambda e: e.get("started_at") or 0)
  return events


def now_ms():
  return int(time.time() * 1000)
