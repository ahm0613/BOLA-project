"""위반 로그 출력: 콘솔 한 줄 요약 + JSONL 파일 (나중에 분석 엔진 전송은 여기에 추가)

역할: 엔진의 출구. rules.py가 만든 위반을 받아 사람이 볼 한 줄(콘솔)과 기계가 읽을 한 줄(output/*.jsonl)로 남긴다.
      run 모드에서 Indexer에서 읽은 전체 API 로그도 JsonlWriter로 날짜별 파일에 남긴다.
"""
import json
import os


def day_of(v):
  """위반이 속한 날짜 (원본 요청 시각 기준, 없으면 탐지 시각). 예: 2026-10-29"""
  t = v.get("event_time") or (v.get("original") or {}).get("time") or v.get("detected_at") or ""
  return t[:10] or "unknown"


def daily_path(path, day):
  """output/violations.jsonl → output/violations-2026-10-29.jsonl"""
  stem, ext = os.path.splitext(path)
  return f"{stem}-{day}{ext}"


class JsonlWriter:
  """JSON 한 줄씩 추가. day를 주면 날짜별 파일(<이름>-YYYY-MM-DD.jsonl)에 나눠 씀"""

  def __init__(self, path):
    """path: 기본 파일 경로. 날짜별로 쓰면 이 이름 뒤에 -YYYY-MM-DD가 붙음"""
    self.path = path
    self.count = 0
    self.files = {}                                        # 실제 파일 경로 → 열린 파일
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

  def write(self, obj, day=None):
    """obj를 JSON 한 줄로 추가. day가 있으면 그 날짜 파일에 씀"""
    path = daily_path(self.path, day) if day else self.path
    if path not in self.files:
      self.files[path] = open(path, "a", encoding="utf-8")
    f = self.files[path]
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    f.flush()
    self.count += 1

  def close(self):
    """열어 둔 파일을 모두 닫음"""
    for f in self.files.values():
      f.close()


class ViolationWriter:
  """daily=True면 원본 요청 날짜별 파일(violations-YYYY-MM-DD.jsonl)에 나눠 씀 (run 모드)"""

  def __init__(self, path, quiet=False, daily=False):
    """quiet=True면 콘솔 출력 없이 파일에만 씀"""
    self.out = JsonlWriter(path)
    self.quiet = quiet
    self.daily = daily

  @property
  def count(self):
    """지금까지 쓴 위반 건수"""
    return self.out.count

  def write(self, v):
    """위반 1건을 파일에 쓰고, 콘솔에 한 줄 요약을 출력 (R4·R6은 사건 단위 요약)"""
    self.out.write(v, day_of(v) if self.daily else None)
    if not self.quiet:
      o, ev = v["original"], v["evidence"]
      if ev["owner_source"] == "aggregate":                # R4: 사용자 단위 사건 경보
        print(f"[{v['rule']['id']}][{v['rule']['severity']}][{ev['window']}] 요청자 {o['user_id']} "
              f"피해 대상 {len(ev['owners'])}명/개, 위반 {ev['violation_count']}건 "
              f"({ev['first_time']} ~ {ev['last_time']})", flush=True)
        return
      if ev["owner_source"] == "sequence":                 # R6: 순차 ID 탐색
        print(f"[{v['rule']['id']}][{v['rule']['severity']}] 요청자 {o['user_id']} {ev['resource']} "
              f"ID {ev['ids'][0]}~{ev['ids'][-1]} {len(ev['ids'])}개 연속 {ev['statuses']} "
              f"({ev['first_time']} ~ {ev['last_time']})", flush=True)
        return
      owners = ",".join(ev["owners"]) or "?"
      print(f"[{v['rule']['id']}][{v['rule']['severity']}] {o['method']} {o['uri']} "
            f"요청자 {o['user_id']} → 주인 {owners} ({ev['owner_source']}) req={o['request_id']}", flush=True)

  def close(self):
    """열어 둔 파일을 모두 닫음"""
    self.out.close()
