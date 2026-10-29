"""위반 로그 출력: 콘솔 한 줄 요약 + JSONL 파일 (나중에 분석 엔진 전송은 여기에 추가)"""
import json
import os


class ViolationWriter:
  def __init__(self, path, quiet=False):
    self.path = path
    self.quiet = quiet
    self.count = 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    self.f = open(path, "a", encoding="utf-8")

  def write(self, v):
    self.count += 1
    self.f.write(json.dumps(v, ensure_ascii=False) + "\n")
    self.f.flush()
    if not self.quiet:
      o, ev = v["original"], v["evidence"]
      if ev["owner_source"] == "aggregate":                # R4: 사용자 단위 사건 경보
        print(f"[{v['rule']['id']}][{v['rule']['severity']}][{ev['window']}] 요청자 {o['user_id']} "
              f"피해 대상 {len(ev['owners'])}명/개, 위반 {ev['violation_count']}건 "
              f"({ev['first_time']} ~ {ev['last_time']})", flush=True)
        return
      owners = ",".join(ev["owners"]) or "?"
      print(f"[{v['rule']['id']}][{v['rule']['severity']}] {o['method']} {o['uri']} "
            f"요청자 {o['user_id']} → 주인 {owners} ({ev['owner_source']}) req={o['request_id']}", flush=True)

  def close(self):
    self.f.close()
