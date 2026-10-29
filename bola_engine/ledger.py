"""장부: '이 객체의 주인은 누구인가'를 기억하는 표

역할: 응답에 주인 정보가 없을 때 쓸 '기억'. rules.py가 로그마다 채우고(R1 응답·목록·방문),
R2(장부 주인 불일치)·R3(처음 다루는 객체)·R6(본인 객체 제외)가 꺼내 쓴다. 파일은 state/ledger.json.

- confirmed: 응답으로 확인된 주인 (응답의 user_id, 내 목록 응답에 나온 객체). 가장 믿을 만함
- visits   : 확인된 주인이 없을 때 쓰는 방문 기록. 여러 날 중 MIN_SHARE 이상 한 사용자가 조회했으면 주인으로 추정
"""
import json
import os
from collections import Counter, defaultdict


class Ledger:
  def __init__(self, min_share=0.7):
    self.min_share = min_share
    self.confirmed = defaultdict(dict)                                       # resource → key → owner
    self.visits = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))  # resource → key → user → {day}

  def confirm(self, resource, key, owner):
    """응답으로 확인된 주인 기록. 새 응답이 항상 옳다고 보고 덮어씀"""
    added = key not in self.confirmed[resource]
    self.confirmed[resource][key] = owner
    return added

  def visit(self, resource, key, user, day):
    self.visits[resource][key][user].add(day)

  def visited_by(self, resource, key, user):
    """요청자가 이 객체를 이전에 정상적으로(위반 없이) 다룬 적이 있나"""
    return bool(self.visits.get(resource, {}).get(key, {}).get(user))

  def owner(self, resource, key):
    """(주인, 근거) 반환. 모르면 (None, None)"""
    owner = self.confirmed.get(resource, {}).get(key)
    if owner is not None:
      return owner, "confirmed"
    users = self.visits.get(resource, {}).get(key)
    if not users:
      return None, None
    days = Counter({u: len(d) for u, d in users.items()})
    user, n = days.most_common(1)[0]
    if len(days) == 1 or n / sum(days.values()) >= self.min_share:
      return user, "inferred"
    return None, None                                     # 여러 사람이 비슷하게 조회 → 공유 객체로 보고 판단 보류

  def stats(self):
    return {
      "confirmed": sum(len(v) for v in self.confirmed.values()),
      "visited": sum(len(v) for v in self.visits.values()),
    }

  def save(self, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data = {
      "min_share": self.min_share,
      "confirmed": self.confirmed,
      "visits": {r: {k: {u: sorted(d) for u, d in users.items()} for k, users in keys.items()}
                 for r, keys in self.visits.items()},
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
      json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)                                 # 저장 중 종료돼도 기존 파일이 깨지지 않게

  @classmethod
  def load(cls, path, min_share=0.7):
    ledger = cls(min_share)
    with open(path, encoding="utf-8") as f:
      data = json.load(f)
    for r, keys in data.get("confirmed", {}).items():
      ledger.confirmed[r].update(keys)
    for r, keys in data.get("visits", {}).items():
      for k, users in keys.items():
        for u, days in users.items():
          ledger.visits[r][k][u].update(days)
    return ledger
