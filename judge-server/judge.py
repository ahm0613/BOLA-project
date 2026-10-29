"""판단 서버: 탐지 엔진의 위반 기록을 읽어 사용자별 점수를 json 파일로 만든다

역할: bola-rule 탐지 엔진이 날짜별로 쓴 violations-YYYY-MM-DD.jsonl을 모두 읽고, 룰별 점수(config.json)를
      사용자마다 더해 output/scores.json(전체)과 output/daily/scores-YYYY-MM-DD.json(날짜별)으로 남긴다.
      차단(Redis·PostgreSQL)은 아직 하지 않는다.

규칙
  - 점수: 위반 1건마다 config.json의 scores[룰 ID]를 더함 (없는 룰은 0점, 횟수만 셈)
  - 합산 기간: scores.json은 입력 파일 전체, 날짜별 파일은 원본 요청 날짜(original.time) 하루
  - 중복: 같은 (룰, request_id)는 1번만 셈 (replay 재실행·run 모드 겹쳐 읽기 대비)

사용법 (judge-server 폴더에서):
  python judge.py                       한 번 계산하고 종료
  python judge.py --watch 10            10초마다 다시 계산
  python judge.py --input ../bola-rule/output/indexer_replay.jsonl   다른 위반 파일로 계산
"""
import argparse
import glob
import json
import os
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve(path):
  """상대 경로는 judge-server 폴더 기준"""
  return path if os.path.isabs(path) else os.path.normpath(os.path.join(BASE_DIR, path))


def load_config(path):
  """config.json(입력·출력 경로, 룰별 점수)을 읽음"""
  with open(path, encoding="utf-8") as f:
    return json.load(f)


def read_violations(pattern):
  """위반 기록 파일(와일드카드 가능, 예: violations-*.jsonl) → 위반 목록. 파일이 없으면 빈 목록, 깨진 줄은 건너뜀"""
  out = []
  for path in sorted(glob.glob(pattern)):
    with open(path, encoding="utf-8", errors="replace") as f:
      for line in f:
        line = line.strip()
        if not line:
          continue
        try:
          out.append(json.loads(line))
        except json.JSONDecodeError:
          continue
  return out


def day_of(v):
  """위반이 속한 날짜 (원본 요청 시각 기준, 없으면 탐지 시각). 엔진의 파일 나누기 기준과 같음"""
  t = (v.get("original") or {}).get("time") or v.get("detected_at") or ""
  return t[:10] or "unknown"


def _when(v):
  """위반이 일어난 시각 (원본 로그 시각, 없으면 탐지 시각)"""
  t = (v.get("original") or {}).get("time") or v.get("detected_at")
  try:
    return datetime.fromisoformat(t) if t else None
  except ValueError:
    return None


def score_users(violations, scores):
  """위반 목록 → 사용자별 점수 목록 (점수 높은 순)"""
  seen = set()
  users = {}
  for v in violations:
    rule = (v.get("rule") or {}).get("id")
    o = v.get("original") or {}
    user, req = o.get("user_id"), o.get("request_id")
    if not rule or user is None:
      continue
    key = (rule, req)
    if req is not None and key in seen:                    # 같은 (룰, 요청)은 1번만
      continue
    seen.add(key)

    u = users.setdefault(str(user), {"user_id": str(user), "score": 0, "rules": {},
                                     "first_seen": None, "last_seen": None})
    u["score"] += scores.get(rule, 0)
    u["rules"][rule] = u["rules"].get(rule, 0) + 1
    t = _when(v)
    if t is not None:
      if u["first_seen"] is None or t < u["first_seen"]:
        u["first_seen"] = t
      if u["last_seen"] is None or t > u["last_seen"]:
        u["last_seen"] = t

  result = sorted(users.values(), key=lambda u: (-u["score"], u["user_id"]))
  for u in result:
    u["rules"] = dict(sorted(u["rules"].items()))
    for k in ("first_seen", "last_seen"):
      u[k] = u[k].isoformat() if u[k] else None
  return result


def write_scores(path, source, users):
  """읽는 쪽이 반쯤 쓴 파일을 보지 않도록 임시 파일에 쓴 뒤 바꿔치기"""
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  doc = {
    "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    "source": source,
    "users": users,
  }
  tmp = path + ".tmp"
  with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
  os.replace(tmp, path)


def run_once(cfg, input_path, output_path, daily_dir):
  """위반 기록을 한 번 읽어 전체 점수(scores.json)와 날짜별 점수(daily/)를 쓰고 상위 10명을 출력"""
  violations = read_violations(input_path)
  scores = cfg.get("scores", {})
  users = score_users(violations, scores)
  write_scores(output_path, input_path, users)

  by_day = {}
  for v in violations:
    by_day.setdefault(day_of(v), []).append(v)
  for day, vs in sorted(by_day.items()):
    write_scores(os.path.join(daily_dir, f"scores-{day}.json"), input_path, score_users(vs, scores))

  print(f"위반 {len(violations)}건 → 사용자 {len(users)}명 → {output_path} "
        f"(날짜별 {len(by_day)}개 → {daily_dir})", flush=True)
  for u in users[:10]:
    rules = ", ".join(f"{r} {n}" for r, n in u["rules"].items())
    print(f"  {u['user_id']:>6}  {u['score']:>5}점  ({rules})", flush=True)
  if len(users) > 10:
    print(f"  ... 외 {len(users) - 10}명", flush=True)


def main():
  """명령줄 인자를 읽어 한 번 계산하거나, --watch면 N초마다 반복"""
  p = argparse.ArgumentParser(description="BOLA 판단 서버: 위반 기록 → 사용자별 점수 json")
  p.add_argument("--config", default=os.path.join(BASE_DIR, "config.json"))
  p.add_argument("--input", help="위반 기록 파일 (기본: config.json의 input)")
  p.add_argument("--output", help="점수 파일 (기본: config.json의 output)")
  p.add_argument("--watch", type=int, metavar="초", help="N초마다 다시 계산 (없으면 한 번만)")
  args = p.parse_args()

  cfg = load_config(args.config)
  input_path = os.path.abspath(args.input) if args.input else resolve(cfg["input"])
  output_path = os.path.abspath(args.output) if args.output else resolve(cfg["output"])
  daily_dir = resolve(cfg.get("daily_dir", "output/daily"))

  if not glob.glob(input_path):
    print(f"위반 기록 파일이 아직 없음: {input_path} (빈 결과로 저장)", flush=True)
  if not args.watch:
    run_once(cfg, input_path, output_path, daily_dir)
    return
  try:
    while True:
      run_once(cfg, input_path, output_path, daily_dir)
      time.sleep(args.watch)
  except KeyboardInterrupt:
    print("종료", flush=True)


if __name__ == "__main__":
  main()
