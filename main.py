"""BOLA 탐지 엔진 실행

역할: 엔진의 시작점(명령줄). 설정을 읽고 bola_engine의 입력·판정·출력을 모드에 맞게 이어 붙인다.

  python main.py check                       Indexer 연결·문서 수 확인
  python main.py learn                       과거 N일 로그로 장부를 새로 만듦
  python main.py run [--relearn]             실시간 탐지 (장부가 없으면 먼저 학습)
  python main.py replay FILE... [--truth CSV] [--service-logs DIR] [--out NAME]
                                             로그 파일로 탐지 + 서비스별 요약 + 정답 대조
"""
import argparse
import json
import os
import sys
import time

import requests

from bola_engine.config import load_config
from bola_engine.evaluate import evaluate, evaluate_service_logs, summarize
from bola_engine.ledger import Ledger
from bola_engine.output import ViolationWriter
from bola_engine.rules import Detector
from bola_engine.sources import Checkpoint, IndexerSource, now_ms, read_files


def make_source(cfg):
  ix = cfg["indexer"]
  return IndexerSource(ix["url"], ix["user"], ix["password"], ix["index"],
                       verify=ix["verify"], batch_size=ix["batch_size"],
                       tls_hostname=ix["tls_hostname"])


def learn(cfg, source, checkpoint=None):
  """과거 N일 로그를 읽어 장부를 만듦 (위반은 출력하지 않음)"""
  ledger = Ledger(cfg["learning"]["min_share"])
  detector = Detector(cfg, ledger)
  start = now_ms() - cfg["learning"]["days"] * 86400 * 1000
  print(f"장부 학습: 최근 {cfg['learning']['days']}일 로그 읽는 중...")
  for doc_id, ts, e in source.iter_range(start):
    if checkpoint is not None:
      checkpoint.mark(doc_id, ts)
    if e is not None:
      detector.process(e)
  ledger.save(cfg["paths"]["ledger"])
  print(f"장부 저장: {cfg['paths']['ledger']} (로그 {detector.counts['events']}건, {ledger.stats()})")
  return ledger


def cmd_check(cfg, args):
  source = make_source(cfg)
  print(f"{cfg['indexer']['url']}/{cfg['indexer']['index']} 문서 수: {source.count()}")


def cmd_learn(cfg, args):
  learn(cfg, make_source(cfg))


def cmd_run(cfg, args):
  source = make_source(cfg)
  ix = cfg["indexer"]
  checkpoint = Checkpoint(cfg["paths"]["checkpoint"], ix["overlap_sec"] * 1000).load()
  fresh = not checkpoint.exists()

  if args.relearn or not os.path.exists(cfg["paths"]["ledger"]):
    # 체크포인트가 없으면 학습한 로그까지 '읽음' 처리 → 학습 직후부터 탐지
    ledger = learn(cfg, source, checkpoint if fresh else None)
  else:
    ledger = Ledger.load(cfg["paths"]["ledger"], cfg["learning"]["min_share"])
    print(f"장부 불러옴: {ledger.stats()}")
  if not checkpoint.exists():
    checkpoint.last_ms = now_ms()                         # 기록이 없으면 지금부터 탐지

  detector = Detector(cfg, ledger)
  writer = ViolationWriter(cfg["paths"]["violations"])
  print(f"실시간 탐지 시작 ({ix['poll_interval_sec']}초 간격). 위반 로그: {cfg['paths']['violations']}")
  try:
    while True:
      new = 0
      try:
        for doc_id, ts, e in source.iter_range(checkpoint.since_ms()):
          if not checkpoint.is_new(doc_id):
            continue
          checkpoint.mark(doc_id, ts)
          new += 1
          if e is not None:
            for v in detector.process(e):
              writer.write(v)
      except requests.RequestException as err:
        print(f"[경고] Indexer 조회 실패, 다음 주기에 재시도: {err}", file=sys.stderr)
      checkpoint.save()
      if new:
        ledger.save(cfg["paths"]["ledger"])
      time.sleep(ix["poll_interval_sec"])
  except KeyboardInterrupt:
    print("\n종료합니다.")
  finally:
    checkpoint.save()
    ledger.save(cfg["paths"]["ledger"])
    writer.close()
    print(f"이번 실행 위반 {writer.count}건, 처리 {detector.counts}")


def cmd_replay(cfg, args):
  """Indexer 없이 파일로 같은 판정 로직을 돌림. 장부는 빈 상태에서 시작해 읽으면서 채움"""
  out = args.out or cfg["paths"]["replay_violations"]
  if not os.path.isabs(out):
    out = os.path.join(os.path.dirname(cfg["paths"]["replay_violations"]), os.path.basename(out))
  if os.path.exists(out):
    os.remove(out)
  ledger = Ledger(cfg["learning"]["min_share"])
  detector = Detector(cfg, ledger)
  writer = ViolationWriter(out, quiet=args.quiet)
  events = read_files(args.files)
  found = []
  for e in events:
    for v in detector.process(e):
      writer.write(v)
      found.append(v)
  writer.close()
  print(f"\n처리 {detector.counts}, 위반 {len(found)}건 → {out}")
  print(f"장부: {ledger.stats()}")

  report = {"files": args.files, "violations_file": out, "counts": detector.counts,
            "ledger": ledger.stats(), "services": summarize(events, found)}
  if args.truth:
    report["eval_truth_csv"] = evaluate(found, args.truth)
  if args.service_logs:
    report["eval_service_logs"] = evaluate_service_logs(events, found, args.service_logs)

  summary_path = os.path.splitext(out)[0] + "_summary.json"
  with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)
  print(f"\n요약 저장: {summary_path}")


def main():
  p = argparse.ArgumentParser(description="Wazuh Indexer API 로그 기반 BOLA 탐지 엔진")
  p.add_argument("--config", help="설정 파일 경로 (기본: config.yaml)")
  sub = p.add_subparsers(dest="cmd", required=True)
  sub.add_parser("check", help="Indexer 연결 확인")
  sub.add_parser("learn", help="장부 새로 학습")
  r = sub.add_parser("run", help="실시간 탐지")
  r.add_argument("--relearn", action="store_true", help="저장된 장부를 버리고 다시 학습")
  rp = sub.add_parser("replay", help="로그 파일로 탐지·평가")
  rp.add_argument("files", nargs="+", help="Kong access.json 또는 Wazuh archives/api.json (여러 개면 시간순으로 합침)")
  rp.add_argument("--out", help="위반 로그 파일 이름 (기본: output/replay_violations.jsonl)")
  rp.add_argument("--truth", help="정답지 CSV (attacks_truth.csv)")
  rp.add_argument("--service-logs", help="API 서버 로그 폴더 (BOLA-APP/logs). owner_id로 채점")
  rp.add_argument("--quiet", action="store_true", help="위반을 콘솔에 한 줄씩 찍지 않음")
  args = p.parse_args()

  cfg = load_config(args.config)
  {"check": cmd_check, "learn": cmd_learn, "run": cmd_run, "replay": cmd_replay}[args.cmd](cfg, args)


if __name__ == "__main__":
  main()
