"""확정 명단 가져오기 (관리자용): ledger_v3.py가 설치 전 이력에서 찾은 BOLA 사용자(confirmed1.json)를 영구 차단

판단 서버가 켜져 있으면 메모리의 명단으로 confirmed.json을 덮어쓰므로, 반드시 판단 서버를 멈춘 뒤 실행한다
(켜져 있으면 이 스크립트가 거부함). 해제는 unblock.py.

  # WSL, /mnt/d/python-rule 에서
  docker compose stop judge
  docker compose run --rm judge python import_confirmed.py /fluent-bit/confirmed1.json --dry-run      미리 보기
  docker compose run --rm judge python import_confirmed.py /fluent-bit/confirmed1.json --by 관리자이름 --note "설치 전 이력 분석"
  docker compose run --rm judge python import_confirmed.py /fluent-bit/confirmed1.json --users 43,21 --by … --note …   일부만
  docker compose start judge

  # 로컬 Python (judge 폴더에서): python import_confirmed.py ..\\fluent-bit\\confirmed1.json --by … --note …

입력 파일 형식 (confirmed.json과 같음): {"requests": [요청 ID...], "users": {"43": 처음 공격한 날(ms), ...}}

하는 일 (사용자마다)
  1. confirmed.json: users에 추가(이미 있으면 더 이른 시각으로), requests 합침
     → 영구 차단 명단 + ledger_v2.py 학습 제외 (그 날 이후 요청)
  2. Redis: blocked:user:<id> 만료 없이 + block:info:<id> 사유 → Kong이 403
  3. output/confirmed_log.jsonl: type user, 근거(가져온 파일), 승인자, 메모
  4. DB(있으면): bola_events에 조치 행(AC-IMPORT-…-L), user_status = confirmed → 대시보드에 표시
requests는 사용자별로 나뉘어 있지 않아서, --users로 일부만 가져올 때는 합치지 않는다
(학습 제외는 users의 시각 이후 요청으로 이미 처리됨).
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import redis

import db
import judge
from blocker import Blocker
from store import ConfirmedStore
from unblock import judge_running

KST = timezone(timedelta(hours=9))


def load_source(path):
    """confirmed.json 형식 파일 → (요청 ID 목록, {사용자: 시각 ms})"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        sys.exit(f"{path}: confirmed.json 형식이 아닙니다 ({{\"requests\": [...], \"users\": {{...}}}})")
    users = {str(u): int(ms) for u, ms in data["users"].items()}
    return list(data.get("requests") or []), users


def build_decisions(requests, users, source, by, note):
    """ConfirmedStore.apply에 넣을 확정 목록 (판단 서버가 확정할 때와 같은 모양 + 근거)"""
    out = [{"type": "user", "user_id": u, "since": ms, "request_ids": [],
            "reason": f"설치 전 이력 분석 ({os.path.basename(source)})", "by": by, "note": note}
           for u, ms in sorted(users.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)]
    if requests:
        out.append({"type": "request", "user_id": ",".join(users), "request_ids": requests,
                    "reason": f"설치 전 이력 분석의 공격 요청 ({os.path.basename(source)})", "by": by, "note": note})
    return out


def record_db(user_ids, blocked, source, by, note):
    """대시보드용: 사용자마다 조치 행 하나 + user_status confirmed. 실패해도 차단은 이미 끝난 상태"""
    if db.psycopg is None or not os.getenv("PG_JUDGE_PASSWORD"):
        print("[DB] psycopg 또는 PG_JUDGE_PASSWORD가 없어 DB 기록은 건너뜀")
        return
    now = datetime.now(KST)
    stamp = int(time.time() * 1000)
    try:
        with db.psycopg.connect(host=os.getenv("PG_HOST", "127.0.0.1"), port=os.getenv("PG_PORT", "5432"),
                                dbname=os.getenv("PG_DB", "bola_judge"), user=os.getenv("PG_JUDGE_USER", "judge"),
                                password=os.getenv("PG_JUDGE_PASSWORD"), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                for u in user_ids:
                    ok = blocked.get(u, False)
                    reason = f"설치 전 이력 분석으로 확정 → 영구 차단 ({'성공' if ok else '실패, 판단 서버 동기화 때 재시도'})"
                    cur.execute(
                        "INSERT INTO bola_events (stream_id, user_id, action_type, detected_at, detection_reasons, "
                        " assessed_at, decision, decision_reason, user_status, user_status_updated_at, "
                        " action_id, action_reason, decided_at, enforcement_status, enforced_at) "
                        "VALUES (%s, %s, 'IMPORT', %s, %s::jsonb, %s, 'attack', %s, 'confirmed', %s, "
                        " %s, %s, %s, %s, %s) ON CONFLICT (stream_id) DO NOTHING",
                        (f"IMPORT-{stamp}-{u}", u, now,
                         json.dumps({"source": source, "by": by, "note": note}, ensure_ascii=False),
                         now, f"관리자 {by} 승인: {note}", now,
                         f"AC-IMPORT-{stamp}-{u}-L", reason, now, "applied" if ok else "failed", now if ok else None))
                    cur.execute(
                        "INSERT INTO user_status (user_id, user_status, user_status_updated_at) "
                        "VALUES (%s, 'confirmed', %s) ON CONFLICT (user_id) DO UPDATE "
                        "SET user_status = 'confirmed', user_status_updated_at = EXCLUDED.user_status_updated_at",
                        (u, now))
        print(f"[DB] 조치 {len(user_ids)}건 기록, user_status → confirmed")
    except Exception as err:        # DB 문제로 가져오기 자체를 실패로 보지 않음
        print(f"[DB] 기록 실패: {err}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="확정 명단 가져오기: 설치 전 이력 분석 결과를 영구 차단 (판단 서버를 멈춘 뒤)")
    p.add_argument("source", help="가져올 파일 (confirmed.json 형식, 예: /fluent-bit/confirmed1.json)")
    p.add_argument("--users", help="일부만 가져오기: 쉼표로 구분한 사용자 번호 (예: 43,21)")
    p.add_argument("--by", help="승인한 사람 (기록용, 필수)")
    p.add_argument("--note", help="승인 메모 (기록용, 필수)")
    p.add_argument("--dry-run", action="store_true", help="무엇을 할지 보여 주기만 함 (판단 서버가 켜져 있어도 됨)")
    args = p.parse_args()

    requests, users = load_source(args.source)
    if args.users:
        want = {u.strip() for u in args.users.split(",") if u.strip()}
        missing = want - set(users)
        if missing:
            sys.exit(f"{args.source}에 없는 사용자: {sorted(missing)}")
        users = {u: ms for u, ms in users.items() if u in want}
        requests = []                   # 요청 ID는 사용자별로 나뉘어 있지 않아 일부만 가져올 때는 합치지 않음

    judge.load_env()
    cfg = judge.load_config()
    store = ConfirmedStore(cfg["paths"]["confirmed"], None if args.dry_run else cfg["paths"]["log"])
    already = [u for u in users if u in store.users]
    new = {u: ms for u, ms in users.items() if u not in store.users}

    print(f"[가져오기] {args.source}")
    for u, ms in sorted(users.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        when = datetime.fromtimestamp(ms / 1000, KST).strftime("%Y-%m-%d %H:%M")
        state = "이미 확정됨 (차단 키만 확인)" if u in already else "새로 확정"
        released = f", 예전에 해제된 적 있음({u} in released)" if u in store.released else ""
        print(f"  사용자 {u:>5}  처음 공격 {when}  → {state}{released}")
    print(f"  요청 ID {len(requests)}건 → confirmed.json requests에 합침" if requests else "  요청 ID: 합치지 않음")
    if args.dry_run:
        print("미리 보기만 했습니다 (--dry-run). 실제로 하려면 --dry-run을 빼고 --by, --note를 주세요")
        return
    if not args.by or not args.note:
        p.error("--by, --note가 모두 필요합니다")

    rc = cfg["redis"]
    r = redis.Redis(host=rc["host"], port=rc["port"], password=rc["password"], decode_responses=True,
                    socket_timeout=10)
    if judge_running(r, rc):
        sys.exit("판단 서버가 켜져 있습니다. 먼저 멈추세요: docker compose stop judge\n"
                 "(켜진 채로 가져오면 판단 서버가 confirmed.json을 메모리 내용으로 덮어씁니다)")

    # 1. confirmed.json (+ confirmed_log.jsonl)
    if store.apply(build_decisions(requests, new, args.source, args.by, args.note)) or requests:
        store.save()
    print(f"[파일] confirmed.json: 새로 확정 {len(new)}명 (이미 있던 {len(already)}명), 요청 {len(requests)}건 합침")

    # 2. Redis 영구 차단 (이미 확정된 사용자도 키가 빠져 있으면 다시 걺)
    blocker = Blocker(r)
    reason = f"설치 전 이력 분석 ({os.path.basename(args.source)}) 관리자 {args.by} 승인: {args.note}"
    blocked = {u: blocker.block_forever(u, reason, by=args.by) for u in users}
    print(f"[Redis] 영구 차단 {sum(blocked.values())}명 / {len(users)}명")

    # 3. DB (새로 확정한 사용자만 조치 행)
    if new:
        record_db(list(new), blocked, args.source, args.by, args.note)
    print("완료. 판단 서버를 다시 켜세요: docker compose start judge")


if __name__ == "__main__":
    main()
