"""영구 차단 해제 (관리자용, 오탐일 때)

판단 서버가 켜져 있으면 메모리의 확정 명단으로 confirmed.json을 덮어쓰고 1분 안에 다시 차단하므로,
반드시 판단 서버를 멈춘 뒤 실행한다 (켜져 있으면 이 스크립트가 거부함).

  # WSL, /mnt/d/python-rule 에서
  docker compose stop judge
  docker compose run --rm judge python unblock.py 7 --by 관리자이름 --note "장부 오류, 본인 주문"
  docker compose start judge

  # 로컬 Python (judge 폴더에서): python unblock.py 7 --by 관리자이름 --note "..."
  python unblock.py --list          지금 영구 차단된 사용자와 사유 보기 (판단 서버가 켜져 있어도 됨)

하는 일
  1. Redis: blocked:user:<id>, block:info:<id> 삭제 → 다음 요청부터 Kong 통과
  2. confirmed.json: users에서 빼고 released에 해제 시각 기록 → 판단 서버가 해제 이전 이벤트로 다시 확정하지 않음
     (requests의 요청 ID는 그대로 → 장부 학습에서는 계속 제외)
  3. output/confirmed_log.jsonl: 누가·언제·왜 해제했는지 한 줄
  4. DB(있으면): 그 사용자의 확정 조치(AC-…-L) → enforcement_status = released, released_at = 지금
                 user_status → normal
"""
import argparse
import os
import sys
import time

import redis

import db
import judge
from blocker import INFO, KEY, Blocker
from store import ConfirmedStore

ALIVE_MS = 15000                    # 판단 서버는 5초마다 XREADGROUP으로 기다리므로, 이보다 최근이면 켜져 있는 것


def judge_running(r, rc):
    """judges 그룹의 판단 서버 소비자가 최근에 Redis를 읽었으면 True"""
    try:
        consumers = r.xinfo_consumers(rc["stream"], rc["group"])
    except redis.ResponseError:     # 그룹이 없음 = 판단 서버가 한 번도 안 떴음
        return False
    return any(c["name"] == rc["consumer"] and c["idle"] < ALIVE_MS for c in consumers)


def list_blocked(r):
    """영구 차단 키 목록과 사유 출력"""
    keys = sorted(r.scan_iter(KEY.format("*")), key=lambda k: (len(k), k))
    if not keys:
        print("영구·임시 차단 키 없음")
    for k in keys:
        uid = k.split(":")[-1]
        ttl = r.ttl(k)
        info = r.hgetall(INFO.format(uid))
        kind = "영구" if ttl == -1 else f"임시 (남은 {ttl}초)"
        print(f"사용자 {uid:>5}  {kind:<14} {info.get('by', '-'):<8} {info.get('reason', '')}")


def update_db(user_id):
    """판단 서버 DB에 해제 기록. 설정이 없거나 실패하면 이유만 출력 (Redis·파일 해제는 이미 끝난 상태)"""
    if db.psycopg is None or not os.getenv("PG_JUDGE_PASSWORD"):
        print("[DB] psycopg 또는 PG_JUDGE_PASSWORD가 없어 DB 기록은 건너뜀")
        return
    try:
        with db.psycopg.connect(host=os.getenv("PG_HOST", "127.0.0.1"), port=os.getenv("PG_PORT", "5432"),
                                dbname=os.getenv("PG_DB", "bola_judge"), user=os.getenv("PG_JUDGE_USER", "judge"),
                                password=os.getenv("PG_JUDGE_PASSWORD"), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE bola_events SET enforcement_status = 'released', released_at = now() "
                            "WHERE user_id = %s AND action_id LIKE %s AND released_at IS NULL", (user_id, "%L"))
                n = cur.rowcount
                cur.execute("UPDATE user_status SET user_status = 'normal', user_status_updated_at = now() "
                            "WHERE user_id = %s", (user_id,))
        print(f"[DB] 확정 조치 {n}건 released, user_status → normal")
    except Exception as err:        # DB 문제로 해제 자체를 실패로 보지 않음
        print(f"[DB] 기록 실패: {err}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="영구 차단 해제 (판단 서버를 멈춘 뒤 실행)")
    p.add_argument("user_id", nargs="?", help="해제할 사용자 번호")
    p.add_argument("--by", help="해제한 사람 (기록용, 필수)")
    p.add_argument("--note", help="해제 이유 (기록용, 필수)")
    p.add_argument("--list", action="store_true", help="차단된 사용자 목록만 보기")
    args = p.parse_args()

    judge.load_env()
    cfg = judge.load_config()
    rc = cfg["redis"]
    r = redis.Redis(host=rc["host"], port=rc["port"], password=rc["password"], decode_responses=True,
                    socket_timeout=10)
    if args.list:
        list_blocked(r)
        return
    if not args.user_id or not args.by or not args.note:
        p.error("사용자 번호, --by, --note가 모두 필요합니다")
    if judge_running(r, rc):
        sys.exit("판단 서버가 켜져 있습니다. 먼저 멈추세요: docker compose stop judge\n"
                 "(켜진 채로 해제하면 판단 서버가 confirmed.json을 덮어쓰고 1분 안에 다시 차단합니다)")

    uid = str(args.user_id)
    now_ms = int(time.time() * 1000)
    removed = Blocker(r).unblock(uid)
    print(f"[Redis] 차단 키 {removed}개 삭제 (blocked:user:{uid}, block:info:{uid})")

    store = ConfirmedStore(cfg["paths"]["confirmed"], cfg["paths"]["log"])
    if store.release(uid, now_ms, args.by, args.note):
        store.save()
        print(f"[파일] confirmed.json에서 사용자 {uid} 해제 (released 기록, 요청 ID는 학습 제외 유지)")
    else:
        print(f"[파일] confirmed.json 확정 명단에 사용자 {uid}가 없음 (Redis 키만 지움)")

    update_db(uid)
    print("완료. 판단 서버를 다시 켜세요: docker compose start judge")


if __name__ == "__main__":
    main()
