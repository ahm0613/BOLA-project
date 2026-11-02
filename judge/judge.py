"""판단 서버: Redis bola:events(realtime.py가 보낸 의심 이벤트)를 읽어 점수를 매기고 공격자를 확정해 confirmed.json을 만듦

  python judge.py                 계속 실행: judges 그룹으로 새 이벤트를 받아 처리 (Ctrl+C로 종료)
  python judge.py --once          한 번 계산: 최근 window_sec(24시간) 이벤트로 계산 후 종료 (그룹은 건드리지 않음)
  python judge.py --once --all    스트림 전체로 한 번 계산
  python judge.py --once --dry-run  계산 결과만 보여 주고 confirmed.json은 쓰지 않음
  python judge.py --once --all --dry-run --trace   과거 이벤트가 어떻게 채점됐는지 한 줄씩 보기
  python judge.py --quiet         실시간 모드에서 이벤트마다 나오는 점수 줄을 끔

실시간 모드에서는 이벤트마다 점수 줄을 화면에 찍고 output/score_log.jsonl에도 남긴다.
DB 기록 (pc3 Streamlit용, db.py): Redis 이벤트 한 건마다 bola_events 한 행(Redis 값 + 판단 + 조치), 사용자 상태는 user_status.
  접속 정보는 .env의 PG_*. DB가 없거나 꺼져 있어도 판단은 계속하고, --dry-run이면 DB에도 쓰지 않음.

영구 차단 (blocker.py, config.json의 block): 공격 확정 순간 Redis blocked:user:<id>를 만료 없이 걸어 pc2 Kong이 막게 함.
  실시간 모드에서는 시작할 때와 block.sync_sec마다 confirmed.json 명단과 Redis 차단 키를 맞춤 (빠진 키를 다시 걺).
  --dry-run이면 차단하지 않음. 해제는 unblock.py.

시작할 때 최근 window_sec 이벤트를 다시 읽어 점수를 복원한 뒤, 그 다음 이벤트부터 그룹으로 받는다.
(복원에서 이미 본 이벤트가 그룹으로 다시 오면 점수에 두 번 넣지 않고 ACK만 한다)
접속 정보: config.json의 redis.*, 비밀번호는 .env의 REDIS_PASSWORD (없으면 비밀번호 없이 접속)
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import redis

import db
from blocker import Blocker
from scoring import Judge, parse_event
from store import ConfirmedStore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATUS_SEC = 60                                         # 몇 초마다 상태를 출력할지
KST = timezone(timedelta(hours=9))


def load_env():
    """같은 폴더의 .env(KEY=VALUE)를 환경변수로 읽음. 이미 있는 환경변수는 덮어쓰지 않음"""
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def load_config():
    """config.json을 읽고, 상대 경로는 이 폴더 기준으로, Redis 주소·비밀번호는 환경변수가 있으면 그것으로"""
    with open(os.path.join(BASE_DIR, "config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in cfg["paths"].items():
        if not os.path.isabs(v):
            cfg["paths"][k] = os.path.normpath(os.path.join(BASE_DIR, v))
    rc = cfg["redis"]
    rc["host"] = os.getenv("REDIS_HOST", rc["host"])
    rc["port"] = int(os.getenv("REDIS_PORT", rc["port"]))
    rc["password"] = os.getenv("REDIS_PASSWORD") or None
    return cfg


USER_STATUS = {"normal": "normal", "watch": "watch", "warning": "warning", "attack": "confirmed"}


def make_db(cfg, dry_run):
    """config.json의 db와 .env의 PG_*로 DbWriter를 만듦. 쓸 수 없으면 이유를 출력하고 None"""
    dc = cfg.get("db") or {}
    if dry_run or not dc.get("enabled", True):
        return None
    if db.psycopg is None:
        print("[DB] psycopg가 없어 DB 기록 안 함 (pip install -r requirements.txt)", flush=True)
        return None
    if not os.getenv("PG_JUDGE_PASSWORD"):
        print("[DB] .env에 PG_JUDGE_PASSWORD가 없어 DB 기록 안 함", flush=True)
        return None
    dsn = db.psycopg.conninfo.make_conninfo(
        host=os.getenv("PG_HOST", "127.0.0.1"), port=os.getenv("PG_PORT", "5432"),
        dbname=os.getenv("PG_DB", "bola_judge"), user=os.getenv("PG_JUDGE_USER", "judge"),
        password=os.getenv("PG_JUDGE_PASSWORD"))
    writer = db.DbWriter(dsn, flush_sec=dc.get("flush_sec", 1), sweep_sec=dc.get("sweep_sec", 10))
    err = writer.check()
    where = f"{os.getenv('PG_HOST', '127.0.0.1')}:{os.getenv('PG_PORT', '5432')}/{os.getenv('PG_DB', 'bola_judge')}"
    print(f"[DB] {where} " + (f"접속 안 됨 ({err.strip()}) → 판단은 계속하고 연결되면 씀" if err else "접속됨"),
          flush=True)
    writer.start()
    return writer


def to_dt(ms):
    """ms → 한국 시간 datetime (DB TIMESTAMPTZ용)"""
    return datetime.fromtimestamp(ms / 1000, KST)


def fmt_ids(ids):
    """["3", "4"] → "{3,4}" (화면 표시용)"""
    return "{" + ",".join(ids) + "}"


def id_key(stream_id):
    """스트림 ID "1793331593445-0" → 비교용 (1793331593445, 0)"""
    ms, seq = stream_id.split("-")
    return int(ms), int(seq)


class Server:
    """Redis에서 이벤트를 읽어 Judge로 채점하고, 확정이 생기면 confirmed.json을 갱신"""
    def __init__(self, cfg, dry_run=False):
        """cfg: 설정. dry_run=True면 파일을 쓰지 않음"""
        self.cfg = cfg
        rc = cfg["redis"]
        self.r = redis.Redis(host=rc["host"], port=rc["port"], password=rc["password"], decode_responses=True,
                             socket_timeout=10, socket_keepalive=True)    # block(5초)보다 길게
        self.stream, self.group, self.me = rc["stream"], rc["group"], rc["consumer"]
        self.store = ConfirmedStore(cfg["paths"]["confirmed"], None if dry_run else cfg["paths"]["log"])
        self.judge = Judge(cfg, confirmed_users=self.store.users.keys(), released=self.store.released)
        self.dry_run = dry_run
        self.last_id = (0, 0)                           # 지금까지 채점한 마지막 스트림 ID
        self.last_status = time.time()
        self.trace = False                              # True면 이벤트마다 점수 한 줄 출력 (실시간 모드에서 켬)
        self.score_log = None if dry_run else cfg["paths"].get("score_log")
        if self.score_log:
            os.makedirs(os.path.dirname(self.score_log), exist_ok=True)
        self.breached_path = None if dry_run else cfg["paths"].get("breached")
        self.saved_hits = 0                             # breached_apis.json을 마지막으로 저장할 때의 hits 수
        self.db = make_db(cfg, dry_run)
        self.rate_sec = (cfg.get("db") or {}).get("rate_block_sec", 600)   # realtime.py의 RATE 임시 차단 길이
        self.user_state = {}                              # user_id → (사용자 상태, 그 상태로 바뀐 시각)
        bc = cfg.get("block") or {}
        self.blocker = Blocker(self.r) if bc.get("enabled") and not dry_run else None
        self.sync_sec = bc.get("sync_sec", 60)
        self.last_sync = 0.0

    def sync_blocks(self, force=False):
        """sync_sec마다 confirmed.json 명단 ↔ Redis 영구 차단 키 맞춤 (Redis 초기화, RATE 10분 키 덮어쓰기 대비)"""
        if not self.blocker or (not force and time.time() - self.last_sync < self.sync_sec):
            return
        self.last_sync = time.time()
        n = self.blocker.sync(self.store.users)
        if n or force:
            print(f"[차단] 명단 동기화: 확정 사용자 {len(self.store.users)}명 중 {n}명 새로 영구 차단", flush=True)

    def handle(self, stream_id, fields):
        """이벤트 하나 처리. 이미 채점한 ID면 건너뜀 (True: 새로 채점함)"""
        if id_key(stream_id) <= self.last_id:
            return False
        self.last_id = id_key(stream_id)
        try:
            decisions = self.judge.process(parse_event(fields, stream_id))
        except Exception as err:                        # 이상한 이벤트 하나 때문에 서버가 멈추지 않게
            print(f"[오류] {stream_id} 처리 실패: {err} {fields}", flush=True)
            return True
        if self.trace:
            self.write_trace(stream_id)
        if self.judge.counts["hits"] != self.saved_hits:    # 새로 털린 (API, 피해자)가 생기면 파일 갱신
            self.save_breached()
        saved = False
        blocked = None                                  # 영구 차단 결과 (차단 기능이 꺼져 있으면 None)
        if decisions and self.store.apply(decisions):
            if not self.dry_run:
                try:
                    self.store.save()
                    saved = True
                except OSError as err:
                    print(f"[오류] confirmed.json 저장 실패: {err}", flush=True)
            for d in decisions:
                if d["type"] == "user":
                    print(f"[확정] 사용자 {d['user_id']} 점수 {d['score']} {d['breakdown']} "
                          f"피해자 {d['victims']} 요청 {len(d['request_ids'])}건", flush=True)
                    for api, victims in d["apis_hit"].items():
                        print(f"        털린 API: {api} {fmt_ids(victims)}", flush=True)
                    if self.blocker:                    # confirmed.json 저장에 실패해도 차단은 함 (보안 우선)
                        blocked = self.blocker.block_forever(
                            d["user_id"], f"공격 확정: 점수 {d['score']} {d['breakdown']} 피해자 {d['victims']}")
                elif d["user_id"] not in self.store.users:  # 확정 사용자의 요청 추가는 건수로만 (상태 줄)
                    print(f"[요청] 사용자 {d['user_id']} {d['reason']}", flush=True)
        if self.db:
            self.record_db(stream_id, decisions, saved, blocked)
        return True

    def record_db(self, stream_id, decisions, saved, blocked=None):
        """방금 채점한 Redis 이벤트 한 건을 bola_events 한 행으로 (Redis 값 + 그 시점의 판단 + 조치), 사용자 상태도 갱신
        실제 쓰기는 db.py 저장 스레드. 조치는 두 가지:
          AC-<스트림ID>-R  RATE 이벤트 = realtime.py의 임시 차단 (만료 시각 = 이벤트 + rate_block_sec)
          AC-<스트림ID>-L  공격 확정 → 영구 차단(blocked:user:N, 만료 없음) + confirmed.json 등록
                           둘 다 성공 applied / 하나라도 실패 failed. blocked=None(차단 기능 꺼짐)이면 confirmed.json만"""
        t = self.judge.last
        if not t or not t.get("result") or t["result"] == "released":
            return                                      # 해제 이전 이벤트는 그때 이미 기록됨 (정리한 DB에 다시 넣지 않음)
        u, now, ts = t["user_id"], datetime.now(KST), to_dt(t["ts"])
        result = t["result"]

        # 판단 결과와 그 근거
        if result == "skip":
            decision, reason = "ignored", "URL 번호가 요청자 본인 → 장부 오탐으로 보고 점수에서 제외"
            prev = self.user_state.get(u)
            status = prev[0] if prev else ("confirmed" if u in self.store.users else
                                           USER_STATUS[self.judge.level_name(self.judge.level.get(u, 0))])
        elif result == "confirmed_user":
            decision, reason, status = "attack", "이미 공격 확정된 사용자 (confirmed.json에 있음)", "confirmed"
        else:
            decision = t["level"]
            reason = t["level_up"]["reason"] if t.get("level_up") else \
                f"{self.judge.window_ms // 3600000}시간 점수 {t['total']}점 → {decision} 단계 유지"
            status = USER_STATUS[decision]
        if self.user_state.get(u, (None,))[0] != status:    # 상태 값이 바뀐 시각만 기억 (점수만 바뀌면 그대로)
            self.user_state[u] = (status, now)

        # 조치 (한 이벤트에 둘 다 있으면 하나로 합침: AC-...-RL)
        acts = []
        if t["kind"] == "RATE":
            acts.append(("R", f"탐지 엔진 RATE 임시 차단: 짧은 시간에 의심 요청이 몰림 ({t['uri']})",
                         ts, "applied", ts, ts + timedelta(seconds=self.rate_sec)))
        if any(d["type"] == "user" for d in decisions):
            d = next(d for d in decisions if d["type"] == "user")
            if blocked is None:
                text, ok = f"공격 확정 ({d['reason']}) → confirmed.json 등록, 장부 학습에서 제외", saved
            else:
                text = (f"공격 확정 ({d['reason']}) → 영구 차단 blocked:user:{u} "
                        f"({'성공' if blocked else '실패, 동기화 때 재시도'}) + confirmed.json 등록, 장부 학습에서 제외")
                ok = saved and blocked
            acts.append(("L", text, now, "applied" if ok else "failed", now if ok else None, None))
        action = {}
        if acts:
            action = {
                "action_id": f"AC-{stream_id}-" + "".join(a[0] for a in acts),
                "action_reason": " / ".join(a[1] for a in acts),
                "decided_at": min(a[2] for a in acts),
                "enforcement_status": acts[0][3],
                "enforced_at": next((a[4] for a in acts if a[4]), None),
                "expires_at": next((a[5] for a in acts if a[5]), None),
            }

        self.db.put_event({
            "stream_id": stream_id, "event_id": t.get("request_id"), "event_at": ts,
            "detected_at": to_dt(id_key(stream_id)[0]), "user_id": u, "action_type": t["kind"] or "UNKNOWN",
            "api_path": t.get("event_api"),
            "detection_reasons": {
                "detail": t.get("detail"), "uri": t["uri"], "status": t["status"],
                "classified_as": t.get("item"), "points": t.get("points"), "victim": t.get("victim"),
                "breakdown": t.get("breakdown"), "victims": t.get("victims"), "api_victims": t.get("api_victims"),
            },
            "risk_score": t.get("score"), "assessed_at": now, "decision": decision, "decision_reason": reason,
            "user_status": status, "user_status_updated_at": self.user_state[u][1], **action,
        })
        self.db.put_user({
            "user_id": u, "user_status": status, "user_status_updated_at": self.user_state[u][1],
            "risk_score": t.get("score"), "last_event_at": ts, "last_stream_id": stream_id,
        })

    def write_trace(self, stream_id):
        """방금 채점한 이벤트를 콘솔에 한 줄, score_log 파일에 JSON 한 줄로 남김
        예: [점수] 14:03:47 사용자 2 BOLA 200 /members/3 → BOLA_PATH +40 = 80/100 {BOLA_PATH: 80} 피해자 [24, 3]"""
        t = self.judge.last
        when = datetime.fromtimestamp(t["ts"] / 1000, KST).strftime("%H:%M:%S")
        head = f"[점수] {when} 사용자 {t['user_id']} {t['kind']} {t['status']} {t['uri']} →"
        result = t.get("result")
        if result == "released":
            line = f"{head} 무시: 관리자가 해제한 사용자의 해제 이전 이벤트"
        elif result == "skip":
            why = "URL 번호가 본인 (장부 오탐)" if t["kind"] in ("BOLA", "ATTEMPT") else "채점 대상 아님"
            line = f"{head} 무시: {why}"
        elif result == "confirmed_user":
            line = f"{head} 이미 확정된 사용자 → 요청만 confirmed.json에 추가"
        else:
            line = (f"{head} {t['item']} +{t['points']} = {t['total']}/{self.judge.threshold}점 "
                    f"{t['breakdown']} 피해자 {t['victims']}")
            if result == "confirmed":
                line += "  ★ 확정"
        if t.get("api"):                                # 이 사용자가 이 API에서 지금까지 턴 피해자 전체
            line += f"  | {t['api']} {fmt_ids(t['api_victims'])}"
        print(line, flush=True)
        if self.score_log:
            with open(self.score_log, "a", encoding="utf-8") as f:
                f.write(json.dumps({"stream_id": stream_id, "time": when, **t}, ensure_ascii=False) + "\n")

    def rebuild(self, all_events=False):
        """최근 window_sec(또는 전체) 이벤트를 XRANGE로 읽어 점수 복원. 읽은 건수 반환"""
        start = "-" if all_events else f"{int(time.time() * 1000) - self.judge.window_ms}-0"
        n = 0
        while True:
            rows = self.r.xrange(self.stream, min=start, max="+", count=1000)
            rows = [(i, f) for i, f in rows if id_key(i) > self.last_id]
            if not rows:
                return n
            for i, f in rows:
                self.handle(i, f)
                n += 1
            start = rows[-1][0]

    def ensure_group(self):
        """judges 그룹이 없으면 만듦 (지금 이후 이벤트부터. 과거는 rebuild가 처리)"""
        try:
            self.r.xgroup_create(self.stream, self.group, id="$", mkstream=True)
            print(f"[Redis] 그룹 {self.group} 만듦", flush=True)
        except redis.ResponseError as err:
            if "BUSYGROUP" not in str(err):
                raise

    def consume(self):
        """그룹으로 받기: ① 받았지만 ACK 못 한 것 ② 새 이벤트. 처리 후 ACK"""
        self.ensure_group()
        for start in ("0", ">"):
            while True:
                resp = self.r.xreadgroup(self.group, self.me, {self.stream: start},
                                         count=100, block=5000 if start == ">" else None)
                events = [ev for _, evs in resp for ev in evs]
                if start == "0" and not events:
                    break                                # 미처리분 다 비움 → 새 이벤트 받기로
                for i, f in events:
                    self.handle(i, f or {})              # ACK 뒤 잘린 항목은 f가 비어 있을 수 있음
                    self.r.xack(self.stream, self.group, i)
                self.status()
                self.sync_blocks()

    def status(self, force=False):
        """STATUS_SEC마다 처리 건수와 점수 상위 사용자 출력"""
        if not force and time.time() - self.last_status < STATUS_SEC:
            return
        self.last_status = time.time()
        c = self.judge.counts
        top = ", ".join(f"{u}:{s}" for s, u, _, _ in self.judge.top(5)) or "없음"
        print(f"[상태] 이벤트 {c['events']} (채점 {c['scored']}, 본인 번호 제외 {c['self_skip']}) "
              f"확정 사용자 {len(self.store.users)} 확정 요청 {len(self.store.requests)} | 점수 상위 {top}", flush=True)
        if self.blocker:
            b = self.blocker.counts
            print(f"[차단] 영구 차단 {b['blocked']}건 (실패 {b['failed']})", flush=True)
        for api, row in self.judge.breached().items():
            print(f"[털린 API] {api} 피해자 {fmt_ids(row['victims'])} ← 공격자 {fmt_ids(row['attackers'])}", flush=True)
        if self.db:
            d = self.db.counts
            print(f"[DB] 기록 이벤트 {d['events']} 사용자 상태 {d['users']} "
                  f"(실패 {d['errors']}, 버림 {d['dropped']})", flush=True)

    def save_breached(self):
        """털린 API 요약을 breached_apis.json으로 저장 (임시 파일에 쓴 뒤 바꿔치기)
        {"GET /members/{id}": {"victims": [...], "attackers": [...]}, ...,
         "_by_user": {"2": {"GET /members/{id}": [...]}, ...}}"""
        self.saved_hits = self.judge.counts["hits"]
        if not self.breached_path:
            return
        data = dict(self.judge.breached())
        data["_by_user"] = {u: self.judge.user_hits(u) for u in sorted(self.judge.hits)}
        os.makedirs(os.path.dirname(self.breached_path), exist_ok=True)
        tmp = self.breached_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.breached_path)


def main():
    """명령줄 인자를 읽어 계속 실행 또는 한 번 계산"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")        # Windows 콘솔에서 한글 깨짐 방지
    p = argparse.ArgumentParser(description="BOLA 판단 서버: Redis 이벤트 → 점수 → confirmed.json")
    p.add_argument("--once", action="store_true", help="한 번 계산하고 종료 (그룹·ACK 사용 안 함)")
    p.add_argument("--all", action="store_true", help="--once와 함께: 스트림 전체로 계산")
    p.add_argument("--dry-run", action="store_true", help="confirmed.json을 쓰지 않고 결과만 출력")
    p.add_argument("--trace", action="store_true", help="시작할 때 복원하는 과거 이벤트도 점수 줄을 출력")
    p.add_argument("--quiet", action="store_true", help="실시간 모드에서 이벤트마다 점수 줄을 출력하지 않음")
    args = p.parse_args()

    load_env()
    cfg = load_config()
    srv = Server(cfg, dry_run=args.dry_run)
    srv.trace = args.trace
    rc = cfg["redis"]
    print(f"[시작] Redis {rc['host']}:{rc['port']} {rc['stream']} → {cfg['paths']['confirmed']}"
          f"{' (dry-run)' if args.dry_run else ''} | 영구 차단 {'켜짐' if srv.blocker else '꺼짐'}", flush=True)

    while True:                                         # 시작할 때 Redis가 아직 안 떠 있어도 기다림
        try:
            n = srv.rebuild(all_events=args.all)
            break
        except redis.AuthenticationError as err:        # 비밀번호 문제는 기다려도 안 풀림 → 바로 안내하고 종료
            sys.exit(f"[Redis] 인증 실패: {err}\n  → judge/.env의 REDIS_PASSWORD를 확인하세요")
        except redis.ConnectionError as err:
            print(f"[Redis] 연결 안 됨, 3초 뒤 다시 시도: {err}", flush=True)
            time.sleep(3)
    print(f"[복원] 최근 이벤트 {n}건 채점", flush=True)
    if args.once:
        if srv.db:
            srv.db.close()                              # 남은 DB 기록을 다 쓰고 끝냄
        srv.status(force=True)
        return
    srv.sync_blocks(force=True)                         # 이미 확정된 사용자(confirmed.json)도 영구 차단 키를 맞춤
    srv.status(force=True)

    srv.trace = not args.quiet                          # 실시간으로 들어오는 이벤트는 점수 줄을 보여 줌
    print(f"[대기] 새 이벤트를 기다리는 중 (점수 로그: {srv.score_log or '파일 안 씀'})", flush=True)
    try:
        while True:
            try:
                srv.consume()
            except redis.ConnectionError as err:        # Redis 재시작·네트워크 끊김 → 잠깐 쉬고 다시
                print(f"[Redis] 연결 끊김, 3초 뒤 다시 시도: {err}", flush=True)
                time.sleep(3)
    except KeyboardInterrupt:
        if srv.db:
            srv.db.close()
        srv.status(force=True)
        print("종료")


if __name__ == "__main__":
    main()
