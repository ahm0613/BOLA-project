"""알림: 관리자(고위험·차단 사용자)와 개발자(취약 API)에게 Slack 웹훅으로 글자 메시지를 보냄

역할: 판단 서버의 세 번째 출구. judge.py가 이벤트를 채점할 때마다 on_scored()를 부르면, 알림이 필요한지 보고
  메모리 큐에 넣기만 하고 바로 돌아감 (판정이 Slack 때문에 느려지지 않게). 알림 스레드가 큐를 비워 보내고,
  매시 정각에 직전 1시간 요약을 보냄.

  관리자 채널 (.env의 SLACK_ADMIN_WEBHOOK)
    high / attack     사용자 단계가 고위험(high)·차단(attack)으로 올라갈 때 (admin_levels).
                      한 이벤트로 high를 건너뛰고 attack이 되면 attack 하나만
                      키 user:<id>:<단계>:r<해제 시각> → 사용자·단계마다 한 번 (관리자가 해제하면 다시 셈)
    rate              RATE 임시 차단. 키 rate:<id>:<날짜> → 사용자마다 하루 한 번 (반복 횟수는 요약에)
    release           unblock.py 실행 기록 (send_tool_alert)
    summary           매시 정각 + summary_delay_sec에 직전 1시간 요약 (일이 없어도 보냄 = 판단 서버 생존 신호)
  개발자 채널 (.env의 SLACK_DEV_WEBHOOK), 사용자 번호는 넣지 않음
    api               API에서 BOLA가 처음 성공했을 때, 또는 quiet_days(7일) 동안 조용하다가 다시 성공했을 때
    summary           매시 정각 + summary_delay_sec에 직전 1시간 동안 털린 API 요약

중복 방지
  - 판단 서버를 다시 시작해 과거 이벤트를 다시 채점하는 동안(live=False)은 알림을 보내지 않음
  - 보낸 알림은 PostgreSQL alerts 테이블에 키로 남기고, 같은 키는 다시 보내지 않음 (DB가 없으면 메모리로만)
  - 요약은 판단 서버가 켜진 뒤에 끝난 시간대만 보냄
실패: 웹훅 오류면 2, 4, 8, 16초 간격으로 다시 시도하고, retries(5)번 실패하면 failed로 기록. 판단·차단에는 영향 없음
웹훅 주소가 없으면 보내지 않고 skipped로만 기록 (주소는 나중에 .env에 넣고 판단 서버를 다시 만들면 됨)

  python notifier.py --test     두 채널에 시험 메시지 (judge 폴더에서)
  docker compose run --rm judge python notifier.py --test    (WSL, /mnt/d/python-rule에서)
"""
import argparse
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

import db
from scoring import DEFAULT_LEVELS, level_label

KST = timezone(timedelta(hours=9))
HOUR_MS = 3600 * 1000
WEBHOOK_ENV = {"admin": "SLACK_ADMIN_WEBHOOK", "dev": "SLACK_DEV_WEBHOOK"}
CHANNEL_NAMES = {"admin": "관리자", "dev": "개발자"}
DEFAULTS = {"enabled": True, "admin_levels": ["high", "attack"], "rate": True, "quiet_days": 7,
            "summary": True, "summary_delay_sec": 30, "retries": 5, "timeout_sec": 10}
SUMMARY_MAX_ROWS = 20                                   # 요약에 한 줄씩 보여 줄 최대 사용자·API 수

SQL_UPSERT = """
INSERT INTO alerts (alert_key, channel, kind, user_id, api_path, message, status, attempts, created_at, sent_at, last_error)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now(), %s, %s)
ON CONFLICT (alert_key) DO UPDATE SET
  status = EXCLUDED.status, attempts = EXCLUDED.attempts, sent_at = EXCLUDED.sent_at, last_error = EXCLUDED.last_error"""
SQL_CLAIM = """
INSERT INTO alerts (alert_key, channel, kind, user_id, api_path, message, status, attempts, created_at)
VALUES (%s, %s, %s, %s, %s, %s, 'pending', 0, now())
ON CONFLICT (alert_key) DO NOTHING RETURNING alert_key"""
BOLA_ITEMS = ("detection_reasons->>'classified_as' IN "
              "('BOLA_PATH', 'BOLA_LEDGER', 'BOLA_PATH_WRITE', 'BOLA_LEDGER_WRITE')")
SQL_API_RECENT = f"""
SELECT max(event_at) FROM bola_events
WHERE api_path = %s AND {BOLA_ITEMS} AND event_at >= %s AND event_at < %s"""
SQL_SUMMARY_DEV = f"""
SELECT api_path, count(*), count(DISTINCT detection_reasons->>'victim'), count(DISTINCT user_id)
FROM bola_events WHERE detected_at >= %s AND detected_at < %s AND {BOLA_ITEMS}
GROUP BY api_path ORDER BY count(*) DESC"""
SQL_SUMMARY_ADMIN = """
SELECT user_id, count(*), max(risk_score),
       count(*) FILTER (WHERE action_type = 'RATE'),
       bool_or(action_id LIKE '%%L'),
       array_agg(DISTINCT decision)
FROM bola_events WHERE detected_at >= %s AND detected_at < %s
GROUP BY user_id"""


def kst(ms):
    """ms → 한국 시간 datetime"""
    return datetime.fromtimestamp(ms / 1000, KST)


def fmt_time(ms):
    """ms → "2026-11-03 15:10:09" """
    return kst(ms).strftime("%Y-%m-%d %H:%M:%S")


def fmt_breakdown(breakdown):
    """{"BOLA_PATH": 120, "+victims": 30} → "BOLA_PATH 120, +victims 30" """
    return ", ".join(f"{k} {v}" for k, v in (breakdown or {}).items()) or "-"


def post_webhook(url, text, timeout=10):
    """Slack 웹훅에 글자 메시지 하나. 실패하면 예외 (HTTP 4xx/5xx도 urlopen이 예외로 냄)"""
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


class AlertDb:
    """alerts 테이블(보낸 알림 기록)과 요약용 bola_events 조회. 실패하면 예외 대신 None (알림은 DB 없이도 동작)"""
    def __init__(self, dsn, connect=None):
        """dsn: psycopg 접속 문자열. connect: 테스트용 연결 함수"""
        self.connect = connect or (lambda: db.psycopg.connect(dsn, connect_timeout=5, autocommit=True))
        self.conn = None
        self.errors = 0

    def _run(self, sql, params, fetch=False):
        """SQL 하나 실행. 성공하면 행 목록(fetch) 또는 True, 실패하면 None"""
        try:
            if self.conn is None or self.conn.closed:
                self.conn = self.connect()
            with self.conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall() if fetch else True
        except Exception as err:                        # DB가 꺼졌거나 alerts 테이블이 아직 없음
            self.errors += 1
            if self.errors == 1 or self.errors % 30 == 0:
                print(f"[알림] DB 사용 실패 ({self.errors}번째), DB 없이 계속: {str(err).strip()}", flush=True)
            try:
                if self.conn is not None:
                    self.conn.close()
            except Exception:
                pass
            self.conn = None
            return None

    def claim(self, item):
        """알림 키를 먼저 등록. 새 키면 True, 이미 있으면 False (다른 때 이미 보냄), DB 실패면 None"""
        rows = self._run(SQL_CLAIM, (item["key"], item["channel"], item["kind"], item.get("user_id"),
                                     item.get("api"), item["text"]), fetch=True)
        return None if rows is None else bool(rows)

    def finish(self, item, status):
        """보낸 결과 기록 (claim 때 DB가 꺼져 있었어도 여기서 새로 들어감)"""
        sent_at = datetime.now(KST) if status == "sent" else None
        self._run(SQL_UPSERT, (item["key"], item["channel"], item["kind"], item.get("user_id"), item.get("api"),
                               item["text"], status, item["attempts"], sent_at, item.get("error")))

    def api_recent(self, api, since_ms, until_ms):
        """since~until 사이 이 API의 마지막 BOLA 성공 시각. (성공 여부, datetime 또는 None)"""
        rows = self._run(SQL_API_RECENT, (api, kst(since_ms), kst(until_ms)), fetch=True)
        return (False, None) if rows is None else (True, rows[0][0] if rows else None)

    def summary_dev(self, start_ms, end_ms):
        """[(api, 성공 건수, 피해자 수, 공격자 수)] 또는 None"""
        return self._run(SQL_SUMMARY_DEV, (kst(start_ms), kst(end_ms)), fetch=True)

    def summary_admin(self, start_ms, end_ms):
        """[(user_id, 이벤트 수, 최고 점수, RATE 수, 확정 여부, 최고 단계 순번)] 또는 None"""
        return self._run(SQL_SUMMARY_ADMIN, (kst(start_ms), kst(end_ms)), fetch=True)


class Notifier:
    """알림 판단 + 큐 + 보내는 스레드. start()로 시작, close()로 남은 것을 보내고 종료"""
    def __init__(self, cfg, webhooks, alert_db=None, released=None, post=post_webhook, clock=time.time):
        """cfg: config.json. webhooks: {"admin": 주소, "dev": 주소}(없으면 None). alert_db: AlertDb 또는 None
        released: 관리자가 해제한 사용자 → 해제 시각(ms) (해제 뒤 다시 올라가면 새 알림)"""
        self.nc = {**DEFAULTS, **(cfg.get("notify") or {})}
        self.webhooks = {ch: (webhooks or {}).get(ch) or None for ch in WEBHOOK_ENV}
        self.db = alert_db
        self.released = released if released is not None else {}
        self.post, self.clock = post, clock
        self.threshold = cfg["threshold"]
        self.level_need = dict(cfg.get("levels") or DEFAULT_LEVELS, attack=cfg["threshold"])
        # 단계 코드 → 순번 (점수 낮은 순, normal 0). 1시간 요약에서 그 시간대 가장 높은 단계를 고를 때 씀
        self.level_rank = {name: i + 1 for i, (name, _) in
                           enumerate(sorted(self.level_need.items(), key=lambda x: x[1]))}
        self.window_label = "누적" if not int(cfg.get("window_sec") or 0) else f"{int(cfg['window_sec']) // 3600}시간"
        self.rate_min = (cfg.get("db") or {}).get("rate_block_sec", 600) // 60
        self.quiet_ms = int(self.nc["quiet_days"] * 86400 * 1000)
        self.live = False                               # False: 과거 이벤트 복원 중 → API 시각만 기억하고 보내지 않음
        self.queue = []
        self.keys = set()                               # 이번 실행에서 넣은 키 (DB가 꺼져 있을 때의 중복 방지)
        self.api_last = {}                              # API → 마지막 BOLA 성공 시각(ms)
        self.results = {}                               # 키 → 마지막 결과 (--test 출력용)
        self.counts = {"sent": 0, "failed": 0, "skipped": 0, "duplicate": 0}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.started_ms = None
        self.last_summary = None                        # 마지막으로 요약한 시간대 시작(ms)
        self.thread = threading.Thread(target=self._run, name="notifier", daemon=True)

    # ------------------------------------------------------------ 판단 서버에서 부르는 곳
    def on_scored(self, t, decisions, blocked, judge):
        """Judge.process 직후 judge.last(t)를 보고 알림을 큐에 넣음. blocked: 영구 차단 결과 (기능 꺼짐이면 None)"""
        if not t or t.get("result") in (None, "released"):
            return
        if t.get("api"):                                # BOLA 성공 (확정 사용자의 요청이어도 API는 털린 것)
            self._on_api_hit(t, judge)
        if not self.live or t.get("result") == "confirmed_user":
            return
        u = t["user_id"]
        lu = t.get("level_up")
        if lu and lu["decision"] in self.nc["admin_levels"]:
            key = f"user:{u}:{lu['decision']}:r{self.released.get(u, 0)}"
            if lu["decision"] == "attack":
                d = next((d for d in decisions if d["type"] == "user"), None)
                self.push(key, "admin", "attack", self._attack_text(t, d, blocked), user_id=u)
            else:
                self.push(key, "admin", lu["decision"], self._level_text(t, lu["decision"]), user_id=u)
        if t["kind"] == "RATE" and self.nc["rate"]:
            self.push(f"rate:{u}:{kst(t['ts']):%Y-%m-%d}", "admin", "rate", self._rate_text(t), user_id=u)

    def _on_api_hit(self, t, judge):
        """API별 마지막 성공 시각을 기억하고, 처음이거나 quiet_days 만에 다시 털렸으면 개발자 알림"""
        api, ts = t["api"], t["ts"]
        prev = self.api_last.get(api)
        self.api_last[api] = max(ts, prev or 0)
        if not self.live or (prev is not None and ts - prev < self.quiet_ms):
            return
        text = self._api_text(t, prev)
        self.push(f"api:{api}:{ts}", "dev", "api", text, api=api, precheck=lambda: self._api_quiet(api, ts))

    def _api_quiet(self, api, ts):
        """DB로 한 번 더 확인: quiet_days 안에 이 API가 털린 기록이 있으면 False (재시작으로 메모리가 비었을 때)"""
        if not self.db:
            return True
        ok, last = self.db.api_recent(api, ts - self.quiet_ms, ts)
        return not ok or last is None

    # ------------------------------------------------------------ 메시지 글
    def _attack_text(self, t, d, blocked):
        u = t["user_id"]
        if blocked is None:
            action = "공격 확정 (영구 차단 기능 꺼짐, confirmed.json에만 등록)"
        else:
            action = "영구 차단함" if blocked else "영구 차단 실패 (판단 서버가 60초마다 다시 시도)"
        d = d or {"score": t.get("total"), "breakdown": t.get("breakdown"), "victims": t.get("victims") or [],
                  "apis_hit": {}}
        lines = [f"[공격 확정] 사용자 {u} {action}",
                 f"{self.window_label} 점수 {d['score']}/{self.threshold}점 = 위험도 100% "
                 f"({fmt_breakdown(d['breakdown'])}, {self.threshold}점을 넘은 점수는 차단 근거)",
                 f"피해자 {', '.join(d['victims']) or '-'}"]
        lines += [f"털린 API {api}: {', '.join(v)}" for api, v in (d.get("apis_hit") or {}).items()]
        lines += [f"마지막 요청 {t['kind']} {t['status']} {t['uri']} ({fmt_time(t['ts'])})",
                  f"오탐이면 해제 (WSL /mnt/d/python-rule): docker compose stop judge → "
                  f"docker compose run --rm judge python unblock.py {u} --by <이름> --note \"<이유>\" → "
                  f"docker compose start judge"]
        return "\n".join(lines)

    def _level_text(self, t, level):
        return "\n".join([
            f"[위험 사용자] 사용자 {t['user_id']} {level_label(level)} 단계, 위험도 {t.get('risk_pct')}% "
            f"({self.window_label} 점수 {t.get('total')}점, {level_label(level)} 기준 {self.level_need.get(level)}점, "
            f"차단 {self.threshold}점)",
            f"내역 {fmt_breakdown(t.get('breakdown'))}",
            f"피해자 {', '.join(t.get('victims') or []) or '-'}",
            f"마지막 요청 {t['kind']} {t['status']} {t['uri']} ({fmt_time(t['ts'])})",
        ])

    def _rate_text(self, t):
        return "\n".join([
            f"[임시 차단] 사용자 {t['user_id']} {self.rate_min}분 임시 차단 (탐지 엔진: 10초에 의심 요청이 몰림)",
            f"{self.window_label} 점수 {t.get('total', t.get('score'))}점 | {t.get('detail') or ''}",
            f"시각 {fmt_time(t['ts'])}. 오늘 이 사용자의 임시 차단은 더 알리지 않고 1시간 요약에 횟수로 표시합니다",
        ])

    def _api_text(self, t, prev):
        if prev is None:
            head = f"[취약 API] {t['api']} 에서 남의 데이터 조회가 성공했습니다"
        else:
            head = (f"[취약 API 재발] {t['api']} 에서 남의 데이터 조회가 다시 성공했습니다 "
                    f"(마지막 성공 후 {(t['ts'] - prev) // 86400000}일 만)")
        why = ("URL의 사용자 번호가 요청자와 다름 (확실)" if (t.get("item") or "").startswith("BOLA_PATH")
               else "학습한 장부의 객체 주인과 요청자가 다름")
        return "\n".join([
            head,
            f"판정 근거: {why}",
            f"발생 시각: {fmt_time(t['ts'])}",
            f"예시 요청 ID: {t.get('request_id') or '-'} (Kong 로그에서 찾을 수 있음)",
            "조치: 이 API가 로그인 사용자와 객체 주인이 같은지 확인하는지 점검하세요. 이후 건수는 1시간 요약에 나옵니다",
        ])

    # ------------------------------------------------------------ 1시간 요약
    def maybe_summary(self):
        """정각 + summary_delay_sec가 지났고, 판단 서버가 켜진 뒤에 끝난 시간대면 요약을 큐에 넣음"""
        if not self.nc["summary"] or self.started_ms is None:
            return
        now_ms = int(self.clock() * 1000)
        end = now_ms // HOUR_MS * HOUR_MS                # 한국 시간도 정각이 같음 (UTC+9)
        start = end - HOUR_MS
        if now_ms < end + self.nc["summary_delay_sec"] * 1000 or end <= self.started_ms or self.last_summary == start:
            return
        self.last_summary = start
        self.push_summaries(start, end)

    def push_summaries(self, start, end):
        """start~end(ms) 요약 두 개 (개발자, 관리자)"""
        label = f"{kst(start):%m-%d %H:%M}~{kst(end):%H:%M}"
        hour = f"{kst(start):%Y-%m-%dT%H}"
        dev_rows = self.db.summary_dev(start, end) if self.db else None
        admin_rows = self.db.summary_admin(start, end) if self.db else None
        self.push(f"summary:dev:{hour}", "dev", "summary", self.dev_summary_text(label, dev_rows))
        self.push(f"summary:admin:{hour}", "admin", "summary", self.admin_summary_text(label, admin_rows))

    def _no_db(self):
        return ("- 판단 서버는 동작 중이지만 DB를 읽지 못해 건수를 셀 수 없습니다 "
                + ("(DB 기록 꺼짐)" if not self.db else "(DB 접속 실패)"))

    def dev_summary_text(self, label, rows):
        lines = [f"[취약 API 1시간 요약] {label}"]
        if rows is None:
            lines.append(self._no_db())
        elif not rows:
            lines.append("- 이 시간에 털린 API 없음")
        else:
            lines += [f"- {api}: 성공 {n}건, 피해자 {v}명, 공격자 {a}명" for api, n, v, a in rows[:SUMMARY_MAX_ROWS]]
            if len(rows) > SUMMARY_MAX_ROWS:
                lines.append(f"- 외 API {len(rows) - SUMMARY_MAX_ROWS}개")
        return "\n".join(lines)

    def admin_summary_text(self, label, rows):
        lines = [f"[위험 사용자 1시간 요약] {label}"]
        if rows is None:
            lines.append(self._no_db())
            return "\n".join(lines)
        events = sum(r[1] for r in rows)
        confirmed = sum(1 for r in rows if r[4])
        rates = sum(r[3] for r in rows)
        lines.append(f"의심 이벤트 {events}건, 사용자 {len(rows)}명 | 확정 {confirmed}명, 임시 차단 {rates}건")
        top = len(self.level_rank)                      # 차단(attack) 순번
        # 그 시간대 판단 단계 중 가장 높은 것의 순번 (확정 조치가 있으면 차단)
        rank = {r[0]: top if r[4] else max((self.level_rank.get(d, 0) for d in (r[5] or [])), default=0)
                for r in rows}
        alert_rank = min(self.level_rank.get(lv, top) for lv in self.nc["admin_levels"]) if self.nc["admin_levels"]             else top
        watch = sorted((r for r in rows if r[4] or r[3] or rank[r[0]] >= alert_rank),
                       key=lambda r: (-rank[r[0]], -(r[2] or 0)))
        names = {i: name for name, i in self.level_rank.items()}
        for uid, _, score, rate, conf, _ in watch[:SUMMARY_MAX_ROWS]:
            pct = "-" if score is None else f"{min(100, int(score) * 100 // self.threshold)}%"
            line = (f"- 사용자 {uid}: {level_label(names.get(rank[uid], 'normal'))} "
                    f"(위험도 {pct}, 최고 {score if score is not None else '-'}점)")
            if rate:
                line += f", 임시 차단 {rate}번"
            lines.append(line)
        if len(watch) > SUMMARY_MAX_ROWS:
            lines.append(f"- 외 {len(watch) - SUMMARY_MAX_ROWS}명")
        if not watch:
            lines.append("- 위험 사용자 없음 (이상 없음)")
        return "\n".join(lines)

    # ------------------------------------------------------------ 큐와 보내기
    def push(self, key, channel, kind, text, user_id=None, api=None, precheck=None):
        """알림 하나를 큐에 넣음. 이번 실행에서 이미 넣은 키면 False"""
        with self.lock:
            if key in self.keys:
                self.counts["duplicate"] += 1
                return False
            self.keys.add(key)
            self.queue.append({"key": key, "channel": channel, "kind": kind, "text": text, "user_id": user_id,
                               "api": api, "precheck": precheck, "attempts": 0, "next_at": 0.0, "claimed": False,
                               "error": None})
            return True

    def run_pending(self):
        """보낼 때가 된 알림을 보냄. 실패한 것은 다음 시도 시각을 정해 큐에 되돌림"""
        now = self.clock()
        with self.lock:
            due = [i for i in self.queue if i["next_at"] <= now]
            self.queue = [i for i in self.queue if i["next_at"] > now]
        for item in due:
            if not self._deliver(item, now):
                with self.lock:
                    self.queue.append(item)

    def _deliver(self, item, now):
        """알림 하나 보내기. 끝났으면(보냄·실패 확정·건너뜀) True, 다시 시도할 거면 False"""
        if not item["claimed"]:
            if item["precheck"] and not item["precheck"]():
                self.counts["duplicate"] += 1
                return True
            if self.db and self.db.claim(item) is False:  # 다른 때(재시작 전) 이미 보낸 알림
                self.counts["duplicate"] += 1
                self.results[item["key"]] = "duplicate"
                return True
            item["claimed"] = True
        url = self.webhooks[item["channel"]]
        if not url:
            self._finish(item, "skipped")
            return True
        try:
            self.post(url, item["text"], self.nc["timeout_sec"])
        except Exception as err:
            item["attempts"] += 1
            item["error"] = str(err)[:500]
            if item["attempts"] >= self.nc["retries"]:
                print(f"[알림] {CHANNEL_NAMES[item['channel']]} 알림 {item['key']} {item['attempts']}번 실패: "
                      f"{item['error']}", flush=True)
                self._finish(item, "failed")
                return True
            item["next_at"] = now + 2 ** item["attempts"]
            return False
        item["attempts"] += 1
        item["error"] = None
        self._finish(item, "sent")
        return True

    def _finish(self, item, status):
        """결과를 세고 alerts 테이블에 기록"""
        self.counts[status] += 1
        self.results[item["key"]] = status
        if self.db:
            self.db.finish(item, status)

    def flush(self, timeout=40.0):
        """큐가 빌 때까지 보냄 (관리자 도구, --test, 종료할 때). 재시도 대기도 포함해 최대 timeout초"""
        deadline = time.time() + timeout
        while True:
            self.run_pending()
            with self.lock:
                if not self.queue:
                    return True
            if time.time() >= deadline:
                return False
            time.sleep(0.5)

    def _run(self):
        """알림 스레드: 1초마다 요약 시각 확인 + 큐 보내기"""
        while not self.stop.wait(1.0):
            try:
                self.maybe_summary()
                self.run_pending()
            except Exception as err:                    # 알림 문제로 스레드가 죽지 않게
                print(f"[알림] 처리 오류: {err}", flush=True)

    def start(self):
        """실시간 알림 시작 (복원이 끝난 뒤 judge.py가 부름)"""
        self.live = True
        self.started_ms = int(self.clock() * 1000)
        self.thread.start()

    def close(self, timeout=10.0):
        """스레드를 멈추고 남은 알림을 보냄"""
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join(timeout=5)
        self.flush(timeout)

    def describe(self):
        """시작할 때 한 줄"""
        hooks = ", ".join(f"{CHANNEL_NAMES[ch]} 웹훅 {'있음' if self.webhooks[ch] else '없음'}" for ch in WEBHOOK_ENV)
        return f"[알림] 켜짐 | {hooks} | 보낸 기록 DB {'씀' if self.db else '안 씀 (메모리로만 중복 방지)'}"

    def status_line(self):
        """[상태] 출력용"""
        c = self.counts
        return (f"[알림] 보냄 {c['sent']} 실패 {c['failed']} 웹훅 없어 건너뜀 {c['skipped']} "
                f"중복 {c['duplicate']} 대기 {len(self.queue)}")


def webhooks_from_env():
    """.env의 SLACK_ADMIN_WEBHOOK, SLACK_DEV_WEBHOOK"""
    return {ch: os.getenv(name, "").strip() or None for ch, name in WEBHOOK_ENV.items()}


def from_env(cfg, released=None):
    """config.json의 notify와 환경변수로 Notifier를 만듦. 알림이 꺼져 있으면 None"""
    if not {**DEFAULTS, **(cfg.get("notify") or {})}["enabled"]:
        return None
    dsn = db.dsn_from_env()
    return Notifier(cfg, webhooks_from_env(), AlertDb(dsn) if dsn else None, released=released)


def send_tool_alert(cfg, kind, text):
    """관리자 도구(unblock.py 등)의 실행 기록을 관리자 채널로. 실패해도 도구는 계속"""
    try:
        n = from_env(cfg)
        if n is None:
            return
        key = f"{kind}:{int(time.time() * 1000)}"
        n.push(key, "admin", kind, text)
        n.flush()
        result = {"sent": "보냄", "skipped": "웹훅 없음 (SLACK_ADMIN_WEBHOOK)", "failed": "실패"}
        print(f"[알림] 관리자 채널: {result.get(n.results.get(key), n.results.get(key, '보내지 못함'))}")
    except Exception as err:
        print(f"[알림] 관리자 알림 실패: {err}")


def main():
    """python notifier.py --test: 두 채널에 시험 메시지"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="알림 시험")
    p.add_argument("--test", action="store_true", help="관리자·개발자 채널에 시험 메시지를 보냄")
    args = p.parse_args()
    if not args.test:
        p.print_help()
        return
    import judge                                        # judge.py가 이 파일을 import하므로 여기서만 불러옴
    judge.load_env()
    cfg = judge.load_config()
    n = from_env(cfg)
    if n is None:
        sys.exit("config.json의 notify.enabled가 false입니다")
    print(n.describe())
    stamp = int(time.time() * 1000)
    for ch in WEBHOOK_ENV:
        n.push(f"test:{ch}:{stamp}", ch, "test",
               f"[시험] BOLA 판단 서버 {CHANNEL_NAMES[ch]} 알림 채널 연결 확인 ({fmt_time(stamp)})")
    n.flush()
    for ch, env in WEBHOOK_ENV.items():
        status = n.results.get(f"test:{ch}:{stamp}", "보내지 못함")
        hint = f" → judge/.env에 {env}=https://hooks.slack.com/... 를 넣으세요" if status == "skipped" else ""
        print(f"  {CHANNEL_NAMES[ch]} 채널: {status}{hint}")


if __name__ == "__main__":
    main()
