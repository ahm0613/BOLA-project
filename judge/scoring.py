"""점수 계산: Redis 이벤트 한 건씩 받아 사용자별 점수를 쌓고, 기준을 넘으면 공격자로 확정

역할: 판단 서버의 핵심 로직. Redis·파일을 모르고 이벤트 dict만 다룬다 (테스트하기 쉽게).
  Judge.process(이벤트) → 이번에 새로 생긴 확정 목록 [{"type": "user"|"request", ...}]

점수 (최근 window_sec 동안, config.json에서 조정)
  BOLA_PATH    /members/{id} 처럼 URL 숫자가 곧 사용자 번호인 API에서 남의 번호 → 확실
  BOLA_LEDGER  그 밖의 BOLA (realtime.py 장부 근거, 장부가 틀릴 수 있음)
  ATTEMPT / UNKNOWN / RATE  realtime.py의 kind 그대로
  보너스: 서로 다른 피해자 여러 명, ATTEMPT 뒤 BOLA 성공, 여러 자원 종류(members·orders…)에서 BOLA

오탐 거르기: URL 숫자가 요청자 본인인 BOLA·ATTEMPT는 점수를 주지 않음 (장부 오염으로 잘못 보고된 경우)
"""
import re
from collections import deque

NUM = re.compile(r"^\d+$")
OWNER_IN_DETAIL = re.compile(r"주인 (\d+)")


def sort_ids(ids):
    """ID 목록을 숫자 순으로 정렬 (숫자가 아닌 값은 뒤로). {"24", "3"} → ["3", "24"]"""
    return sorted(ids, key=lambda v: (0, int(v), "") if str(v).isdigit() else (1, 0, str(v)))


def parse_event(fields, stream_id=None):
    """Redis 이벤트 필드(모두 문자열) → 판단용 dict. 시각은 started_at, 없으면 스트림 ID의 ms"""
    try:
        ts = int(float(fields.get("started_at") or 0))
    except ValueError:
        ts = 0
    if not ts and stream_id:
        ts = int(stream_id.split("-")[0])
    owner = fields.get("owner")
    if not owner:                                       # realtime.py가 owner 필드를 안 보내면 detail 문장에서
        m = OWNER_IN_DETAIL.search(fields.get("detail") or "")
        owner = m.group(1) if m else None
    try:
        status = int(fields.get("status") or 0)
    except ValueError:
        status = 0
    return {
        "id": stream_id,
        "kind": fields.get("kind"),
        "user_id": str(fields.get("user_id")),
        "api": fields.get("api") or "",
        "uri": fields.get("uri") or "",
        "status": status,
        "request_id": fields.get("request_id") or None,
        "ts": ts,
        "owner": owner,
        "detail": fields.get("detail") or "",
    }


def _family(api):
    """"GET /members/{id}/addresses" → "members" (자원 종류)"""
    path = api.split(" ", 1)[-1]
    return next((s for s in path.split("/") if s), path)


class Judge:
    """사용자별 최근 의심 이벤트를 기억하고 점수를 매겨 확정을 결정"""
    def __init__(self, cfg, confirmed_users=None):
        """cfg: config.json 내용. confirmed_users: 이미 확정된 사용자 (재시작 시 confirmed.json에서)"""
        self.window_ms = int(cfg["window_sec"]) * 1000
        self.threshold = cfg["threshold"]
        self.points = cfg["points"]
        self.bonus = cfg["bonus"]
        self.path_owners = [[s for s in t.split("/") if s] for t in cfg.get("path_owners") or []]
        self.recent = {}                                # user_id → deque[채점된 이벤트]
        self.last = {}                                  # 마지막으로 처리한 이벤트의 채점 결과 (점수 로그용)
        self.hits = {}                                  # 털린 API: user_id → {"GET /members/{id}/addresses": {피해자}}
        self.confirmed = set(confirmed_users or [])
        self.counts = {"events": 0, "scored": 0, "self_skip": 0, "hits": 0}

    def path_owner(self, uri):
        """URL이 path_owners 모양이면 그 안의 사용자 번호, 아니면 None. /members/3/addresses → "3" """
        segs = [s for s in uri.split("?")[0].split("/") if s]
        for t in self.path_owners:
            if len(segs) >= len(t) and all((NUM.match(s) if p == "{id}" else s == p) for p, s in zip(t, segs)):
                return segs[max(i for i, p in enumerate(t) if p == "{id}")]
        return None

    def classify(self, e):
        """이벤트 → (점수 항목, 피해자) . 점수를 주지 않을 이벤트면 (None, None)"""
        kind, me = e["kind"], e["user_id"]
        path_owner = self.path_owner(e["uri"])
        if kind in ("BOLA", "ATTEMPT") and path_owner == me:
            return None, None                           # 본인 번호 → 장부 오염 등으로 잘못 보고된 것
        if kind == "BOLA":
            if path_owner:
                return "BOLA_PATH", path_owner
            return "BOLA_LEDGER", e["owner"]
        if kind in ("ATTEMPT", "UNKNOWN", "RATE"):
            return kind, path_owner
        return None, None

    def score(self, events):
        """채점된 이벤트 목록 → (총점, 항목별 내역, 피해자 목록, BOLA API 목록)"""
        breakdown = {}
        for x in events:
            breakdown[x["item"]] = breakdown.get(x["item"], 0) + self.points.get(x["item"], 0)
        bolas = [x for x in events if x["item"].startswith("BOLA")]
        victims = sorted({x["victim"] for x in bolas if x["victim"]})
        # 자원 종류(경로 첫 부분) 기준: /members/{id}와 /members/{id}/addresses는 같은 회원 데이터라 1종류
        apis = sorted({_family(x["api"]) for x in bolas})
        if len(victims) >= self.bonus["victims"]["min"]:
            breakdown["+victims"] = self.bonus["victims"]["points"]
        first_attempt = min((x["ts"] for x in events if x["item"] == "ATTEMPT"), default=None)
        if first_attempt is not None and any(x["ts"] > first_attempt for x in bolas):
            breakdown["+attempt_then_bola"] = self.bonus["attempt_then_bola"]["points"]
        if len(apis) >= self.bonus["multi_api"]["min"]:
            breakdown["+multi_api"] = self.bonus["multi_api"]["points"]
        return sum(breakdown.values()), breakdown, victims, apis

    def process(self, e):
        """이벤트 하나를 채점. 새로 확정된 것들을 반환
        - URL로 확인된 BOLA는 사용자 확정과 상관없이 그 요청을 바로 확정 (type=request)
        - 점수가 threshold 이상이면 사용자 확정 (type=user, 그 사용자의 최근 의심 요청 전부 포함)
        - 이미 확정된 사용자의 새 의심 요청도 requests에 추가"""
        self.counts["events"] += 1
        item, victim = self.classify(e)
        me = e["user_id"]
        # 이번 이벤트를 어떻게 채점했는지 (실시간 점수 로그용). status: skip / confirmed_user / scored / confirmed
        self.last = {"ts": e["ts"], "user_id": me, "kind": e["kind"], "uri": e["uri"], "status": e["status"],
                     "item": item, "victim": victim, "points": self.points.get(item, 0) if item else 0}
        if item is None:
            if e["kind"] in ("BOLA", "ATTEMPT"):
                self.counts["self_skip"] += 1
            self.last["result"] = "skip"
            return []
        self.counts["scored"] += 1
        rid = e["request_id"]
        out = []
        if item.startswith("BOLA") and victim:            # 실제로 털린 것(BOLA 성공)만 API별 피해자 기록 (확정과 무관)
            hit = self.hits.setdefault(me, {}).setdefault(e["api"], set())
            if victim not in hit:
                self.counts["hits"] += 1                # 새 (공격자, API, 피해자) 조합 수 → 바뀌면 파일 저장
            hit.add(victim)
            self.last.update({"api": e["api"], "api_victims": sort_ids(hit)})

        if me in self.confirmed:                         # 이미 확정 → 점수 계산 없이 요청만 추가
            self.last["result"] = "confirmed_user"
            return [{"type": "request", "user_id": me, "request_ids": [rid], "reason": "확정 사용자의 의심 요청"}] if rid else []
        if item == "BOLA_PATH" and rid:
            out.append({"type": "request", "user_id": me, "request_ids": [rid],
                        "reason": f"URL로 확인된 BOLA ({e['uri']}, 피해자 {victim})"})

        q = self.recent.setdefault(me, deque())
        q.append({"ts": e["ts"], "item": item, "victim": victim, "api": e["api"], "request_id": rid, "uri": e["uri"]})
        while q and q[0]["ts"] < e["ts"] - self.window_ms:
            q.popleft()
        total, breakdown, victims, apis = self.score(q)
        self.last.update({"total": total, "breakdown": breakdown, "victims": victims, "events": len(q),
                          "result": "scored" if total < self.threshold else "confirmed"})
        if total < self.threshold:
            return out

        self.confirmed.add(me)
        first_ts = min(x["ts"] for x in q)
        out.append({
            "type": "user",
            "user_id": me,
            "since": first_ts,
            "score": total,
            "breakdown": breakdown,
            "victims": victims,
            "apis": apis,
            "apis_hit": self.user_hits(me),
            "events": len(q),
            "request_ids": [x["request_id"] for x in q if x["request_id"]],
            "reason": f"{self.window_ms // 3600000}시간 점수 {total} ≥ {self.threshold}",
        })
        self.recent.pop(me, None)
        return out

    def user_hits(self, user):
        """한 사용자가 턴 API와 피해자. {"GET /members/{id}": ["3", "24"], ...}"""
        return {api: sort_ids(v) for api, v in sorted((self.hits.get(user) or {}).items())}

    def breached(self):
        """API별로 누가 누구 것을 털었나. {"GET /members/{id}": {"victims": [...], "attackers": [...]}, ...}"""
        out = {}
        for user, apis in self.hits.items():
            for api, victims in apis.items():
                row = out.setdefault(api, {"victims": set(), "attackers": set()})
                row["victims"] |= victims
                row["attackers"].add(user)
        return {api: {"victims": sort_ids(r["victims"]), "attackers": sort_ids(r["attackers"])}
                for api, r in sorted(out.items())}

    def top(self, n=10):
        """확정 전 사용자 중 점수가 높은 순 (상태 출력용)"""
        rows = []
        for user, q in self.recent.items():
            if q:
                total, breakdown, victims, _ = self.score(q)
                rows.append((total, user, breakdown, len(victims)))
        return sorted(rows, reverse=True)[:n]
