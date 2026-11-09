"""점수 계산: Redis 이벤트 한 건씩 받아 사용자별 점수를 쌓고, 기준을 넘으면 공격자로 확정

역할: 판단 서버의 핵심 로직. Redis·파일을 모르고 이벤트 dict만 다룬다 (테스트하기 쉽게).
  Judge.process(이벤트) → 이번에 새로 생긴 확정 목록 [{"type": "user"|"request", ...}]

점수 (config.json에서 조정. window_sec 동안 합산, window_sec이 0이면 기간 제한 없이 누적)
  BOLA_PATH    /members/{id} 처럼 URL 숫자가 곧 사용자 번호인 API에서 남의 번호 → 확실
  BOLA_LEDGER  그 밖의 BOLA (realtime.py 장부 근거, 장부가 틀릴 수 있음)
  *_WRITE      위 BOLA를 PUT/PATCH/DELETE(남의 객체 수정·삭제)로 한 경우 → 조회보다 위험하므로 더 높은 점수
               (BOLA_PATH_WRITE, BOLA_LEDGER_WRITE). 메서드는 이벤트의 api("PATCH /members/{id}")에서 읽음
  ATTEMPT / UNKNOWN / RATE  realtime.py의 kind 그대로
  단, path_owners API(/members/{id} 등)에서 장부에 없어 UNKNOWN으로 온 성공(200/204) 요청은
  URL 번호로 주인을 알 수 있으므로 BOLA_PATH로 올림
  보너스: 서로 다른 피해자 여러 명, ATTEMPT 뒤 BOLA 성공, 여러 자원 종류(members·orders…)에서 BOLA

오탐 거르기: URL 숫자가 요청자 본인인 BOLA·ATTEMPT는 점수를 주지 않음 (장부 오염으로 잘못 보고된 경우)

위험도와 단계 (화면·DB용. 확정 판단은 점수로만 함)
  위험도(%) = min(점수 ÷ threshold, 1) × 100. 100% = 차단. 100점을 넘은 점수(150 등)는 차단 근거로만 남김
  단계: 정상 normal → 주의 caution(10) → 위험 danger(30) → 고위험 high(60) → 차단 attack(threshold)
        경계는 config.json의 levels (점수 기준, threshold 100이면 % 기준과 같음)
"""
import re
from collections import deque

NUM = re.compile(r"^\d+$")
OWNER_IN_DETAIL = re.compile(r"주인 (\d+)")
WRITE_METHODS = {"PUT", "PATCH", "DELETE"}             # 남의 객체에 쓰기(수정·삭제) = 조회보다 위험
SUCCESS = (200, 204)                                    # realtime.py와 같음: 데이터를 받아 가거나 지운 요청
DEFAULT_LEVELS = {"caution": 10, "danger": 30, "high": 60}   # config.json에 levels가 없을 때
LEVEL_LABELS = {"normal": "정상", "caution": "주의", "danger": "위험", "high": "고위험", "attack": "차단"}


def level_label(name):
    """단계 코드 → 화면·알림용 한국어 이름. 모르는 코드는 그대로"""
    return LEVEL_LABELS.get(name, name)


def sort_ids(ids):
    """ID 목록을 숫자 순으로 정렬 (숫자가 아닌 값은 뒤로). {"24", "3"} → ["3", "24"]"""
    return sorted(ids, key=lambda v: (0, int(v), "") if str(v).isdigit() else (1, 0, str(v)))


def object_id(uri):
    """URL의 객체 번호. /orders/99 → "99", /members/4/addresses/5 → "4/5". 번호가 없으면 None
    "털린 API"에 주인(피해자)이 아니라 실제로 접근한 객체 번호를 보여 주기 위해 씀"""
    ids = re.findall(r"/(\d+)(?=/|$)", uri.split("?")[0])
    return "/".join(ids) if ids else None


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
    def __init__(self, cfg, confirmed_users=None, released=None):
        """cfg: config.json 내용. confirmed_users: 이미 확정된 사용자 (재시작 시 confirmed.json에서)
        released: 관리자가 해제한 사용자 → 해제 시각(ms). 그 이전 이벤트는 채점하지 않음 (다시 확정되지 않게)"""
        self.window_ms = int(cfg.get("window_sec") or 0) * 1000    # 0 = 영구 누적 (오래된 이벤트를 빼지 않음)
        self.window_label = f"{self.window_ms // 3600000}시간" if self.window_ms else "누적"   # 판단 사유 문구용
        self.threshold = cfg["threshold"]
        self.points = cfg["points"]
        self.bonus = cfg["bonus"]
        po = cfg.get("path_owners")
        self.set_path_owners(po if isinstance(po, list) else [])   # "auto"면 판단 서버가 장부로 추론해 나중에 넣음
        self.recent = {}                                # user_id → deque[채점된 이벤트]
        self.last = {}                                  # 마지막으로 처리한 이벤트의 채점 결과 (점수 로그용)
        self.hits = {}                                  # 털린 API: user_id → {"GET /members/{id}/addresses": {털린 객체 번호}}
        # 단계: 점수가 낮은 순으로 (이름, 기준). 마지막 attack은 threshold와 같음 (확정)
        levels = cfg.get("levels") or DEFAULT_LEVELS
        self.levels = sorted(levels.items(), key=lambda x: x[1]) + [("attack", self.threshold)]
        self.level_rank = {name: i + 1 for i, (name, _) in enumerate(self.levels)}   # 단계 코드 → 순번 (normal은 0)
        self.level = {}                                 # user_id → 지금까지 올라간 가장 높은 단계 순번 (0=normal)
        self.scores = {}                                # user_id → 마지막으로 계산한 점수 (확정 뒤 이벤트의 risk_score용)
        self.confirmed = set(confirmed_users or [])
        self.released = {str(u): int(ms) for u, ms in (released or {}).items()}
        self.counts = {"events": 0, "scored": 0, "self_skip": 0, "hits": 0}

    def set_path_owners(self, templates):
        """URL 번호 = 사용자 번호인 경로 목록을 바꿈. ["/members/{id}", ...] (수동 설정 또는 api_infer.py 추론 결과)"""
        self.path_owner_list = list(templates)
        self.path_owners = [[s for s in t.split("/") if s] for t in self.path_owner_list]

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
        if kind in ("BOLA", "ATTEMPT", "UNKNOWN") and path_owner == me:
            return None, None                           # 본인 번호 → 장부 오염·장부 미학습으로 잘못 보고된 것
        # 남의 객체에 쓰기(PUT/PATCH/DELETE)면 _WRITE 항목으로 더 높은 점수. 메서드는 api 앞부분에서 읽음
        write = e.get("api", "").split(" ", 1)[0] in WRITE_METHODS
        # URL 번호 = 주인인 API는 장부가 없어도 주인을 앎 → 장부에 없어 UNKNOWN으로 온 성공 요청도 BOLA_PATH
        if path_owner and (kind == "BOLA" or (kind == "UNKNOWN" and e["status"] in SUCCESS)):
            return ("BOLA_PATH_WRITE" if write else "BOLA_PATH"), path_owner
        if kind == "BOLA":
            return ("BOLA_LEDGER_WRITE" if write else "BOLA_LEDGER"), e["owner"]
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
        # 이번 이벤트를 어떻게 채점했는지 (실시간 점수 로그용). result: released / skip / confirmed_user / scored / confirmed
        self.last = {"ts": e["ts"], "user_id": me, "kind": e["kind"], "uri": e["uri"], "status": e["status"],
                     "event_api": e["api"], "request_id": e["request_id"], "detail": e["detail"],
                     "item": item, "victim": victim, "points": self.points.get(item, 0) if item else 0,
                     "score": self.scores.get(me)}       # 점수를 다시 계산하지 않는 이벤트(무시·확정 사용자)는 마지막 점수
        if e["ts"] <= self.released.get(me, 0):           # 관리자가 해제하기 전 이벤트 → 다시 확정하지 않게 채점 안 함
            self.last["result"] = "released"
            return []
        if item is None:
            if e["kind"] in ("BOLA", "ATTEMPT"):
                self.counts["self_skip"] += 1
            self.last["result"] = "skip"
            return []
        self.counts["scored"] += 1
        rid = e["request_id"]
        out = []
        obj = object_id(e["uri"])                         # 털린 API에는 주인이 아니라 접근한 객체 번호를 기록
        if item.startswith("BOLA") and obj:               # 실제로 털린 것(BOLA 성공)만 API별 객체 번호 기록 (확정과 무관)
            hit = self.hits.setdefault(me, {}).setdefault(e["api"], set())
            if obj not in hit:
                self.counts["hits"] += 1                # 새 (공격자, API, 객체) 조합 수 → 바뀌면 파일 저장
            hit.add(obj)
            self.last.update({"api": e["api"], "api_objects": sort_ids(hit)})

        if me in self.confirmed:                         # 이미 확정 → 점수 계산 없이 요청만 추가
            self.last["result"] = "confirmed_user"
            return [{"type": "request", "user_id": me, "request_ids": [rid], "reason": "확정 사용자의 의심 요청"}] if rid else []
        if item.startswith("BOLA_PATH") and rid:         # 쓰기(BOLA_PATH_WRITE)도 URL로 확인되므로 즉시 요청 확정
            out.append({"type": "request", "user_id": me, "request_ids": [rid],
                        "reason": f"URL로 확인된 BOLA ({e['uri']}, 피해자 {victim})"})

        q = self.recent.setdefault(me, deque())
        q.append({"ts": e["ts"], "item": item, "victim": victim, "api": e["api"], "request_id": rid, "uri": e["uri"]})
        while self.window_ms and q and q[0]["ts"] < e["ts"] - self.window_ms:
            q.popleft()
        total, breakdown, victims, apis = self.score(q)
        self.scores[me] = self.last["score"] = total
        rank = sum(1 for _, need in self.levels if total >= need)   # 0=normal, 1=caution … 마지막=attack
        self.last.update({"total": total, "risk_pct": self.risk_pct(total),
                          "breakdown": breakdown, "victims": victims, "events": len(q),
                          "first_ts": q[0]["ts"], "level": self.level_name(max(rank, self.level.get(me, 0))),
                          "result": "scored" if total < self.threshold else "confirmed"})
        if rank > self.level.get(me, 0):                 # 단계가 올라갔을 때만 탐지 사건 (내려가는 것은 기록 안 함)
            self.level[me] = rank
            need = self.levels[rank - 1][1]
            self.last["level_up"] = {"decision": self.level_name(rank), "need": need,
                                     "reason": f"{self.window_label} 점수 {total}점 ≥ "
                                               f"{level_label(self.level_name(rank))} 기준 {need}점"}
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
            "reason": f"{self.window_label} 점수 {total} ≥ {self.threshold}",
        })
        self.recent.pop(me, None)
        return out

    def level_name(self, rank):
        """단계 순번 → 이름. 0=normal, 1부터 levels 순서 (caution, danger, high, attack)"""
        return "normal" if rank <= 0 else self.levels[rank - 1][0]

    def risk_pct(self, score):
        """점수 → 위험도(%). 차단 기준(threshold)이 100%, 넘어도 100. 점수가 없으면 None
        내림으로 계산해서 기준에 못 미친 점수가 100%로 보이지 않게 함 (99.9% → 99)"""
        if score is None:
            return None
        return max(0, min(100, int(score) * 100 // self.threshold))

    def user_hits(self, user):
        """한 사용자가 턴 API와 털린 객체 번호. {"GET /members/{id}": ["3", "24"], ...}"""
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
