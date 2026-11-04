"""1대1 추론 엔진: 학습 장부(ledger.json)만 보고 "URL 번호 = 사용자 번호"인 API를 찾아 path_owners를 만듦

역할: 사람이 앱 소스를 보고 config.json에 적던 path_owners를 트래픽 학습 결과로 대신한다.
  BOLA-APP의 코드·DB는 보지 않는다. Redis·파일을 모르고 장부 dict만 다룬다 (테스트하기 쉽게).

원리: 정상 사용자는 자기 것만 본다. 그래서 /members/{id}처럼 번호가 곧 사용자 번호인 API는
  학습된 주인이 번호와 늘 같고(225=225), /orders/{id}처럼 객체 번호인 API는 거의 다르다(1203=400).

판정 (자원 = API 키를 첫 {id}까지 자른 것. GET·PATCH·하위 경로를 한 자원으로 묶음)
  표본 min_samples개 이상 + 일치율 min_ratio 이상 → one_to_one (path_owners에 넣음)
  표본 min_samples개 이상 + 일치율 max_ratio 이하 → ledger (장부로 판단)
  그 사이이거나 표본 부족                          → undecided (쓰지 않음)
  주인이 null인 공유 객체는 표본에서 뺌

덤: one_to_one 자원에서 번호 ≠ 주인인 항목은 장부 오염(공격 흔적)일 가능성이 높아 따로 돌려줌

  python api_infer.py                      장부를 읽어 결과 출력 (judge 폴더에서, config.json 경로 사용)
  python api_infer.py ..\\fluent-bit\\ledger.json
"""
import json
import os
import sys
from collections import Counter

DEFAULTS = {"min_samples": 30, "min_ratio": 0.95, "max_ratio": 0.05}
MAX_MISMATCHES = 50                                     # one_to_one 자원마다 돌려줄 불일치 항목 수 (메모리·로그 보호)


def resource_of(api):
    """"GET /members/{id}/addresses" → "/members/{id}" (첫 {id}까지). {id}가 없으면 None"""
    path = api.split(" ", 1)[-1]
    i = path.find("{id}")
    return path[:i + 4] if i >= 0 else None


def infer(ledger, min_samples=DEFAULTS["min_samples"], min_ratio=DEFAULTS["min_ratio"],
          max_ratio=DEFAULTS["max_ratio"]):
    """장부 → (path_owners 목록, 자원별 통계)
    통계: {"/members/{id}": {"samples", "match", "mismatch", "shared", "ratio", "decision",
                              "mismatches": [(api, 객체번호, 주인), ...], "suspects": {주인: 건수}}}"""
    stats = {}
    for api, objs in (ledger or {}).items():
        res = resource_of(api)
        if res is None:
            continue
        s = stats.setdefault(res, {"match": 0, "mismatch": 0, "shared": 0, "mismatches": []})
        for oid, owner in (objs or {}).items():
            if owner is None:
                s["shared"] += 1
            elif str(oid).split("/")[0] == str(owner):      # 번호가 여러 개면(4/55) 첫 번호가 사용자 번호 후보
                s["match"] += 1
            else:
                s["mismatch"] += 1
                s["mismatches"].append((api, str(oid), str(owner)))

    owners = []
    for res, s in stats.items():
        n = s["match"] + s["mismatch"]
        s["samples"] = n
        s["ratio"] = s["match"] / n if n else 0.0
        if n >= min_samples and s["ratio"] >= min_ratio:
            s["decision"] = "one_to_one"
            owners.append(res)
            s["suspects"] = dict(Counter(o for _, _, o in s["mismatches"]).most_common())
            s["mismatches"] = s["mismatches"][:MAX_MISMATCHES]
        else:
            s["decision"] = "ledger" if n >= min_samples and s["ratio"] <= max_ratio else "undecided"
            s["suspects"] = {}
            s["mismatches"] = []                        # 1대1이 아니면 불일치가 정상이라 보관하지 않음
    return sorted(owners), stats


def load_ledger(path):
    """ledger.json → dict. 없거나 깨졌으면 None"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


LABEL = {"one_to_one": "1대1", "ledger": "장부 사용", "undecided": "판단 보류"}


def describe(owners, stats):
    """로그용 줄 목록 (일치율 높은 순)"""
    lines = []
    for res, s in sorted(stats.items(), key=lambda kv: (-kv[1]["ratio"], kv[0])):
        lines.append(f"[1대1 추론] {res:<22} 표본 {s['samples']:>5}건, 일치 {s['match']:>5}건 "
                     f"({s['ratio'] * 100:5.1f}%) → {LABEL[s['decision']]}")
        if s["suspects"]:
            top = ", ".join(f"{u}({n}건)" for u, n in list(s["suspects"].items())[:5])
            lines.append(f"            번호≠주인 {s['mismatch']}건 (장부 오염 의심), 주인으로 적힌 사용자: {top}")
    lines.append(f"[1대1 추론] path_owners = {owners}")
    return lines


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "config.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(base, cfg["paths"].get("ledger", "../fluent-bit/ledger.json"))
    ledger = load_ledger(path)
    if ledger is None:
        sys.exit(f"장부를 읽을 수 없습니다: {path}")
    owners, stats = infer(ledger, **{**DEFAULTS, **(cfg.get("path_infer") or {})})
    print(f"장부: {os.path.normpath(path)}")
    print("\n".join(describe(owners, stats)))


if __name__ == "__main__":
    main()
