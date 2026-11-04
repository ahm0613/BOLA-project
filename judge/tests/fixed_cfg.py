"""테스트용 고정 설정: 운영 config.json의 점수·path_owners를 바꿔도 테스트가 로직만 검증하게 기준값으로 덮어씀

운영에서는 점수를 조정하거나(예: 운영 config.json은 RATE=10) path_owners를 "auto"·[]로 바꿀 수 있지만,
테스트의 기대값(40+40+40=120, 40+20+40=100 등)은 아래 기준값으로 계산돼 있다.
"""
POINTS = {"BOLA_PATH": 40, "BOLA_PATH_WRITE": 60, "BOLA_LEDGER": 25, "BOLA_LEDGER_WRITE": 40,
          "ATTEMPT": 5, "UNKNOWN": 20, "RATE": 20}
PATH_OWNERS = ["/members/{id}", "/profiles/{id}"]


def pin(cfg):
    """설정 dict의 점수·path_owners를 기준값으로 바꿔서 돌려줌"""
    cfg["points"] = dict(POINTS)
    cfg["path_owners"] = list(PATH_OWNERS)
    return cfg
