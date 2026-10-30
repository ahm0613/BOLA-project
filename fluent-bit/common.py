import json
import os
import re
import time


def parse_line(line):
    """한 줄 → 딕셔너리. 빈 줄·깨진 줄이면 None"""
    line = line.strip().strip("\x00")
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def load_logs(path):
    """파일 전체를 한 번에 읽기 (학습용)"""
    logs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e is not None:
                logs.append(e)
    return logs


def follow(path, from_start=False):
    """파일 끝에 새로 추가되는 줄만 계속 읽기 (실시간 탐지용, tail -f 와 같음)"""
    with open(path, encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)          # 지금 파일 끝으로 이동 → 이후 새 줄만
        pending = ""
        while True:
            line = f.readline()
            if not line:                    # 새 줄 없음
                if os.path.getsize(path) < f.tell():
                    f.seek(0)               # 파일이 비워졌거나 새로 만들어짐 → 처음부터
                time.sleep(0.5)
                continue
            if not line.endswith("\n"):     # Kong이 아직 쓰는 중인 줄 → 모아 두기
                pending += line
                continue
            e = parse_line(pending + line)
            pending = ""
            if e is not None:
                yield e


def api_key(e):
    """GET /orders/7  →  GET /orders/{id}"""
    path = e["uri"].split("?")[0]
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return f'{e["method"]} {path}'