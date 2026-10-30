"""confirmed.json 읽기·쓰기 + 확정 근거 기록(confirmed_log.jsonl)

역할: 판단 서버의 출구. ledger_v2.py가 장부를 학습할 때 이 파일의 요청·사용자를 빼고 학습한다.

  {"requests": ["979917aa-...", ...],         확정된 공격 요청 request_id
   "users": {"43": 1792681200000, ...}}       확정된 사용자 → 이 시각(ms) 이후 요청을 학습에서 제외

파일은 임시 파일에 쓴 뒤 바꿔치기해서, 다른 프로그램이 쓰다 만 파일을 읽지 않게 한다.
"""
import json
import os
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))


class ConfirmedStore:
    """확정 목록. 한 번 들어간 요청·사용자는 지우지 않음 (잘못 확정되면 사람이 파일에서 직접 지움)"""
    def __init__(self, path, log_path):
        """path: confirmed.json, log_path: 확정 근거를 한 줄씩 남길 jsonl"""
        self.path = path
        self.log_path = log_path
        self.requests = []
        self._request_set = set()
        self.users = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for rid in data.get("requests") or []:
                self._add_request(rid)
            self.users = {str(k): int(v) for k, v in (data.get("users") or {}).items()}
        if log_path:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)

    def _add_request(self, rid):
        """요청 하나 추가. 새로 들어갔으면 True"""
        if not rid or rid in self._request_set:
            return False
        self._request_set.add(rid)
        self.requests.append(rid)
        return True

    def apply(self, decisions):
        """Judge가 낸 확정들을 반영하고 근거를 기록. 바뀐 것이 있으면 True"""
        changed = False
        for d in decisions:
            added = [rid for rid in d.get("request_ids", []) if self._add_request(rid)]
            if d["type"] == "user":
                since = min(d["since"], self.users.get(d["user_id"], d["since"]))
                if self.users.get(d["user_id"]) != since:
                    self.users[d["user_id"]] = since
                    changed = True
            changed = changed or bool(added)
            if d["type"] == "user" or added:
                self._log({**d, "added_requests": len(added)})
        return changed

    def _log(self, d):
        """확정 근거 한 줄 기록 (사람이 오탐 여부를 판단할 때 봄). log_path가 None이면 기록 안 함 (dry-run)"""
        if not self.log_path:
            return
        row ={"logged_at": datetime.now(KST).isoformat(timespec="seconds"), **d}
        if "since" in row:
            row["since_time"] = datetime.fromtimestamp(row["since"] / 1000, KST).isoformat(timespec="seconds")
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def save(self):
        """confirmed.json 저장 (임시 파일에 쓴 뒤 바꿔치기)"""
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"requests": self.requests, "users": self.users}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)
