"""영구 차단: 확정된 공격자를 Redis에 만료 없이 등록 → pc2 Kong이 요청마다 확인해서 403

pc2 담당자가 정한 방식 그대로 (Kong은 blocked:user:<id> 키가 있기만 하면 막음, kong.yml post-function)
  blocked:user:<id>  "confirmed"  TTL 없음 = 영구
  block:info:<id>    {reason, blocked_at(ms), by}  왜·언제·누가 막았는지 (Kong은 보지 않음, 사람이 확인용)

기준 명단은 confirmed.json의 users. Redis 키가 사라졌거나(Redis 초기화) realtime.py RATE의 10분 키로
덮여 만료가 붙었으면 sync()가 다시 영구로 건다. Redis 연결·비밀번호는 판단 서버와 같은 것(.env)을 쓴다.
"""
import time

import redis

KEY = "blocked:user:{}"
INFO = "block:info:{}"
VALUE = "confirmed"


class Blocker:
    """Redis 영구 차단 키를 걸고 풀고 맞춤. Redis 오류는 예외 대신 False/0으로 돌려줘서 판단이 멈추지 않게 함"""
    def __init__(self, r):
        """r: redis.Redis (decode_responses=True)"""
        self.r = r
        self.counts = {"blocked": 0, "failed": 0}

    def block_forever(self, user_id, reason, by="judge"):
        """영구 차단. 성공 True, Redis 오류면 False (다음 sync 때 다시 시도됨)"""
        user_id = str(user_id)
        try:
            p = self.r.pipeline()
            p.set(KEY.format(user_id), VALUE)            # ex 없음 → 영구. RATE의 10분 키가 있으면 덮어써서 만료를 없앰
            p.hset(INFO.format(user_id), mapping={"reason": reason, "blocked_at": int(time.time() * 1000), "by": by})
            p.execute()
        except redis.RedisError as err:
            self.counts["failed"] += 1
            print(f"[차단] 사용자 {user_id} 영구 차단 실패: {err} → 다음 동기화 때 다시 시도", flush=True)
            return False
        self.counts["blocked"] += 1
        print(f"[차단] 사용자 {user_id} 영구 차단 (blocked:user:{user_id}) {reason}", flush=True)
        return True

    def not_blocked(self, users):
        """users 중 영구 차단 키가 없는 사용자 목록. TTL -1 = 영구, -2 = 키 없음, 양수 = 만료가 붙은 임시 차단"""
        users = [str(u) for u in users]
        if not users:
            return []
        p = self.r.pipeline()
        for u in users:
            p.ttl(KEY.format(u))
        return [u for u, ttl in zip(users, p.execute()) if ttl != -1]

    def sync(self, users):
        """confirmed.json 명단과 Redis를 맞춤: 영구 차단 키가 없는 사용자를 다시 차단. 새로 건 수"""
        try:
            missing = self.not_blocked(users)
        except redis.RedisError as err:
            print(f"[차단] 명단 동기화 실패 (Redis): {err}", flush=True)
            return 0
        return sum(self.block_forever(u, "confirmed.json 확정 사용자 (명단 동기화)") for u in missing)

    def unblock(self, user_id):
        """차단 해제 (키 두 개 삭제). 지운 키 수"""
        user_id = str(user_id)
        return self.r.delete(KEY.format(user_id), INFO.format(user_id))
