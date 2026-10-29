"""실환경 스모크 테스트: alice로 로그인해 정상 요청과 BOLA 공격을 섞어 보냄 (test.ps1의 Python 버전)
엔진(python main.py run)을 켜 둔 상태에서 실행 → 30초~1분 안에 BOLA-R1/R2 위반이 찍혀야 함

역할: 엔진 코드는 아니고, 실제 Kong에 요청을 보내 Kong → Wazuh → Indexer → 엔진 전체 경로를 시험하는 도구.
대상 주소는 .env의 KONG_URL (학원 환경에서는 pc1-bola의 Kong 주소, 아직 미정)
"""
import os

import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
BASE = os.getenv("KONG_URL", "http://localhost:8000")


def login(user, password):
  r = requests.post(f"{BASE}/auth/login", json={"username": user, "password": password}, timeout=10)
  r.raise_for_status()
  return {"Authorization": f"Bearer {r.json()['accessToken']}"}


def call(method, path, headers, expect, json=None):
  r = requests.request(method, f"{BASE}{path}", headers=headers, json=json, timeout=10)
  print(f"{r.status_code}  {method:6s} {path:32s} {expect}")


if __name__ == "__main__":
  bob = login("bob", "bob123")
  alice = login("alice", "alice123")

  print("--- 장부 채우기 (bob 본인 요청) ---")
  call("GET", "/orders", bob, "bob 주문 목록 → 장부: bob 주문 = bob")
  call("GET", "/orders/2", bob, "정상")

  print("--- alice 정상 요청 ---")
  call("GET", "/members/1", alice, "정상")
  call("GET", "/orders", alice, "정상")

  print("--- BOLA 공격 (Python 룰 대상) ---")
  call("GET", "/members/2", alice, "⚠ BOLA-R1 (응답 user_id=2)")
  call("GET", "/members/2/addresses", alice, "⚠ BOLA-R1 (응답 [].user_id=2)")
  call("GET", "/orders/2", alice, "⚠ BOLA-R1 (응답 user_id=2)")
  call("PATCH", "/orders/2/delivery-memo", alice, "⚠ BOLA-R2 (응답에 주인 없음 → 장부)",
       json={"memo": "smoke test"})

  print("--- 시도 (Wazuh 룰 담당, Python은 위반 없음) ---")
  call("GET", "/profiles/2", alice, "403")
  call("GET", "/orders/999999", alice, "404")
