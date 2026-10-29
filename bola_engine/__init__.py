"""bola_engine: BOLA 탐지 엔진 패키지

역할: main.py가 불러 쓰는 엔진 본체. 로그 입력 → 이벤트 정리 → 룰 판정 → 위반 출력까지를 나눠 맡는다.

  config.py    설정 읽기 (config.yaml + .env)
  sources.py   로그 입력 (Wazuh Indexer 조회, 파일 리플레이, 체크포인트)
  event.py     로그 한 건 → 이벤트 정리, URL에서 API·객체 뽑기
  ledger.py    장부: 객체 → 주인 기억 (R2·R3가 사용)
  rules.py     BOLA 룰 R1~R6 판정 (Detector)
  output.py    위반 출력 (콘솔 + JSONL)
  evaluate.py  리플레이 결과 채점·요약 (정답지 대조)
"""
