# 실시간 탐지 엔진 이미지 (realtime.py)
# 역할: Fluent Bit이 mTLS로 보내는 Kong 로그를 받아 장부로 BOLA 판정 → Redis bola:events 보고
# 코드·장부(ledger.json)·인증서(certs)·.env는 이미지에 넣지 않고, docker-compose.yml이 이 폴더를 /app에 읽기 전용으로 붙임
#   → 장부를 다시 학습하면 realtime.py가 60초 안에 자동으로 다시 읽고, 코드를 고치면 재시작만 하면 됨
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Seoul

RUN pip install --no-cache-dir "redis>=5.0"
WORKDIR /app
EXPOSE 5170
CMD ["python", "realtime.py"]
