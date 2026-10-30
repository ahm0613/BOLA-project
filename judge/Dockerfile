# 판단 서버 이미지
# 역할: Redis bola:events를 읽어 점수 → 공격자 확정 → confirmed.json, 판단·조치·사용자 상태를 PostgreSQL에 기록
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Seoul

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY judge.py scoring.py store.py db.py config.json ./

VOLUME ["/app/output"]
CMD ["python", "judge.py"]
