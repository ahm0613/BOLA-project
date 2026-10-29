# 판단 서버 이미지
# 역할: bola-rule이 쓴 violations-*.jsonl을 읽어 사용자별 점수(scores.json)를 주기적으로 다시 계산
# 표준 라이브러리만 써서 설치할 패키지가 없음
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=KST-9

# config.json의 입력 경로 ../bola-rule/output/... 가 그대로 맞도록 /app/judge-server에 둠
# (bola-rule의 output 폴더를 /app/bola-rule/output에 붙임, docker-compose.yml 참고)
WORKDIR /app/judge-server

COPY judge.py config.json ./

VOLUME ["/app/judge-server/output"]

# 1초마다 다시 계산 (바꾸려면 docker-compose.yml의 command 수정)
CMD ["python", "judge.py", "--watch", "1"]
