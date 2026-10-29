# bola-rule 탐지 엔진 이미지
# 역할: Wazuh Indexer(bola-api-*)를 주기적으로 조회해 BOLA 룰(R1~R6)을 판정하는 main.py run을 컨테이너로 실행
# 접속 정보(.env)와 CA 인증서(root-ca.pem)는 이미지에 넣지 않고 실행할 때 파일로 붙인다 (docker-compose.yml 참고)
FROM python:3.12-slim

# PYTHONUNBUFFERED: 로그를 바로 출력 / TZ: 한국 시간 (tzdata 없이 쓰는 POSIX 표기, UTC+9)
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=KST-9

# judge-server 컨테이너와 같은 폴더 모양(/app/bola-rule, /app/judge-server)을 쓰려고 /app 아래에 둠
WORKDIR /app/bola-rule

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py config.yaml ./
COPY bola_engine ./bola_engine

# 장부·체크포인트(state)와 위반·API 로그(output)는 컨테이너를 지워도 남도록 볼륨으로 뺌
VOLUME ["/app/bola-rule/state", "/app/bola-rule/output"]

CMD ["python", "main.py", "run"]
