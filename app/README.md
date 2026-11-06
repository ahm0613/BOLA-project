# app: 게이트웨이 PC 구성
게이트웨이 PC(192.168.0.39)에서 실행되는 전체 구성이다: WAF → Kong → API 서비스, DB, Redis, 로그 수집(Fluent Bit, Wazuh agent).
이 문서의 경로는 `app/` 폴더 기준이고, `../engine/`은 저장소 루트의 탐지 엔진 폴더다.

## 저장소에 없는 파일 (직접 준비해야 하는 것)

비밀 키·인증서와 크기가 큰 생성 파일은 `.gitignore`로 제외했다. 저장소를 받은 뒤 아래 파일을 **직접 만들거나 복사해야** 시스템이 동작한다.

| 경로 | 무엇 | 쓰는 곳 | 놓는 PC |
|---|---|---|---|
| `keys/private.pem` | JWT 서명용 **개인 키** | `auth` 서비스 (토큰 발급) | 게이트웨이 (192.168.0.39) |
| `keys/public.pem` | JWT 검증용 공개 키 | API 서비스 6개 + `kong/kong.yml` | 게이트웨이 |
| `nginx/certs/server.crt`, `server.key` | WAF HTTPS 인증서 | `waf` 컨테이너 (443) | 게이트웨이 |
| `fluent-bit/certs/ca.crt`, `client.crt`, `client.key` | 로그 전송 mTLS **클라이언트** 인증서 | `fluent-bit` 컨테이너 → 탐지 엔진 | 게이트웨이 |
| `../engine/certs/ca.crt`, `server.crt`, `server.key` | 로그 수신 mTLS **서버** 인증서 | `engine/realtime.py` (5170) | 탐지 엔진 PC (192.168.0.40) |
| `../engine/root-ca.pem` | Wazuh 인덱서 CA 인증서 | `engine/ledger.py` (Wazuh 조회) | 학습 엔진을 돌리는 PC |
| `log-certs/` | mTLS 인증서를 만들 때 쓰는 작업 폴더 (CA 포함) | 만들 때만 | **어느 PC에도 두지 않는다** (아래 참고) |

> 개인 키(`*.key`, `private.pem`)는 절대 Git에 올리지 않는다. 실수로 올라갔다면 기록을 지우는 것만으로는 부족하고, **키를 새로 만들어 교체**해야 한다.

아래 명령은 `app` 폴더에서 **Git Bash**로 실행한다 (Git for Windows에 `openssl`이 들어 있다).

---

### 1. JWT 키 (`keys/`)

`auth` 서비스가 개인 키로 토큰에 서명하고, Kong과 각 API 서비스가 공개 키로 검증한다.

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

**Kong 설정에도 공개 키를 넣어야 한다.** `kong/kong.yml`의 `rsa_public_key:` 아래 블록을 새 `public.pem` 내용으로 바꾼다.
- 직접 바꾸거나,
- 기존 키 블록(`-----BEGIN PUBLIC KEY-----`부터 `-----END PUBLIC KEY-----`까지)을 `__PUBLIC_KEY__` 한 줄로 바꾼 뒤 PowerShell에서 `.\set-kong-key.ps1`을 실행하면 들여쓰기에 맞춰 자동으로 넣어 준다.

키를 바꾼 뒤에는 Kong과 서비스를 다시 시작한다. 이전에 발급된 토큰은 모두 무효가 되므로 다시 로그인해야 한다.

```bash
docker compose up -d --force-recreate kong auth members profiles orders payments catalog cart
```

### 2. WAF HTTPS 인증서 (`nginx/certs/`)

WAF(`owasp/modsecurity-crs` nginx)가 443 포트에서 쓰는 자체 서명 인증서다. 브라우저로 접속할 주소를 `subjectAltName`에 넣는다.

```bash
mkdir -p nginx/certs
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout nginx/certs/server.key -out nginx/certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.168.0.39"
```

**WAF 컨테이너는 uid 101로 실행되므로, 키 파일 소유자와 권한을 맞춰야 한다.** 맞추지 않으면 WAF가 키를 읽지 못해 재시작을 반복한다. (cmd에서 실행)

```bash
docker run --rm -v "%cd%\nginx\certs:/c" busybox:1.36 sh -c "chown 101:101 /c/server.key && chmod 400 /c/server.key"
```

### 3. 로그 전송 mTLS 인증서 (`fluent-bit/certs/`, `../engine/certs/`)

게이트웨이의 Fluent Bit이 Kong 로그를 탐지 엔진(`realtime.py`)으로 보낼 때 **서로 인증서를 확인**한다. CA 하나로 서버·클라이언트 인증서를 만든다.

| 인증서 | CN | 용도 |
|---|---|---|
| CA | `bola-log-ca` | 두 인증서에 서명 |
| 서버 | `bola-detector` | 탐지 엔진 (`serverAuth`, SAN = 탐지 엔진 PC IP) |
| 클라이언트 | `fluent-bit` | Fluent Bit (`clientAuth`) |

```bash
mkdir -p log-certs && cd log-certs

# CA (10년)
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.crt -subj "/CN=bola-log-ca"

# 서버 인증서: SAN에는 탐지 엔진 PC의 IP를 넣는다
printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.0.40\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" > server.ext
MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=bola-detector"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -extfile server.ext -out server.crt

# 클라이언트 인증서
printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" > client.ext
MSYS_NO_PATHCONV=1 openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=fluent-bit"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -extfile client.ext -out client.crt

cd ..
```

**나눠서 복사하기**

| 복사할 파일 | 위치 | PC |
|---|---|---|
| `ca.crt`, `client.crt`, `client.key` | `fluent-bit/certs/` | 게이트웨이 |
| `ca.crt`, `server.crt`, `server.key` | `../engine/certs/` | 탐지 엔진 PC |

```bash
mkdir -p fluent-bit/certs ../engine/certs
cp log-certs/ca.crt log-certs/client.crt log-certs/client.key fluent-bit/certs/
cp log-certs/ca.crt log-certs/server.crt log-certs/server.key ../engine/certs/
```

> **`log-certs/ca.key`는 두 PC 어디에도 남기지 않는다.** 이 키가 있으면 누구나 "믿을 수 있는" 인증서를 만들 수 있다. USB 등에 따로 보관하고, 인증서를 새로 만들 때만 꺼내 쓴다.

> 참고: 지금 쓰고 있는 서버 인증서는 SAN이 `192.168.0.39`인데, Fluent Bit이 접속하는 탐지 엔진은 `192.168.0.40`이다. Fluent Bit은 기본 설정에서 이름(SAN)을 확인하지 않아 동작은 하지만, 새로 만들 때는 위처럼 **탐지 엔진 PC의 IP**를 넣는 것이 맞다.

### 4. Wazuh 인덱서 CA (`../engine/root-ca.pem`)

`ledger.py`가 Wazuh 인덱서(`https://192.168.0.26:9200`)에 HTTPS로 접속할 때 서버 인증서를 확인하는 데 쓴다. 새로 만드는 것이 아니라 **Wazuh 서버에서 복사**한다.

- Wazuh 서버의 인덱서 인증서 폴더에 있는 `root-ca.pem`을 `../engine/root-ca.pem`으로 복사한다. (일반적인 설치에서는 `/etc/wazuh-indexer/certs/root-ca.pem`)
- Wazuh 계정은 코드에 쓰지 않고 환경 변수로 넣는다: `WAZUH_USER`, `WAZUH_PASS` (읽기 전용 계정 권장).
- 인덱서 인증서에 적힌 이름은 `wazuh.indexer`이고, `ledger.py`의 `WAZUH_CERT_NAME`과 같아야 한다.

---

## 저장소에 없는 생성 파일

다시 만들 수 있는 파일이라 올리지 않았다.

| 경로 | 만드는 방법 |
|---|---|
| `../engine/test_users.csv`, `../engine/test_users_more.csv` | `python db\make_seed.py`, `python db\make_more_users.py` (테스트 계정 비밀번호가 평문으로 들어 있다) |
| `../engine/data/access_fake*.json` | DB를 띄운 상태에서 `python db\gen_fake_logs.py --scale 2 --attack-days 0` (공격 없는 로그) |
| `../engine/ledger_days/` | 탐지 PC의 `engine` 폴더에서 `python ledger_v2.py` (`ledger.json`도 다시 만들어짐) |
| `../engine/confirmed.json` | 판단 엔진(`judge/`)이 확정한 공격자·요청 기록 |
| `logs/` | 실행 중에 생기는 API 서버 로그 |

## 처음 설치할 때 순서

1. 위 1~4번으로 키와 인증서를 준비한다.
2. 게이트웨이 PC에서 `docker compose up -d`로 전체를 띄운다.
3. 탐지 엔진 PC에서 장부를 학습하고(`engine` 폴더에서 `python ledger_v2.py`), `engine` 폴더와 `judge` 폴더에서 각각 `docker compose up -d --build`로 탐지 엔진과 판단 엔진을 띄운다. 자세한 내용은 `engine/README.md`, `judge/README.md`.
4. `https://192.168.0.39`로 접속해서 로그인이 되는지 확인한다.

## 참고

- `docker-compose.yml`에는 실험용 DB·Redis 비밀번호가 들어 있다. 폐쇄망 실험용이며, 실제로 운영한다면 `.env`로 분리해야 한다.
- Kong 관리 포트(8001)는 `127.0.0.1`에만 열려 있다. 외부에 열지 않는다.
