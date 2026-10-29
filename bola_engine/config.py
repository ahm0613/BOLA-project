"""config.yaml(룰·동작 설정) + .env(Indexer 접속 정보) 읽기"""
import os

import yaml
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config(path=None):
  load_dotenv(os.path.join(BASE_DIR, ".env"))
  with open(path or os.path.join(BASE_DIR, "config.yaml"), encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

  # 상대 경로는 PYTHON-ENGIN 폴더 기준으로
  for k, v in (cfg.get("paths") or {}).items():
    if not os.path.isabs(v):
      cfg["paths"][k] = os.path.join(BASE_DIR, v)

  cfg["indexer"]["url"] = os.getenv("INDEXER_URL", "https://localhost:9200")
  cfg["indexer"]["user"] = os.getenv("INDEXER_USER", "admin")
  cfg["indexer"]["password"] = os.getenv("INDEXER_PASSWORD", "")
  verify = os.getenv("INDEXER_VERIFY_TLS", "false")
  # false / true / CA 인증서 경로 (상대 경로는 이 폴더 기준)
  verify = {"false": False, "true": True}.get(verify.lower(), verify)
  if isinstance(verify, str) and not os.path.isabs(verify):
    verify = os.path.normpath(os.path.join(BASE_DIR, verify))
  cfg["indexer"]["verify"] = verify
  # 인증서에 IP가 없을 때 검사에 쓸 이름 (예: wazuh.indexer)
  cfg["indexer"]["tls_hostname"] = os.getenv("INDEXER_TLS_HOSTNAME") or None
  return cfg
