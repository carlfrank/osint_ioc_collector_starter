from datetime import datetime
import time

def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def safe_strip(s: str) -> str:
    return s.strip() if isinstance(s, str) else s
