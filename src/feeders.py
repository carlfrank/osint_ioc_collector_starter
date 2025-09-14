import requests
from typing import Optional

def fetch_text(url: str, timeout: int = 20) -> Optional[str]:
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        # Many feeds are plain text or CSV
        return resp.text
    except Exception as e:
        print(f"[WARN] Could not fetch {url}: {e}")
        return None
