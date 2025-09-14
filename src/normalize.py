import csv
import io
import re
from typing import Iterable, Dict, List
from .utils import utc_now_iso, safe_strip

# Regex for IPv4 (optionally with CIDR) and SHA256 hashes
IP_CIDR_RE = re.compile(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/\d{1,2})?\s*$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def parse_spamhaus_drop(text: str, source: str) -> Iterable[Dict]:
    """
    Parse Spamhaus DROP plain-text list.
    Lines look like: '203.0.113.0/24 ; comment'
    We keep the left-hand token (IP or CIDR).
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip_cidr = line.split(";")[0].strip()
        if IP_CIDR_RE.match(ip_cidr):
            yield {
                "indicator": ip_cidr,
                "type": "ip",
                "source": source,
                "first_seen": utc_now_iso(),
            }


def parse_urlhaus_csv(text: str, source: str) -> Iterable[Dict]:
    """
    Parse URLhaus CSV and **collapse full URLs to domains**.
    Expected header:
      id,dateadded,url,url_status,threat,urlhaus_link,reporter

    Why collapse?
    - URLhaus contains many distinct URLs from the same host.
      Converting to domains reduces noise and creates logical deduplication.

    Fields produced:
      indicator -> <domain.tld> (lowercased)
      type      -> "domain"
      source    -> source name passed in
      first_seen-> dateadded (fallback to now)
      category  -> threat (e.g., 'phishing', 'malware_download')
    """
    f = io.StringIO(text)
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#") or row[0].lower() == "id":
            continue
        try:
            _, dateadded, url, _url_status, threat, *_ = row
        except ValueError:
            # Skip malformed rows
            continue

        url = safe_strip(url)
        if not url:
            continue

        # --- Normalization: keep only the host (domain[:port]) from the URL ---
        u = url.lower()
        if "://" in u:
            u = u.split("://", 1)[1]
        domain = u.split("/", 1)[0]          # drop path/query
        # If you prefer to drop ports as well, uncomment the next line:
        # domain = domain.split(":", 1)[0]

        category = (threat or "").strip().lower()

        yield {
            "indicator": domain,
            "type": "domain",
            "source": source,
            "first_seen": dateadded or utc_now_iso(),
            "category": category,  # extra metadata from URLhaus
        }


def parse_malwarebazaar_csv(text: str, source: str) -> Iterable[Dict]:
    """
    Parse MalwareBazaar CSV and extract SHA256 hashes either from the 'sha256'
    column or by scanning cells for 64-hex tokens.
    """
    f = io.StringIO(text)
    reader = csv.reader(f)
    header = next(reader, [])
    # Try to locate a column named 'sha256'
    sha_idx = None
    for i, name in enumerate(header):
        if (name or "").strip().lower() == "sha256":
            sha_idx = i
            break
    if sha_idx is not None:
        for row in reader:
            if sha_idx < len(row):
                h = (row[sha_idx] or "").strip()
                if SHA256_RE.match(h):
                    yield {
                        "indicator": h.lower(),
                        "type": "hash",
                        "source": source,
                        "first_seen": utc_now_iso(),
                    }
    else:
        # Fallback: scan every cell for SHA256-like tokens
        for row in reader:
            for cell in row:
                cell = (cell or "").strip()
                if SHA256_RE.match(cell):
                    yield {
                        "indicator": cell.lower(),
                        "type": "hash",
                        "source": source,
                        "first_seen": utc_now_iso(),
                    }


def normalize_records(records: Iterable[Dict]) -> List[Dict]:
    """
    Normalize raw records into a consistent schema and enforce basic sanity:
      - lowercased indicators and types
      - allowed types: ip, domain, hash, url
      - include 'category' when present (used by URLhaus)
    """
    out: List[Dict] = []
    for r in records:
        ind = (r.get("indicator", "") or "").strip().lower()
        typ = (r.get("type", "") or "").strip().lower()
        src = (r.get("source", "") or "").strip()
        first_seen = (r.get("first_seen", "") or "").strip() or utc_now_iso()
        category = (r.get("category", "") or "").strip().lower()

        if not ind or typ not in {"ip", "domain", "hash", "url"}:
            continue

        out.append({
            "indicator": ind,
            "type": typ,
            "source": src,
            "first_seen": first_seen,
            "category": category,  # safe to be empty for non-URLhaus sources
        })
    return out
