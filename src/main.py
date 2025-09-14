import json, os, pathlib
from typing import List, Dict
from .feeders import fetch_text
from .normalize import (
    parse_spamhaus_drop,
    parse_urlhaus_csv,
    parse_malwarebazaar_csv,
    normalize_records,
)
from .storage import write_csv, write_json

# Base paths
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
FEEDS_FILE = BASE_DIR / "feeds.json"
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"  # used for offline testing if a feed fails


def load_feeds() -> List[Dict]:
    """Load enabled feeds from feeds.json."""
    with open(FEEDS_FILE, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return [x for x in obj.get("feeds", []) if x.get("enabled", True)]


def deduplicate(rows: List[Dict]) -> List[Dict]:
    """
    Deduplicate by (indicator, type).
    This collapses repeated entries across feeds after normalization.
    """
    seen = set()
    out: List[Dict] = []
    for r in rows:
        key = (r["indicator"], r["type"])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def collect() -> List[Dict]:
    """
    Fetch each enabled feed, route to the appropriate parser,
    fall back to local sample files if download fails,
    then normalize and deduplicate all records.
    """
    rows: List[Dict] = []
    feeds = load_feeds()

    for feed in feeds:
        name = feed["name"]
        url  = feed["url"]
        kind = feed.get("kind", "mixed")
        print(f"[INFO] Fetching {name}: {url}")

        text = fetch_text(url)

        # --- Offline fallback: use local sample files if the HTTP fetch fails ---
        if not text:
            sample = ""
            if "spamhaus" in url.lower():
                sample_path = DATA_DIR / "spamhaus_drop_sample.txt"
                if sample_path.exists():
                    sample = sample_path.read_text(encoding="utf-8")
            elif "urlhaus" in url.lower():
                sample_path = DATA_DIR / "urlhaus_recent_sample.csv"
                if sample_path.exists():
                    sample = sample_path.read_text(encoding="utf-8")
            # You can add more elif branches for other feeds' samples if needed.
            text = sample

        if not text:
            print(f"[WARN] No data for {name}")
            continue

        # --- Route to parser based on the feed URL ---
        if "spamhaus" in url.lower():
            parsed = list(parse_spamhaus_drop(text, name))
        elif "urlhaus" in url.lower():
            parsed = list(parse_urlhaus_csv(text, name))
        elif "malwarebazaar" in url.lower():
            parsed = list(parse_malwarebazaar_csv(text, name))
        elif "feodotracker" in url.lower():
            # Feodo publishes simple IP lists; reuse the Spamhaus-style parser
            parsed = list(parse_spamhaus_drop(text, name))
        else:
            parsed = []

        print(f"[INFO] Parsed {len(parsed)} records from {name}")
        rows.extend(parsed)

    # Normalize field casing/shape and enforce schema
    rows = normalize_records(rows)
    # Remove exact duplicates by (indicator, type)
    rows = deduplicate(rows)
    return rows


def main():
    rows = collect()
    print(f"[INFO] Total normalized unique records: {len(rows)}")

    # --- Main exports ---
    write_csv(str(OUTPUT_DIR / "iocs.csv"), rows)
    write_json(str(OUTPUT_DIR / "iocs.json"), rows)
    print(f"[OK] Wrote {OUTPUT_DIR/'iocs.csv'} and {OUTPUT_DIR/'iocs.json'}")

    # --- Extra exports by type (useful for demo/presentation) ---
    ips     = [r for r in rows if r["type"] == "ip"]
    domains = [r for r in rows if r["type"] == "domain"]
    hashes  = [r for r in rows if r["type"] == "hash"]

    write_csv(str(OUTPUT_DIR / "iocs_ips.csv"), ips)
    write_csv(str(OUTPUT_DIR / "iocs_domains.csv"), domains)
    write_csv(str(OUTPUT_DIR / "iocs_hashes.csv"), hashes)

    print(f"[OK] Split exports -> ips:{len(ips)} domains:{len(domains)} hashes:{len(hashes)}")


if __name__ == "__main__":
    main()
