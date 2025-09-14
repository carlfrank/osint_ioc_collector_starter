# geo_enrich_ips.py
# Purpose: Geolocate IP indicators using ip-api.com (batch) and merge results into the enriched dataset.
# Input : output/iocs_enriched.csv
# Output: output/iocs_enriched_geo.csv
#
# Notes:
# - Handles plain IPs and CIDR (takes the first address of the network).
# - Respects ip-api free tier using batches (<=100 per request).
# - Caches lookups to data/ip_geo_cache.json to avoid requerying.

import os
import json
import time
import ipaddress
import requests
import pandas as pd

INPUT_FILE = "output/iocs_enriched.csv"
OUTPUT_FILE = "output/iocs_enriched_geo.csv"
CACHE_FILE = "data/ip_geo_cache.json"

BATCH_URL = "http://ip-api.com/batch"  # free, http only
BATCH_SIZE = 100
SLEEP_BETWEEN_CALLS = 1.5  # seconds; stay polite to the free tier

# --- utilities ---

def first_ip_from_indicator(indicator: str) -> str | None:
    """
    Return a single IPv4 address to query:
    - If indicator is a single IP -> return it.
    - If indicator is CIDR -> return the network's first IP.
    - Otherwise -> None (skip).
    """
    try:
        if "/" in indicator:
            net = ipaddress.ip_network(indicator, strict=False)
            return str(net.network_address)
        else:
            ipaddress.ip_address(indicator)
            return indicator
    except Exception:
        return None

def load_cache(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def query_batch(ips: list[str]) -> list[dict]:
    """
    Query ip-api batch endpoint. Returns list of result dicts in the same order.
    Each result contains fields like status, query, country, countryCode, isp, org, as, etc.
    """
    try:
        resp = requests.post(BATCH_URL, json=ips, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[WARN] Batch request failed: {e}")
        return [{"status": "fail", "query": ip, "message": "request_failed"} for ip in ips]

# --- main flow ---

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[ERR] Missing {INPUT_FILE}. Run enrich.py first.")
        return

    df = pd.read_csv(INPUT_FILE)

    # Filter IP-type indicators and prepare a map: indicator -> ip_to_query
    ip_rows = df[df["type"] == "ip"].copy()
    if ip_rows.empty:
        print("[INFO] No IP indicators found. Nothing to geolocate.")
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"[OK] Wrote {OUTPUT_FILE}")
        return

    ip_rows["ip_lookup"] = ip_rows["indicator"].apply(first_ip_from_indicator)
    ip_rows = ip_rows[ip_rows["ip_lookup"].notna()]

    # Load cache
    cache = load_cache(CACHE_FILE)

    # Determine which IPs need querying
    to_lookup = [ip for ip in ip_rows["ip_lookup"].unique() if ip not in cache]

    print(f"[INFO] Unique IPs to lookup: {len(to_lookup)} (cached: {len(cache)})")

    # Batch query missing IPs
    for i in range(0, len(to_lookup), BATCH_SIZE):
        batch = to_lookup[i:i + BATCH_SIZE]
        print(f"[INFO] Querying batch {i // BATCH_SIZE + 1} ({len(batch)} IPs)")
        results = query_batch(batch)
        # Store in cache keyed by 'query' (the IP string)
        for res in results:
            key = str(res.get("query", "")).strip()
            if key:
                cache[key] = res
        save_cache(CACHE_FILE, cache)
        time.sleep(SLEEP_BETWEEN_CALLS)

    # Build a small dataframe with geo info per original indicator
    def geo_fields_for_indicator(indicator: str) -> dict:
        ipq = first_ip_from_indicator(indicator)
        if not ipq:
            return {}
        res = cache.get(ipq, {})
        if not res or res.get("status") != "success":
            return {"geo_country": "", "geo_country_code": "", "geo_as": "", "geo_org": "", "geo_isp": ""}
        return {
            "geo_country": res.get("country", ""),
            "geo_country_code": res.get("countryCode", ""),
            "geo_as": res.get("as", ""),     # e.g., "AS15169 Google LLC"
            "geo_org": res.get("org", ""),   # org name
            "geo_isp": res.get("isp", ""),   # ISP
        }

    geo_df = ip_rows[["indicator"]].drop_duplicates().copy()
    geo_df = geo_df.assign(**geo_df["indicator"].apply(geo_fields_for_indicator).apply(pd.Series))

    # Merge geo info back to the full dataset on indicator (only IP rows will get values)
    out = df.merge(geo_df, on="indicator", how="left")

    # Save final file
    out.to_csv(OUTPUT_FILE, index=False)
    print(f"[OK] Wrote {OUTPUT_FILE}")
    # Small summary
    print("Countries (top 10):")
    print(out["geo_country"].value_counts().head(10).to_string())

if __name__ == "__main__":
    main()
