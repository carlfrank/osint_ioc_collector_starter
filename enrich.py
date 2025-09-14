# enrich.py
# Purpose: Enrich IOC dataset with last_seen, combined sources, category prioritization, and a simple risk score.
# Input : output/iocs.csv  (from your main pipeline)
# Output: output/iocs_enriched.csv

import pandas as pd
from datetime import datetime

# --- Helpers ---

SEVERITY_ORDER = [
    "malware_download", "malware", "c2", "command-and-control", "botnet",
    "phishing", "spam", "suspicious", "unknown", ""
]

def pick_category(values):
    """
    Choose the 'most severe' category among a set of values, based on SEVERITY_ORDER priority.
    """
    vals = { (str(v) or "").strip().lower() for v in values if pd.notna(v) }
    if not vals:
        return ""
    for sev in SEVERITY_ORDER:
        if sev in vals:
            return sev
    return sorted(vals)[0]

def calc_risk_score(source: str, category: str) -> str:
    """
    Assign a simple risk score:
      - HIGH   if Spamhaus is the source OR if the category is malware-related (malware_download/malware/c2/command-and-control).
      - MEDIUM if category is phishing.
      - LOW    otherwise.
    """
    s = (source or "").lower()
    c = (category or "").lower()
    if "spamhaus" in s:
        return "HIGH"
    if c in {"malware_download", "malware", "c2", "command-and-control"}:
        return "HIGH"
    if c == "phishing":
        return "MEDIUM"
    return "LOW"

def iso(ts):
    """
    Safely convert to ISO datetime string. If parsing fails, return current UTC time.
    """
    try:
        return pd.to_datetime(ts, utc=True).isoformat()
    except Exception:
        return datetime.utcnow().isoformat()

# --- Main ---

def main():
    # Load base CSV
    df = pd.read_csv("output/iocs.csv")

    # Ensure required columns exist
    for col in ["indicator", "type", "source", "first_seen", "category"]:
        if col not in df.columns:
            df[col] = ""

    # Parse first_seen column to datetime
    df["first_seen_dt"] = pd.to_datetime(df["first_seen"], errors="coerce", utc=True)

    # --- Aggregate by (indicator, type) ---
    agg = df.groupby(["indicator", "type"]).agg(
        source=("source", lambda s: "|".join(sorted(set([str(x) for x in s if pd.notna(x)])))),
        first_seen_dt=("first_seen_dt", "min"),
        last_seen_dt=("first_seen_dt", "max"),
        category=("category", pick_category),
    ).reset_index()

    # Fill missing timestamps with now
    now_iso = datetime.utcnow().isoformat()
    agg["first_seen"] = agg["first_seen_dt"].apply(lambda x: x.isoformat() if pd.notna(x) else now_iso)
    agg["last_seen"]  = agg["last_seen_dt"].apply(lambda x: x.isoformat() if pd.notna(x) else now_iso)

    # --- Risk score assignment ---
    agg["risk_score"] = agg.apply(lambda r: calc_risk_score(r["source"], r["category"]), axis=1)

    # Final column order
    cols = ["indicator", "type", "source", "first_seen", "last_seen", "category", "risk_score"]
    agg = agg[cols]

    # --- Save enriched dataset ---
    agg.to_csv("output/iocs_enriched.csv", index=False)

    # Print summary to console
    print("[OK] Wrote output/iocs_enriched.csv")
    print("Counts by risk_score:")
    print(agg["risk_score"].value_counts(dropna=False).to_string())

if __name__ == "__main__":
    main()
