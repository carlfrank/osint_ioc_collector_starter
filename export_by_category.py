# export_by_category.py
# Purpose: Split the enriched IOC dataset into separate CSVs by category.
# Input : output/iocs_enriched.csv
# Output: output/iocs_<category>.csv for each category

import pandas as pd
import os

# Load enriched dataset
df = pd.read_csv("output/iocs_enriched.csv")

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

# Iterate over categories
for cat in sorted(df['category'].fillna('').unique()):
    if not cat:
        continue
    safe_cat = cat.replace(" ", "_").replace("/", "_")
    out_file = f"output/iocs_{safe_cat}.csv"
    subset = df[df['category'] == cat]
    subset.to_csv(out_file, index=False)
    print(f"[OK] Wrote {out_file} -> {len(subset)} rows")
