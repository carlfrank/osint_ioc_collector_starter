import pandas as pd

# Load main CSV
df = pd.read_csv("output/iocs.csv")

# Total number of records (including header)
total = len(df)

# Unique records by (indicator, type)
unique = len(df.drop_duplicates(subset=["indicator", "type"]))

# Duplicates removed
duplicates = total - unique

print(f"📊 Total indicators: {total}")
print(f"✅ Unique indicators: {unique}")
print(f"🗑️ Duplicates removed: {duplicates}")
