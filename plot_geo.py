# plot_geo.py
# Purpose: Plot top N countries for IP indicators from iocs_enriched_geo.csv
# Output: output/geo_top_countries.png

import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("output/iocs_enriched_geo.csv")

# Keep only IP rows with a country
ip_df = df[(df["type"] == "ip") & (df["geo_country"].notna()) & (df["geo_country"] != "")]

counts = ip_df["geo_country"].value_counts().head(10)
print("Top countries:")
print(counts.to_string())

plt.bar(counts.index, counts.values)
plt.title("Top Countries (IP Indicators)")
plt.ylabel("Count")
plt.xticks(rotation=30, ha="right")
plt.tight_layout()
plt.savefig("output/geo_top_countries.png")
print("📈 Saved output/geo_top_countries.png")
