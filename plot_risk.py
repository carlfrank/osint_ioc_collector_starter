# plot_risk.py
# Purpose: Visualize IOC distribution by risk_score as a bar chart.
# Input : output/iocs_enriched.csv
# Output: output/risk_chart.png

import pandas as pd
import matplotlib.pyplot as plt

# Load enriched dataset
df = pd.read_csv("output/iocs_enriched.csv")

# Count records by risk_score
counts = df["risk_score"].value_counts()
print("📊 IOC counts by risk_score:")
for k, v in counts.items():
    print(f" - {k}: {v}")

# Create bar chart
plt.bar(counts.index, counts.values)
plt.title("IOC Risk Distribution")
plt.ylabel("Count")
plt.savefig("output/risk_chart.png")

print("📈 Saved output/risk_chart.png")
