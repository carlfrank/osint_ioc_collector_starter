import pandas as pd
import matplotlib.pyplot as plt

# Load main CSV
df = pd.read_csv("output/iocs.csv")

# Count records by type
counts = df["type"].value_counts()

# Print counts
print("📊 IOC counts by type:")
for t, c in counts.items():
    print(f" - {t}: {c}")

# Plot bar chart
plt.bar(counts.index, counts.values, color=["blue", "green", "orange", "red"])
plt.title("IOCs by Type")
plt.ylabel("Count")

# Save chart
plt.savefig("output/types_chart.png")
print("📈 Chart saved as output/types_chart.png")
