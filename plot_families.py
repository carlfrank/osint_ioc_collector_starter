"""
plot_families.py
Bar chart of malware families frequency
"""

import matplotlib.pyplot as plt
import pandas as pd

def plot_families(csv_file="output/iocs.csv", output="output/families_chart.png"):
    # Mock: read CSV with column "tags"
    df = pd.read_csv(csv_file)

    families = df['tags'].dropna().str.extractall(r"malware_family=([a-zA-Z0-9_-]+)")[0]
    counts = families.value_counts().head(10)

    plt.figure(figsize=(10,6))
    counts.plot(kind="bar", color="red")
    plt.title("Top 10 Malware Families")
    plt.xlabel("Family")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output)
    print(f"[+] Chart saved as {output}")


if __name__ == "__main__":
    # Mock demo
    data = {"tags": ["malware_family=trickbot", "malware_family=emotet", "phishing", None]}
    pd.DataFrame(data).to_csv("output/mock_iocs.csv", index=False)
    plot_families("output/mock_iocs.csv", "output/mock_families.png")
