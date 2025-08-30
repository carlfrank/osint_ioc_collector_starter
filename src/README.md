## Results – Week 1

During the first week, I set up and executed the IOC Collector.  
The feeds from **URLhaus** and **Spamhaus** were enabled, while MalwareBazaar was disabled to reduce initial load.  

The collector automatically fetched, normalized, and deduplicated indicators.  
Results were exported to:

- `output/iocs.csv`
- `output/iocs.json`

### Statistics
- Total IOCs collected: **22,566**
- Feeds used:
  - URLhaus (malicious URLs)
  - Spamhaus DROP (malicious IP ranges)

### Example output (first rows of CSV):

## Week 2 – Normalization, Deduplication & Visualization

This week we improved data quality and presentation:

- Collapsed **URLhaus full URLs → domains** (logical deduplication).
- Added **`category`** from URLhaus (`threat` column).
- Enforced **lowercase/trim normalization**.
- Removed exact duplicates by `(indicator, type)`.
- Wrote split exports by type: `ip`, `domain`, `hash`.
- Added **verification** (`verify_dedup.py`) and **visualization** (`plot_types.py`, `plot_dedup.py`).

---

### 🔧 Prereqs (one-time)

From project root (same folder as `README.md`):

```bash

#### Activate virtualenv
```bash
source .venv/bin/activate

# Install base deps (already used in Week 1)
pip install -r requirements.txt

# Install helper deps for Week 2 scripts
pip install pandas matplotlib

# Run the Collector 
python -m src.main

# Expected console (sample from this run):
[INFO] Fetching URLhaus (malicious URLs): https://urlhaus.abuse.ch/downloads/csv_recent/
[INFO] Parsed 20870 records from URLhaus (malicious URLs)
[INFO] Fetching Spamhaus DROP (malicious IP ranges): https://www.spamhaus.org/drop/drop.txt
[INFO] Parsed 1548 records from Spamhaus DROP (malicious IP ranges)
[INFO] Fetching Feodo Tracker (C2 IPs): https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
[INFO] Parsed 0 records from Feodo Tracker (C2 IPs)
[INFO] Total normalized unique records: 8832
[OK] Wrote output/iocs.csv and output/iocs.json
[OK] Split exports -> ips:1548 domains:7284 hashes:0

# Generated files:

output/iocs.csv

output/iocs.json

output/iocs_ips.csv

output/iocs_domains.csv

output/iocs_hashes.csv

#### 🔍 Quick checks (shell) 

# List outputs with sizes
ls -lh output/

# Check CSV header includes 'category'
head -n 1 output/iocs.csv

# Preview first rows
head -n 10 output/iocs.csv

# Total lines (includes header)
wc -l output/iocs.csv

# Unique by (indicator,type) – skip header
tail -n +2 output/iocs.csv | cut -d',' -f1,2 | sort | uniq | wc -l

# Domains unique count (after URL→domain collapse)
tail -n +2 output/iocs_domains.csv | cut -d',' -f1 | sort | uniq | wc -l

# Top 15 domains (for slides)
tail -n +2 output/iocs_domains.csv | cut -d',' -f1 | sort | uniq -c | sort -nr | head -15

# Category distribution (URLhaus)
tail -n +2 output/iocs.csv | cut -d',' -f5 | sort | uniq -c | sort -nr | head

### Current run results:

Total normalized unique: 8,832

By type: domains 7,284, IPs 1,548, hashes 0

# ✅ Verify deduplication (script)

We created verify_dedup.py to confirm if duplicates were removed.

python verify_dedup.py

# Output (this run):
📊 Total indicators: 8832
✅ Unique indicators: 8832
🗑️ Duplicates removed: 0

# 📊 Visualizations

python plot_types.py

Creates output/types_chart.png.
Console (this run):

📊 IOC counts by type:
 - domain: 7284
 - ip: 1548
 - hash: 0
📈 Chart saved as output/types_chart.png

📂 Week 2 Deliverables

output/iocs.csv (schema: indicator,type,source,first_seen,category)

output/iocs.json

output/iocs_ips.csv

output/iocs_domains.csv

output/iocs_hashes.csv

output/types_chart.png (distribution by type)

output/dedup_chart.png

🔎 Example CSV (first rows)

indicator,type,source,first_seen,category
zazadawg3.comslut.xyz,domain,URLhaus (malicious URLs),2025-08-24 00:04:11,phishing
ykapi.luyou.360.cn,domain,URLhaus (malicious URLs),2025-08-23 23:59:01,malware_download
yeklam.com,domain,URLhaus (malicious URLs),2025-08-23 23:58:44,malware_download
xxx-click.com,domain,URLhaus (malicious URLs),2025-08-23 23:58:21,phishing
