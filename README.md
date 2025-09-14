# OSINT IOC Collector (Starter)

A safe, weekend-friendly project that fetches **Indicators of Compromise (IOCs)** from public feeds (no API keys), 
normalizes them, removes duplicates, and exports results to CSV/JSON.

> **Safety:** This project **does not** download or execute malware—only **textual indicators** like IPs/domains/hashes.

## Features
- Fetch IOCs from public feeds (e.g., URLhaus, Spamhaus DROP, Feodo Tracker, MalwareBazaar CSV exports).
- Normalize fields into a common schema: `indicator`, `type`, `source`, `first_seen`.
- Deduplicate indicators across feeds.
- Export to `output/iocs.csv` and `output/iocs.json`.
- Optional: schedule runs with `cron` or Windows Task Scheduler.

## Quickstart
```bash
# 1) Create & activate a virtual env (recommended)
python3 -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the collector
python src/main.py

# 4) See results
ls output/
```

## Configuring feeds
Edit `feeds.json` to enable/disable feeds or add new ones. Each entry supports a `url`, `type` (ip|domain|hash|mixed), and `enabled` flag.

## Scheduling
**Linux/macOS (cron):**
```bash
crontab -e
# Run daily at 03:15
15 3 * * * /full/path/to/.venv/bin/python /full/path/to/src/main.py >> /full/path/to/output/cron.log 2>&1
```

**Windows (Task Scheduler):** Create a basic task to run `python src\main.py` daily.

## Project structure
```
osint_ioc_collector_starter/
├─ data/                # sample data for offline testing
├─ output/              # normalized outputs (CSV/JSON)
└─ src/
   ├─ main.py           # entry point
   ├─ feeders.py        # download helpers for each feed
   ├─ normalize.py      # parsers + normalization
   ├─ storage.py        # save/export helpers
   └─ utils.py          # common helpers (timestamp, safe http, etc.)
```

## Legal / Ethical
Use these feeds **only for learning and defense**. Respect each feed's terms of use. Do **not** use indicators to target systems.
