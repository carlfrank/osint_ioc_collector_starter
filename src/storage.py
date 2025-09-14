import csv, json, os
from typing import List, Dict

def write_csv(path: str, rows: List[Dict]):
    """
    Write normalized records to CSV.
    We include the 'category' field so URLhaus metadata (e.g., phishing, malware_download)
    is preserved. For non-URLhaus records this field will be empty.
    """
    if not rows:
        # Nothing to write; keep behavior simple (no file created)
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Unified schema (matches normalize_records output)
    fieldnames = ["indicator", "type", "source", "first_seen", "category"]

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            # DictWriter handles missing keys by writing empty cells
            w.writerow(r)


def write_json(path: str, rows: List[Dict]):
    """
    Write records to JSON (pretty-printed). Keeping keys as-is so downstream
    tooling can consume the same schema as the CSV file.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
