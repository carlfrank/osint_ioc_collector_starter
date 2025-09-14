# IOC Collector – OSINT Project

## Week 1 – Initial Setup & Collection

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

### Example output
indicator,type,source,first_seen  
example.com,domain,URLhaus,2025-08-23 23:59:01  
1.2.3.4,ip,Spamhaus DROP,2025-08-23 23:59:01  

### Deliverables
- `output/iocs.csv`  
- `output/iocs.json`  

## Week 2 – Normalization, Deduplication & Visualization

This week we improved data quality and presentation:

- Collapsed URLhaus full URLs → domains.  
- Added `category` from URLhaus (`threat` column).  
- Enforced lowercase/trim normalization.  
- Removed duplicates by `(indicator, type)`.  
- Added verification (`verify_dedup.py`) and visualization (`plot_types.py`, `plot_dedup.py`).  

### Setup
- Activate virtualenv  
- Install dependencies (`requirements.txt`, pandas, matplotlib)  

### Run the Collector
`python -m src.main`  

### Sample output
- Parsed 20,870 records from URLhaus  
- Parsed 1,548 records from Spamhaus DROP  
- Total normalized unique records: 8,832  
- Split exports -> ips:1548 domains:7284 hashes:0  

### Quick checks
- `head -n 5 output/iocs.csv`  
- `tail -n +2 output/iocs.csv | cut -d',' -f1,2 | sort | uniq | wc -l`  

### Deliverables
- `output/iocs.csv`  
- `output/iocs.json`  
- `output/iocs_ips.csv`  
- `output/iocs_domains.csv`

## Week 3 – Enrichment, Risk Scoring & Geolocation

In Week 3 we expanded the IOC Collector with enrichment, a risk model, and geolocation.  

### Features
- Aggregation `(indicator, type)` with `first_seen` and `last_seen`.  
- Risk scoring model:  
  - HIGH → Spamhaus / malware  
  - MEDIUM → phishing  
  - LOW → everything else  
- Geolocation for IPs (country, ASN, Org, ISP, cached in `data/ip_geo_cache.json`).  
- Visualizations: IOC type, IOC risk, Top IP countries.  

### Run enrichment
`python enrich.py`  

### Enrichment output
- Wrote `output/iocs_enriched.csv`  
- Risk score counts: low 7284, high 1548  

### Geolocation
`python geo_enrich_ips.py`  

### Geolocation output
- Wrote `output/iocs_enriched_geo.csv`  
- Top countries: US, UK, CN, CA, JP  

### Deliverables
- `output/iocs_enriched.csv`  
- `output/iocs_enriched_geo.csv`  
- `output/risk_chart.png`  
- `output/geo_top_countries.png`  
- (optional) `output/iocs_<category>.csv`  

- `output/types_chart.png`  
- `output/dedup_chart.png`  

## Week 4 – Mock Reputation & Confidence (No API)

En la última fase extendimos el colector con **mock enrichment** (sin APIs externas).  
Todo el enriquecimiento es simulado para cumplir con la regla original: *no external API keys required*.  

---

### 🔍 What we added

- **Reputation score (mock)**  
  - Columna `reputation_score` (0–100) generada internamente.  
  - Columna `confidence`:  
    - HIGH → score > 80  
    - MEDIUM → 60–80  
    - LOW → < 60  

- **Tags (mock)**  
  - Ejemplos de etiquetas: `malware_family=trickbot`, `phishing`.  
  - Solo con fines de demo, no reales.  

- **Export improvements**  
  - Nuevo dataset enriquecido → `output/iocs_enriched.csv`.  
  - Incluye: `indicator, type, source, first_seen, last_seen, category, risk_score, reputation_score, confidence, tags`.  

---

### Run

```bash
python src/enrich.py
