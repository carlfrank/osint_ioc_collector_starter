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
