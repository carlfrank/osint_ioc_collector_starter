"""
stix_export.py
Prototype exporter: IOC Collector -> STIX 2.1 Bundle
"""

from stix2 import Indicator, Bundle
import json
from datetime import datetime

def export_to_stix(iocs, output_file="output/iocs_stix.json"):
    """
    Convert IOC list to STIX 2.1 Bundle.
    iocs: list of dicts with keys [indicator, type, reputation_score, confidence, tags]
    """
    stix_objects = []

    for ioc in iocs:
        pattern = f"[{ioc['type']} = '{ioc['indicator']}']"
        ind = Indicator(
            id=f"indicator--{ioc['indicator'][:12]}",
            created=datetime.utcnow(),
            modified=datetime.utcnow(),
            name=f"IOC {ioc['indicator']}",
            pattern=pattern,
            pattern_type="stix",
            confidence=80 if ioc.get("confidence") == "HIGH" else 50,
            labels=[ioc['type'], "osint", *(ioc.get("tags") or [])]
        )
        stix_objects.append(ind)

    bundle = Bundle(objects=stix_objects)
    with open(output_file, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"[+] STIX export saved to {output_file}")


if __name__ == "__main__":
    # Mock demo
    mock_iocs = [
        {"indicator": "1.2.3.4", "type": "ipv4-addr", "confidence": "HIGH", "tags": ["botnet"]},
        {"indicator": "malicious.com", "type": "domain-name", "confidence": "MEDIUM", "tags": ["phishing"]}
    ]
    export_to_stix(mock_iocs)
