import json
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

def save_report(alert_id: str, record: dict):
    """
    Save enrichment record as JSON for the report server.
    """
    path = REPORT_DIR / f"{alert_id}.json"
    # Always include all keys, keep Unicode characters
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    return str(path)
