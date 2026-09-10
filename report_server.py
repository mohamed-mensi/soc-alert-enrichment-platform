from flask import Flask, render_template, abort
import json
from pathlib import Path

app = Flask(__name__, template_folder="templates")
REPORT_DIR = Path("reports")

# Map report_type discriminator → template. Reports without a report_type
# (the original phishing reports) fall back to report.html so existing
# reports keep rendering unchanged.
TEMPLATE_BY_TYPE = {
    "dlp_email_investigation": "dlp_report.html",
    "phishing": "report.html",
}
DEFAULT_TEMPLATE = "report.html"


@app.route("/report/<alert_id>")
def report(alert_id):
    path = REPORT_DIR / f"{alert_id}.json"
    if not path.exists():
        abort(404, description=f"Report {alert_id} not found")
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    template = TEMPLATE_BY_TYPE.get(data.get("report_type"), DEFAULT_TEMPLATE)
    return render_template(template, **data)


if __name__ == "__main__":
    app.run(port=5000, debug=True)
