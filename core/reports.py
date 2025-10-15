import json
from datetime import datetime
import os
from jinja2 import Template

REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>SafeHarbor Forensics — Report</title>
<style>
body{font-family: Arial, sans-serif; margin:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:8px;text-align:left}
th{background:#f5f5f5}
.risk-high{background:#ffdddd}
</style>
</head>
<body>
<h1>SafeHarbor Forensics - Report</h1>
<p>Generated at: {{generated_at}}</p>
<h2>Summary</h2>
<ul>
<li>Total files: {{summary.total_files}}</li>
<li>High risk: {{summary.high_risk}}</li>
<li>Medium risk: {{summary.medium_risk}}</li>
<li>Low risk: {{summary.low_risk}}</li>
</ul>

<h2>Evidence</h2>
<table>
<tr><th>Path</th><th>SHA-256</th><th>MIME</th><th>Risk</th><th>Notes</th></tr>
{% for it in items %}
<tr class="{{'risk-high' if it.risk_score>=0.8 else ''}}">
<td>{{it.path}}</td>
<td>{{it.hash_sha256}}</td>
<td>{{it.mime}}</td>
<td>{{'%.2f'|format(it.risk_score)}}</td>
<td>
{% if it.wallet_matches %}Wallets: {{it.wallet_matches|join(', ')}}<br/>{% endif %}
{% if it.stego_flag %}Stego: suspected{% endif %}
</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

def generate_reports(items, out_basename="report"):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    json_path = os.path.join(REPORTS_DIR, f"{out_basename}_{ts}.json")
    html_path = os.path.join(REPORTS_DIR, f"{out_basename}_{ts}.html")

    summary = {
        "total_files": len(items),
        "high_risk": sum(1 for i in items if i.risk_score >= 0.8),
        "medium_risk": sum(1 for i in items if 0.5 <= i.risk_score < 0.8),
        "low_risk": sum(1 for i in items if i.risk_score < 0.5),
    }

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "items": [i.__dict__ for i in items]
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(generated_at=payload["generated_at"], summary=summary, items=payload["items"])
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    return {"json": json_path, "html": html_path}
