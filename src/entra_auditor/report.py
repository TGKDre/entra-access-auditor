from __future__ import annotations

import csv
import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def write_csv(findings, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["check", "severity", "name", "upn", "detail"])
        for f in findings:
            writer.writerow([f.check, f.severity, f.display_name, f.upn, f.detail])
    return path


def write_html(findings, path, users_scanned: int) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    by_check = Counter(f.check for f in findings)
    by_sev = Counter(f.severity for f in findings)

    rows = "\n".join(
        f"<tr class='{html.escape(f.severity)}'><td>{html.escape(f.severity)}</td>"
        f"<td>{html.escape(f.check)}</td><td>{html.escape(f.display_name)}</td>"
        f"<td>{html.escape(f.upn)}</td><td>{html.escape(f.detail)}</td></tr>"
        for f in findings
    ) or "<tr><td colspan='5'>No findings. Clean tenant.</td></tr>"

    summary = "".join(f"<li>{html.escape(k)}: {v}</li>" for k, v in sorted(by_check.items())) or "<li>none</li>"
    stamp = datetime.now(timezone.utc)

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra identity hygiene report</title>
<style>
  body {{ font-family: system-ui, -apple-system, Arial, sans-serif; margin: 2rem; color: #1b1b1b; }}
  h1 {{ margin-bottom: 0; }}
  .muted {{ color: #666; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; text-align: left; }}
  th {{ background: #f3f4f6; }}
  tr.high {{ background: #fde8e8; }}
  tr.medium {{ background: #fef3c7; }}
  tr.low {{ background: #eef2ff; }}
</style></head>
<body>
  <h1>Entra identity hygiene report</h1>
  <p class="muted">
    Generated {stamp:%Y-%m-%d %H:%M UTC} &middot;
    {users_scanned} accounts scanned &middot;
    {len(findings)} findings &middot;
    high {by_sev.get('high', 0)}, medium {by_sev.get('medium', 0)}, low {by_sev.get('low', 0)}
  </p>
  <h2>By check</h2>
  <ul>{summary}</ul>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Check</th><th>Name</th><th>UPN</th><th>Detail</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body></html>"""
    path.write_text(doc, encoding="utf-8")
    return path
