from __future__ import annotations

import argparse
import json
from pathlib import Path

from .checks import run_all
from .models import User
from .report import write_csv, write_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit Microsoft Entra ID accounts for access and license hygiene."
    )
    parser.add_argument("--input", required=True, help="Path to a JSON export of accounts (array of objects).")
    parser.add_argument("--out", default="reports", help="Output directory for findings.csv and report.html.")
    parser.add_argument("--stale-days", type=int, default=90, help="Days without sign-in before an account is stale.")
    parser.add_argument(
        "--license-stale-days", type=int, default=90, help="Days without sign-in before a license is reclaimable."
    )
    args = parser.parse_args(argv)

    raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
    users = [User.from_dict(item) for item in raw]

    config = {"stale_days": args.stale_days, "license_stale_days": args.license_stale_days}
    findings = run_all(users, config=config)

    out = Path(args.out)
    csv_path = write_csv(findings, out / "findings.csv")
    html_path = write_html(findings, out / "report.html", len(users))

    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    print(f"Scanned {len(users)} accounts. {len(findings)} findings (high {high}, medium {medium}, low {low}).")
    print(f"Wrote {csv_path} and {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
