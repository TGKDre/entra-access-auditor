# Entra Access Auditor

A focused identity governance auditor for Microsoft Entra ID accounts. Point it at
an account export and it flags the things that quietly cost money and create risk:
stale enabled accounts, guest sprawl, licenses sitting on disabled users,
reclaimable licenses, MFA gaps, and privileged accounts that are stale or missing MFA.

It prints a plain summary, writes a CSV for tracking, and writes a self-contained
HTML report for a manager or a ticket.

This is a clean-room project. It ships with synthetic sample data and needs no
live tenant to run. Point it at a real export (or wire the optional Graph fetch)
when you adopt it.

## Why it exists

License and access drift is invisible until someone asks why a departed
contractor still holds an E5 seat or why a Global Administrator has no MFA. This
turns an account export into a ranked findings list in one command.

## Quick start

```bash
python -m pip install -r requirements-dev.txt
python -m entra_auditor.cli --input data/sample/users.json --out reports
```

Output:

```
Scanned 9 accounts. 9 findings (high 3, medium 3, low 3).
Wrote reports/findings.csv and reports/report.html
```

## Checks

- `stale_account`: enabled, but no sign-in in N days (or never).
- `guest_account`: external guest accounts still enabled.
- `wasted_license`: licenses assigned to a disabled account.
- `reclaimable_license`: licensed but stale, so the seat can be reclaimed.
- `mfa_gap`: enabled account without MFA registered.
- `privileged_risk`: holds a privileged directory role and is stale or missing MFA.

Thresholds and the privileged-role list are configurable (`--stale-days`,
`--license-stale-days`, and the `DEFAULT_CONFIG` in `checks.py`).

## Input format

A JSON array of accounts. Field names match Microsoft Graph object properties so a
real export drops in:

```json
[
  {
    "id": "1",
    "displayName": "Jane Doe",
    "userPrincipalName": "jane.doe@example.com",
    "accountEnabled": true,
    "userType": "Member",
    "lastSignInDateTime": "2026-11-01T00:00:00Z",
    "assignedLicenses": ["E3"],
    "roles": [],
    "mfaRegistered": true
  }
]
```

## Structure

```
src/entra_auditor/models.py    account model
src/entra_auditor/checks.py    the detection rules
src/entra_auditor/report.py    CSV and HTML output
src/entra_auditor/cli.py       command line entry point
data/sample/users.json         synthetic sample export
tests/test_checks.py           unit tests
```

## Safety

Read-only by design. This tool only reads an export and writes reports. It never
changes an account, and it needs no credentials to run on an export. If you wire a
live Graph fetch, use a read-only service principal with least privilege.

## License

MIT. See LICENSE.
