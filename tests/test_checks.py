from datetime import datetime, timezone

from entra_auditor.checks import (
    guest_accounts,
    mfa_gaps,
    privileged_risk,
    reclaimable_licenses,
    run_all,
    stale_accounts,
    wasted_licenses,
)
from entra_auditor.models import User
from entra_auditor.report import write_csv, write_html

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def make_user(**overrides) -> User:
    base = {
        "id": "1",
        "display_name": "A Person",
        "upn": "a.person@example.com",
        "enabled": True,
        "last_sign_in": "2026-11-01T00:00:00Z",
        "licenses": ["E3"],
        "mfa_registered": True,
    }
    base.update(overrides)
    return User(**base)


def test_stale_detects_old_and_never_signed_in():
    users = [
        make_user(upn="old@example.com", last_sign_in="2026-06-01T00:00:00Z"),
        make_user(upn="never@example.com", last_sign_in=None),
        make_user(upn="fresh@example.com", last_sign_in="2026-11-01T00:00:00Z"),
    ]
    upns = {f.upn for f in stale_accounts(users, now=NOW)}
    assert "old@example.com" in upns
    assert "never@example.com" in upns
    assert "fresh@example.com" not in upns


def test_disabled_accounts_are_not_stale():
    assert stale_accounts([make_user(enabled=False, last_sign_in="2020-01-01T00:00:00Z")], now=NOW) == []


def test_guest_detection():
    users = [make_user(user_type="Guest"), make_user(user_type="Member")]
    assert len(guest_accounts(users, now=NOW)) == 1


def test_wasted_license_on_disabled_account():
    users = [make_user(enabled=False, licenses=["E5"]), make_user(enabled=True)]
    findings = wasted_licenses(users, now=NOW)
    assert len(findings) == 1
    assert findings[0].check == "wasted_license"


def test_reclaimable_license_when_stale():
    findings = reclaimable_licenses([make_user(licenses=["E3"], last_sign_in="2026-01-01T00:00:00Z")], now=NOW)
    assert len(findings) == 1
    assert findings[0].check == "reclaimable_license"


def test_mfa_gap():
    users = [make_user(mfa_registered=False), make_user(mfa_registered=True)]
    assert len(mfa_gaps(users, now=NOW)) == 1


def test_privileged_risk_requires_role_and_problem():
    risky = make_user(upn="admin@example.com", roles=["Global Administrator"], mfa_registered=False)
    safe = make_user(upn="admin2@example.com", roles=["Global Administrator"], mfa_registered=True)
    findings = privileged_risk([risky, safe], now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_run_all_orders_high_severity_first():
    users = [make_user(mfa_registered=False), make_user(last_sign_in="2026-06-01T00:00:00Z")]
    findings = run_all(users, now=NOW)
    assert findings[0].severity == "high"


def test_reports_are_written(tmp_path):
    findings = run_all([make_user(mfa_registered=False)], now=NOW)
    csv_path = tmp_path / "findings.csv"
    html_path = tmp_path / "report.html"
    write_csv(findings, csv_path)
    write_html(findings, html_path, users_scanned=1)
    assert csv_path.read_text(encoding="utf-8").splitlines()[0] == "check,severity,name,upn,detail"
    assert "Entra identity hygiene report" in html_path.read_text(encoding="utf-8")
