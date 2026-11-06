from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import User


@dataclass
class Finding:
    check: str
    severity: str
    display_name: str
    upn: str
    detail: str


DEFAULT_CONFIG: dict = {
    "stale_days": 90,
    "license_stale_days": 90,
    "privileged_roles": [
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "User Administrator",
    ],
}


def _parse(dt: str | None) -> datetime | None:
    if not dt:
        return None
    try:
        parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ref(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def _cfg(config: dict | None) -> dict:
    return {**DEFAULT_CONFIG, **(config or {})}


def stale_accounts(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    cfg = _cfg(config)
    ref = _ref(now)
    out: list[Finding] = []
    for u in users:
        if not u.enabled:
            continue
        last = _parse(u.last_sign_in)
        if last is None:
            out.append(Finding("stale_account", "medium", u.display_name, u.upn, "Never signed in"))
        elif (ref - last) > timedelta(days=cfg["stale_days"]):
            out.append(
                Finding("stale_account", "medium", u.display_name, u.upn, f"No sign-in in {(ref - last).days} days")
            )
    return out


def guest_accounts(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    return [
        Finding("guest_account", "low", u.display_name, u.upn, "Guest account enabled")
        for u in users
        if u.enabled and u.user_type.lower() == "guest"
    ]


def wasted_licenses(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    return [
        Finding("wasted_license", "low", u.display_name, u.upn, f"{len(u.licenses)} license(s) on a disabled account")
        for u in users
        if not u.enabled and u.licenses
    ]


def reclaimable_licenses(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    cfg = _cfg(config)
    ref = _ref(now)
    out: list[Finding] = []
    for u in users:
        if not u.enabled or not u.licenses:
            continue
        last = _parse(u.last_sign_in)
        if last is None or (ref - last) > timedelta(days=cfg["license_stale_days"]):
            state = "never signs in" if last is None else "stale sign-in"
            out.append(
                Finding("reclaimable_license", "medium", u.display_name, u.upn, f"Licensed but {state}: {', '.join(u.licenses)}")
            )
    return out


def mfa_gaps(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    return [
        Finding("mfa_gap", "high", u.display_name, u.upn, "Enabled account without MFA")
        for u in users
        if u.enabled and not u.mfa_registered
    ]


def privileged_risk(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    cfg = _cfg(config)
    ref = _ref(now)
    privileged = {r.lower() for r in cfg["privileged_roles"]}
    out: list[Finding] = []
    for u in users:
        if not u.enabled:
            continue
        held = [r for r in u.roles if r.lower() in privileged]
        if not held:
            continue
        problems: list[str] = []
        if not u.mfa_registered:
            problems.append("no MFA")
        last = _parse(u.last_sign_in)
        if last is None or (ref - last) > timedelta(days=cfg["stale_days"]):
            problems.append("stale sign-in")
        if problems:
            out.append(
                Finding("privileged_risk", "high", u.display_name, u.upn, f"{', '.join(held)} with {' and '.join(problems)}")
            )
    return out


ALL_CHECKS = [stale_accounts, guest_accounts, wasted_licenses, reclaimable_licenses, mfa_gaps, privileged_risk]

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def run_all(users: list[User], config: dict | None = None, now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(users, config=config, now=now))
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.check))
    return findings
