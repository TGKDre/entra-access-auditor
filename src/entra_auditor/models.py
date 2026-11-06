from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class User:
    id: str
    display_name: str
    upn: str
    enabled: bool
    user_type: str = "Member"
    last_sign_in: str | None = None
    created: str | None = None
    licenses: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    mfa_registered: bool = True
    department: str | None = None
    job_title: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> User:
        return cls(
            id=str(d.get("id", "")),
            display_name=d.get("displayName") or d.get("display_name") or "",
            upn=d.get("userPrincipalName") or d.get("upn") or "",
            enabled=bool(d.get("accountEnabled", d.get("enabled", True))),
            user_type=d.get("userType") or d.get("user_type") or "Member",
            last_sign_in=d.get("lastSignInDateTime") or d.get("last_sign_in"),
            created=d.get("createdDateTime") or d.get("created"),
            licenses=list(d.get("licenses") or d.get("assignedLicenses") or []),
            roles=list(d.get("roles") or []),
            mfa_registered=bool(d.get("mfaRegistered", d.get("mfa_registered", True))),
            department=d.get("department"),
            job_title=d.get("jobTitle") or d.get("job_title"),
        )
