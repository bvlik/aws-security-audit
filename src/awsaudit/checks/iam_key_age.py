"""IAM-KEYAGE: active IAM access keys older than a rotation threshold."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings

MAX_KEY_AGE_DAYS = 90


def key_age_days(create_date: datetime, now: datetime | None = None) -> int:
    """Pure helper: age in days of an access key, tolerant of naive datetimes."""
    now = now or datetime.now(timezone.utc)
    if create_date.tzinfo is None:
        create_date = create_date.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return (now - create_date).days


class IamAccessKeyAgeCheck(Check):
    id = "IAM-KEYAGE"
    title = "IAM access keys older than the rotation threshold"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        iam = clients.client("iam")
        now = datetime.now(timezone.utc)
        stale: list[str] = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                name = user["UserName"]
                for key in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                    if key.get("Status") != "Active":
                        continue
                    age = key_age_days(key["CreateDate"], now)
                    if age > MAX_KEY_AGE_DAYS:
                        stale.append(f"{name}:{key['AccessKeyId']} ({age}d)")
        if not stale:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource="iam",
                detail=f"{len(stale)} active access key(s) older than {MAX_KEY_AGE_DAYS} days.",
                remediation="Rotate access keys regularly; prefer short-lived roles / IAM Identity Center.",
                evidence={"keys": stale[:50]},
            )
        ]
