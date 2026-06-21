"""IAM-MFA: IAM users without an MFA device."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


class IamUserMfaCheck(Check):
    id = "IAM-MFA"
    title = "IAM users without MFA"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        iam = clients.client("iam")
        without_mfa: list[str] = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                name = user["UserName"]
                devices = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
                if not devices:
                    without_mfa.append(name)
        if not without_mfa:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.HIGH,
                resource="iam",
                detail=f"{len(without_mfa)} IAM user(s) have no MFA device.",
                remediation="Require MFA for all IAM users (or move to IAM Identity Center / SSO).",
                evidence={"users": without_mfa[:50]},
            )
        ]
