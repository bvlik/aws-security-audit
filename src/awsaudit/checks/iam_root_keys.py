"""IAM-ROOT-KEYS: the root account still has active access keys."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def root_has_access_keys(summary_map: dict) -> bool:
    """Pure helper: True if the IAM account summary reports root access keys."""
    return bool(summary_map.get("AccountAccessKeysPresent"))


class IamRootKeysCheck(Check):
    id = "IAM-ROOT-KEYS"
    title = "Root account has active access keys"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        iam = clients.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        if not root_has_access_keys(summary):
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.CRITICAL,
                resource="root",
                detail="The AWS account root user has one or more access keys.",
                remediation="Delete root access keys; use IAM roles / Identity Center for programmatic access.",
            )
        ]
