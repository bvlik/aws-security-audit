"""EBS-ENC: unencrypted EBS volumes."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def unencrypted_volumes(volumes: list[dict]) -> list[str]:
    """Pure helper: ids of EBS volumes that are not encrypted at rest."""
    return [v.get("VolumeId", "unknown") for v in volumes if not v.get("Encrypted")]


class EbsEncryptionCheck(Check):
    id = "EBS-ENC"
    title = "Unencrypted EBS volumes"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        ec2 = clients.client("ec2")
        bad: list[str] = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            bad.extend(unencrypted_volumes(page.get("Volumes", [])))
        if not bad:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource="ec2:ebs",
                detail=f"{len(bad)} EBS volume(s) are not encrypted at rest.",
                remediation="Enable EBS encryption by default and re-create/restore volumes encrypted.",
                evidence={"volumes": bad[:50]},
            )
        ]
