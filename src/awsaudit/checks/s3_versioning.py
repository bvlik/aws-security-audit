"""S3-VERSIONING: buckets without versioning enabled."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def versioning_disabled(status: str | None) -> bool:
    """Pure helper: True unless versioning status is exactly 'Enabled'."""
    return status != "Enabled"


class S3VersioningCheck(Check):
    id = "S3-VERSIONING"
    title = "S3 buckets without versioning"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        s3 = clients.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            status = s3.get_bucket_versioning(Bucket=name).get("Status")
            if versioning_disabled(status):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.LOW,
                        resource=name,
                        detail="Bucket versioning is not enabled (no protection against overwrite/deletion).",
                        remediation="Enable versioning (and consider MFA delete) on buckets holding important data.",
                    )
                )
        return findings
