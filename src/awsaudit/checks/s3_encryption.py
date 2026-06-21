"""S3-ENC: buckets without default server-side encryption."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


class S3EncryptionCheck(Check):
    id = "S3-ENC"
    title = "S3 buckets without default encryption"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        s3 = clients.client("s3")
        findings: list[Finding] = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            if not self._is_encrypted(s3, name):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        resource=name,
                        detail="Bucket has no default server-side encryption configured.",
                        remediation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
                    )
                )
        return findings

    @staticmethod
    def _is_encrypted(s3, name: str) -> bool:
        try:
            cfg = s3.get_bucket_encryption(Bucket=name)
            rules = cfg.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            return bool(rules)
        except Exception:  # noqa: BLE001 - no encryption configuration => not encrypted
            return False
