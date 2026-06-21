"""S3-PUBLIC: buckets that allow public access."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings

_PUBLIC_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


class S3PublicBucketsCheck(Check):
    id = "S3-PUBLIC"
    title = "S3 buckets allowing public access"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        s3 = clients.client("s3")
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            if self._is_public(s3, name):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.HIGH,
                        resource=name,
                        detail="Bucket is not fully protected by a public access block or has a public ACL grant.",
                        remediation="Enable S3 Block Public Access (account + bucket) and remove public ACL grants.",
                    )
                )
        return findings

    @staticmethod
    def _is_public(s3, name: str) -> bool:
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                return False
        except Exception:  # noqa: BLE001 - no block configured => potentially public
            pass
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                if grant.get("Grantee", {}).get("URI") == _PUBLIC_URI:
                    return True
        except Exception:  # noqa: BLE001
            return True
        return True
