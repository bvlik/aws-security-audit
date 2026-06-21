"""CT-LOGGING: account has no multi-region CloudTrail logging."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def has_multiregion_logging(trails: list[dict]) -> bool:
    """Pure helper: is at least one multi-region trail actively logging?"""
    return any(t.get("IsMultiRegionTrail") and t.get("IsLogging") for t in trails)


class CloudTrailLoggingCheck(Check):
    id = "CT-LOGGING"
    title = "No multi-region CloudTrail logging"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        ct = clients.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        enriched = []
        for t in trails:
            name = t.get("Name") or t.get("TrailARN")
            status = ct.get_trail_status(Name=t.get("TrailARN", name))
            enriched.append({**t, "IsLogging": status.get("IsLogging", False)})
        if has_multiregion_logging(enriched):
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.HIGH,
                resource="cloudtrail",
                detail="No actively-logging multi-region trail was found.",
                remediation="Enable a multi-region CloudTrail with log file validation.",
                evidence={"trail_count": len(trails)},
            )
        ]
