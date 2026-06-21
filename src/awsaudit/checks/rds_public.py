"""RDS-PUBLIC: RDS instances reachable from the Internet."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def public_instances(db_instances: list[dict]) -> list[str]:
    """Pure helper: identifiers of RDS instances that are publicly accessible."""
    return [
        db.get("DBInstanceIdentifier", "unknown")
        for db in db_instances
        if db.get("PubliclyAccessible")
    ]


class RdsPublicCheck(Check):
    id = "RDS-PUBLIC"
    title = "RDS instances publicly accessible"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        rds = clients.client("rds")
        findings: list[Finding] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            for ident in public_instances(page.get("DBInstances", [])):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=Severity.HIGH,
                        resource=ident,
                        detail="RDS instance is marked PubliclyAccessible.",
                        remediation="Disable public accessibility; place the instance in private subnets.",
                    )
                )
        return findings
