"""RDS-ENCRYPTION: RDS instances without storage encryption at rest."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def unencrypted_db_instances(dbs: list[dict]) -> list[str]:
    """Pure helper: identifiers of RDS instances without StorageEncrypted."""
    return [d["DBInstanceIdentifier"] for d in dbs if not d.get("StorageEncrypted")]


class RdsEncryptionCheck(Check):
    id = "RDS-ENCRYPTION"
    title = "RDS instances without storage encryption"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        rds = clients.client("rds")
        instances: list[dict] = []
        for page in rds.get_paginator("describe_db_instances").paginate():
            instances.extend(page.get("DBInstances", []))
        unencrypted = unencrypted_db_instances(instances)
        if not unencrypted:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.HIGH,
                resource="rds",
                detail=f"{len(unencrypted)} RDS instance(s) store data without encryption at rest.",
                remediation="Recreate instances with StorageEncrypted=true (encryption can't be toggled in place).",
                evidence={"instances": unencrypted[:50]},
            )
        ]
