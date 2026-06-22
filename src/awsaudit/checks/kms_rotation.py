"""KMS-ROTATION: customer-managed KMS keys without automatic rotation."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def keys_without_rotation(rotation_status: dict[str, bool]) -> list[str]:
    """Pure helper: key ids whose rotation flag is falsy, sorted."""
    return sorted(key_id for key_id, enabled in rotation_status.items() if not enabled)


class KmsRotationCheck(Check):
    id = "KMS-ROTATION"
    title = "Customer-managed KMS keys without rotation"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        kms = clients.client("kms")
        rotation_status: dict[str, bool] = {}
        for page in kms.get_paginator("list_keys").paginate():
            for entry in page.get("Keys", []):
                key_id = entry["KeyId"]
                meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                # only customer-managed, enabled keys can have rotation
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                    continue
                status = kms.get_key_rotation_status(KeyId=key_id)
                rotation_status[key_id] = bool(status.get("KeyRotationEnabled"))
        stale = keys_without_rotation(rotation_status)
        if not stale:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource="kms",
                detail=f"{len(stale)} customer-managed key(s) do not have automatic rotation enabled.",
                remediation="Enable automatic annual key rotation on customer-managed CMKs.",
                evidence={"keys": stale[:50]},
            )
        ]
