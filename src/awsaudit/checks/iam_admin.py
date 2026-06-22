"""IAM-ADMIN: principals with AdministratorAccess attached directly."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings

_ADMIN_ARN_SUFFIX = ":policy/AdministratorAccess"


def is_admin_policy_arn(arn: str) -> bool:
    """Pure helper: True for the AWS-managed AdministratorAccess policy ARN."""
    return arn.endswith(_ADMIN_ARN_SUFFIX)


def admin_attachments(attachments: list[tuple[str, str]]) -> list[str]:
    """Pure helper: principals (name) whose attached policy ARN is admin.

    ``attachments`` is a list of ``(principal, policy_arn)`` pairs.
    """
    return [name for name, arn in attachments if is_admin_policy_arn(arn)]


class IamAdminPolicyCheck(Check):
    id = "IAM-ADMIN"
    title = "Principals with AdministratorAccess attached"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        iam = clients.client("iam")
        attachments: list[tuple[str, str]] = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                name = user["UserName"]
                for pol in iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", []):
                    attachments.append((f"user/{name}", pol.get("PolicyArn", "")))
        for page in iam.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                name = role["RoleName"]
                for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
                    attachments.append((f"role/{name}", pol.get("PolicyArn", "")))

        admins = admin_attachments(attachments)
        if not admins:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.HIGH,
                resource="iam",
                detail=f"{len(admins)} principal(s) have AdministratorAccess attached directly.",
                remediation="Replace broad admin with least-privilege policies; gate admin behind assumed roles + MFA.",
                evidence={"principals": admins[:50]},
            )
        ]
