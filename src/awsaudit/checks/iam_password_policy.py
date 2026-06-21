"""IAM-PWPOLICY: weak or missing account password policy."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings

MIN_PASSWORD_LENGTH = 14


def password_policy_issues(policy: dict | None) -> list[str]:
    """Pure helper: list the weaknesses of an IAM account password policy."""
    if not policy:
        return ["no account password policy is set"]
    issues: list[str] = []
    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        issues.append(f"minimum length < {MIN_PASSWORD_LENGTH}")
    if not policy.get("RequireSymbols"):
        issues.append("symbols not required")
    if not policy.get("RequireNumbers"):
        issues.append("numbers not required")
    if not policy.get("RequireUppercaseCharacters"):
        issues.append("uppercase not required")
    if not policy.get("RequireLowercaseCharacters"):
        issues.append("lowercase not required")
    if not policy.get("ExpirePasswords"):
        issues.append("passwords never expire")
    return issues


class IamPasswordPolicyCheck(Check):
    id = "IAM-PWPOLICY"
    title = "Weak IAM account password policy"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        iam = clients.client("iam")
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy")
        except Exception:  # noqa: BLE001 - no policy configured
            policy = None
        issues = password_policy_issues(policy)
        if not issues:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource="iam:account",
                detail="Account password policy is weak: " + "; ".join(issues) + ".",
                remediation="Set a strong password policy (length >= 14, complexity, rotation).",
                evidence={"issues": issues},
            )
        ]
