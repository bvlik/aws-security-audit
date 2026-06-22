"""EC2-IMDSV2: instances not enforcing IMDSv2 (HttpTokens=required)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


def instances_without_imdsv2(reservations: list[dict]) -> list[str]:
    """Pure helper: ids of running instances whose metadata service allows IMDSv1."""
    out: list[str] = []
    for reservation in reservations:
        for inst in reservation.get("Instances", []):
            options = inst.get("MetadataOptions", {})
            if options.get("HttpTokens") != "required":
                out.append(inst["InstanceId"])
    return out


class Ec2Imdsv2Check(Check):
    id = "EC2-IMDSV2"
    title = "EC2 instances not enforcing IMDSv2"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        ec2 = clients.client("ec2")
        reservations: list[dict] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            reservations.extend(page.get("Reservations", []))
        vulnerable = instances_without_imdsv2(reservations)
        if not vulnerable:
            return []
        return [
            Finding(
                check_id=self.id,
                title=self.title,
                severity=Severity.MEDIUM,
                resource="ec2",
                detail=f"{len(vulnerable)} instance(s) allow IMDSv1, which eases SSRF-based credential theft.",
                remediation="Set HttpTokens=required (IMDSv2) on instances and in launch templates.",
                evidence={"instances": vulnerable[:50]},
            )
        ]
