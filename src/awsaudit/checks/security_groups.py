"""SG-OPEN: security groups exposing SSH/RDP to the Internet."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import Finding, Severity
from .base import Check

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings

MGMT_PORTS = {22: "SSH", 3389: "RDP"}


def open_management_ports(ip_permissions: list[dict]) -> list[int]:
    """Pure helper: which management ports an SG's ip_permissions expose to 0.0.0.0/0."""
    exposed: set[int] = set()
    for perm in ip_permissions:
        ranges = perm.get("IpRanges", [])
        if not any(r.get("CidrIp") == "0.0.0.0/0" for r in ranges):
            continue
        if perm.get("IpProtocol") == "-1":  # all traffic
            exposed.update(MGMT_PORTS)
            continue
        from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
        if from_port is None or to_port is None:
            continue
        for port in MGMT_PORTS:
            if from_port <= port <= to_port:
                exposed.add(port)
    return sorted(exposed)


class SecurityGroupOpenPortsCheck(Check):
    id = "SG-OPEN"
    title = "Security groups exposing management ports to the Internet"

    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        findings: list[Finding] = []
        ec2 = clients.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                ports = open_management_ports(sg.get("IpPermissions", []))
                if ports:
                    exposed = ", ".join(f"{p} ({MGMT_PORTS[p]})" for p in ports)
                    findings.append(
                        Finding(
                            check_id=self.id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            resource=sg.get("GroupId", "unknown"),
                            detail=f"Open to 0.0.0.0/0 on port(s): {exposed}.",
                            remediation="Restrict inbound to known IPs; use SSM Session Manager / a bastion.",
                            evidence={"group_name": sg.get("GroupName")},
                        )
                    )
        return findings
