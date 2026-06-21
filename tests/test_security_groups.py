"""Tests for the pure security-group analysis helper (no AWS needed)."""
from awsaudit.checks.security_groups import open_management_ports


def _perm(from_port, to_port, cidr="0.0.0.0/0", proto="tcp"):
    return {"FromPort": from_port, "ToPort": to_port, "IpProtocol": proto, "IpRanges": [{"CidrIp": cidr}]}


def test_open_ssh_is_detected():
    assert open_management_ports([_perm(22, 22)]) == [22]


def test_restricted_cidr_is_ignored():
    assert open_management_ports([_perm(22, 22, cidr="10.0.0.0/8")]) == []


def test_port_range_covering_rdp():
    assert 3389 in open_management_ports([_perm(3000, 4000)])


def test_all_traffic_protocol_exposes_both():
    perm = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    assert set(open_management_ports([perm])) == {22, 3389}


def test_no_ranges_is_safe():
    assert open_management_ports([{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": []}]) == []
