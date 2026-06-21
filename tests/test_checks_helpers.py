"""Tests for the pure helpers behind the AWS checks (no boto3 needed)."""
from datetime import datetime, timedelta, timezone

from awsaudit.checks.cloudtrail import has_multiregion_logging
from awsaudit.checks.ebs_encryption import unencrypted_volumes
from awsaudit.checks.iam_key_age import key_age_days
from awsaudit.checks.iam_password_policy import password_policy_issues
from awsaudit.checks.rds_public import public_instances

NOW = datetime(2026, 6, 21, tzinfo=timezone.utc)


# --- IAM key age ---------------------------------------------------------------
def test_key_age_days_counts_correctly():
    assert key_age_days(NOW - timedelta(days=120), NOW) == 120


def test_key_age_days_tolerates_naive_datetime():
    naive = (NOW - timedelta(days=10)).replace(tzinfo=None)
    assert key_age_days(naive, NOW) == 10


# --- IAM password policy -------------------------------------------------------
def test_password_policy_missing_is_flagged():
    assert password_policy_issues(None) == ["no account password policy is set"]


def test_strong_password_policy_has_no_issues():
    strong = {
        "MinimumPasswordLength": 16,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "ExpirePasswords": True,
    }
    assert password_policy_issues(strong) == []


def test_short_password_policy_is_flagged():
    issues = password_policy_issues({"MinimumPasswordLength": 6, "RequireSymbols": True,
                                     "RequireNumbers": True, "RequireUppercaseCharacters": True,
                                     "RequireLowercaseCharacters": True, "ExpirePasswords": True})
    assert any("minimum length" in i for i in issues)


# --- CloudTrail ----------------------------------------------------------------
def test_multiregion_logging_detected():
    trails = [{"IsMultiRegionTrail": True, "IsLogging": True}]
    assert has_multiregion_logging(trails) is True


def test_multiregion_trail_not_logging_is_insufficient():
    trails = [{"IsMultiRegionTrail": True, "IsLogging": False}]
    assert has_multiregion_logging(trails) is False


# --- RDS -----------------------------------------------------------------------
def test_public_rds_instances_selected():
    dbs = [
        {"DBInstanceIdentifier": "prod", "PubliclyAccessible": True},
        {"DBInstanceIdentifier": "internal", "PubliclyAccessible": False},
    ]
    assert public_instances(dbs) == ["prod"]


# --- EBS -----------------------------------------------------------------------
def test_unencrypted_volumes_selected():
    vols = [{"VolumeId": "vol-1", "Encrypted": False}, {"VolumeId": "vol-2", "Encrypted": True}]
    assert unencrypted_volumes(vols) == ["vol-1"]
