"""Tests for the pure helpers behind the AWS checks (no boto3 needed)."""
from datetime import datetime, timedelta, timezone

from awsaudit.checks import ALL_CHECKS
from awsaudit.checks.cloudtrail import has_multiregion_logging
from awsaudit.checks.ebs_encryption import unencrypted_volumes
from awsaudit.checks.ec2_imdsv2 import instances_without_imdsv2
from awsaudit.checks.iam_admin import admin_attachments, is_admin_policy_arn
from awsaudit.checks.iam_key_age import key_age_days
from awsaudit.checks.iam_password_policy import password_policy_issues
from awsaudit.checks.iam_root_keys import root_has_access_keys
from awsaudit.checks.kms_rotation import keys_without_rotation
from awsaudit.checks.rds_encryption import unencrypted_db_instances
from awsaudit.checks.rds_public import public_instances
from awsaudit.checks.s3_versioning import versioning_disabled

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


# --- IAM root keys -------------------------------------------------------------
def test_root_access_keys_present_detected():
    assert root_has_access_keys({"AccountAccessKeysPresent": 1}) is True
    assert root_has_access_keys({"AccountAccessKeysPresent": 0}) is False
    assert root_has_access_keys({}) is False


# --- IAM admin -----------------------------------------------------------------
def test_is_admin_policy_arn():
    assert is_admin_policy_arn("arn:aws:iam::aws:policy/AdministratorAccess") is True
    assert is_admin_policy_arn("arn:aws:iam::aws:policy/ReadOnlyAccess") is False


def test_admin_attachments_selects_admins():
    attachments = [
        ("user/alice", "arn:aws:iam::aws:policy/AdministratorAccess"),
        ("role/app", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
        ("role/ops", "arn:aws:iam::aws:policy/AdministratorAccess"),
    ]
    assert admin_attachments(attachments) == ["user/alice", "role/ops"]


# --- S3 versioning -------------------------------------------------------------
def test_versioning_disabled_logic():
    assert versioning_disabled(None) is True
    assert versioning_disabled("Suspended") is True
    assert versioning_disabled("Enabled") is False


# --- EC2 IMDSv2 ----------------------------------------------------------------
def test_instances_without_imdsv2_selected():
    reservations = [
        {"Instances": [
            {"InstanceId": "i-weak", "MetadataOptions": {"HttpTokens": "optional"}},
            {"InstanceId": "i-strong", "MetadataOptions": {"HttpTokens": "required"}},
            {"InstanceId": "i-default", "MetadataOptions": {}},
        ]},
    ]
    assert instances_without_imdsv2(reservations) == ["i-weak", "i-default"]


# --- KMS rotation --------------------------------------------------------------
def test_keys_without_rotation_selected_and_sorted():
    status = {"key-b": False, "key-a": True, "key-c": False}
    assert keys_without_rotation(status) == ["key-b", "key-c"]


# --- RDS encryption ------------------------------------------------------------
def test_unencrypted_db_instances_selected():
    dbs = [
        {"DBInstanceIdentifier": "plain", "StorageEncrypted": False},
        {"DBInstanceIdentifier": "enc", "StorageEncrypted": True},
        {"DBInstanceIdentifier": "missing"},
    ]
    assert unencrypted_db_instances(dbs) == ["plain", "missing"]


# --- registry integrity --------------------------------------------------------
def test_all_checks_have_unique_ids():
    ids = [c.id for c in ALL_CHECKS]
    assert len(ids) == len(set(ids))
    assert len(ALL_CHECKS) == 15


def test_every_check_has_id_and_title():
    assert all(c.id and c.title for c in ALL_CHECKS)
