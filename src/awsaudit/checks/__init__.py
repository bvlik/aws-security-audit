"""Check registry."""
from .cloudtrail import CloudTrailLoggingCheck
from .ebs_encryption import EbsEncryptionCheck
from .iam_key_age import IamAccessKeyAgeCheck
from .iam_mfa import IamUserMfaCheck
from .iam_password_policy import IamPasswordPolicyCheck
from .rds_public import RdsPublicCheck
from .s3_encryption import S3EncryptionCheck
from .s3_public import S3PublicBucketsCheck
from .security_groups import SecurityGroupOpenPortsCheck

ALL_CHECKS = [
    SecurityGroupOpenPortsCheck(),
    S3PublicBucketsCheck(),
    S3EncryptionCheck(),
    IamUserMfaCheck(),
    IamAccessKeyAgeCheck(),
    IamPasswordPolicyCheck(),
    CloudTrailLoggingCheck(),
    RdsPublicCheck(),
    EbsEncryptionCheck(),
]
