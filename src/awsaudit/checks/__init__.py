"""Check registry."""
from .cloudtrail import CloudTrailLoggingCheck
from .ebs_encryption import EbsEncryptionCheck
from .ec2_imdsv2 import Ec2Imdsv2Check
from .iam_admin import IamAdminPolicyCheck
from .iam_key_age import IamAccessKeyAgeCheck
from .iam_mfa import IamUserMfaCheck
from .iam_password_policy import IamPasswordPolicyCheck
from .iam_root_keys import IamRootKeysCheck
from .kms_rotation import KmsRotationCheck
from .rds_encryption import RdsEncryptionCheck
from .rds_public import RdsPublicCheck
from .s3_encryption import S3EncryptionCheck
from .s3_public import S3PublicBucketsCheck
from .s3_versioning import S3VersioningCheck
from .security_groups import SecurityGroupOpenPortsCheck

ALL_CHECKS = [
    SecurityGroupOpenPortsCheck(),
    S3PublicBucketsCheck(),
    S3EncryptionCheck(),
    S3VersioningCheck(),
    IamUserMfaCheck(),
    IamRootKeysCheck(),
    IamAdminPolicyCheck(),
    IamAccessKeyAgeCheck(),
    IamPasswordPolicyCheck(),
    CloudTrailLoggingCheck(),
    RdsPublicCheck(),
    RdsEncryptionCheck(),
    EbsEncryptionCheck(),
    Ec2Imdsv2Check(),
    KmsRotationCheck(),
]
