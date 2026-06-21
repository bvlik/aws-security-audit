"""Check registry."""
from .iam_mfa import IamUserMfaCheck
from .s3_public import S3PublicBucketsCheck
from .security_groups import SecurityGroupOpenPortsCheck

ALL_CHECKS = [
    SecurityGroupOpenPortsCheck(),
    S3PublicBucketsCheck(),
    IamUserMfaCheck(),
]
