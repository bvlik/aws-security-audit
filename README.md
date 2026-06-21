<div align="center">

# ☁️ aws-security-audit

**Read-only AWS security posture auditor.**
Uses the boto3 default credential chain, runs a suite of security checks (public S3, management ports open to the Internet, IAM users without MFA) and reports findings with severity and remediation.

[![CI](https://github.com/bvlik/aws-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/bvlik/aws-security-audit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10+-0A1929?style=for-the-badge&logo=python&logoColor=12ABDB)
![AWS](https://img.shields.io/badge/AWS-boto3-0A1929?style=for-the-badge&logo=amazonaws&logoColor=12ABDB)
![Read--only](https://img.shields.io/badge/Mode-Read--only-0070AD?style=for-the-badge)

</div>

---

## Why

Completes a cloud trilogy alongside [`m365-security-audit`](https://github.com/bvlik/m365-security-audit) and
[`cloud-cis-checker`](https://github.com/bvlik/cloud-cis-checker): a fast, **read-only** baseline of common
AWS mistakes — public buckets, SSH/RDP open to the world, IAM users without MFA.

> ⚠️ **Read-only.** Only `list`/`get`/`describe` API calls. Never mutates your account.

## Checks (v0)

| ID | Check | Severity |
|----|-------|----------|
| `SG-OPEN` | Security groups exposing 22/3389 to `0.0.0.0/0` | Critical |
| `S3-PUBLIC` | S3 buckets allowing public access | High |
| `IAM-MFA` | IAM users without an MFA device | High |

## Setup

```bash
pip install -r requirements.txt
export AWS_REGION=eu-west-1          # plus standard AWS credentials (env / profile / role)
python -m awsaudit --format console,json
```

The IAM principal needs read-only access — the AWS managed **`SecurityAudit`** or **`ReadOnlyAccess`** policy is enough.

## Roadmap
- [ ] CloudTrail enabled / multi-region check
- [ ] Access key age & unused credentials
- [ ] Public RDS / unencrypted EBS
- [ ] HTML report + CIS AWS mapping
