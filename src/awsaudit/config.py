"""Configuration (region + boto3 default credential chain)."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    region: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(region=os.getenv("AWS_REGION", "us-east-1"))
