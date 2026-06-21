"""boto3 session wrapper (uses the default credential chain)."""
from __future__ import annotations

import boto3

from .config import Settings


class AwsClients:
    def __init__(self, settings: Settings):
        self._session = boto3.Session(region_name=settings.region)

    def client(self, name: str):
        return self._session.client(name)
