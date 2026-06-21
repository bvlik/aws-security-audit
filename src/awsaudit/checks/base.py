"""Abstract base for AWS checks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from ..models import Finding

if TYPE_CHECKING:
    from ..clients import AwsClients
    from ..config import Settings


class Check(ABC):
    id: str
    title: str

    @abstractmethod
    def run(self, clients: AwsClients, settings: Settings) -> list[Finding]:
        raise NotImplementedError
