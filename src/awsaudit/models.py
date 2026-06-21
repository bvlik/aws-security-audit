"""Core domain models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    detail: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class CheckResult:
    check_id: str
    title: str
    findings: list[Finding]
    error: str | None = None
