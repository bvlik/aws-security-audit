"""Command-line entrypoint: python -m awsaudit"""
from __future__ import annotations

import argparse
import sys

from . import report
from .checks import ALL_CHECKS
from .clients import AwsClients
from .config import Settings
from .models import CheckResult, Severity


def run(formats: list[str]) -> int:
    settings = Settings.from_env()
    clients = AwsClients(settings)

    results: list[CheckResult] = []
    for check in ALL_CHECKS:
        try:
            results.append(CheckResult(check.id, check.title, check.run(clients, settings)))
        except Exception as exc:  # noqa: BLE001 - surface per-check AWS errors
            results.append(CheckResult(check.id, check.title, [], error=str(exc)))

    if "console" in formats:
        report.to_console(results)
    if "json" in formats:
        report.to_json(results)
        print("Wrote report.json")

    worst = max((f.severity for r in results for f in r.findings), default=Severity.INFO)
    return 1 if worst >= Severity.HIGH else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="awsaudit", description="Read-only AWS security audit")
    parser.add_argument("--format", default="console", help="comma-separated: console,json")
    args = parser.parse_args(argv)
    return run([f.strip() for f in args.format.split(",") if f.strip()])


if __name__ == "__main__":
    sys.exit(main())
