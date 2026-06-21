"""Console + JSON reporting."""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .models import CheckResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def to_console(results: list[CheckResult]) -> None:
    console = Console()
    table = Table(title="AWS Security Audit", header_style="bold #12ABDB")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Finding")

    rows = 0
    for r in results:
        if r.error:
            table.add_row("[bold red]ERROR", r.check_id, "-", r.error)
            rows += 1
            continue
        for f in sorted(r.findings, key=lambda x: x.severity, reverse=True):
            table.add_row(f"[{_SEV_STYLE[f.severity]}]{f.severity.name}", f.check_id, f.resource, f.title)
            rows += 1
    if rows == 0:
        console.print("[bold green]No findings — baseline checks passed.[/]")
    else:
        console.print(table)


def to_json(results: list[CheckResult], path: str = "report.json") -> None:
    payload = [
        {"check_id": r.check_id, "title": r.title, "error": r.error,
         "findings": [f.to_dict() for f in r.findings]}
        for r in results
    ]
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
