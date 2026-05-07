"""Rich terminal output and JSON report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console(highlight=False)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def print_banner() -> None:
    console.print(Panel.fit(
        "[bold yellow]KEYCHECK[/] — API Key Compromise Scanner\n"
        "[dim]All keys are handled in-memory. Nothing is stored in plaintext.[/]",
        border_style="yellow",
    ))


def print_key_info(masked: str, provider: str, valid_format: bool, hint: str) -> None:
    status = "[green]✓ Known format[/]" if valid_format else "[yellow]⚠ Unknown format[/]"
    console.print(f"\n[bold]Key:[/] [cyan]{masked}[/]  Provider: [bold]{provider}[/]  {status}")
    console.print(f"[dim]{hint}[/]\n")


def print_scan_result(source: str, found: bool, details: dict[str, Any]) -> None:
    icon = "[red]⚠ LEAKED[/]" if found else "[green]✓ Clean[/]"
    console.print(f"  {icon}  [bold]{source}[/]")
    if found and details:
        for k, v in details.items():
            console.print(f"       [dim]{k}:[/] {v}")


def print_report(results: dict[str, Any], output_path: Path | None = None) -> None:
    table = Table(box=box.ROUNDED, title="Scan Summary", show_lines=True)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Detail")

    for source, data in results.get("scans", {}).items():
        found = data.get("found", False)
        status = "[red]LEAKED[/]" if found else "[green]CLEAN[/]"
        detail = data.get("summary", "—")
        table.add_row(source, status, detail)

    console.print(table)

    if results.get("compromised"):
        console.print(Panel(
            "[bold red]ACTION REQUIRED[/]\n"
            "This key has been found in public sources.\n"
            "Run [cyan]keysentinel revoke[/] to invalidate it immediately.",
            border_style="red",
        ))

    if output_path:
        safe_results = _sanitize_for_output(results)
        output_path.write_text(json.dumps(safe_results, indent=2))
        console.print(f"\n[dim]Report saved to {output_path}[/]")


def _sanitize_for_output(data: dict[str, Any]) -> dict[str, Any]:
    """Ensure no plaintext key leaks into the JSON report."""
    out = json.loads(json.dumps(data))
    for field in ("key", "raw_key", "secret", "token"):
        if field in out:
            out[field] = "REDACTED"
    return out
