"""KeySentinel CLI — entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from dotenv import dotenv_values
from rich.console import Console

from keysentinel.core import reporter, validator
from keysentinel.core.vault import SecureBytes, redact
from keysentinel.scanners import github, gitguardian
from keysentinel.providers import openai, anthropic, stripe
from keysentinel.providers import github as github_provider
from keysentinel.providers import google, sendgrid, resend, groq, huggingface, slack, replicate, supabase
from keysentinel.remediator import revoker

app = typer.Typer(
    name="keysentinel",
    help="Detect compromised API keys, audit usage, and remediate leaks.",
    add_completion=False,
)
console = Console()

# ------------------------------------------------------------------
# Global exception handler — redacts key patterns before printing
# ------------------------------------------------------------------

def _safe_excepthook(exc_type, exc_val, tb):
    msg = redact(str(exc_val))
    console.print(f"[red]Error:[/] {msg}")
    sys.exit(1)

sys.excepthook = _safe_excepthook


# ------------------------------------------------------------------
# scan command
# ------------------------------------------------------------------

@app.command()
def scan(
    key: Annotated[Optional[str], typer.Option(
        "--key", "-k",
        help="API key (prefer env var substitution: --key $VAR). "
             "WARNING: bare values appear in 'ps aux' — use interactive prompt or --env for production."
    )] = None,
    env_file: Annotated[Optional[Path], typer.Option("--env", "-e", help=".env file to scan all keys")] = None,
    provider: Annotated[Optional[str], typer.Option("--provider", "-p", help="Force provider (openai, anthropic, aws, stripe, github)")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Save JSON report to file")] = None,
    no_github: Annotated[bool, typer.Option("--no-github", help="Skip GitHub scan")] = False,
    no_gg: Annotated[bool, typer.Option("--no-gitguardian", help="Skip GitGuardian scan")] = False,
):
    """Scan one or more API keys for leaks and audit provider usage."""
    reporter.print_banner()

    if key:
        if key == key.strip() and len(key) >= 8:
            console.print("[dim yellow]⚠  Key passed as CLI arg — visible in process list (ps aux). Prefer interactive prompt.[/]")
        _scan_single(key, output, no_github, no_gg)

    elif env_file:
        if not env_file.exists():
            console.print(f"[red]File not found:[/] {env_file}")
            raise typer.Exit(1)
        values = dotenv_values(env_file)
        for var_name, raw_val in values.items():
            if raw_val and len(raw_val) >= 8:
                console.print(f"[dim]Scanning {var_name}...[/]")
                _scan_single(raw_val, output, no_github, no_gg)
                # Zero the value in the dict immediately after use
                values[var_name] = "\x00" * len(raw_val)

    else:
        raw = typer.prompt("Enter API key", hide_input=True)
        _scan_single(raw, output, no_github, no_gg)
        raw = "\x00" * len(raw)


def _scan_single(raw_key: str, output: Path | None, no_github: bool, no_gg: bool) -> None:
    try:
        info = validator.validate(raw_key)
    except ValueError as exc:
        console.print(f"[red]Invalid input:[/] {exc}")
        return

    reporter.print_key_info(info.masked, info.provider.value, info.valid_format, info.hint)

    with SecureBytes(raw_key) as secure_key:
        results: dict = {"key_masked": info.masked, "provider": info.provider.value, "scans": {}}

        # GitHub scan
        if not no_github:
            console.print("[dim]Scanning GitHub public repos...[/]")
            gh_result = github.scan(secure_key)
            results["scans"]["github"] = gh_result
            reporter.print_scan_result("GitHub", gh_result["found"], {"detail": gh_result["summary"]})

        # GitGuardian scan
        if not no_gg:
            console.print("[dim]Checking GitGuardian database...[/]")
            gg_result = gitguardian.scan(secure_key)
            results["scans"]["gitguardian"] = gg_result
            reporter.print_scan_result("GitGuardian", gg_result["found"], {"detail": gg_result["summary"]})

        # Provider audit
        prov = info.provider.value
        audit_result = None
        if prov == "openai":
            audit_result = openai.audit(secure_key)
        elif prov == "anthropic":
            audit_result = anthropic.audit(secure_key)
        elif prov in ("stripe_live", "stripe_test"):
            audit_result = stripe.audit(secure_key)
        elif prov == "github":
            audit_result = github_provider.audit(secure_key)
        elif prov == "google":
            audit_result = google.audit(secure_key)
        elif prov == "sendgrid":
            audit_result = sendgrid.audit(secure_key)
        elif prov == "resend":
            audit_result = resend.audit(secure_key)
        elif prov == "groq":
            audit_result = groq.audit(secure_key)
        elif prov == "huggingface":
            audit_result = huggingface.audit(secure_key)
        elif prov == "slack":
            audit_result = slack.audit(secure_key)
        elif prov == "replicate":
            audit_result = replicate.audit(secure_key)
        elif prov == "supabase":
            audit_result = supabase.audit(secure_key)
        elif prov == "aws":
            audit_result = {
                "valid": None,
                "found": False,
                "summary": "Requires both Access Key ID and Secret Key — use --env to provide both.",
            }

        if audit_result:
            audit_result.setdefault("found", False)
            results["scans"]["provider_audit"] = audit_result
            is_valid = audit_result.get("valid")
            if is_valid is None:
                icon = "[dim]─ Skipped[/]"
            elif is_valid:
                icon = "[green]✓ Active[/]"
            else:
                icon = "[yellow]⚠ Invalid/Revoked[/]"
            console.print(f"  {icon}  [bold]{prov} audit[/]")
            console.print(f"       [dim]detail:[/] {audit_result.get('summary', '')}")

        compromised = any(s.get("found") for s in results["scans"].values())
        results["compromised"] = compromised
        reporter.print_report(results, output)


# ------------------------------------------------------------------
# revoke command
# ------------------------------------------------------------------

@app.command()
def revoke(
    key: Annotated[Optional[str], typer.Option("--key", "-k")] = None,
    provider: Annotated[Optional[str], typer.Option("--provider", "-p")] = None,
):
    """Revoke a compromised key and print manual remediation steps."""
    reporter.print_banner()

    raw_key = key or typer.prompt("Enter API key to revoke", hide_input=True)

    try:
        info = validator.validate(raw_key)
    except ValueError as exc:
        console.print(f"[red]Invalid input:[/] {exc}")
        raise typer.Exit(1)

    console.print(f"\n[bold red]Revoking:[/] {info.masked} ({info.provider.value})")
    confirmed = typer.confirm("Are you sure you want to revoke this key?")
    if not confirmed:
        console.print("[yellow]Aborted.[/]")
        raise typer.Exit(0)

    with SecureBytes(raw_key) as secure_key:
        result = revoker.revoke(secure_key, info.provider)

    if result.get("revoked"):
        console.print(f"[green]✓ {result['message']}[/]")
    else:
        console.print(f"[yellow]⚠ {result['message']}[/]")
        steps = result.get("manual_steps", [])
        if steps:
            console.print("\n[bold]Manual steps:[/]")
            for step in steps:
                console.print(f"  {step}")


# ------------------------------------------------------------------
# version command
# ------------------------------------------------------------------

@app.command()
def version():
    """Show keysentinel version."""
    from keysentinel import __version__
    console.print(f"keysentinel {__version__}")


if __name__ == "__main__":
    app()
