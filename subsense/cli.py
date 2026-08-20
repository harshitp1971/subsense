"""Typer entry point. `subsense -d target.com` runs a passive-only scan by default; aggressive
stages (active enum, nuclei, AI) are opt-in flags per CLAUDE.md's architecture principles.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from subsense.config import Config
from subsense.models import SEVERITY_ORDER, ScanState, Subdomain, Finding
from subsense.pipeline import Pipeline

app = typer.Typer(add_completion=False, help="subsense — subdomain enumeration + DNS vulnerability discovery")
console = Console()


@app.command()
def scan(
    domain: str = typer.Option(..., "-d", "--domain", help="Target root domain, e.g. example.com"),
    active: bool = typer.Option(
        False, "--active", help="Enable active enumeration: bruteforce + pattern-permutation. Touches the target directly."
    ),
    nuclei: bool = typer.Option(False, "--nuclei", help="Enable nuclei vulnerability scanning."),
    ai: bool = typer.Option(
        False, "--ai", help="Enable AI-powered permutation + finding triage via a local Ollama instance."
    ),
    resume: bool = typer.Option(False, "--resume", help="Resume the most recent unfinished scan for this domain."),
    config_path: Path | None = typer.Option(
        None, "--config", exists=True, help="YAML config file to merge over config/default.yaml."
    ),
    output: Path | None = typer.Option(None, "-o", "--output", help="Override the report output directory."),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose logging."),
) -> None:
    """Run a subsense scan against DOMAIN.

    Default run: passive enum + resolve + DNS checks + HTTP probe + report (low-noise, safe).
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )

    console.print(f"[bold cyan]subsense[/bold cyan] — scanning [bold]{domain}[/bold]")
    console.print("[dim]For authorized security testing only. Discovery is not authorization to test.[/dim]")
    if active or nuclei or ai:
        enabled = ", ".join(name for name, flag in (("active", active), ("nuclei", nuclei), ("ai", ai)) if flag)
        console.print(f"[yellow]Opt-in stages enabled: {enabled}[/yellow]\n")
    else:
        console.print()

    config = Config.load(config_path)
    if output is not None:
        config.report.out_dir = output

    pipeline = Pipeline(config, domain, active=active, nuclei=nuclei, ai=ai, resume=resume)

    try:
        with console.status("[bold green]Running pipeline...[/bold green]", spinner="dots"):
            state, subdomains, findings = asyncio.run(pipeline.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — progress is checkpointed. Re-run with --resume to continue.[/yellow]")
        raise typer.Exit(code=130) from None

    _print_summary(console, state, subdomains, findings)
    for path in pipeline.report_paths:
        console.print(f"Report: [bold]{path}[/bold]")


def _print_summary(console: Console, state: ScanState, subdomains: list[Subdomain], findings: list[Finding]) -> None:
    table = Table(title=f"subsense — {state.target_domain}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            table.add_row(sev.value, str(count))
    if findings:
        console.print(table)
    else:
        console.print("[dim]No findings.[/dim]")

    resolved = sum(1 for s in subdomains if s.resolved)
    in_scope = sum(1 for s in subdomains if s.in_scope)
    console.print(
        f"\n[bold]{len(subdomains)}[/bold] subdomains discovered · "
        f"[bold]{resolved}[/bold] resolved · [bold]{in_scope}[/bold] in scope · "
        f"[bold]{len(findings)}[/bold] findings"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
