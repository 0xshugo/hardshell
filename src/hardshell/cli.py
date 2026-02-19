"""CLI entry point using Typer."""

from __future__ import annotations

import asyncio
import json
import platform
import socket
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from hardshell import __version__
from hardshell.config import ScanConfig, load_config
from hardshell.models import ScanResult, ScanSummary

app = typer.Typer(
    name="hardshell",
    help="VPS security hardening tool — scan, enrich with CTI, prioritize, remediate.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"hardshell {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-V", callback=version_callback, is_eager=True),
    ] = None,
) -> None:
    """hardshell — VPS security hardening tool."""


@app.command()
def scan(
    scanner: Annotated[
        str | None,
        typer.Option("--scanner", "-s", help="Comma-separated scanner names"),
    ] = None,
    enrich: Annotated[bool, typer.Option("--enrich", "-e", help="Enrich with CTI data")] = False,
    analyze: Annotated[bool, typer.Option("--analyze", "-a", help="Run LLM analysis")] = False,
    format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "terminal",
    output: Annotated[
        str | None, typer.Option("--output", "-o", help="Output file path")
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Config file path")
    ] = None,
) -> None:
    """Run security scan on this host."""
    cfg = load_config(config)

    if scanner:
        cfg.scanners = [s.strip() for s in scanner.split(",")]
    cfg.enrich = enrich or cfg.enrich
    cfg.analyze = analyze or cfg.analyze
    cfg.format = format
    cfg.output = output

    asyncio.run(_run_scan(cfg))


async def _run_scan(cfg: ScanConfig) -> None:
    from hardshell.scanners import get_scanner, list_available_scanners

    available = list_available_scanners()
    scanners_to_run = []
    for name in cfg.scanners:
        if name == "all":
            scanners_to_run = [get_scanner(n) for n in available]
            break
        if name in available:
            scanners_to_run.append(get_scanner(name))
        else:
            console.print(f"[yellow]Scanner '{name}' not available, skipping[/yellow]")

    if not scanners_to_run:
        console.print("[red]No scanners available to run.[/red]")
        raise typer.Exit(1)

    console.print(
        f"[bold]hardshell[/bold] v{__version__} — "
        f"running {len(scanners_to_run)} scanner(s): "
        f"{', '.join(s.name for s in scanners_to_run)}"
    )

    all_findings = []
    for s in scanners_to_run:
        console.print(f"\n[cyan]▶ Running {s.name} scanner...[/cyan]")
        findings = await s.scan(cfg)
        console.print(f"  Found {len(findings)} finding(s)")
        all_findings.extend(findings)

    # CTI enrichment
    if cfg.enrich:
        console.print("\n[cyan]▶ Enriching with CTI data...[/cyan]")
        from hardshell.intel.epss import enrich_epss
        from hardshell.intel.kev import enrich_kev

        await enrich_kev(all_findings)
        await enrich_epss(all_findings)

    # Risk scoring
    from hardshell.analysis.scorer import score_findings

    score_findings(all_findings)

    # Build result
    result = ScanResult(
        hostname=socket.gethostname(),
        os_info=f"{platform.system()} {platform.release()}",
        scanners_used=[s.name for s in scanners_to_run],
        findings=all_findings,
        summary=ScanSummary.from_findings(all_findings),
    )

    # LLM analysis
    if cfg.analyze:
        console.print("\n[cyan]▶ Running LLM analysis...[/cyan]")
        from hardshell.analysis.llm import analyze

        result.llm_analysis = await analyze(result)

    # Report
    _output_report(result, cfg)


def _output_report(result: ScanResult, cfg: ScanConfig) -> None:
    if cfg.format == "json":
        from hardshell.reporters.json_report import render_json

        text = render_json(result)
    elif cfg.format == "markdown":
        from hardshell.reporters.markdown import render_markdown

        text = render_markdown(result)
    else:
        from hardshell.reporters.terminal import render_terminal

        render_terminal(result, console)
        return

    if cfg.output:
        Path(cfg.output).write_text(text)
        console.print(f"\n[green]Report saved to {cfg.output}[/green]")
    else:
        console.print(text)


@app.command()
def status() -> None:
    """Show available scanners and their status."""
    from hardshell.scanners import SCANNER_CLASSES

    console.print(f"[bold]hardshell[/bold] v{__version__}\n")
    console.print("[bold]Scanners:[/bold]")

    for name, cls in SCANNER_CLASSES.items():
        available = cls.is_available()
        icon = "[green]✓[/green]" if available else "[dim]✗[/dim]"
        console.print(f"  {icon} {name}")


@app.command(name="config")
def config_show(
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Config file path")
    ] = None,
) -> None:
    """Show current configuration."""
    cfg = load_config(config)
    console.print_json(json.dumps(cfg.model_dump(), default=str))
