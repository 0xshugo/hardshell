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
    enrich: Annotated[bool, typer.Option("--enrich", "-e")] = False,
    analyze: Annotated[bool, typer.Option("--analyze", "-a")] = False,
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[str | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
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


@app.command()
def fix(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Print script only, do not execute"),
    ] = True,
    execute: Annotated[bool, typer.Option("--execute", help="Execute AUTO-tier actions")] = False,
    tier: Annotated[str, typer.Option("--tier", help="auto | propose | all")] = "all",
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Scan report JSON to act on"),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Save fix script to file"),
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Generate or execute remediation actions."""
    asyncio.run(
        _run_fix(
            dry_run=not execute,
            tier=tier,
            report_path=report,
            output=output,
            config_path=config,
        )
    )


@app.command()
def notify(
    report: Annotated[Path, typer.Argument(help="Scan report JSON")],
    prev: Annotated[Path | None, typer.Option("--prev", help="Previous report for delta")] = None,
    webhook: Annotated[str | None, typer.Option("--webhook", help="Discord webhook URL")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Send scan results to Discord (delta alerts + proposal notifications)."""
    asyncio.run(_run_notify(report, prev, webhook, config))


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
    report = Path(__file__).resolve().parents[2] / "build" / "early-warning.json"
    console.print("\n[bold]Early warning / AI budget:[/bold]")
    try:
        from datetime import UTC, datetime

        saved = json.loads(report.read_text())
        generated = datetime.fromisoformat(saved["generated_at"].replace("Z", "+00:00"))
        age = (datetime.now(UTC) - generated).total_seconds()
        if not 0 <= age <= 45 * 60:
            console.print("  [red]stale: scheduled report needs attention[/red]")
        for provider, readiness in saved.get("ai_readiness", {}).items():
            console.print(
                f"  {provider}: {readiness.get('status', 'unknown')} "
                f"({readiness.get('reason', 'funding observed; see checked_at')})"
            )
        if not saved.get("ai_readiness"):
            console.print("  [yellow]AI funding not verified[/yellow]")
    except (OSError, ValueError, KeyError, TypeError):
        console.print("  [yellow]unverified: no valid scheduled report[/yellow]")


@app.command(name="config")
def config_show(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Show current configuration."""
    cfg = load_config(config)
    console.print_json(json.dumps(cfg.model_dump(), default=str))


@app.command(name="collect-hermes-registry")
def collect_hermes_registry_command(
    hermes_config: Annotated[
        Path | None,
        typer.Option("--hermes-config", help="Hermes config.yaml to read"),
    ] = None,
    env_file: Annotated[
        Path | None,
        typer.Option("--env-file", help="Optional .env file to inventory without values"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Registry JSON output path"),
    ] = Path("build/hardshell-agent-posture.json"),
    profile: Annotated[str, typer.Option("--profile", help="Hermes profile name")] = "default",
) -> None:
    """Write a secret-redacted Hermes agent registry for agent posture scanners."""
    from hardshell.collectors.hermes_registry import write_hermes_registry

    write_hermes_registry(
        output_path=output,
        config_path=hermes_config,
        env_path=env_file,
        profile=profile,
    )
    console.print(f"[green]Hermes registry saved to {output}[/green]")


@app.command(name="watch")
def watch(
    inventory: Annotated[
        Path | None, typer.Option(help="Normalized runtime JSON; omit to probe Docker")
    ] = None,
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("build/early-warning.json"),
    ai: Annotated[
        bool, typer.Option("--ai", help="Opt in to configured Jev/local LLM calls")
    ] = False,
) -> None:
    """Fetch official PHP advisories and prepare approval-bound cases. Never remediate."""
    asyncio.run(_run_watch(inventory, output, ai))


async def _run_watch(inventory_path, output, ai):
    import os
    import time
    from datetime import UTC, datetime

    from hardshell.early_warning import build_report, collect_php
    from hardshell.intel.vendor import fetch_php

    state = Path(__file__).resolve().parents[2] / "build" / "state"
    try:
        intel = await fetch_php(cache_dir=state / "vendor")
    except Exception:
        intel = {"advisories": [], "gaps": [{"source": "php.net", "reason": "acquisition_failed"}]}
    try:
        if inventory_path:
            if inventory_path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("inventory_too_large")
            inventory = json.loads(inventory_path.read_text())
        else:
            inventory = await asyncio.to_thread(collect_php)
        result = build_report(intel, inventory)
    except Exception:
        result = {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "status": "insufficient_evidence",
            "cases": [],
            "execution_enabled": False,
            "feed_gaps": intel.get("gaps", []) + [{"reason": "inventory_failed"}],
        }
    if ai:
        from hardshell.analysis.budget import BudgetDeniedError, BudgetLedger
        from hardshell.analysis.funding import check_funding
        from hardshell.analysis.readiness import local_readiness
        from hardshell.analysis.triage import review

        try:
            budget = BudgetLedger(state / "ai")
        except BudgetDeniedError:
            budget = None

        if budget is not None:
            result["ai_readiness"] = {
                "jev": await check_funding(
                    budget,
                    api_key=os.environ.get("TYPESAFE_API_KEY"),
                    cookie=os.environ.get("HARDSHELL_TYPESAFE_BILLING_COOKIE"),
                ),
                "llm": await local_readiness(
                    budget,
                    os.environ.get("HARDSHELL_LLM_URL"),
                    os.environ.get("HARDSHELL_LLM_MODEL"),
                ),
            }
            capacity = budget.readiness("jev")
            if capacity["status"] != "ready" and result["ai_readiness"]["jev"]["status"] == "ready":
                result["ai_readiness"]["jev"] = capacity
            result["ai_readiness"]["jev"]["budget"] = capacity
        else:
            result["ai_readiness"] = {
                "jev": {"status": "unavailable", "reason": "budget_store_unavailable"}
            }

        ai_deadline = time.monotonic() + 100
        for case in result["cases"][:10]:
            if any(v.get("status") != "ready" for v in result["ai_readiness"].values()):
                case["ai_review"] = {
                    "status": "deferred",
                    "reason": "ai_pipeline_unavailable",
                    "executable": False,
                }
                continue
            if time.monotonic() > ai_deadline - 90:
                case["ai_review"] = {
                    "status": "deferred",
                    "reason": "run_time_budget",
                    "executable": False,
                }
                continue
            if result["feed_gaps"] or case["status"] != "potentially_affected":
                case["ai_review"] = {
                    "status": "deferred",
                    "reason": "evidence_incomplete",
                    "executable": False,
                }
                continue
            try:
                case["ai_review"] = await review(
                    case,
                    jev_key=os.environ.get("TYPESAFE_API_KEY"),
                    jev_model=os.environ.get("HARDSHELL_JEV_MODEL", "jev-1.13.0"),
                    budget=budget,
                    llm_url=os.environ.get("HARDSHELL_LLM_URL"),
                    llm_model=os.environ.get("HARDSHELL_LLM_MODEL"),
                )
            except ValueError:
                case["ai_review"] = {
                    "status": "needs_review",
                    "error": "invalid_ai_config_or_state",
                    "executable": False,
                }
    if ai and budget is not None:
        try:
            result["ai_budget_usage"] = budget.totals()
            for provider in ("jev", "llm"):
                capacity = budget.readiness(provider)
                current = result["ai_readiness"].get(provider, {})
                if current.get("status") == "ready" and capacity["status"] != "ready":
                    result["ai_readiness"][provider] = capacity
                else:
                    current["budget"] = capacity
        except (BudgetDeniedError, OSError):
            result["ai_budget_usage"] = {"error": "budget_store_unavailable"}
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(".tmp")
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    temp.chmod(0o600)
    temp.replace(output)
    console.print(
        f"Early warning: {len(result['cases'])} cases; {result['status']}; saved to {output}"
    )
    if ai and any(v.get("status") != "ready" for v in result.get("ai_readiness", {}).values()):
        for provider, readiness in result["ai_readiness"].items():
            if readiness.get("status") != "ready":
                console.print(f"AI unavailable ({provider}): " + readiness["reason"])
        raise typer.Exit(3)
    if ai and any(
        c.get("ai_review", {}).get("jev") == "failed"
        or c.get("ai_review", {}).get("llm") == "failed"
        for c in result["cases"]
    ):
        console.print("AI call failed; cases retained for review")
        raise typer.Exit(3)
    if result["feed_gaps"] or any(
        gap.get("reason") != "php_runtime_unverified" for gap in result.get("coverage_gaps", [])
    ):
        raise typer.Exit(2)


# ── Internal async implementations ──────────────────────────────────────────


async def _run_scan(cfg: ScanConfig) -> None:
    from hardshell.scanners import get_scanner, list_available_scanners

    available = list_available_scanners()
    scanners_to_run = []
    scanner_status = {}
    scanner_evidence = {}
    for name in cfg.scanners:
        if name == "all":
            scanners_to_run = [get_scanner(n) for n in available]
            break
        if name in available:
            scanners_to_run.append(get_scanner(name))
        else:
            scanner_status[name] = "unavailable"
            console.print(f"[yellow]Scanner '{name}' not available, skipping[/yellow]")

    if not scanners_to_run:
        result = ScanResult(
            hostname=socket.gethostname(), status="partial", scanner_status=scanner_status
        )
        _output_report(result, cfg)
        console.print("[red]No scanners available to run.[/red]")
        raise typer.Exit(2)

    console.print(
        f"[bold]hardshell[/bold] v{__version__} — "
        f"running {len(scanners_to_run)} scanner(s): "
        f"{', '.join(s.name for s in scanners_to_run)}"
    )

    all_findings = []
    for s in scanners_to_run:
        console.print(f"\n[cyan]▶ Running {s.name} scanner...[/cyan]")
        try:
            findings = await s.scan(cfg)
        except Exception:
            scanner_status[s.name] = "failed"
            console.print("  [red]Scan failed; evidence is incomplete[/red]")
            continue
        scanner_status[s.name] = "ok"
        if isinstance(getattr(s, "evidence", None), dict):
            scanner_evidence[s.name] = s.evidence
        console.print(f"  Found {len(findings)} finding(s)")
        all_findings.extend(findings)

    all_findings = _apply_allowlist(all_findings, cfg)

    if cfg.enrich:
        console.print("\n[cyan]▶ Enriching with CTI data...[/cyan]")
        from hardshell.intel.epss import enrich_epss
        from hardshell.intel.kev import enrich_kev

        await enrich_kev(all_findings)
        await enrich_epss(all_findings)

    from hardshell.analysis.scorer import score_findings

    score_findings(all_findings)

    result = ScanResult(
        hostname=socket.gethostname(),
        os_info=f"{platform.system()} {platform.release()}",
        scanners_used=[s.name for s in scanners_to_run],
        findings=all_findings,
        summary=ScanSummary.from_findings(all_findings),
        status="complete" if all(v == "ok" for v in scanner_status.values()) else "partial",
        scanner_status=scanner_status,
        scanner_evidence=scanner_evidence,
    )

    if cfg.analyze:
        console.print("\n[cyan]▶ Running LLM analysis...[/cyan]")
        from hardshell.analysis.llm import analyze

        result.llm_analysis = await analyze(result)

    _output_report(result, cfg)
    if result.status != "complete":
        raise typer.Exit(2)


async def _run_fix(
    dry_run: bool,
    tier: str,
    report_path: Path | None,
    output: str | None,
    config_path: Path | None,
) -> None:
    from hardshell.remediate.actions import RemediationTier
    from hardshell.remediate.runner import execute_auto, render_fix_script

    cfg = load_config(config_path)

    # Load findings from report
    findings = []
    if report_path and report_path.exists():
        data = json.loads(report_path.read_text())
        result = ScanResult.model_validate(data)
        findings = result.findings
    else:
        console.print("[yellow]No report specified. Run 'hardshell scan' first.[/yellow]")
        raise typer.Exit(1)

    if dry_run:
        tiers = None if tier == "all" else [RemediationTier(tier)]
        script = render_fix_script(findings, tiers=tiers)
        if output:
            Path(output).write_text(script)
            console.print(f"[green]Fix script saved to {output}[/green]")
        else:
            console.print(script)
        return

    # Execute AUTO tier
    if not cfg.remediate.auto_enabled:
        console.print("[yellow]auto_enabled=false in config. Skipping execution.[/yellow]")
        return

    console.print("[cyan]▶ Executing AUTO-tier remediations...[/cyan]")
    result_exec = await execute_auto(findings)

    for action, _ in result_exec.succeeded:
        console.print(f"  [green]✓[/green] {action.title}")
    for action, err in result_exec.failed:
        console.print(f"  [red]✗[/red] {action.title}: {err[:80]}")

    if result_exec.all_ok:
        console.print("\n[green]All auto-remediations succeeded.[/green]")
    else:
        console.print("\n[red]Some remediations failed — check logs.[/red]")
        raise typer.Exit(1)


async def _run_notify(
    report_path: Path,
    prev_path: Path | None,
    webhook_url: str | None,
    config_path: Path | None,
) -> None:
    from hardshell.delta import compare_results
    from hardshell.remediate.actions import RemediationTier
    from hardshell.remediate.generator import plan_actions
    from hardshell.reporters.discord import notify_delta, notify_proposals

    if not report_path.exists():
        console.print(f"[red]Report not found: {report_path}[/red]")
        raise typer.Exit(1)

    data = json.loads(report_path.read_text())
    result = ScanResult.model_validate(data)

    # Delta notification
    delta = compare_results(prev_path, result)
    await notify_delta(delta, result.hostname, webhook_url)
    if delta.has_new_critical_high:
        console.print(
            f"[green]Delta notification sent ({len(delta.new_findings)} new findings)[/green]"
        )
    else:
        console.print("[dim]No new CRITICAL/HIGH findings — notification skipped[/dim]")

    # PROPOSE-tier proposals
    proposals = plan_actions(result.findings, tiers=[RemediationTier.PROPOSE])
    if proposals:
        await notify_proposals(proposals, result.hostname, webhook_url)
        console.print(f"[cyan]Proposals sent ({len(proposals)} actions)[/cyan]")


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
        output_path = Path(cfg.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        console.print(f"\n[green]Report saved to {output_path}[/green]")
    else:
        console.print(text)


def _apply_allowlist(findings, cfg):
    if not cfg.allowlist:
        return findings
    kept = []
    suppressed = 0
    for f in findings:
        match = False
        for entry in cfg.allowlist:
            if entry.finding_id != f.id:
                continue
            if not entry.affected or any(a == f.affected for a in entry.affected):
                match = True
                break
        if match:
            suppressed += 1
        else:
            kept.append(f)
    if suppressed:
        console.print(f"  [yellow]↳ Allowlist suppressed {suppressed} finding(s)[/yellow]")
    return kept
