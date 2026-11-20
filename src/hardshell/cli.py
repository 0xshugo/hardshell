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
guard_app = typer.Typer(
    name="guard",
    help="Local AI agent runaway & cost circuit breaker and emergency kill switch.",
    no_args_is_help=True,
)
app.add_typer(guard_app, name="guard")
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


def _guardian_root() -> Path:
    """Prefer HARDSHELL_HOME, then cwd with build/, then package checkout root."""
    import os

    env = os.environ.get("HARDSHELL_HOME")
    if env:
        return Path(env)
    cwd = Path.cwd()
    if (cwd / "build").is_dir() or (cwd / "pyproject.toml").exists():
        return cwd
    return Path(__file__).resolve().parents[2]


@app.command()
def status() -> None:
    """Show scanners, early-warning coverage, and latest remediation posture."""
    from hardshell.scanners import SCANNER_CLASSES

    root = _guardian_root()
    console.print(f"[bold]hardshell[/bold] v{__version__}  ·  Solo VPS Guardian\n")
    console.print("[bold]Scanners:[/bold]")
    for name, cls in SCANNER_CLASSES.items():
        available = cls.is_available()
        icon = "[green]✓[/green]" if available else "[dim]✗[/dim]"
        console.print(f"  {icon} {name}")
    report = root / "build" / "early-warning.json"
    console.print("\n[bold]Early warning:[/bold]")
    try:
        from datetime import UTC, datetime

        saved = json.loads(report.read_text())
        generated = datetime.fromisoformat(saved["generated_at"].replace("Z", "+00:00"))
        age = (datetime.now(UTC) - generated).total_seconds()
        age_label = f"{int(age // 60)}m ago" if age >= 0 else "future"
        status_value = saved.get("status", "unknown")
        cases = saved.get("cases") or []
        actionable = [c for c in cases if c.get("status") == "actionable"]
        potential = [c for c in cases if c.get("status") == "potentially_affected"]
        runtimes = saved.get("observed_runtimes") or []
        by_product: dict[str, int] = {}
        for asset in runtimes:
            product = str(asset.get("product") or "unknown")
            by_product[product] = by_product.get(product, 0) + 1
        gaps = saved.get("coverage_gaps") or []
        gap_reasons: dict[str, int] = {}
        for gap in gaps:
            reason = str(gap.get("reason") or "unknown")
            gap_reasons[reason] = gap_reasons.get(reason, 0) + 1
        console.print(f"  report: {status_value} · {age_label} · {report}")
        if not 0 <= age <= 45 * 60:
            console.print("  [red]stale: scheduled report needs attention[/red]")
        console.print(
            f"  cases: {len(cases)} total · actionable={len(actionable)} · "
            f"potentially_affected={len(potential)} · runtimes={by_product or '{}'}"
        )
        if actionable:
            for case in actionable[:5]:
                console.print(
                    f"  [red]HIGH[/red] `{case.get('advisory_id')}` "
                    f"{case.get('product')} `{case.get('asset_id')}` "
                    f"{case.get('installed')}→{case.get('fixed')}"
                )
            if len(actionable) > 5:
                console.print(f"  … and {len(actionable) - 5} more actionable")
        if potential:
            seen_targets: set[tuple] = set()
            shown = 0
            for case in potential:
                key = (
                    case.get("product"),
                    case.get("asset_id"),
                    case.get("installed"),
                    case.get("fixed"),
                )
                if key in seen_targets:
                    continue
                seen_targets.add(key)
                console.print(
                    f"  [yellow]REVIEW[/yellow] {case.get('product')} `{case.get('asset_id')}` "
                    f"{case.get('installed')}→{case.get('fixed')}"
                )
                shown += 1
                if shown >= 5:
                    break
        console.print(
            "  coverage_gaps: "
            + (
                ", ".join(f"{k}={v}" for k, v in sorted(gap_reasons.items()))
                if gap_reasons
                else "none"
            )
        )
        feed_gaps = saved.get("feed_gaps") or []
        if feed_gaps:
            feed_reasons: dict[str, int] = {}
            for fg in feed_gaps:
                fr = str((fg or {}).get("reason") or "unknown")
                feed_reasons[fr] = feed_reasons.get(fr, 0) + 1
            console.print(
                "  [red]feed_gaps[/red]: "
                + ", ".join(f"{k}={v}" for k, v in sorted(feed_reasons.items()))
            )
        notification = saved.get("notification")
        if isinstance(notification, dict):
            n_status = str(notification.get("status") or "unknown")
            failures = int(notification.get("consecutive_failures") or 0)
            if n_status in {"failed", "skipped_unconfigured"} or failures > 0:
                console.print(
                    f"  [red]discord[/red]: {n_status} (failures={failures}, "
                    f"err={notification.get('last_error')})"
                )
            else:
                console.print(f"  discord: {n_status}")
        for provider, readiness in saved.get("ai_readiness", {}).items():
            console.print(
                f"  ai/{provider}: {readiness.get('status', 'unknown')} "
                f"({readiness.get('reason', 'funding observed; see checked_at')})"
            )
        if not saved.get("ai_readiness"):
            console.print("  ai: not used on last watch (AI-less or unset)")
    except (OSError, ValueError, KeyError, TypeError):
        console.print("  [yellow]unverified: no valid scheduled report[/yellow]")

    rem_dir = root / "build" / "remediation"
    console.print("\n[bold]Remediation:[/bold]")
    try:
        receipts = sorted(rem_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not receipts:
            console.print("  none yet (approve_then_apply receipts land here)")
        else:
            latest = json.loads(receipts[0].read_text())
            console.print(
                f"  last: {receipts[0].name} · status={latest.get('status')} · "
                f"{latest.get('advisory_id')} `{latest.get('asset_id')}`"
            )
            console.print(f"  control_mode={latest.get('control_mode')} · total={len(receipts)}")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        console.print("  [yellow]unverified remediation directory[/yellow]")


@app.command(name="ops-check")
def ops_check(
    json_output: Annotated[
        bool, typer.Option("--json", help="Print machine-readable operational health JSON")
    ] = False,
    no_systemd: Annotated[
        bool, typer.Option("--no-systemd", help="Skip systemd timer/service checks")
    ] = False,
) -> None:
    """Verify Hardshell operational health and Discord alert delivery."""
    from hardshell.ops_health import evaluate_ops_health

    report = evaluate_ops_health(_guardian_root(), check_systemd=not no_systemd)
    if json_output:
        typer.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        console.print(
            f"[bold]hardshell ops-check[/bold] · overall=[bold]{report['overall_status']}[/bold]"
        )
        for name, check in report["checks"].items():
            st = check.get("status", "unknown")
            color = "green" if st == "ok" else ("yellow" if st in {"warn", "skipped"} else "red")
            detail = (
                check.get("reason")
                or check.get("delivery_status")
                or check.get("report_status")
                or ""
            )
            console.print(f"  [{color}]{st}[/{color}] {name}: {detail}")
        if report["follow_up_actions"]:
            console.print("\n[bold]Follow-up actions:[/bold]")
            for action in report["follow_up_actions"]:
                console.print(f"  • {action}")
    if report["follow_up_needed"]:
        raise typer.Exit(2)


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


@app.command(name="posture-export")
def posture_export_command(
    scan_report: Annotated[
        Path | None,
        typer.Option("--scan-report", help="Path to hardshell scan JSON report"),
    ] = None,
    early_warning: Annotated[
        Path | None,
        typer.Option("--early-warning", help="Path to early-warning JSON report"),
    ] = None,
    remediation_dir: Annotated[
        Path | None,
        typer.Option("--remediation-dir", help="Directory containing remediation receipt JSONs"),
    ] = None,
    subject: Annotated[
        str,
        typer.Option("--subject", help="Public-safe subject label (avoid sensitive hostnames)"),
    ] = "self-hosted-vps",
    sign_key: Annotated[
        Path | None,
        typer.Option("--sign-key", help="Optional Ed25519 private key PEM file for signing"),
    ] = None,
    sign_key_id: Annotated[
        str,
        typer.Option("--sign-key-id", help="Key identifier embedded in signature envelope"),
    ] = "",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write posture JSON to file (default: stdout)"),
    ] = None,
) -> None:
    """Export a secret-free, canonical-hashed (and optionally Ed25519-signed) posture summary."""
    import os

    from hardshell.posture_export import build_posture_summary

    env_home = os.environ.get("HARDSHELL_HOME")
    root = Path(env_home) if env_home else Path.cwd()
    ew_path = early_warning if early_warning is not None else root / "build" / "early-warning.json"
    rem_path = (
        remediation_dir if remediation_dir is not None else root / "build" / "remediation"
    )
    if sign_key is not None and not sign_key_id:
        console.print("[red]--sign-key-id is required when --sign-key is specified[/red]")
        raise typer.Exit(2)

    try:
        envelope = build_posture_summary(
            scan_report_path=scan_report,
            early_warning_path=ew_path,
            remediation_dir=rem_path,
            subject_label=subject,
            signing_key_path=sign_key,
            signing_key_id=sign_key_id,
        )
    except ValueError as exc:
        console.print(f"[red]Posture export failed: {exc}[/red]")
        raise typer.Exit(2) from exc

    rendered = json.dumps(envelope, ensure_ascii=False, indent=2)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        temp = output.with_suffix(".tmp")
        temp.write_text(rendered + "\n", encoding="utf-8")
        temp.chmod(0o644)
        temp.replace(output)
        console.print(f"[green]Posture summary saved to {output}[/green]")
    else:
        typer.echo(rendered)


def _default_guard_db(db: Path | None) -> Path:
    if db is not None:
        return db
    import os

    env_home = os.environ.get("HARDSHELL_HOME")
    base = Path(env_home) if env_home else Path.cwd()
    return base / "build" / "state" / "circuit-breaker.sqlite3"


@guard_app.command(name="status")
def guard_status_command(
    agent: Annotated[str | None, typer.Option("--agent", help="Filter to one agent")] = None,
    db: Annotated[Path | None, typer.Option("--db", help="Circuit breaker SQLite path")] = None,
) -> None:
    """Show local AI agent circuit-breaker states and spend totals."""
    from hardshell.circuit_breaker import CircuitBreakerStore

    store = CircuitBreakerStore(_default_guard_db(db))
    typer.echo(json.dumps(store.status(agent), ensure_ascii=False, indent=2))


@guard_app.command(name="check")
def guard_check_command(
    agent: Annotated[str, typer.Argument(help="Agent identifier (e.g. openclaw, n8n, hermes)")],
    cost_usd: Annotated[str, typer.Option("--cost-usd", help="Estimated USD cost of call")] = "0",
    action: Annotated[
        str, typer.Option("--action", help="Action/tool signature hashed locally for loop checks")
    ] = "",
    daily_cap: Annotated[str, typer.Option("--daily-cap", help="Max daily USD spend")] = "5.00",
    monthly_cap: Annotated[
        str, typer.Option("--monthly-cap", help="Max monthly USD spend")
    ] = "50.00",
    rpm: Annotated[int, typer.Option("--rpm", help="Max requests per minute")] = 30,
    db: Annotated[Path | None, typer.Option("--db", help="Circuit breaker SQLite path")] = None,
) -> None:
    """Evaluate local circuit breaker before an AI call (exit 0=allow, exit 4=blocked)."""
    from hardshell.circuit_breaker import (
        AgentGuardPolicy,
        CircuitBreakerStore,
        CircuitOpenError,
        fingerprint_action,
    )

    policy = AgentGuardPolicy(
        max_requests_per_minute=rpm,
        max_daily_usd=daily_cap,
        max_monthly_usd=monthly_cap,
    )
    store = CircuitBreakerStore(_default_guard_db(db), policies={agent: policy})
    fp = fingerprint_action(action) if action else ""
    try:
        res = store.admit(agent, cost_usd=cost_usd, fingerprint=fp)
        typer.echo(json.dumps({"allowed": True, **res}, ensure_ascii=False))
    except CircuitOpenError as exc:
        typer.echo(
            json.dumps(
                {"allowed": False, "agent": exc.agent, "code": exc.code, "detail": exc.detail},
                ensure_ascii=False,
            )
        )
        raise typer.Exit(4) from exc


@guard_app.command(name="kill")
def guard_kill_command(
    agent: Annotated[str, typer.Argument(help="Agent identifier to kill immediately")],
    reason: Annotated[str, typer.Option("--reason", help="Audit reason")] = "manual_kill_switch",
    db: Annotated[Path | None, typer.Option("--db", help="Circuit breaker SQLite path")] = None,
) -> None:
    """Engage emergency local Kill Switch for an AI agent (never auto-resets)."""
    from hardshell.circuit_breaker import CircuitBreakerStore

    store = CircuitBreakerStore(_default_guard_db(db))
    res = store.kill(agent, reason=reason)
    typer.echo(json.dumps(res, ensure_ascii=False))


@guard_app.command(name="reset")
def guard_reset_command(
    agent: Annotated[str, typer.Argument(help="Agent identifier to re-arm")],
    reason: Annotated[str, typer.Option("--reason", help="Audit reason")] = "operator_reset",
    db: Annotated[Path | None, typer.Option("--db", help="Circuit breaker SQLite path")] = None,
) -> None:
    """Explicitly re-arm a tripped or killed AI agent after operator investigation."""
    from hardshell.circuit_breaker import CircuitBreakerStore

    store = CircuitBreakerStore(_default_guard_db(db))
    res = store.reset(agent, reason=reason)
    typer.echo(json.dumps(res, ensure_ascii=False))


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
    """Fetch official PHP/nginx advisories and prepare approval-bound cases. Never remediate."""
    asyncio.run(_run_watch(inventory, output, ai))


async def _run_watch(inventory_path, output, ai):
    import os
    import time
    from datetime import UTC, datetime

    from hardshell.early_warning import build_report, collect_inventory
    from hardshell.intel.vendor import fetch_nginx, fetch_php

    state = _guardian_root() / "build" / "state"
    advisories = []
    gaps = []
    source_requests = []
    observed_stamps = []
    try:
        php_intel = await fetch_php(cache_dir=state / "vendor")
        for item in php_intel.get("advisories", []):
            row = dict(item)
            row["observed_at"] = php_intel.get("observed_at")
            advisories.append(row)
        gaps.extend(php_intel.get("gaps", []))
        source_requests.extend(php_intel.get("source_requests", []))
        if php_intel.get("observed_at"):
            observed_stamps.append(php_intel["observed_at"])
    except Exception:
        gaps.append({"source": "php.net", "reason": "acquisition_failed"})
    try:
        nginx_intel = await fetch_nginx(cache_dir=state / "vendor")
        for item in nginx_intel.get("advisories", []):
            row = dict(item)
            row["observed_at"] = nginx_intel.get("observed_at")
            advisories.append(row)
        gaps.extend(nginx_intel.get("gaps", []))
        source_requests.extend(nginx_intel.get("source_requests", []))
        if nginx_intel.get("observed_at"):
            observed_stamps.append(nginx_intel["observed_at"])
    except Exception:
        gaps.append({"source": "nginx.org", "reason": "acquisition_failed"})
    intel = {
        "observed_at": min(observed_stamps) if observed_stamps else None,
        "advisories": advisories,
        "gaps": gaps,
        "source_requests": source_requests,
    }
    try:
        if inventory_path:
            if inventory_path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("inventory_too_large")
            inventory = json.loads(inventory_path.read_text())
        else:
            inventory = await asyncio.to_thread(collect_inventory)
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
    try:
        import socket

        from hardshell.reporters.discord import deliver_early_warning

        delivery = await deliver_early_warning(
            result,
            socket.gethostname(),
            state_path=state / "early-warning-alerts.json",
        )
        result["notification"] = {k: v for k, v in delivery.items() if k != "ok"}
        if result.get("status") == "actionable" and not delivery.get("ok"):
            console.print("[yellow]Discord HIGH notify failed or webhook unset[/yellow]")
    except Exception:
        result["notification"] = {
            "channel": "discord",
            "status": "failed",
            "checked_at": datetime.now(UTC).isoformat(),
            "last_error": "local_notify_error",
        }
        console.print("[yellow]Discord HIGH notify skipped due to local error[/yellow]")
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
            if isinstance(getattr(s, "evidence", None), dict):
                scanner_evidence[s.name] = s.evidence
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
        from hardshell.reporters.discord import notify_proposals

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
