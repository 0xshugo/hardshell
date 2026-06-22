import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_WRAPPER = ROOT / "bin" / "scan.sh"
SCRATCH_SYNC = ROOT / "bin" / "scratch-sync.sh"


def run_scan_dry_run(*args: str, **env_overrides: str) -> str:
    env = os.environ.copy()
    env["HARDSHELL_DRY_RUN"] = "1"
    env.update(env_overrides)
    result = subprocess.run(
        ["bash", str(SCAN_WRAPPER), *args],
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )
    return result.stdout


def test_daily_wrapper_runs_agent_posture_scanners() -> None:
    script = SCAN_WRAPPER.read_text()

    assert 'SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy"' in script


def test_weekly_wrapper_runs_agent_posture_scanners() -> None:
    script = SCAN_WRAPPER.read_text()

    assert 'SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy,grype,lynis"' in script


def test_wrapper_uses_configured_agent_registry_paths() -> None:
    example_config = (ROOT / "hardshell.toml.example").read_text()

    assert "agent_registry_paths" in example_config
    assert "hardshell-agent-posture.json" in example_config


def test_wrapper_collects_hermes_registry_before_scanning() -> None:
    script = SCAN_WRAPPER.read_text()

    collect_index = script.index("collect-hermes-registry")
    scan_index = script.index("scan \\")
    assert collect_index < scan_index
    assert "AGENT_REGISTRY_OUT" in script
    assert "--hermes-config" in script
    assert "--env-file" in script


def test_wrapper_sends_always_on_discord_status_report() -> None:
    script = SCAN_WRAPPER.read_text()

    notify_index = script.index("notify \"$OUTFILE\"")
    status_index = script.index("discord-status.sh")
    metrics_index = script.index("metrics.sh")
    assert notify_index < status_index < metrics_index

    status_script = (ROOT / "bin" / "discord-status.sh").read_text()
    assert "secfeed MCP" in status_script
    assert "Critical/High findings" in status_script


def test_scratch_sync_autostashes_before_pull() -> None:
    script = SCRATCH_SYNC.read_text()

    assert "git pull --rebase --autostash --quiet" in script


def test_wrapper_supports_report_date_override_for_backfill() -> None:
    stdout = run_scan_dry_run("daily", "2026-06-20")

    assert "mode=daily" in stdout
    assert "report_date=2026-06-20" in stdout
    assert "outfile=/home/shugo/hardshell/reports/daily-2026-06-20.json" in stdout


def test_backfill_dry_run_disables_current_run_side_effects_by_default() -> None:
    stdout = run_scan_dry_run("daily", "2026-06-20")

    assert "current_run_mutations_default=false" in stdout
    assert "auto_fix=false" in stdout
    assert "delta_notify=false" in stdout
    assert "status_report=false" in stdout
    assert "metrics=false" in stdout
    assert "scratch_sync=false" in stdout


def test_backfill_side_effects_can_be_explicitly_enabled() -> None:
    stdout = run_scan_dry_run("daily", "2026-06-20", HARDSHELL_SCRATCH_SYNC="true")

    assert "scratch_sync=true" in stdout


def test_reports_are_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text().splitlines()

    assert "reports/" in gitignore
