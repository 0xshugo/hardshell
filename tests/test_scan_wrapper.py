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

    notify_index = script.index('notify "$OUTFILE"')
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
    # HARDSHELL_HOME はスクリプト位置 (= リポジトリルート) から自動導出される
    assert f"outfile={ROOT}/reports/daily-2026-06-20.json" in stdout


def test_wrapper_install_dir_is_overridable_via_env() -> None:
    stdout = run_scan_dry_run("daily", "2026-06-20", HARDSHELL_HOME="/opt/hardshell")

    assert "outfile=/opt/hardshell/reports/daily-2026-06-20.json" in stdout


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


def test_wrapper_refuses_env_file_with_loose_permissions() -> None:
    script = SCAN_WRAPPER.read_text()

    # .env は 600/400 かつ運用ユーザー or root 所有の場合のみ source する
    assert "refusing to source" in script
    source_index = script.index('source "$ENV_FILE"')
    perms_check_index = script.index("ENV_PERMS")
    assert perms_check_index < source_index


def test_reports_are_gitignored() -> None:
    gitignore = (ROOT / ".gitignore").read_text().splitlines()

    assert "reports/" in gitignore


def test_partial_scan_still_reports_status_and_never_runs_remediation(tmp_path):
    import shutil
    import sys

    root = tmp_path / "installation"
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True)
    wrapper = bin_dir / "scan.sh"
    shutil.copy2(SCAN_WRAPPER, wrapper)
    fake = bin_dir / "hardshell"
    fake.write_text(
        "#!" + sys.executable + "\n"
        "import json,sys\nfrom pathlib import Path\n"
        "if sys.argv[1] == 'scan':\n"
        "    Path(sys.argv[sys.argv.index('-o')+1]).write_text(json.dumps({'status':'partial'}))\n"
        "    raise SystemExit(2)\n"
        "if sys.argv[1] == 'fix':\n"
        "    Path(__file__).with_name('unexpected-fix').touch()\n"
    )
    fake.chmod(0o700)
    sudo = bin_dir / "sudo"
    sudo.write_text('#!/bin/sh\nshift\nexec "$@"\n')
    sudo.chmod(0o700)
    status = bin_dir / "discord-status.sh"
    status.write_text('#!/bin/sh\ntouch "$(dirname "$0")/status-rendered"\n')
    status.chmod(0o700)
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            "HARDSHELL_HOME": str(root),
            "HARDSHELL_BIN": str(fake),
            "HARDSHELL_ENV_FILE": str(tmp_path / "missing.env"),
            "HARDSHELL_AUTO_FIX": "true",
            "HARDSHELL_STATUS_REPORT": "true",
            "HARDSHELL_DELTA_NOTIFY": "false",
            "HARDSHELL_METRICS": "false",
            "HARDSHELL_SCRATCH_SYNC": "false",
            "HARDSHELL_DRY_RUN": "false",
        }
    )
    result = subprocess.run(
        ["bash", str(wrapper), "daily"], env=env, capture_output=True, text=True
    )
    assert result.returncode == 2, result.stderr
    assert (bin_dir / "status-rendered").exists(), result.stdout
    assert not (bin_dir / "unexpected-fix").exists()
