from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_WRAPPER = ROOT / "bin" / "scan.sh"


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
