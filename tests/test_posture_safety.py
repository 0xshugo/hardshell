from pathlib import Path

from hardshell.collectors.hermes_registry import collect_hermes_registry
from hardshell.models import ControlStatus, Finding, Severity
from hardshell.posture import RuntimePostureEvaluator
from hardshell.remediate.runner import render_fix_script


async def test_empty_registry_never_passes_unevaluated_controls(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text("{}")
    policy = Path(__file__).resolve().parents[1] / "hardshell-agent-policy.yaml"
    state = await RuntimePostureEvaluator(policy).evaluate_registry(registry)
    assert set(state.controls.values()) == {ControlStatus.UNKNOWN}


def test_destination_and_missing_permissions_do_not_prove_controls(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("mcp_servers:\n  example:\n    url: https://example.invalid/mcp\n")
    empty_env = tmp_path / "empty.env"
    empty_env.write_text("")
    result = collect_hermes_registry(config, empty_env)
    assert result["agents"][0]["kill_switch"] is None
    assert result["mcp_servers"][0]["domain_allowlist"] == []
    assert result["mcp_servers"][0]["permissions"] == ["unknown"]


def test_fix_script_keeps_untrusted_multiline_title_in_comments():
    finding = Finding(
        id="SYS-F2B-DOWN",
        scanner="system",
        severity=Severity.HIGH,
        title="example\nINERT_SENTINEL\rSECOND_SENTINEL",
        affected="test",
    )
    rendered = render_fix_script([finding])
    assert "INERT_SENTINEL" not in rendered.splitlines()
    assert "SECOND_SENTINEL" not in rendered.splitlines()
    assert "# INERT_SENTINEL" in rendered.splitlines()
    assert "# SECOND_SENTINEL" in rendered.splitlines()


def test_status_notification_never_marks_partial_or_missing_scanners_green(tmp_path, monkeypatch):
    import json
    import sys

    wrapper = (Path(__file__).resolve().parents[1] / "bin/discord-status.sh").read_text()
    code = wrapper.split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    code = code.split("request = urllib.request.Request(", 1)[0]
    report = tmp_path / "report.json"
    monkeypatch.setenv("HARDSHELL_STATUS_WEBHOOK_URL", "https://example.invalid/never-sent")
    monkeypatch.setattr(sys, "argv", ["status", str(report), "daily", str(tmp_path / "missing")])
    for status, scanner_status, expected in [
        ("partial", {"trivy": "failed"}, "❔"),
        ("complete", {}, "❔"),
        ("complete", {"trivy": "ok"}, "✅"),
    ]:
        report.write_text(
            json.dumps(
                {
                    "status": status,
                    "scanners_used": ["trivy"],
                    "scanner_status": scanner_status,
                    "findings": [],
                }
            )
        )
        scope = {}
        exec(compile(code, "<status render only>", "exec"), scope)
        assert scope["content"].startswith(expected)


async def test_stdio_transport_does_not_prove_absence_of_network_access(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "mcp_servers:\n  unknown:\n    command: example\n"
        "  explicit:\n    command: example\n    network_access: true\n"
    )
    env = tmp_path / "empty.env"
    env.write_text("")
    result = collect_hermes_registry(config, env)
    assert result["mcp_servers"][0]["network_access"] is None
    assert result["mcp_servers"][1]["network_access"] is True
    registry = tmp_path / "registry.json"
    import json

    registry.write_text(json.dumps({"mcp_servers": [result["mcp_servers"][0]]}))
    policy = Path(__file__).resolve().parents[1] / "hardshell-agent-policy.yaml"
    state = await RuntimePostureEvaluator(policy).evaluate_registry(registry)
    assert state.controls["CT-MCP-NETWORK-EGRESS"] == ControlStatus.UNKNOWN


async def test_system_exec_real_success_with_discarded_stderr():
    import sys

    from hardshell.scanners.system import SystemScanner

    rc, stdout, stderr = await SystemScanner()._run(sys.executable, "-c", "print('ready')")
    assert rc == 0
    assert stdout.strip() == "ready"
    assert stderr == ""


def test_invalid_audit_flag_does_not_become_confirmed_logging(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text('mcp_servers:\n  example:\n    command: example\n    audit_log: "false"\n')
    env = tmp_path / "empty.env"
    env.write_text("")
    result = collect_hermes_registry(config, env)
    assert result["mcp_servers"][0]["audit_log"] is None


async def test_registry_scan_requires_real_readable_input_for_each_component(tmp_path):
    import json

    import pytest

    from hardshell.config import ScanConfig
    from hardshell.scanners.agent_registry import (
        AgentRegistryScanner,
        SecretConfigScanner,
        ToolMCPScanner,
    )

    for scanner_type in (AgentRegistryScanner, ToolMCPScanner, SecretConfigScanner):
        for paths in ([], [str(tmp_path / "missing")]):
            with pytest.raises(RuntimeError, match="registry_input_unavailable"):
                await scanner_type().scan(ScanConfig(agent_registry_paths=paths))
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"agents": [{"id": "example"}], "mcp_servers": [], "secrets": []}))
    for scanner_type in (AgentRegistryScanner, ToolMCPScanner, SecretConfigScanner):
        scanner = scanner_type()
        await scanner.scan(ScanConfig(agent_registry_paths=[str(path)]))
        assert scanner.evidence["source_count"] == 1
        assert len(scanner.evidence["source_sha256"][0]) == 64


async def test_report_carries_registry_observation_proof(tmp_path):
    import json

    from hardshell.cli import _run_scan
    from hardshell.config import ScanConfig

    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [{"id": "a", "kill_switch": True, "tools": []}],
                "mcp_servers": [],
                "secrets": [],
            }
        )
    )
    output = tmp_path / "report.json"
    names = ["agent-registry", "tool-mcp", "secret-config"]
    await _run_scan(
        ScanConfig(
            scanners=names, agent_registry_paths=[str(registry)], format="json", output=str(output)
        )
    )
    report = json.loads(output.read_text())
    assert report["status"] == "complete"
    assert set(report["scanner_evidence"]) == set(names)
    assert all(proof["source_count"] == 1 for proof in report["scanner_evidence"].values())
