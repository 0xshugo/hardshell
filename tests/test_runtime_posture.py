import json
from pathlib import Path

import yaml

from hardshell.models import ControlStatus
from hardshell.posture import RuntimePostureEvaluator, load_agent_policy

POLICY = Path(__file__).resolve().parents[1] / "hardshell-agent-policy.yaml"


def test_agent_policy_declares_core_runtime_controls() -> None:
    policy = load_agent_policy(POLICY)

    control_ids = {control["id"] for control in policy["controls"]}
    assert {
        "CT-RUNTIME-KILL-SWITCH",
        "CT-TOOL-LEAST-PRIVILEGE",
        "CT-MCP-NETWORK-EGRESS",
        "CT-MCP-AUDIT-LOGGING",
        "CT-SECRET-MANAGED-STORAGE",
        "CT-SECRET-LEAST-PRIVILEGE",
    }.issubset(control_ids)
    assert yaml.safe_load(POLICY.read_text())["schema_version"] == "hardshell.agent_policy.v1"


async def test_runtime_posture_evaluator_maps_registry_to_assets_controls_and_findings(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "hermes/default",
                        "kill_switch": False,
                        "tools": [{"id": "toolset:web", "permissions": ["read"]}],
                    }
                ],
                "mcp_servers": [
                    {
                        "id": "secfeed",
                        "transport": "streamable_http",
                        "network_access": True,
                        "domain_allowlist": [],
                    }
                ],
                "secrets": [
                    {"id": "OPENAI_API_KEY", "storage": "keychain", "scoped_to_agent": True}
                ],
            }
        )
    )

    state = await RuntimePostureEvaluator(policy_path=POLICY).evaluate_registry(registry)

    assert {asset.stable_key for asset in state.assets} == {
        "agent:hermes/default",
        "tool:toolset:web",
        "mcp_server:secfeed",
        "credential:OPENAI_API_KEY",
        "policy:hardshell-agent-policy",
    }
    assert state.controls["CT-RUNTIME-KILL-SWITCH"] == ControlStatus.FAIL
    assert state.controls["CT-MCP-NETWORK-EGRESS"] == ControlStatus.FAIL
    assert state.controls["CT-SECRET-MANAGED-STORAGE"] == ControlStatus.PASS
    assert state.controls["CT-SECRET-LEAST-PRIVILEGE"] == ControlStatus.PASS
    assert {finding.id for finding in state.findings} == {
        "AGENT-KILL-SWITCH-001",
        "AGENT-MCP-NETWORK-ALLOWLIST-001",
    }
