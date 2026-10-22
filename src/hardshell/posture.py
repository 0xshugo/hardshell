"""Runtime posture evaluation for AI-agent registry manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from hardshell.models import Asset, AssetType, ControlStatus, PostureState
from hardshell.scanners.agent_registry import (
    AgentRegistryScanner,
    SecretConfigScanner,
    ToolMCPScanner,
)


def load_agent_policy(path: Path) -> dict[str, Any]:
    """Load a hardshell agent policy YAML file."""
    data = yaml.safe_load(path.expanduser().read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Agent policy is not a mapping: {path}")
    controls = data.get("controls")
    if not isinstance(controls, list):
        raise ValueError(f"Agent policy has no controls list: {path}")
    return data


class RuntimePostureEvaluator:
    """Evaluate registry assets and policy controls without mutating runtime state."""

    def __init__(self, policy_path: Path | None = None) -> None:
        self.policy_path = policy_path or Path("hardshell-agent-policy.yaml")
        self.policy = load_agent_policy(self.policy_path)

    async def evaluate_registry(self, registry_path: Path) -> PostureState:
        registry_path = registry_path.expanduser()
        payload = json.loads(registry_path.read_text())
        if not isinstance(payload, dict):
            payload = {}

        findings = []
        findings.extend(AgentRegistryScanner()._evaluate_registry(payload, registry_path))
        findings.extend(ToolMCPScanner()._evaluate_mcp_servers(payload, registry_path))
        findings.extend(SecretConfigScanner()._evaluate_secrets(payload, registry_path))

        return PostureState(
            assets=self._collect_assets(payload),
            controls=self._evaluate_controls(findings, payload),
            findings=findings,
        )

    def _evaluate_controls(self, findings, payload) -> dict[str, ControlStatus]:
        failed = {finding.control_id for finding in findings}
        agents = payload.get("agents", [])
        servers = payload.get("mcp_servers", [])
        secrets = payload.get("secrets", [])
        agents = (
            [item for item in agents if isinstance(item, dict)] if isinstance(agents, list) else []
        )
        servers = (
            [item for item in servers if isinstance(item, dict)]
            if isinstance(servers, list)
            else []
        )
        secrets = (
            [item for item in secrets if isinstance(item, dict)]
            if isinstance(secrets, list)
            else []
        )
        tools = [
            tool for agent in agents for tool in agent.get("tools", []) if isinstance(tool, dict)
        ]

        def known_permissions(item):
            return (
                isinstance(item.get("permissions"), list)
                and bool(item["permissions"])
                and all(permission in ("read", "write") for permission in item["permissions"])
            )

        confirmed = {
            "CT-RUNTIME-KILL-SWITCH": bool(agents)
            and all(agent.get("kill_switch") is True for agent in agents),
            "CT-TOOL-LEAST-PRIVILEGE": bool(tools)
            and all(known_permissions(tool) for tool in tools),
            "CT-MCP-NETWORK-EGRESS": bool(servers)
            and all(
                isinstance(server.get("network_access"), bool)
                and (server["network_access"] is False or bool(server.get("domain_allowlist")))
                for server in servers
            ),
            "CT-MCP-AUDIT-LOGGING": bool(servers)
            and all(
                known_permissions(server)
                and ("write" not in server["permissions"] or server.get("audit_log") is True)
                for server in servers
            ),
            "CT-SECRET-MANAGED-STORAGE": bool(secrets)
            and all(
                secret.get("storage") in {"keychain", "secret_manager", "vault"}
                for secret in secrets
            ),
            "CT-SECRET-LEAST-PRIVILEGE": bool(secrets)
            and all(secret.get("scoped_to_agent") is True for secret in secrets),
        }
        return {
            str(control["id"]): (
                ControlStatus.FAIL
                if str(control["id"]) in failed
                else ControlStatus.PASS
                if confirmed.get(str(control["id"]), False)
                else ControlStatus.UNKNOWN
            )
            for control in self.policy["controls"]
            if isinstance(control, dict) and control.get("id")
        }

    def _collect_assets(self, payload: dict[str, Any]) -> list[Asset]:
        assets = [
            Asset(
                type=AssetType.POLICY,
                identifier=str(self.policy.get("id", "agent-policy")),
            )
        ]
        for agent in payload.get("agents", []):
            if not isinstance(agent, dict):
                continue
            agent_id = str(agent.get("id") or agent.get("name") or "agent")
            assets.append(Asset(type=AssetType.AGENT, identifier=agent_id))
            for tool in agent.get("tools", []):
                if isinstance(tool, dict):
                    tool_id = str(tool.get("id") or tool.get("name") or "tool")
                    assets.append(
                        Asset(
                            type=AssetType.TOOL,
                            identifier=tool_id,
                            metadata={"agent_id": agent_id},
                        )
                    )
        for server in payload.get("mcp_servers", []):
            if isinstance(server, dict):
                server_id = str(server.get("id") or server.get("name") or "mcp_server")
                assets.append(Asset(type=AssetType.MCP_SERVER, identifier=server_id))
        for secret in payload.get("secrets", []):
            if isinstance(secret, dict):
                secret_id = str(secret.get("id") or secret.get("name") or "credential")
                assets.append(Asset(type=AssetType.CREDENTIAL, identifier=secret_id))
        return assets
