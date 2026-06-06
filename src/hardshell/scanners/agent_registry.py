"""Read-only scanner for AI-agent registry manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hardshell.config import ScanConfig
from hardshell.models import AgentFinding, Asset, AssetType, Evidence, Finding, Severity


class AgentRegistryScanner:
    """Scan JSON agent registries without mutating agent runtime state.

    Expected input is intentionally simple and vendor-neutral::

        {
          "agents": [
            {
              "id": "mythos/orchestrator",
              "kill_switch": true,
              "tools": [{"id": "mcp:filesystem", "permissions": ["read"]}]
            }
          ]
        }
    """

    name = "agent-registry"

    @staticmethod
    def is_available() -> bool:
        return True

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for registry_path in config.agent_registry_paths:
            path = Path(registry_path).expanduser()
            if not path.exists() or not path.is_file():
                continue

            try:
                payload = json.loads(path.read_text())
            except json.JSONDecodeError:
                findings.append(self._invalid_registry_finding(path))
                continue

            findings.extend(
                agent_finding.to_finding(scanner=self.name)
                for agent_finding in self._evaluate_registry(payload, path)
            )
        return findings

    def _evaluate_registry(self, payload: Any, path: Path) -> list[AgentFinding]:
        if not isinstance(payload, dict):
            return []

        agents = payload.get("agents", [])
        if not isinstance(agents, list):
            return []

        findings: list[AgentFinding] = []
        for index, agent in enumerate(agents):
            if not isinstance(agent, dict):
                continue

            agent_id = str(agent.get("id") or agent.get("name") or f"agent[{index}]")
            if agent.get("kill_switch") is not True:
                findings.append(
                    AgentFinding(
                        id="AGENT-KILL-SWITCH-001",
                        severity=Severity.HIGH,
                        title="Agent has no confirmed kill switch",
                        asset=Asset(type=AssetType.AGENT, identifier=agent_id),
                        control_id="CT-RUNTIME-KILL-SWITCH",
                        threat_id="TH-RUNAWAY-AUTONOMY",
                        requirement_id="REQ-RUNTIME-001",
                        description=(
                            "Agent registry does not confirm an operator-controlled "
                            "kill switch for this agent."
                        ),
                        evidence=[
                            Evidence(
                                source=self.name,
                                locator=f"{path}#/agents/{index}/kill_switch",
                                observed_value=agent.get("kill_switch"),
                            )
                        ],
                        remediation=(
                            "Define and test an operator-controlled kill switch before "
                            "allowing autonomous execution."
                        ),
                    )
                )

            findings.extend(self._evaluate_tools(agent, agent_id, index, path))
        return findings

    def _evaluate_tools(
        self, agent: dict[str, Any], agent_id: str, agent_index: int, path: Path
    ) -> list[AgentFinding]:
        tools = agent.get("tools", [])
        if not isinstance(tools, list):
            return []

        findings: list[AgentFinding] = []
        for tool_index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                continue
            permissions = tool.get("permissions", [])
            if not isinstance(permissions, list):
                continue

            normalized_permissions = {str(permission).lower() for permission in permissions}
            if "write" not in normalized_permissions:
                continue

            tool_id = str(tool.get("id") or tool.get("name") or f"tool[{tool_index}]")
            findings.append(
                AgentFinding(
                    id="AGENT-TOOL-WRITE-001",
                    severity=Severity.HIGH,
                    title="Writable tool exposed to agent",
                    asset=Asset(
                        type=AssetType.TOOL,
                        identifier=tool_id,
                        metadata={"agent_id": agent_id},
                    ),
                    control_id="CT-TOOL-LEAST-PRIVILEGE",
                    threat_id="TH-TOOL-ABUSE",
                    requirement_id="REQ-TOOL-001",
                    description=(
                        "Agent registry grants write permission to a tool. Writable tools "
                        "require explicit scope, approval gates, and audit evidence."
                    ),
                    evidence=[
                        Evidence(
                            source=self.name,
                            locator=f"{path}#/agents/{agent_index}/tools/{tool_index}/permissions",
                            observed_value=permissions,
                        )
                    ],
                    remediation=(
                        "Reduce tool permissions to read-only where possible, or bind write "
                        "access to explicit scope, approval, audit log, and rollback controls."
                    ),
                )
            )
        return findings

    def _invalid_registry_finding(self, path: Path) -> Finding:
        return Finding(
            id="AGENT-REGISTRY-INVALID-JSON",
            scanner=self.name,
            severity=Severity.MEDIUM,
            title="Agent registry is not valid JSON",
            affected=str(path),
            description="Configured agent registry could not be parsed as JSON.",
            remediation="Fix registry JSON syntax or remove the path from hardshell config.",
        )
