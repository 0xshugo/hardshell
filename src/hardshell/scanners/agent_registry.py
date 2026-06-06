"""Read-only scanner for AI-agent registry manifests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hardshell.config import ScanConfig
from hardshell.models import AgentFinding, Asset, AssetType, Evidence, Finding, Severity


class _RegistryFileMixin:
    """Shared read-only JSON registry loading for agent posture scanners."""

    name = "registry-file"

    @staticmethod
    def is_available() -> bool:
        return True

    def _load_payloads(self, config: ScanConfig) -> list[tuple[Path, Any]]:
        payloads: list[tuple[Path, Any]] = []
        for registry_path in config.agent_registry_paths:
            path = Path(registry_path).expanduser()
            if not path.exists() or not path.is_file():
                continue
            try:
                payloads.append((path, json.loads(path.read_text())))
            except json.JSONDecodeError:
                continue
        return payloads


class AgentRegistryScanner(_RegistryFileMixin):
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


class ToolMCPScanner(_RegistryFileMixin):
    """Scan MCP server posture from read-only registry manifests."""

    name = "tool-mcp"

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path, payload in self._load_payloads(config):
            findings.extend(
                agent_finding.to_finding(scanner=self.name)
                for agent_finding in self._evaluate_mcp_servers(payload, path)
            )
        return findings

    def _evaluate_mcp_servers(self, payload: Any, path: Path) -> list[AgentFinding]:
        if not isinstance(payload, dict):
            return []
        servers = payload.get("mcp_servers", [])
        if not isinstance(servers, list):
            return []

        findings: list[AgentFinding] = []
        for index, server in enumerate(servers):
            if not isinstance(server, dict):
                continue
            server_id = str(server.get("id") or server.get("name") or f"mcp_server[{index}]")
            findings.extend(self._network_allowlist_findings(server, server_id, index, path))
            findings.extend(self._audit_log_findings(server, server_id, index, path))
        return findings

    def _network_allowlist_findings(
        self, server: dict[str, Any], server_id: str, index: int, path: Path
    ) -> list[AgentFinding]:
        transport = str(server.get("transport", "")).lower()
        network_access = server.get("network_access") is True or transport in {
            "http",
            "sse",
            "websocket",
            "streamable_http",
        }
        allowlist = server.get("domain_allowlist", [])
        if not network_access or (isinstance(allowlist, list) and allowlist):
            return []
        return [
            AgentFinding(
                id="AGENT-MCP-NETWORK-ALLOWLIST-001",
                severity=Severity.HIGH,
                title="Network-capable MCP server has no domain allowlist",
                asset=Asset(type=AssetType.MCP_SERVER, identifier=server_id),
                control_id="CT-MCP-NETWORK-EGRESS",
                threat_id="TH-TOOL-ABUSE",
                requirement_id="REQ-MCP-001",
                description=(
                    "MCP server can reach network resources but the registry does not define "
                    "a non-empty domain allowlist."
                ),
                evidence=[
                    Evidence(
                        source=self.name,
                        locator=f"{path}#/mcp_servers/{index}/domain_allowlist",
                        observed_value=allowlist,
                    )
                ],
                remediation=(
                    "Restrict network-capable MCP servers to an explicit domain allowlist and "
                    "review exceptions through change control."
                ),
            )
        ]

    def _audit_log_findings(
        self, server: dict[str, Any], server_id: str, index: int, path: Path
    ) -> list[AgentFinding]:
        permissions = server.get("permissions", [])
        if not isinstance(permissions, list):
            return []
        normalized_permissions = {str(permission).lower() for permission in permissions}
        if "write" not in normalized_permissions or server.get("audit_log") is True:
            return []
        return [
            AgentFinding(
                id="AGENT-MCP-AUDIT-001",
                severity=Severity.HIGH,
                title="Writable MCP server has no confirmed audit log",
                asset=Asset(type=AssetType.MCP_SERVER, identifier=server_id),
                control_id="CT-MCP-AUDIT-LOGGING",
                threat_id="TH-TOOL-ABUSE",
                requirement_id="REQ-MCP-002",
                description=(
                    "MCP server exposes write-capable operations but the registry does not "
                    "confirm tamper-evident audit logging."
                ),
                evidence=[
                    Evidence(
                        source=self.name,
                        locator=f"{path}#/mcp_servers/{index}/audit_log",
                        observed_value=server.get("audit_log"),
                    )
                ],
                remediation=(
                    "Enable audit logging for write-capable MCP servers and retain logs with "
                    "operator, agent, tool, input, output, and approval context."
                ),
            )
        ]


class SecretConfigScanner(_RegistryFileMixin):
    """Scan credential posture from read-only registry manifests."""

    name = "secret-config"

    async def scan(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []
        for path, payload in self._load_payloads(config):
            findings.extend(
                agent_finding.to_finding(scanner=self.name)
                for agent_finding in self._evaluate_secrets(payload, path)
            )
        return findings

    def _evaluate_secrets(self, payload: Any, path: Path) -> list[AgentFinding]:
        if not isinstance(payload, dict):
            return []
        secrets = payload.get("secrets", [])
        if not isinstance(secrets, list):
            return []

        findings: list[AgentFinding] = []
        for index, secret in enumerate(secrets):
            if not isinstance(secret, dict):
                continue
            secret_id = str(secret.get("id") or secret.get("name") or f"secret[{index}]")
            findings.extend(self._plaintext_secret_findings(secret, secret_id, index, path))
            if str(secret.get("storage", "")).lower() not in {
                "plaintext",
                "plaintext_env",
                "env_file",
            }:
                findings.extend(self._scope_findings(secret, secret_id, index, path))
        return findings

    def _plaintext_secret_findings(
        self, secret: dict[str, Any], secret_id: str, index: int, path: Path
    ) -> list[AgentFinding]:
        storage = str(secret.get("storage", "")).lower()
        if storage not in {"plaintext", "plaintext_env", "env_file"}:
            return []
        return [
            AgentFinding(
                id="AGENT-SECRET-PLAINTEXT-001",
                severity=Severity.CRITICAL,
                title="Agent credential is stored in plaintext configuration",
                asset=Asset(type=AssetType.CREDENTIAL, identifier=secret_id),
                control_id="CT-SECRET-MANAGED-STORAGE",
                threat_id="TH-CREDENTIAL-THEFT",
                requirement_id="REQ-SECRET-001",
                description=(
                    "Credential storage is marked as plaintext or file-based environment "
                    "configuration, which is not acceptable for autonomous agent runtimes."
                ),
                evidence=[
                    Evidence(
                        source=self.name,
                        locator=f"{path}#/secrets/{index}/storage",
                        observed_value=secret.get("storage"),
                    )
                ],
                remediation=(
                    "Move credentials into a managed secret store or OS keychain, then expose "
                    "only short-lived scoped tokens to the agent runtime."
                ),
            )
        ]

    def _scope_findings(
        self, secret: dict[str, Any], secret_id: str, index: int, path: Path
    ) -> list[AgentFinding]:
        if secret.get("scoped_to_agent") is True:
            return []
        return [
            AgentFinding(
                id="AGENT-SECRET-SCOPE-001",
                severity=Severity.HIGH,
                title="Agent credential is not scoped to a specific agent",
                asset=Asset(type=AssetType.CREDENTIAL, identifier=secret_id),
                control_id="CT-SECRET-LEAST-PRIVILEGE",
                threat_id="TH-CREDENTIAL-THEFT",
                requirement_id="REQ-SECRET-002",
                description=(
                    "Credential can be used outside a specific agent scope according to the "
                    "registry metadata."
                ),
                evidence=[
                    Evidence(
                        source=self.name,
                        locator=f"{path}#/secrets/{index}/scoped_to_agent",
                        observed_value=secret.get("scoped_to_agent"),
                    )
                ],
                remediation=(
                    "Bind credentials to one agent, one tool purpose, one environment, and a "
                    "short rotation window wherever the provider supports it."
                ),
            )
        ]
