"""Tests for AI agent registry scanner."""

import json

import pytest

from hardshell.config import ScanConfig
from hardshell.models import Severity
from hardshell.scanners.agent_registry import (
    AgentRegistryScanner,
    SecretConfigScanner,
    ToolMCPScanner,
)


@pytest.mark.asyncio
async def test_agent_registry_scanner_flags_missing_kill_switch(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "mythos/orchestrator",
                        "tools": [],
                        "kill_switch": False,
                    }
                ]
            }
        )
    )

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-KILL-SWITCH-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected == "agent:mythos/orchestrator"
    assert "CT-RUNTIME-KILL-SWITCH" in findings[0].description


@pytest.mark.asyncio
async def test_agent_registry_scanner_flags_writable_tools(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "mythos/orchestrator",
                        "kill_switch": True,
                        "tools": [
                            {"id": "mcp:filesystem", "permissions": ["read", "write"]},
                            {"id": "mcp:browser", "permissions": ["read"]},
                        ],
                    }
                ]
            }
        )
    )

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-TOOL-WRITE-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected == "tool:mcp:filesystem"
    assert "REQ-TOOL-001" in findings[0].description


@pytest.mark.asyncio
async def test_agent_registry_scanner_accepts_fully_governed_writable_tool_exception(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "mythos/orchestrator",
                        "kill_switch": True,
                        "tools": [
                            {
                                "id": "mcp:filesystem",
                                "permissions": ["read", "write"],
                                "write_exception": {
                                    "approved": True,
                                    "risk_accepted": True,
                                    "audit_log": True,
                                    "rollback": True,
                                    "scope": "scratch workspace only",
                                    "approver": "shugo",
                                },
                            }
                        ],
                    }
                ]
            }
        )
    )

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert findings == []


@pytest.mark.asyncio
async def test_agent_registry_scanner_flags_incomplete_writable_tool_exception(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "id": "mythos/orchestrator",
                        "kill_switch": True,
                        "tools": [
                            {
                                "id": "mcp:filesystem",
                                "permissions": ["read", "write"],
                                "write_exception": {
                                    "approved": True,
                                    "risk_accepted": False,
                                    "audit_log": True,
                                    "rollback": True,
                                    "scope": "scratch workspace only",
                                },
                            }
                        ],
                    }
                ]
            }
        )
    )

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-TOOL-WRITE-001"
    assert findings[0].remediation is not None
    assert "approval" in findings[0].remediation.lower()


@pytest.mark.asyncio
async def test_agent_registry_scanner_skips_missing_registry_files(tmp_path):
    missing = tmp_path / "missing.json"

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(missing)]))

    assert findings == []


@pytest.mark.asyncio
async def test_tool_mcp_scanner_flags_network_mcp_without_allowlist(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "mcp_servers": [
                    {
                        "id": "mcp:browser",
                        "transport": "http",
                        "network_access": True,
                        "domain_allowlist": [],
                    }
                ]
            }
        )
    )

    findings = await ToolMCPScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-MCP-NETWORK-ALLOWLIST-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected == "mcp_server:mcp:browser"
    assert "REQ-MCP-001" in findings[0].description


@pytest.mark.asyncio
async def test_tool_mcp_scanner_flags_write_mcp_without_audit_log(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "mcp_servers": [
                    {
                        "id": "mcp:filesystem",
                        "transport": "stdio",
                        "permissions": ["read", "write"],
                        "audit_log": False,
                    }
                ]
            }
        )
    )

    findings = await ToolMCPScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-MCP-AUDIT-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected == "mcp_server:mcp:filesystem"
    assert "REQ-MCP-002" in findings[0].description


@pytest.mark.asyncio
async def test_secret_config_scanner_flags_plaintext_agent_secret(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "secrets": [
                    {
                        "id": "openai-api-key",
                        "storage": "plaintext_env",
                        "scoped_to_agent": False,
                    }
                ]
            }
        )
    )

    findings = await SecretConfigScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-SECRET-PLAINTEXT-001"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].affected == "credential:openai-api-key"
    assert "REQ-SECRET-001" in findings[0].description


@pytest.mark.asyncio
async def test_secret_config_scanner_flags_unscoped_credential(tmp_path):
    registry = tmp_path / "agents.json"
    registry.write_text(
        json.dumps(
            {
                "secrets": [
                    {
                        "id": "browser-cookie",
                        "storage": "keychain",
                        "scoped_to_agent": False,
                    }
                ]
            }
        )
    )

    findings = await SecretConfigScanner().scan(ScanConfig(agent_registry_paths=[str(registry)]))

    assert len(findings) == 1
    assert findings[0].id == "AGENT-SECRET-SCOPE-001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].affected == "credential:browser-cookie"
    assert "REQ-SECRET-002" in findings[0].description
