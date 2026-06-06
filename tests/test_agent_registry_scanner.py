"""Tests for AI agent registry scanner."""

import json

import pytest

from hardshell.config import ScanConfig
from hardshell.models import Severity
from hardshell.scanners.agent_registry import AgentRegistryScanner


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
async def test_agent_registry_scanner_skips_missing_registry_files(tmp_path):
    missing = tmp_path / "missing.json"

    findings = await AgentRegistryScanner().scan(ScanConfig(agent_registry_paths=[str(missing)]))

    assert findings == []
