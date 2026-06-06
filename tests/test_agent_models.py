"""Tests for AI agent security posture models."""

from hardshell.models import (
    AgentFinding,
    Asset,
    AssetType,
    ControlStatus,
    Evidence,
    PostureState,
    Severity,
)


def test_asset_stable_key_includes_type_and_identifier():
    asset = Asset(type=AssetType.AGENT, identifier="mythos/orchestrator")

    assert asset.stable_key == "agent:mythos/orchestrator"


def test_evidence_defaults_to_read_only_source():
    evidence = Evidence(source="agent-registry", locator="/tmp/agents.json")

    assert evidence.source == "agent-registry"
    assert evidence.locator == "/tmp/agents.json"
    assert evidence.observed_value is None


def test_agent_finding_converts_to_legacy_finding():
    asset = Asset(type=AssetType.TOOL, identifier="mcp:filesystem")
    evidence = Evidence(
        source="agent-registry",
        locator="/tmp/agents.json#/agents/0/tools/0",
        observed_value={"permission": "write"},
    )
    finding = AgentFinding(
        id="AGENT-TOOL-WRITE-001",
        severity=Severity.HIGH,
        title="Writable tool exposed to agent",
        asset=asset,
        control_id="CT-TOOL-LEAST-PRIVILEGE",
        threat_id="TH-TOOL-ABUSE",
        requirement_id="REQ-TOOL-001",
        evidence=[evidence],
        remediation="Limit filesystem tool to read-only paths.",
    )

    legacy = finding.to_finding(scanner="agent-registry")

    assert legacy.id == "AGENT-TOOL-WRITE-001"
    assert legacy.scanner == "agent-registry"
    assert legacy.severity == Severity.HIGH
    assert legacy.affected == "tool:mcp:filesystem"
    assert "CT-TOOL-LEAST-PRIVILEGE" in legacy.description
    assert legacy.remediation == "Limit filesystem tool to read-only paths."


def test_posture_state_counts_control_statuses():
    state = PostureState(
        assets=[Asset(type=AssetType.AGENT, identifier="agent-a")],
        controls={
            "CT-A": ControlStatus.PASS,
            "CT-B": ControlStatus.FAIL,
            "CT-C": ControlStatus.UNKNOWN,
        },
    )

    assert state.summary() == {
        "assets": 1,
        "controls_pass": 1,
        "controls_fail": 1,
        "controls_unknown": 1,
    }
