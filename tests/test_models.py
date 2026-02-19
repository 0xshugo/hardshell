"""Tests for Pydantic models."""

from hardshell.models import Finding, ScanSummary, Severity


def test_severity_weight():
    assert Severity.CRITICAL.weight == 10.0
    assert Severity.HIGH.weight == 7.5
    assert Severity.INFO.weight == 0.0


def test_finding_is_cve():
    f = Finding(
        id="CVE-2024-1234",
        scanner="test",
        severity=Severity.HIGH,
        title="Test vuln",
        affected="pkg",
    )
    assert f.is_cve is True

    f2 = Finding(
        id="SYS-SSH-PASSWD",
        scanner="system",
        severity=Severity.HIGH,
        title="Test finding",
        affected="sshd",
    )
    assert f2.is_cve is False


def test_finding_defaults():
    f = Finding(
        id="TEST-001",
        scanner="test",
        severity=Severity.LOW,
        title="Test",
        affected="test",
    )
    assert f.epss_score is None
    assert f.in_cisa_kev is False
    assert f.risk_score == 0.0


def test_scan_summary_from_findings():
    findings = [
        Finding(id="1", scanner="t", severity=Severity.CRITICAL, title="t", affected="a"),
        Finding(id="2", scanner="t", severity=Severity.CRITICAL, title="t", affected="a"),
        Finding(id="3", scanner="t", severity=Severity.HIGH, title="t", affected="a"),
        Finding(id="4", scanner="t", severity=Severity.LOW, title="t", affected="a"),
    ]
    summary = ScanSummary.from_findings(findings)
    assert summary.critical == 2
    assert summary.high == 1
    assert summary.medium == 0
    assert summary.low == 1
    assert summary.total == 4


def test_scan_summary_empty():
    summary = ScanSummary.from_findings([])
    assert summary.total == 0
