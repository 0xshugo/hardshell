"""Tests for risk scoring engine."""

from hardshell.analysis.scorer import score_findings
from hardshell.models import Finding, Severity


def _make_finding(**kwargs) -> Finding:
    defaults = {
        "id": "TEST-001",
        "scanner": "test",
        "severity": Severity.HIGH,
        "title": "Test",
        "affected": "test",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_base_scoring():
    findings = [
        _make_finding(severity=Severity.CRITICAL),
        _make_finding(severity=Severity.HIGH),
        _make_finding(severity=Severity.MEDIUM),
        _make_finding(severity=Severity.LOW),
        _make_finding(severity=Severity.INFO),
    ]
    score_findings(findings)

    assert findings[0].risk_score == 100.0  # CRITICAL: 10 * 10 * 1.0
    assert findings[1].risk_score == 75.0  # HIGH: 7.5 * 10 * 1.0
    assert findings[2].risk_score == 50.0  # MEDIUM: 5.0 * 10 * 1.0
    assert findings[3].risk_score == 25.0  # LOW: 2.5 * 10 * 1.0
    assert findings[4].risk_score == 0.0  # INFO: 0 * 10 * 1.0


def test_kev_boost():
    f = _make_finding(severity=Severity.HIGH, in_cisa_kev=True)
    score_findings([f])
    # HIGH (75) * KEV (2.0) = 150 -> capped at 100
    assert f.risk_score == 100.0


def test_epss_high_boost():
    f = _make_finding(severity=Severity.MEDIUM, epss_score=0.8)
    score_findings([f])
    # MEDIUM (50) * EPSS>0.7 (1.8) = 90
    assert f.risk_score == 90.0


def test_epss_medium_boost():
    f = _make_finding(severity=Severity.MEDIUM, epss_score=0.4)
    score_findings([f])
    # MEDIUM (50) * EPSS>0.3 (1.3) = 65
    assert f.risk_score == 65.0


def test_public_exploit_boost():
    f = _make_finding(severity=Severity.MEDIUM, has_public_exploit=True)
    score_findings([f])
    # MEDIUM (50) * exploit (1.5) = 75
    assert f.risk_score == 75.0


def test_kev_takes_priority_over_epss():
    f = _make_finding(severity=Severity.HIGH, in_cisa_kev=True, epss_score=0.9)
    score_findings([f])
    # KEV factor (2.0) should be used, not EPSS (1.8)
    assert f.risk_score == 100.0  # 75 * 2.0 = 150 -> capped at 100


def test_cap_at_100():
    f = _make_finding(severity=Severity.CRITICAL, in_cisa_kev=True)
    score_findings([f])
    assert f.risk_score == 100.0
