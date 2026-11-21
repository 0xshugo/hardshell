"""Tests for remediation action matching, severity gating, and fix rendering."""

from __future__ import annotations

from hardshell.models import Finding, Severity
from hardshell.remediate.actions import RemediationTier, get_rule
from hardshell.remediate.generator import plan_actions
from hardshell.remediate.runner import render_fix_script


def test_ssl_expiry_info_does_not_trigger_auto_renewal():
    finding = Finding(
        id="SSL-EXPIRY-factory-p1-aoifuture-com",
        scanner="ssl",
        severity=Severity.INFO,
        title="SSL cert 'factory-p1.aoifuture.com' valid for 57 days",
        affected="factory-p1.aoifuture.com",
    )
    assert get_rule(finding.id, severity=finding.severity) is None
    assert plan_actions([finding], tiers=[RemediationTier.AUTO]) == []


def test_ssl_expiry_medium_high_critical_trigger_auto_renewal():
    for sev in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL):
        finding = Finding(
            id="SSL-EXPIRY-factory-p1-aoifuture-com",
            scanner="ssl",
            severity=sev,
            title="SSL cert expiring soon",
            affected="factory-p1.aoifuture.com",
        )
        actions = plan_actions([finding], tiers=[RemediationTier.AUTO])
        assert len(actions) == 1
        assert actions[0].title == "Renew SSL certificate"


def test_render_fix_script_utc_header_and_empty_when_info_only():
    info_ssl = Finding(
        id="SSL-EXPIRY-apps-aoifuture-com",
        scanner="ssl",
        severity=Severity.INFO,
        title="SSL cert valid for 45 days",
        affected="*.apps.aoifuture.com",
    )
    rendered = render_fix_script([info_ssl], tiers=[RemediationTier.AUTO])
    assert "UTC" in rendered
    assert "certbot renew" not in rendered
