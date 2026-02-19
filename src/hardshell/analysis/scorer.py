"""Risk scoring engine for findings."""

from __future__ import annotations

from hardshell.models import Finding


def score_findings(findings: list[Finding]) -> None:
    """Calculate risk_score for each finding in-place."""
    for f in findings:
        f.risk_score = _calculate_score(f)


def _calculate_score(f: Finding) -> float:
    base = f.severity.weight * 10.0  # 0-100 base from severity

    # Exploit factor
    exploit_factor = 1.0
    if f.in_cisa_kev:
        exploit_factor = 2.0
    elif f.epss_score is not None and f.epss_score > 0.7:
        exploit_factor = 1.8
    elif f.has_public_exploit:
        exploit_factor = 1.5
    elif f.epss_score is not None and f.epss_score > 0.3:
        exploit_factor = 1.3

    score = base * exploit_factor

    # Cap at 100
    return min(score, 100.0)
