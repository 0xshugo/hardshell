"""Map scan findings to remediation actions."""

from __future__ import annotations

from hardshell.models import Finding
from hardshell.remediate.actions import RemediationAction, RemediationTier, get_rule


class PlannedAction(RemediationAction):
    finding: Finding


def plan_actions(
    findings: list[Finding],
    tiers: list[RemediationTier] | None = None,
) -> list[PlannedAction]:
    """Return deduplicated remediation actions for the given findings."""
    if tiers is None:
        tiers = list(RemediationTier)

    seen_commands: set[str] = set()
    actions: list[PlannedAction] = []

    for finding in sorted(findings, key=lambda f: f.risk_score, reverse=True):
        rule = get_rule(finding.id)
        if rule is None:
            continue
        if rule.tier not in tiers:
            continue
        # Deduplicate by command (e.g., certbot renew for multiple SSL findings)
        dedup_key = rule.command or rule.finding_id_pattern
        if dedup_key in seen_commands:
            continue
        seen_commands.add(dedup_key)
        actions.append(PlannedAction(**rule.model_dump(), finding=finding))

    return actions
