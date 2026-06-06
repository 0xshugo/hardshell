"""Execute remediation actions and generate fix scripts."""

from __future__ import annotations

import asyncio
from datetime import datetime

from hardshell.models import Finding
from hardshell.remediate.actions import RemediationTier
from hardshell.remediate.generator import PlannedAction, plan_actions


class RemediationResult:
    def __init__(self) -> None:
        self.succeeded: list[tuple[PlannedAction, str]] = []
        self.failed: list[tuple[PlannedAction, str]] = []

    @property
    def all_ok(self) -> bool:
        return len(self.failed) == 0


async def execute_auto(findings: list[Finding]) -> RemediationResult:
    """Execute all AUTO-tier actions and return results."""
    actions = plan_actions(findings, tiers=[RemediationTier.AUTO])
    result = RemediationResult()

    for action in actions:
        if not action.command:
            continue
        try:
            proc = await asyncio.create_subprocess_shell(
                action.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = (stdout + stderr).decode(errors="replace").strip()
            if proc.returncode == 0:
                result.succeeded.append((action, output))
            else:
                result.failed.append((action, output))
        except Exception as e:
            result.failed.append((action, str(e)))

    return result


def render_fix_script(findings: list[Finding], tiers: list[RemediationTier] | None = None) -> str:
    """Generate a shell script that applies all matching remediations."""
    if tiers is None:
        tiers = [RemediationTier.AUTO, RemediationTier.PROPOSE]

    actions = plan_actions(findings, tiers=tiers)
    lines = [
        "#!/usr/bin/env bash",
        "# hardshell fix script — generated " + datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "# Review before executing. Run with: sudo bash fix.sh",
        "set -euo pipefail",
        "",
    ]

    if not actions:
        lines.append("echo 'No actionable remediations found.'")
        return "\n".join(lines)

    for action in actions:
        if not action.command:
            continue
        lines.append(f"# [{action.tier.upper()}] {action.title}")
        lines.append(f"# Finding: {action.finding.id} — {action.finding.title[:70]}")
        lines.append(f"echo '>>> {action.title}'")
        lines.append(action.command)
        lines.append("")

    return "\n".join(lines)
