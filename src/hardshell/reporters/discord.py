"""Discord webhook notifier — delta alerts and remediation reports."""

from __future__ import annotations

import os
from datetime import datetime

import httpx

from hardshell.delta import DeltaResult
from hardshell.models import Severity
from hardshell.remediate.actions import RemediationTier
from hardshell.remediate.generator import PlannedAction

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟠",
    Severity.LOW: "🟡",
    Severity.INFO: "⚪",
}

TIER_EMOJI = {
    RemediationTier.AUTO: "✅",
    RemediationTier.PROPOSE: "💡",
    RemediationTier.ALERT: "⚠️",
}


def _get_webhook_url(webhook_url: str | None, env_var: str = "DISCORD_WEBHOOK_URL") -> str | None:
    return webhook_url or os.environ.get(env_var)


async def notify_delta(
    delta: DeltaResult,
    hostname: str,
    webhook_url: str | None = None,
) -> bool:
    """Send new/resolved findings to Discord. Returns True on success."""
    url = _get_webhook_url(webhook_url)
    if not url:
        return False

    new_ch = [f for f in delta.new_findings if f.severity == Severity.CRITICAL]
    new_hi = [f for f in delta.new_findings if f.severity == Severity.HIGH]

    # Only notify if there are new CRITICAL or HIGH findings
    if not new_ch and not new_hi:
        return True  # Nothing to report, but not a failure

    lines = [f"**hardshell** | `{hostname}` | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"]
    lines.append("")

    if new_ch:
        lines.append(f"🚨 **{len(new_ch)} new CRITICAL**")
        for f in new_ch[:5]:
            kev = " `KEV`" if f.in_cisa_kev else ""
            lines.append(f"  • `{f.id}` {f.title[:60]}{kev}")
        if len(new_ch) > 5:
            lines.append(f"  • … and {len(new_ch) - 5} more")

    if new_hi:
        lines.append(f"🔴 **{len(new_hi)} new HIGH**")
        for f in new_hi[:3]:
            lines.append(f"  • `{f.id}` {f.title[:60]}")
        if len(new_hi) > 3:
            lines.append(f"  • … and {len(new_hi) - 3} more")

    if delta.resolved_findings:
        lines.append(f"✅ {len(delta.resolved_findings)} finding(s) resolved")

    return await _send(url, "\n".join(lines))


async def notify_remediation(
    succeeded: list[tuple[PlannedAction, str]],
    failed: list[tuple[PlannedAction, str]],
    hostname: str,
    webhook_url: str | None = None,
) -> bool:
    """Send auto-remediation execution report."""
    url = _get_webhook_url(webhook_url)
    if not url or (not succeeded and not failed):
        return True

    lines = [
        f"**hardshell auto-fix** | `{hostname}` | "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    ]
    lines.append("")

    for action, _ in succeeded:
        lines.append(f"✅ {action.title} ({action.finding.id})")

    for action, output in failed:
        snippet = output[:100].replace("\n", " ")
        lines.append(f"❌ {action.title} ({action.finding.id}): `{snippet}`")

    return await _send(url, "\n".join(lines))


async def notify_proposals(
    actions: list[PlannedAction],
    hostname: str,
    webhook_url: str | None = None,
) -> bool:
    """Send PROPOSE-tier actions to Discord for awareness."""
    url = _get_webhook_url(webhook_url)
    if not url or not actions:
        return True

    lines = [
        f"**hardshell proposals** | `{hostname}` | "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"💡 {len(actions)} action(s) available — apply when ready:",
        "",
    ]
    for a in actions:
        cmd = f"`{a.command[:60]}`" if a.command else "(manual)"
        lines.append(f"  • **{a.title}** — {a.finding.id}")
        lines.append(f"    {cmd}")
    lines.append("")
    lines.append("Run: `hardshell fix --execute --tier propose`")

    return await _send(url, "\n".join(lines))


async def _send(webhook_url: str, content: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={"content": content[:2000]})
            return resp.status_code in (200, 204)
    except Exception:
        return False
