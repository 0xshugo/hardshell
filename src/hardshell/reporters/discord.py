"""Discord webhook notifier — delta alerts and remediation reports."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

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


def _actionable_cases(report: dict) -> list[dict]:
    return [
        case
        for case in report.get("cases", [])
        if case.get("status") == "actionable"
        and str(case.get("priority", "")).upper() in {"P1", "P0"}
    ]


def _load_alert_state(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text())
        return set(data.get("case_ids", []))
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return set()


def _save_alert_state(path: Path, case_ids: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_suffix(".tmp")
    temp.write_text(
        json.dumps(
            {
                "updated_at": datetime.now(UTC).isoformat(),
                "case_ids": sorted(case_ids),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    temp.chmod(0o600)
    temp.replace(path)


async def notify_early_warning(
    report: dict,
    hostname: str,
    *,
    state_path: Path | None = None,
    webhook_url: str | None = None,
) -> bool:
    """Alert on new actionable early-warning cases (rule-based HIGH). Dedupes by case_id."""
    url = _get_webhook_url(webhook_url) or _get_webhook_url(
        None, env_var="HARDSHELL_STATUS_WEBHOOK_URL"
    )
    actionable = _actionable_cases(report)
    if not url or not actionable:
        return True

    known: set[str] = set()
    if state_path is not None:
        known = _load_alert_state(state_path)
    fresh = [case for case in actionable if case.get("case_id") not in known]
    if not fresh:
        return True

    lines = [
        f"🔴 **hardshell HIGH early-warning** | `{hostname}` | "
        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"{len(fresh)} actionable case(s) — approve_then_apply only:",
        "",
    ]
    for case in fresh[:8]:
        lines.append(
            f"  • `{case.get('advisory_id')}` {case.get('product')} "
            f"`{case.get('asset_id')}` {case.get('installed')}→{case.get('fixed')} "
            f"exposure={case.get('exposure', 'unknown')}"
        )
        summary = (case.get("public_summary") or "")[:80]
        if summary:
            lines.append(f"    {summary}")
    if len(fresh) > 8:
        lines.append(f"  • … and {len(fresh) - 8} more")
    lines.extend(
        [
            "",
            "Playbook: `operations/playbooks/nginx-upgrade.md`",
            "Do not auto-remediate from orca-control.",
        ]
    )
    ok = await _send(url, "\n".join(lines))
    if ok and state_path is not None:
        _save_alert_state(state_path, known | {c["case_id"] for c in fresh if c.get("case_id")})
    return ok


async def _send(webhook_url: str, content: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={"content": content[:2000]})
            return resp.status_code in (200, 204)
    except Exception:
        return False
