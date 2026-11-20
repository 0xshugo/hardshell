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


def _playbook_for_product(product: str | None) -> str:
    if (product or "").lower() == "php":
        return "operations/playbooks/php-upgrade.md"
    return "operations/playbooks/nginx-upgrade.md"


def _load_alert_state_doc(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        pass
    return {}


def _load_alert_state(path: Path) -> set[str]:
    data = _load_alert_state_doc(path)
    raw_ids = data.get("case_ids") or []
    return {str(cid) for cid in raw_ids if isinstance(cid, str)}


def _save_alert_state(
    path: Path, case_ids: set[str], *, delivery: dict | None = None
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload: dict = {
        "updated_at": datetime.now(UTC).isoformat(),
        "case_ids": sorted(case_ids),
    }
    if delivery is not None:
        payload["last_delivery"] = delivery
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    temp.chmod(0o600)
    temp.replace(path)


async def notify_remediation_lifecycle(
    *,
    phase: str,
    advisory_id: str,
    asset_id: str,
    hostname: str,
    detail: str = "",
    product: str = "nginx",
    webhook_url: str | None = None,
) -> bool:
    """Discord templates for approve_then_apply: pending_approval / completed / failed."""
    url = _get_webhook_url(webhook_url) or _get_webhook_url(
        None, env_var="HARDSHELL_STATUS_WEBHOOK_URL"
    )
    if not url:
        return True
    labels = {
        "pending_approval": ("⏳", "要承認"),
        "completed": ("✅", "完了"),
        "failed": ("❌", "失敗"),
    }
    emoji, label = labels.get(phase, ("ℹ️", phase))
    lines = [
        f"{emoji} **hardshell remediation · {label}** | `{hostname}` | "
        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"`{advisory_id}` · asset=`{asset_id}`",
    ]
    if detail:
        lines.append(detail[:300])
    if phase == "pending_approval":
        lines.append(f"Playbook: `{_playbook_for_product(product)}`")
    return await _send(url, "\n".join(lines))


async def deliver_early_warning(
    report: dict,
    hostname: str,
    *,
    state_path: Path | None = None,
    webhook_url: str | None = None,
) -> dict:
    """Alert on new actionable early-warning cases (rule-based HIGH) and return delivery status."""
    now_iso = datetime.now(UTC).isoformat()
    url = _get_webhook_url(webhook_url) or _get_webhook_url(
        None, env_var="HARDSHELL_STATUS_WEBHOOK_URL"
    )
    actionable = _actionable_cases(report)
    state_doc = _load_alert_state_doc(state_path) if state_path is not None else {}
    known = {str(cid) for cid in (state_doc.get("case_ids") or []) if isinstance(cid, str)}
    prev_delivery = (
        state_doc.get("last_delivery") if isinstance(state_doc.get("last_delivery"), dict) else {}
    )
    prev_failures = int(prev_delivery.get("consecutive_failures") or 0)
    last_sent_at = prev_delivery.get("last_sent_at")

    if not actionable:
        delivery = {
            "channel": "discord",
            "status": "idle",
            "checked_at": now_iso,
            "actionable_count": 0,
            "fresh_count": 0,
            "consecutive_failures": 0,
            "last_sent_at": last_sent_at,
            "last_error": None,
        }
        if state_path is not None:
            _save_alert_state(state_path, known, delivery=delivery)
        return {"ok": True, **delivery}

    if not url:
        delivery = {
            "channel": "discord",
            "status": "skipped_unconfigured",
            "checked_at": now_iso,
            "actionable_count": len(actionable),
            "fresh_count": len([c for c in actionable if c.get("case_id") not in known]),
            "consecutive_failures": prev_failures + 1,
            "last_sent_at": last_sent_at,
            "last_error": "discord_webhook_unconfigured",
        }
        if state_path is not None:
            _save_alert_state(state_path, known, delivery=delivery)
        return {"ok": False, **delivery}

    fresh = [case for case in actionable if case.get("case_id") not in known]
    if not fresh:
        delivery = {
            "channel": "discord",
            "status": "deduped",
            "checked_at": now_iso,
            "actionable_count": len(actionable),
            "fresh_count": 0,
            "consecutive_failures": 0,
            "last_sent_at": last_sent_at,
            "last_error": None,
        }
        if state_path is not None:
            _save_alert_state(state_path, known, delivery=delivery)
        return {"ok": True, **delivery}

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
    playbooks = sorted({_playbook_for_product(case.get("product")) for case in fresh})
    lines.append("")
    for pb in playbooks:
        lines.append(f"Playbook: `{pb}`")
    lines.append("Do not auto-remediate from orca-control.")

    ok = await _send(url, "\n".join(lines))
    if ok:
        new_known = known | {c["case_id"] for c in fresh if c.get("case_id")}
        delivery = {
            "channel": "discord",
            "status": "sent",
            "checked_at": now_iso,
            "actionable_count": len(actionable),
            "fresh_count": len(fresh),
            "consecutive_failures": 0,
            "last_sent_at": now_iso,
            "last_error": None,
        }
        if state_path is not None:
            _save_alert_state(state_path, new_known, delivery=delivery)
        return {"ok": True, **delivery}

    delivery = {
        "channel": "discord",
        "status": "failed",
        "checked_at": now_iso,
        "actionable_count": len(actionable),
        "fresh_count": len(fresh),
        "consecutive_failures": prev_failures + 1,
        "last_sent_at": last_sent_at,
        "last_error": "discord_webhook_post_failed",
    }
    if state_path is not None:
        _save_alert_state(state_path, known, delivery=delivery)
    return {"ok": False, **delivery}


async def notify_early_warning(
    report: dict,
    hostname: str,
    *,
    state_path: Path | None = None,
    webhook_url: str | None = None,
) -> bool:
    """Alert on new actionable early-warning cases (rule-based HIGH). Dedupes by case_id."""
    result = await deliver_early_warning(
        report, hostname, state_path=state_path, webhook_url=webhook_url
    )
    return bool(result.get("ok"))


async def _send(webhook_url: str, content: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={"content": content[:2000]})
            return resp.status_code in (200, 204)
    except Exception:
        return False
