"""Read-only Hardshell VPS operational and Discord alerting health checks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from hardshell.early_warning import blocking_coverage_gaps


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _summarize_cases(cases: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, dict[tuple, dict]] = {"actionable": {}, "potentially_affected": {}}
    for case in cases:
        if not isinstance(case, dict):
            continue
        status = case.get("status")
        if status not in grouped:
            continue
        key = (
            case.get("product"),
            case.get("asset_id"),
            case.get("installed"),
            case.get("fixed"),
            case.get("exposure"),
        )
        slot = grouped[status].setdefault(
            key,
            {
                "product": case.get("product"),
                "asset_id": case.get("asset_id"),
                "installed": case.get("installed"),
                "fixed": case.get("fixed"),
                "exposure": case.get("exposure"),
                "advisory_count": 0,
                "sample_advisories": [],
            },
        )
        slot["advisory_count"] += 1
        adv_id = case.get("advisory_id")
        if adv_id and len(slot["sample_advisories"]) < 5:
            slot["sample_advisories"].append(adv_id)
    return {
        "actionable": list(grouped["actionable"].values()),
        "potentially_affected": list(grouped["potentially_affected"].values()),
    }


def _check_systemd(systemd_dir: Path = Path("/etc/systemd/system")) -> dict:
    if shutil.which("systemctl") is None:
        return {"status": "skipped", "reason": "systemctl_unavailable"}
    try:
        timer = subprocess.run(
            ["systemctl", "is-active", "hardshell-watch.timer"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        timer_state = timer.stdout.strip() or timer.stderr.strip() or "unknown"
        svc = subprocess.run(
            [
                "systemctl",
                "show",
                "hardshell-watch.service",
                "-p",
                "ActiveState,Result,ExecMainStatus,ExecMainExitTimestamp",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        props: dict[str, str] = {}
        for line in svc.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()
        discord_dropin = (systemd_dir / "hardshell-watch.service.d" / "20-discord.conf").exists()
        exit_code = props.get("ExecMainStatus", "")
        result = props.get("Result", "")
        ok = (
            timer_state == "active"
            and result == "success"
            and exit_code in {"0", "2"}
        )
        status = "ok" if ok else "follow_up_needed"
        reason = None if ok else f"timer={timer_state},service_result={result},exit={exit_code}"
        if ok and not discord_dropin:
            status = "warn"
            reason = "discord_dropin_missing"
        return {
            "status": status,
            "reason": reason,
            "timer_active": timer_state,
            "service_result": result,
            "service_exit_code": exit_code,
            "last_exit_at": props.get("ExecMainExitTimestamp"),
            "discord_dropin_present": discord_dropin,
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "warn", "reason": f"systemd_check_failed:{type(exc).__name__}"}


def _check_scan_reports(root: Path, now: datetime) -> dict:
    candidates = [root / "reports", root / "build" / "reports"]
    readable_dirs = [d for d in candidates if d.is_dir() and os.access(d, os.R_OK | os.X_OK)]
    if not readable_dirs:
        return {"status": "warn", "reason": "scan_reports_dir_missing_or_unreadable"}
    files: list[Path] = []
    for d in readable_dirs:
        try:
            files.extend(p for p in d.glob("*.json") if p.is_file())
        except OSError:
            continue
    if not files:
        return {"status": "follow_up_needed", "reason": "no_scan_reports_found"}
    latest = max(files, key=lambda p: p.stat().st_mtime)
    age_hours = (now.timestamp() - latest.stat().st_mtime) / 3600.0
    if age_hours > 36.0:
        return {
            "status": "follow_up_needed",
            "reason": "scan_reports_stale",
            "latest_report": latest.name,
            "age_hours": round(age_hours, 1),
        }
    return {
        "status": "ok",
        "latest_report": latest.name,
        "age_hours": round(age_hours, 1),
    }


def evaluate_ops_health(
    root: Path,
    *,
    check_systemd: bool = True,
    now: datetime | None = None,
    systemd_dir: Path = Path("/etc/systemd/system"),
) -> dict:
    """Evaluate Hardshell operational and Discord alert health without mutating state."""
    now = now or datetime.now(UTC)
    ew_path = root / "build" / "early-warning.json"
    alerts_path = root / "build" / "state" / "early-warning-alerts.json"
    rem_dir = root / "build" / "remediation"
    follow_up_actions: list[str] = []

    saved: dict | None = None
    ew_check: dict
    try:
        saved = json.loads(ew_path.read_text())
        if not isinstance(saved, dict):
            raise ValueError("invalid_early_warning_json")
        gen = _parse_iso(saved.get("generated_at"))
        if gen is None:
            ew_check = {
                "status": "follow_up_needed",
                "reason": "missing_or_invalid_generated_at",
                "path": str(ew_path),
            }
            follow_up_actions.append(f"Inspect or regenerate {ew_path}")
        else:
            age_seconds = (now - gen).total_seconds()
            feed_gaps = saved.get("feed_gaps") or []
            cov_gaps = saved.get("coverage_gaps") or []
            # Low-priority gaps (internal_only Coolify recreate) stay listed only.
            unexpected_cov = blocking_coverage_gaps(cov_gaps)
            cases = saved.get("cases") or []
            grouped = _summarize_cases(cases)
            issues: list[str] = []
            if not 0 <= age_seconds <= 45 * 60:
                issues.append("early_warning_stale")
                follow_up_actions.append(
                    "Check hardshell-watch.timer/service; report is older than 45m"
                )
            if feed_gaps:
                issues.append("feed_gaps_present")
                follow_up_actions.append(
                    "Investigate early-warning feed_gaps (e.g. php.net/nginx.org acquisition)"
                )
            if unexpected_cov:
                issues.append("unexpected_coverage_gaps")
                follow_up_actions.append("Investigate non-php_runtime_unverified coverage_gaps")
            ew_check = {
                "status": "follow_up_needed" if issues else "ok",
                "reasons": issues,
                "report_status": saved.get("status", "unknown"),
                "age_minutes": round(age_seconds / 60.0, 1),
                "feed_gaps_count": len(feed_gaps),
                "feed_gaps": feed_gaps[:10],
                "unexpected_coverage_gaps_count": len(unexpected_cov),
                "actionable_count": len([c for c in cases if c.get("status") == "actionable"]),
                "potentially_affected_count": len(
                    [c for c in cases if c.get("status") == "potentially_affected"]
                ),
                "summary_targets": grouped,
            }
    except PermissionError:
        ew_check = {
            "status": "follow_up_needed",
            "reason": "early_warning_permission_denied",
            "path": str(ew_path),
        }
        follow_up_actions.append(f"Run ops-check as owner user or grant read access to {ew_path}")
    except (OSError, ValueError, json.JSONDecodeError):
        ew_check = {
            "status": "follow_up_needed",
            "reason": "early_warning_missing_or_invalid",
            "path": str(ew_path),
        }
        follow_up_actions.append(f"Verify {ew_path} exists and is valid JSON")

    # Discord alerting check
    alerts_doc: dict | None = None
    try:
        if alerts_path.exists():
            parsed_alerts = json.loads(alerts_path.read_text())
            if isinstance(parsed_alerts, dict):
                alerts_doc = parsed_alerts
    except (OSError, json.JSONDecodeError):
        alerts_doc = None

    notification = saved.get("notification") if isinstance(saved, dict) else None
    if not isinstance(notification, dict) and isinstance(alerts_doc, dict):
        notification = alerts_doc.get("last_delivery")

    actionable_cases = (
        [
            c
            for c in (saved.get("cases") or [])
            if isinstance(c, dict) and c.get("status") == "actionable"
        ]
        if isinstance(saved, dict)
        else []
    )
    known_ids = (
        {str(x) for x in (alerts_doc.get("case_ids") or []) if isinstance(x, str)}
        if isinstance(alerts_doc, dict)
        else set()
    )
    unalerted = (
        [c.get("case_id") for c in actionable_cases if c.get("case_id") not in known_ids]
        if (actionable_cases and alerts_doc is not None)
        else []
    )

    if isinstance(notification, dict):
        n_status = str(notification.get("status") or "unknown")
        failures = int(notification.get("consecutive_failures") or 0)
        if n_status in {"failed", "skipped_unconfigured"} or failures > 0 or unalerted:
            discord_check = {
                "status": "follow_up_needed",
                "delivery_status": n_status,
                "consecutive_failures": failures,
                "last_error": notification.get("last_error"),
                "unalerted_actionable_count": len(unalerted),
                "checked_at": notification.get("checked_at"),
                "last_sent_at": notification.get("last_sent_at"),
            }
            follow_up_actions.append(
                "Follow up Discord alerting: verify build/state/discord.env and re-run watch"
            )
        else:
            discord_check = {
                "status": "ok",
                "delivery_status": n_status,
                "consecutive_failures": failures,
                "checked_at": notification.get("checked_at"),
                "last_sent_at": notification.get("last_sent_at"),
            }
    elif saved is None:
        discord_check = {
            "status": "follow_up_needed",
            "reason": "notification_unverified_without_report",
        }
    elif actionable_cases:
        discord_check = {
            "status": "follow_up_needed",
            "reason": "actionable_without_delivery_telemetry",
            "actionable_count": len(actionable_cases),
        }
        follow_up_actions.append(
            "Actionable cases lack Discord delivery telemetry; verify webhook and deploy latest"
        )
    else:
        discord_check = {
            "status": "warn",
            "reason": "notification_telemetry_missing",
        }

    systemd_check = (
        _check_systemd(systemd_dir=systemd_dir)
        if check_systemd
        else {"status": "skipped", "reason": "disabled"}
    )
    if systemd_check.get("status") == "follow_up_needed":
        follow_up_actions.append(
            f"Check systemd units: {systemd_check.get('reason')}"
        )

    scan_check = _check_scan_reports(root, now)
    if scan_check.get("status") == "follow_up_needed":
        follow_up_actions.append(
            f"Check daily/weekly full scan schedule (bin/scan.sh): {scan_check.get('reason')}"
        )

    remediation_count = 0
    if rem_dir.is_dir() and os.access(rem_dir, os.R_OK | os.X_OK):
        remediation_count = len(list(rem_dir.glob("*.json")))

    remediation_check = {
        "status": "follow_up_needed" if actionable_cases else "ok",
        "pending_actionable_count": len(actionable_cases),
        "receipts_count": remediation_count,
    }
    if actionable_cases:
        follow_up_actions.append(
            f"Review {len(actionable_cases)} actionable case(s) via approve_then_apply playbooks"
        )

    checks = {
        "early_warning": ew_check,
        "discord_alerting": discord_check,
        "systemd_watch": systemd_check,
        "scan_reports": scan_check,
        "remediation": remediation_check,
    }
    statuses = [c.get("status") for c in checks.values()]
    if "follow_up_needed" in statuses:
        overall = "follow_up_needed"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "ok"

    return {
        "generated_at": now.isoformat(),
        "root": str(root),
        "overall_status": overall,
        "follow_up_needed": overall == "follow_up_needed",
        "checks": checks,
        "follow_up_actions": follow_up_actions,
    }
