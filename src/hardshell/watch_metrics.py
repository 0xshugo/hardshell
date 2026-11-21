"""Prometheus Pushgateway exposition for hardshell-watch early-warning reports."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx

_CASE_STATUSES = ("actionable", "potentially_affected", "needs_evidence")


def _parse_timestamp(value: Any, fallback: float) -> float:
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.timestamp()
        except ValueError:
            pass
    return fallback


def format_watch_metrics(report: dict[str, Any], *, now: float | None = None) -> str:
    """Format an early-warning report dictionary into Prometheus text exposition."""
    now_ts = time.time() if now is None else float(now)
    cases = [c for c in (report.get("cases") or []) if isinstance(c, dict)]
    counts = {status: 0 for status in _CASE_STATUSES}
    for case in cases:
        status = str(case.get("status") or "")
        if status in counts:
            counts[status] += 1

    feed_gaps = len(report.get("feed_gaps") or [])
    coverage_gaps = len(report.get("coverage_gaps") or [])
    notification = report.get("notification")
    discord_failures = 0
    if isinstance(notification, dict):
        discord_failures = int(notification.get("consecutive_failures") or 0)
        if (
            notification.get("status") in {"failed", "skipped_unconfigured"}
            and discord_failures == 0
        ):
            discord_failures = 1

    last_run_ts = _parse_timestamp(report.get("generated_at"), now_ts)

    lines = [
        "# HELP hardshell_watch_cases_total Early-warning cases by status",
        "# TYPE hardshell_watch_cases_total gauge",
    ]
    for status in _CASE_STATUSES:
        lines.append(f'hardshell_watch_cases_total{{status="{status}"}} {counts[status]}')

    lines.extend(
        [
            "# HELP hardshell_watch_feed_gaps_total Official vendor feed gaps",
            "# TYPE hardshell_watch_feed_gaps_total gauge",
            f"hardshell_watch_feed_gaps_total {feed_gaps}",
            "# HELP hardshell_watch_coverage_gaps_total Asset coverage gaps",
            "# TYPE hardshell_watch_coverage_gaps_total gauge",
            f"hardshell_watch_coverage_gaps_total {coverage_gaps}",
            "# HELP hardshell_watch_discord_failures Consecutive Discord watch delivery failures",
            "# TYPE hardshell_watch_discord_failures gauge",
            f"hardshell_watch_discord_failures {discord_failures}",
            "# HELP hardshell_watch_last_run_timestamp Unix timestamp of last watch run",
            "# TYPE hardshell_watch_last_run_timestamp gauge",
            f"hardshell_watch_last_run_timestamp {last_run_ts:.0f}",
        ]
    )
    return "\n".join(lines) + "\n"


async def push_watch_metrics(
    report: dict[str, Any],
    pushgateway_url: str,
    *,
    timeout: float = 3.0,
) -> bool:
    """Best-effort push of watch metrics to Prometheus Pushgateway."""
    parsed = urlparse(pushgateway_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False

    endpoint = f"{pushgateway_url.strip().rstrip('/')}/metrics/job/hardshell_watch"
    payload = format_watch_metrics(report)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                endpoint,
                content=payload.encode("utf-8"),
                headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
            )
            return 200 <= resp.status_code < 300
    except Exception:
        return False
