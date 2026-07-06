#!/usr/bin/env bash
set -euo pipefail

# Send a compact always-on Hardshell status report to Discord.
# Usage: discord-status.sh <json-report> [daily|weekly]

REPORT_FILE="${1:?json report required}"
MODE="${2:-daily}"
WEBHOOK_URL="${HARDSHELL_STATUS_WEBHOOK_URL:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARDSHELL_HOME="${HARDSHELL_HOME:-$(dirname "$SCRIPT_DIR")}"
REGISTRY_FILE="${HARDSHELL_AGENT_REGISTRY:-$HARDSHELL_HOME/build/hardshell-agent-posture.json}"

if [[ -z "$WEBHOOK_URL" ]]; then
  echo "[$(date)] HARDSHELL_STATUS_WEBHOOK_URL not set — skipping status report"
  exit 0
fi

if [[ ! -f "$REPORT_FILE" ]]; then
  echo "ERROR: JSON report not found: $REPORT_FILE" >&2
  exit 1
fi

python3 - "$REPORT_FILE" "$MODE" "$REGISTRY_FILE" <<'PY'
from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path

report_path = Path(sys.argv[1])
mode = sys.argv[2]
registry_path = Path(sys.argv[3])
webhook_url = os.environ["HARDSHELL_STATUS_WEBHOOK_URL"]

report = json.loads(report_path.read_text())
summary = report.get("summary") or {}
findings = report.get("findings") or []
scanners = report.get("scanners_used") or []
registry = {}
if registry_path.exists():
    try:
        registry = json.loads(registry_path.read_text())
    except json.JSONDecodeError:
        registry = {}

mcp_servers = registry.get("mcp_servers") or []
secfeed = next((s for s in mcp_servers if str(s.get("id")) == "secfeed"), None)
agent_posture_findings = [
    f for f in findings if f.get("scanner") in {"agent-registry", "tool-mcp", "secret-config"}
]
secret_findings = [f for f in findings if f.get("scanner") == "secret-config"]
critical_or_high = [
    f for f in findings if str(f.get("severity", "")).lower() in {"critical", "high"}
]

status_icon = "✅" if not critical_or_high else "⚠️"
secfeed_status = "未検出"
if secfeed:
    permissions = ",".join(secfeed.get("permissions") or []) or "unknown"
    allowlist = ",".join(secfeed.get("domain_allowlist") or []) or "none"
    secfeed_status = f"検出済み / permissions={permissions} / allowlist={allowlist}"

lines = [
    f"{status_icon} **Hardshell security status** ({mode})",
    f"Host: `{report.get('hostname') or socket.gethostname()}`",
    f"Report: `{report_path.name}` / timestamp: `{report.get('timestamp', 'unknown')}`",
    "",
    "**Summary**",
    (
        f"critical={summary.get('critical', 0)} / high={summary.get('high', 0)} / "
        f"medium={summary.get('medium', 0)} / low={summary.get('low', 0)} / "
        f"info={summary.get('info', 0)} / total={summary.get('total', 0)}"
    ),
    "",
    "**New agent-security posture**",
    f"- scanners: `{', '.join(scanners)}`",
    f"- secfeed MCP: {secfeed_status}",
    f"- agent/MCP/secret findings: {len(agent_posture_findings)} total; secret findings={len(secret_findings)}",
]

if critical_or_high:
    lines.extend(["", "**Critical/High findings (top 5)**"])
    for finding in critical_or_high[:5]:
        lines.append(
            f"- {str(finding.get('severity', '')).upper()} `{finding.get('id')}`: "
            f"{finding.get('title')} / affected=`{finding.get('affected')}`"
        )
    if len(critical_or_high) > 5:
        lines.append(f"- … and {len(critical_or_high) - 5} more")
else:
    lines.extend(["", "No CRITICAL/HIGH findings in this run."])

content = "\n".join(lines)[:1900]
request = urllib.request.Request(
    webhook_url,
    data=json.dumps({"content": content}).encode(),
    headers={"Content-Type": "application/json", "User-Agent": "hardshell/0.1"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status not in {200, 204}:
            raise SystemExit(f"Discord webhook returned HTTP {response.status}")
except urllib.error.HTTPError as exc:
    raise SystemExit(f"Discord webhook returned HTTP {exc.code}") from exc
PY

echo "[$(date)] Discord status report sent"
