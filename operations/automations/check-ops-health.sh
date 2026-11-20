#!/usr/bin/env bash
# Read-only Hardshell VPS operational & Discord alerting health check.
# Exits 0 only when watch timer, early-warning report, and Discord alerting are healthy.
# Exits 2 when follow-up is required (prints structured JSON summary to stdout).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROD_ROOT="${HARDSHELL_PROD_HOME:-/home/shugo/hardshell}"

PYTHON_BIN="${HARDSHELL_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$ROOT_DIR/.venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

TARGET_ROOT=""
if [[ -r "$PROD_ROOT/build/early-warning.json" ]]; then
  TARGET_ROOT="$PROD_ROOT"
elif [[ -n "${HARDSHELL_HOME:-}" && -r "${HARDSHELL_HOME}/build/early-warning.json" ]]; then
  TARGET_ROOT="$HARDSHELL_HOME"
fi

if [[ -n "$TARGET_ROOT" ]]; then
  HARDSHELL_HOME="$TARGET_ROOT" PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$PYTHON_BIN" -m hardshell ops-check --json
  exit $?
fi

# Fallback when running from an unprivileged sandbox (e.g. orca-control) where
# /home/shugo/hardshell/build/early-warning.json is mode 0600 owned by shugo.
PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_BIN" - "$PROD_ROOT" <<'PY'
import json
import sys
from pathlib import Path
from hardshell.ops_health import _check_systemd

prod_root = Path(sys.argv[1])
systemd_check = _check_systemd()
follow_up = []
if systemd_check.get("status") == "follow_up_needed":
    follow_up.append(f"systemd_watch: {systemd_check.get('reason')}")
if not systemd_check.get("discord_dropin_present"):
    follow_up.append("Install /etc/systemd/system/hardshell-watch.service.d/20-discord.conf")
follow_up.append(
    f"Production artifacts under {prod_root}/build/ are unreadable from this user; "
    "run `HARDSHELL_HOME=/home/shugo/hardshell hardshell ops-check` as shugo to verify Discord delivery and scan freshness"
)

payload = {
    "root": str(prod_root),
    "overall_status": "follow_up_needed",
    "follow_up_needed": True,
    "checks": {
        "systemd_watch": systemd_check,
        "early_warning": {
            "status": "follow_up_needed",
            "reason": "production_report_unreadable_from_sandbox",
            "path": str(prod_root / "build" / "early-warning.json"),
        },
        "discord_alerting": {
            "status": "follow_up_needed",
            "reason": "alert_state_unreadable_from_sandbox",
            "discord_dropin_present": systemd_check.get("discord_dropin_present"),
        },
    },
    "follow_up_actions": follow_up,
}
print(json.dumps(payload, ensure_ascii=False, indent=2))
raise SystemExit(2)
PY
