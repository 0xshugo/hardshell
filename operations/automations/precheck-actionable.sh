#!/usr/bin/env bash
# Precheck for the Orca automation hardshell-actionable-review (runs as orca-control).
#
# Exit 0 -> run the review agent:
#   - a real, fresh production report contains status=actionable cases, or
#   - no real report is readable / it is unparseable / it is older than the max age
#     (the agent must then report "cannot see production" instead of staying silent).
# Exit 1 -> skip: a fresh, readable production report has nothing actionable.
#
# Candidates, first readable wins:
#   1. $HARDSHELL_EARLY_WARNING
#   2. $HARDSHELL_SHARED_DIR/early-warning.json   (default /var/lib/hardshell-shared)
#   3. $HARDSHELL_PROD_HOME/build/early-warning.json (default /home/shugo/hardshell)
# The workspace's own build/early-warning.json is a placeholder and is never evidence.
#
# The last stdout line is "precheck: decision=<run|skip> reason=<...> path=<...>".
set -uo pipefail

SHARED_DIR="${HARDSHELL_SHARED_DIR:-/var/lib/hardshell-shared}"
PROD_HOME="${HARDSHELL_PROD_HOME:-/home/shugo/hardshell}"
MAX_AGE="${HARDSHELL_EARLY_WARNING_MAX_AGE_SECONDS:-7200}"

candidates=(
  "${HARDSHELL_EARLY_WARNING:-}"
  "$SHARED_DIR/early-warning.json"
  "$PROD_HOME/build/early-warning.json"
)

for path in "${candidates[@]}"; do
  [[ -n "$path" && -f "$path" && -r "$path" ]] || continue
  python3 - "$path" "$MAX_AGE" <<'PY'
import json
import os
import sys
from datetime import UTC, datetime

path, max_age = sys.argv[1], int(sys.argv[2])


def decide(decision: str, reason: str, **extra: object) -> None:
    fields = " ".join(f"{k}={v}" for k, v in extra.items())
    print(f"precheck: decision={decision} reason={reason} path={path} {fields}".rstrip())
    # 10 = skip; anything else (including a crash) makes the agent run.
    raise SystemExit(0 if decision == "run" else 10)


try:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    if not isinstance(report, dict):
        raise ValueError("report is not a JSON object")
except (OSError, ValueError) as exc:
    decide("run", "unparseable", error=type(exc).__name__)

generated = None
raw = report.get("generated_at")
if isinstance(raw, str):
    try:
        generated = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=UTC)
    except ValueError:
        generated = None
if generated is None:
    generated = datetime.fromtimestamp(os.stat(path).st_mtime, UTC)
age = int((datetime.now(UTC) - generated).total_seconds())
if age > max_age:
    decide("run", "stale", age_seconds=age, max_age_seconds=max_age)

cases = report.get("cases")
if not isinstance(cases, list):
    decide("run", "unparseable", error="cases_missing")
actionable = [c for c in cases if isinstance(c, dict) and c.get("status") == "actionable"]
if actionable:
    decide("run", "actionable", cases=len(actionable), age_seconds=age)
decide("skip", "no_actionable", status=report.get("status"), age_seconds=age)
PY
  rc=$?
  if [[ "$rc" -eq 10 ]]; then
    exit 1
  fi
  if [[ "$rc" -ne 0 ]]; then
    echo "precheck: decision=run reason=precheck_error path=$path rc=$rc"
  fi
  exit 0
done

tried="$(printf '%s,' "${candidates[@]}")"
tried="${tried#,}"
echo "precheck: decision=run reason=unreadable path=none tried=${tried%,}"
exit 0
