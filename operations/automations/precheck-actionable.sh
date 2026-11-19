#!/usr/bin/env bash
# Exit 0 only when an early-warning report contains actionable cases.
set -euo pipefail
candidates=(
  "${HARDSHELL_EARLY_WARNING:-}"
  /home/shugo/hardshell/build/early-warning.json
  "$(cd "$(dirname "$0")/../.." && pwd)/build/early-warning.json"
)
for path in "${candidates[@]}"; do
  [[ -n "$path" && -r "$path" ]] || continue
  python3 - "$path" <<'PY'
import json, sys
report = json.loads(open(sys.argv[1]).read())
cases = [c for c in report.get("cases", []) if c.get("status") == "actionable"]
raise SystemExit(0 if cases else 1)
PY
  exit $?
done
exit 1
