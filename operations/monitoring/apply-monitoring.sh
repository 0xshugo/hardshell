#!/usr/bin/env bash
# apply-monitoring: install the host-health collector and HardShell/host alert rules.
#
# The owner runs this from the production tree (/home/shugo/hardshell). Default is a
# dry run that changes nothing and prints every command it would run.
#
#   sudo operations/monitoring/apply-monitoring.sh                 # dry run (default)
#   sudo operations/monitoring/apply-monitoring.sh --validate      # promtool check + unit tests
#   sudo operations/monitoring/apply-monitoring.sh --apply         # install collector service/timer
#   sudo operations/monitoring/apply-monitoring.sh --apply --merge # + merge groups, HUP Prometheus
#   operations/monitoring/apply-monitoring.sh --rollback           # print the rollback steps
#
# Options:
#   --dry-run            print what would change (default)
#   --apply              make changes (requires root)
#   --validate           run promtool `check rules` and `test rules` in a throwaway container
#   --merge              also merge the rule groups into the aoi-system alert file. With
#                        --dry-run it only shows the diff. Without --merge the manual
#                        merge steps are printed instead.
#   --alerts-file PATH   alert file to merge into
#                        (default /home/shugo/services/aoi-system/monitoring/prometheus-alerts.yml)
#   --rollback           print the rollback steps and exit
#
# Environment:
#   PROMTOOL_IMAGE   image for promtool (default: the image of task-prometheus, else prom/prometheus)
#   PYTHON           python with PyYAML for --merge (default: python3, then the hardshell venv)
#
# Never reads or writes secrets (docker/secrets, build/state, *.env). Idempotent: running
# it again reinstalls identical files and merging again produces the same alert file.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/rules"
RULE_FILES=("hardshell-alerts.yml" "host-alerts.yml")
TEST_FILES=("hardshell-alerts.test.yml" "host-alerts.test.yml")

ALERTS_FILE="/home/shugo/services/aoi-system/monitoring/prometheus-alerts.yml"
PROM_CONTAINER="task-prometheus"
PROM_API="http://127.0.0.1:9099"
PUSHGATEWAY="http://127.0.0.1:9091"
LIBEXEC_DIR="/usr/local/libexec/hardshell"
COLLECTOR_DEST="$LIBEXEC_DIR/host-health-push"
UNIT_DIR="/etc/systemd/system"
UNITS=("hardshell-host-health.service" "hardshell-host-health.timer")
COLLECTOR_USER="orca-control"

MODE="dry-run"
DO_VALIDATE=0
DO_MERGE=0
DO_ROLLBACK=0

usage() { sed -n '2,30p' "$0"; }

while (($#)); do
  case "$1" in
    --dry-run) MODE="dry-run" ;;
    --apply) MODE="apply" ;;
    --validate) DO_VALIDATE=1 ;;
    --merge) DO_MERGE=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    --alerts-file)
      [[ $# -ge 2 ]] || { echo "--alerts-file needs a path" >&2; exit 2; }
      ALERTS_FILE="$2"
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

say() { printf '%s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# run <cmd...>: execute in apply mode, print in dry-run mode.
run() {
  if [[ "$MODE" == "apply" ]]; then
    say "+ $*"
    "$@"
  else
    say "[dry-run] $*"
  fi
}

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="$ALERTS_FILE.bak-$TS"

print_rollback() {
  local backup="${1:-$ALERTS_FILE.bak-<timestamp>}"
  cat <<EOF
Rollback (run as root):
  systemctl disable --now hardshell-host-health.timer
  rm -f $UNIT_DIR/hardshell-host-health.service $UNIT_DIR/hardshell-host-health.timer $COLLECTOR_DEST
  systemctl daemon-reload
  curl -fsS -X DELETE $PUSHGATEWAY/metrics/job/host_health
  # alert rules: copy the backup back IN PLACE (cp, not mv: the file is a single-file bind mount)
  cp $backup $ALERTS_FILE
  docker kill -s HUP $PROM_CONTAINER
EOF
}

if ((DO_ROLLBACK)); then
  print_rollback
  exit 0
fi

if [[ "$MODE" == "apply" && "$EUID" -ne 0 ]]; then
  die "--apply needs root: sudo $0 --apply"
fi

for f in "${RULE_FILES[@]}"; do
  [[ -f "$RULES_DIR/$f" ]] || die "missing rule file $RULES_DIR/$f"
done

promtool_image() {
  if [[ -n "${PROMTOOL_IMAGE:-}" ]]; then
    printf '%s' "$PROMTOOL_IMAGE"
    return
  fi
  local img
  img="$(docker inspect -f '{{.Config.Image}}' "$PROM_CONTAINER" 2>/dev/null || true)"
  printf '%s' "${img:-prom/prometheus}"
}

# promtool runs as root inside a throwaway, network-less container with read-only mounts
# (the image's default user `nobody` may not be able to read 0600/0640 rule files).
promtool_run() {
  docker run --rm --network none --user 0:0 --entrypoint promtool "$@" 2>&1 | sed 's/^/  /'
  return "${PIPESTATUS[0]}"
}

validate_repo_rules() {
  local image="$1" checks=() tests=()
  for f in "${RULE_FILES[@]}"; do checks+=("/rules/$f"); done
  for f in "${TEST_FILES[@]}"; do tests+=("/rules/tests/$f"); done
  say "promtool image: $image"
  say "+ promtool check rules ${checks[*]}"
  promtool_run -v "$RULES_DIR:/rules:ro" "$image" check rules "${checks[@]}" \
    || die "promtool check rules failed"
  say "+ promtool test rules ${tests[*]}"
  promtool_run -v "$RULES_DIR:/rules:ro" "$image" test rules "${tests[@]}" \
    || die "promtool test rules failed"
}

validate_alert_file() {
  local image="$1" file="$2"
  say "+ promtool check rules $file"
  promtool_run -v "$file:/check/alerts.yml:ro" "$image" check rules /check/alerts.yml \
    || die "promtool check rules failed for $file"
}

find_python() {
  local candidate
  for candidate in "${PYTHON:-}" python3 /home/shugo/hardshell/.venv/bin/python; do
    [[ -n "$candidate" ]] || continue
    if "$candidate" -c 'import yaml' >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

print_manual_merge() {
  local image="$1"
  cat <<EOF
Manual merge of the alert rules (recommended over --merge if you want to keep comments):
  1. Back up:   sudo cp -p $ALERTS_FILE $BACKUP
  2. Edit IN PLACE (the file is bind-mounted as a single file, so a rename/mv leaves the
     container on the old inode; vim/nano write in place, \`sed -i\` and \`mv\` do not):
       - replace the whole \`- name: hardshell_alerts\` group with the group in
         $RULES_DIR/hardshell-alerts.yml
       - append the \`- name: host_health_alerts\` group from
         $RULES_DIR/host-alerts.yml at the end of \`groups:\`
       - keep app_alerts, container_alerts and resource_alerts unchanged
  3. Validate:  docker run --rm --network none --user 0:0 -v $ALERTS_FILE:/check/alerts.yml:ro \\
                  --entrypoint promtool $image check rules /check/alerts.yml
  4. Reload:    docker kill -s HUP $PROM_CONTAINER
  5. Verify:    curl -s $PROM_API/api/v1/rules | jq -r '.data.groups[].name'
                curl -s $PROM_API/api/v1/rules | jq -r '.data.groups[] | select(.name=="hardshell_alerts") | .rules[].name'
     If HardshellNewKEV is missing after the HUP, the container still sees the old inode:
     \`docker restart $PROM_CONTAINER\` (owner decision; brief gap in alerting).
EOF
}

# --- 1. collector service/timer ------------------------------------------------------------
section "1. host-health collector ($MODE)"
if ! id "$COLLECTOR_USER" >/dev/null 2>&1; then
  die "user $COLLECTOR_USER does not exist"
fi
say "preview of the metrics (collector --print, read-only):"
bash "$SCRIPT_DIR/host-health-push.sh" --print \
  | grep -v '^#' | sed 's/^/  /' || true

changed=0
if ! cmp -s "$SCRIPT_DIR/host-health-push.sh" "$COLLECTOR_DEST" 2>/dev/null; then changed=1; fi
for unit in "${UNITS[@]}"; do
  if ! cmp -s "$SCRIPT_DIR/$unit" "$UNIT_DIR/$unit" 2>/dev/null; then changed=1; fi
done
if ((changed)); then say "collector files differ from the installed copies; installing"; else
  say "collector files already installed and identical"; fi

run install -d -o root -g root -m 0755 "$LIBEXEC_DIR"
run install -o root -g root -m 0755 "$SCRIPT_DIR/host-health-push.sh" "$COLLECTOR_DEST"
for unit in "${UNITS[@]}"; do
  run install -o root -g root -m 0644 "$SCRIPT_DIR/$unit" "$UNIT_DIR/$unit"
done
run systemctl daemon-reload
run systemctl enable --now hardshell-host-health.timer
run systemctl start hardshell-host-health.service
say "verify: curl -s $PUSHGATEWAY/metrics | grep -E '^(orca_server|host_|systemd_unit_active)'"

# --- 2. validate rules ---------------------------------------------------------------------
section "2. validate rule files"
IMAGE="$(promtool_image)"
if ((DO_VALIDATE)) || [[ "$MODE" == "apply" ]]; then
  validate_repo_rules "$IMAGE"
else
  say "[dry-run] docker run --rm --network none --user 0:0 -v $RULES_DIR:/rules:ro --entrypoint promtool $IMAGE check rules /rules/${RULE_FILES[0]} /rules/${RULE_FILES[1]}"
  say "[dry-run] docker run --rm --network none --user 0:0 -v $RULES_DIR:/rules:ro --entrypoint promtool $IMAGE test rules /rules/tests/${TEST_FILES[0]} /rules/tests/${TEST_FILES[1]}"
  say "(run with --validate to execute them)"
fi

# --- 3. merge into the aoi-system alert file -----------------------------------------------
section "3. alert rules in $ALERTS_FILE"
if ((DO_MERGE == 0)); then
  print_manual_merge "$IMAGE"
else
  [[ -f "$ALERTS_FILE" ]] || die "alert file not found: $ALERTS_FILE"
  PY="$(find_python)" || die "no python with PyYAML found; set PYTHON=/path/to/python or merge manually"
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  CANDIDATE="$WORK/prometheus-alerts.yml"
  "$PY" "$SCRIPT_DIR/merge-alert-groups.py" "$ALERTS_FILE" "$CANDIDATE" \
    "$RULES_DIR/${RULE_FILES[0]}" "$RULES_DIR/${RULE_FILES[1]}" | sed 's/^/  /'
  chmod 0644 "$CANDIDATE"
  if cmp -s "$CANDIDATE" "$ALERTS_FILE"; then
    say "alert file already up to date; nothing to merge"
  else
    say "diff (current -> merged; YAML comments in the current file are not kept):"
    diff -u "$ALERTS_FILE" "$CANDIDATE" | sed 's/^/  /' || true
    if [[ "$MODE" == "apply" ]]; then
      validate_alert_file "$IMAGE" "$CANDIDATE"
      run cp -p "$ALERTS_FILE" "$BACKUP"
      # cp into the existing file keeps its inode, owner and mode (single-file bind mount).
      run cp "$CANDIDATE" "$ALERTS_FILE"
      run docker kill -s HUP "$PROM_CONTAINER"
      say "backup: $BACKUP"
      say "verify: curl -s $PROM_API/api/v1/rules | jq -r '.data.groups[].name'"
    else
      say "[dry-run] would validate the merged file, back up to $BACKUP, copy it in place and HUP $PROM_CONTAINER"
    fi
  fi
fi

section "rollback"
if [[ "$MODE" == "apply" && -f "$BACKUP" ]]; then
  print_rollback "$BACKUP"
else
  print_rollback
fi
