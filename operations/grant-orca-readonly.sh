#!/usr/bin/env bash
# One-time root setup: give orca-control a read-only view of hardshell production output.
#
# Review, then run once from the deployed production tree:
#   sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh --dry-run
#   sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh
#
# What it does (idempotent; re-run after pulling a new helper version):
#   1. create /var/lib/hardshell-shared            root:orca-control 0750
#   2. install the share helper                    /usr/local/libexec/hardshell/share-report (root 0755)
#   3. install the watch drop-in                   /etc/systemd/system/hardshell-watch.service.d/50-share-report.conf
#   4. systemctl daemon-reload
#   5. (only with --with-journal) add orca-control to systemd-journal
#
# What it never does: ACLs or permission changes under /home/shugo, copying
# build/state/ or any .env, docker commands, or remediation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_HELPER="$SCRIPT_DIR/share/hardshell-share-report.sh"
SRC_DROPIN="$SCRIPT_DIR/systemd/hardshell-watch.service.d/50-share-report.conf"

SHARED_DIR=/var/lib/hardshell-shared
HELPER_DIR=/usr/local/libexec/hardshell
HELPER=$HELPER_DIR/share-report
DROPIN_DIR=/etc/systemd/system/hardshell-watch.service.d
DROPIN=$DROPIN_DIR/50-share-report.conf
ORCA_USER=orca-control
ORCA_GROUP=orca-control

DRY_RUN=0
WITH_JOURNAL=0
RUN_NOW=0

usage() {
  cat <<EOF
Usage: sudo $0 [--dry-run] [--with-journal] [--run-now]

  --dry-run       print the actions without changing anything (root not required)
  --with-journal  also add $ORCA_USER to the systemd-journal group (see note below)
  --run-now       start hardshell-watch.service once so the shared copy appears immediately
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --with-journal) WITH_JOURNAL=1 ;;
    --run-now) RUN_NOW=1 ;;
    -h | --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]; then
  echo "must run as root (or pass --dry-run)" >&2
  exit 1
fi
for f in "$SRC_HELPER" "$SRC_DROPIN"; do
  [[ -f "$f" ]] || { echo "missing source file: $f" >&2; exit 1; }
done
if ! getent group "$ORCA_GROUP" >/dev/null; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] warning: group $ORCA_GROUP does not exist here" >&2
  else
    echo "group $ORCA_GROUP does not exist" >&2
    exit 1
  fi
fi

# 1. Shared directory: root-owned so neither shugo nor orca-control can plant files;
#    group orca-control may list and read, nobody else may enter.
run install -d -m 0750 -o root -g "$ORCA_GROUP" "$SHARED_DIR"

# 2. Helper: root-owned copy so the root ExecStartPost never executes a file that
#    shugo (or anything running as shugo) could modify in /home/shugo/hardshell.
run install -d -m 0755 -o root -g root "$HELPER_DIR"
run install -m 0755 -o root -g root "$SRC_HELPER" "$HELPER"

# 3. Drop-in for hardshell-watch.service.
run install -d -m 0755 -o root -g root "$DROPIN_DIR"
run install -m 0644 -o root -g root "$SRC_DROPIN" "$DROPIN"

# 4. Reload unit definitions.
run systemctl daemon-reload

# 5. Optional journal access.
#    NOTE: systemd-journal membership lets orca-control read the ENTIRE system journal
#    (every unit, sshd, sudo, kernel), not just hardshell-watch. Journal lines may carry
#    hostnames, IPs, usernames and command lines. There is no per-unit journal ACL, so
#    only enable this if that breadth is acceptable. version.json already records the
#    last watch result without it.
if [[ "$WITH_JOURNAL" -eq 1 ]]; then
  if id -nG "$ORCA_USER" 2>/dev/null | tr ' ' '\n' | grep -qx systemd-journal; then
    echo "$ORCA_USER is already in systemd-journal"
  else
    run usermod -aG systemd-journal "$ORCA_USER"
    echo "note: $ORCA_USER sessions must restart to pick up the new group"
  fi
fi

if [[ "$RUN_NOW" -eq 1 ]]; then
  run systemctl start hardshell-watch.service
fi

cat <<EOF

Done$([[ "$DRY_RUN" -eq 1 ]] && echo " (dry-run: nothing changed)").
The next hardshell-watch run (timer, every ~15 min) will populate $SHARED_DIR:
  early-warning.json  daily-latest.json  weekly-latest.json  version.json
Verify as orca-control:
  sudo -u $ORCA_USER jq '.git_commit, .watch' $SHARED_DIR/version.json

Rollback:
  sudo rm -f $DROPIN
  sudo systemctl daemon-reload
  sudo rm -f $HELPER && sudo rmdir --ignore-fail-on-non-empty $HELPER_DIR
  sudo rm -rf $SHARED_DIR
EOF
if [[ "$WITH_JOURNAL" -eq 1 ]]; then
  echo "  sudo gpasswd -d $ORCA_USER systemd-journal"
fi
