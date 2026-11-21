#!/usr/bin/env bash
# Publish a read-only copy of hardshell production output for orca-control.
#
# Installed by operations/grant-orca-readonly.sh as
#   /usr/local/libexec/hardshell/share-report   (root:root 0755)
# and run by systemd as root via the hardshell-watch drop-in 50-share-report.conf:
#   ExecStartPost=+... publish   -> only after watch succeeded (exit 0 or 2)
#   ExecStopPost=+...  status    -> after every run, success or failure
#
# Subcommands
#   publish  copy build/early-warning.json and the latest reports/{daily,weekly}-*.json
#   status   write version.json (git commit, dirty flag, last watch result)
#
# Only the files listed above are ever copied. build/state/ and any .env are never
# read: they hold the Discord webhook and AI provider credentials.
#
# Source files are read with the owner's (shugo's) privileges, never root's, so a
# symlink planted in the source tree cannot expose a file shugo could not read.
# The helper is best-effort and always exits 0 so it never fails the watch unit.
#
# Environment (defaults match production):
#   HARDSHELL_HOME          /home/shugo/hardshell
#   HARDSHELL_REPORT_DIR    $HARDSHELL_HOME/reports   (where bin/scan.sh writes)
#   HARDSHELL_SHARED_DIR    /var/lib/hardshell-shared
#   HARDSHELL_OWNER         owner of $HARDSHELL_HOME (shugo)
#   HARDSHELL_SHARED_GROUP  orca-control
#   HARDSHELL_SHARE_MAX_BYTES  per-file size cap (default 20 MiB)
set -uo pipefail
umask 077

HARDSHELL_HOME="${HARDSHELL_HOME:-/home/shugo/hardshell}"
REPORT_DIR="${HARDSHELL_REPORT_DIR:-$HARDSHELL_HOME/reports}"
SHARED_DIR="${HARDSHELL_SHARED_DIR:-/var/lib/hardshell-shared}"
OWNER="${HARDSHELL_OWNER:-$(stat -c %U "$HARDSHELL_HOME" 2>/dev/null || echo shugo)}"
SHARED_GROUP="${HARDSHELL_SHARED_GROUP:-orca-control}"
MAX_BYTES="${HARDSHELL_SHARE_MAX_BYTES:-20971520}"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log() { echo "hardshell-share-report: $*" >&2; }

is_root() { [[ "$(id -u)" -eq 0 ]]; }

# Run a command with the source owner's privileges (no-op when not root, e.g. tests).
as_owner() {
  if is_root && [[ "$OWNER" != "root" ]]; then
    local owner_home
    owner_home="$(getent passwd "$OWNER" | cut -d: -f6)"
    setpriv --reuid="$OWNER" --regid="$OWNER" --init-groups -- \
      env -i PATH="$PATH" HOME="${owner_home:-/nonexistent}" LANG=C.UTF-8 "$@"
  else
    "$@"
  fi
}

# Refuse anything outside the allowlist, even if a caller passes it in.
is_forbidden_source() {
  case "$1" in
    */build/state/* | */.env | */*.env | *.env.* | */.git/*) return 0 ;;
  esac
  return 1
}

# install_shared <source> <name>: atomically place a 0640 root:<group> copy in SHARED_DIR.
install_shared() {
  local src="$1" name="$2" tmp size
  if is_forbidden_source "$src"; then
    log "refusing forbidden source $src"
    return 1
  fi
  if [[ -L "$src" || ! -f "$src" ]]; then
    log "skip $name: $src is missing, not a regular file, or a symlink"
    return 1
  fi
  tmp="$(mktemp "$SHARED_DIR/.${name}.XXXXXX")" || return 1
  if ! as_owner head -c "$((MAX_BYTES + 1))" -- "$src" >"$tmp"; then
    log "skip $name: cannot read $src as $OWNER"
    rm -f -- "$tmp"
    return 1
  fi
  size="$(stat -c %s "$tmp")"
  if [[ "$size" -gt "$MAX_BYTES" ]]; then
    log "skip $name: larger than $MAX_BYTES bytes"
    rm -f -- "$tmp"
    return 1
  fi
  chmod 0640 "$tmp"
  if is_root; then
    chown "root:$SHARED_GROUP" "$tmp"
  fi
  touch -r "$src" "$tmp" 2>/dev/null || true
  mv -f -- "$tmp" "$SHARED_DIR/$name"
}

latest_report() {
  # Report names are <mode>-YYYY-MM-DD.json, so lexical order is date order.
  local mode="$1" f latest=""
  for f in "$REPORT_DIR/$mode"-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].json; do
    [[ -f "$f" ]] && latest="$f"
  done
  [[ -n "$latest" ]] && printf '%s\n' "$latest"
}

cmd_publish() {
  install_shared "$HARDSHELL_HOME/build/early-warning.json" early-warning.json || true
  local mode src
  for mode in daily weekly; do
    src="$(latest_report "$mode")" || continue
    install_shared "$src" "$mode-latest.json" || continue
    # Record which dated report the stable name points to.
    printf '%s\n' "$(basename -- "$src")" >"$SHARED_DIR/.${mode}-source"
    chmod 0640 "$SHARED_DIR/.${mode}-source"
    if is_root; then chown "root:$SHARED_GROUP" "$SHARED_DIR/.${mode}-source"; fi
  done
}

# Keep only characters that are safe inside a JSON string without escaping.
sanitize() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._:/+@-' | head -c 200; }

json_str_or_null() {
  local v
  v="$(sanitize "$1")"
  if [[ -n "$v" ]]; then printf '"%s"' "$v"; else printf 'null'; fi
}

json_int_or_str() {
  if [[ "$1" =~ ^[0-9]+$ ]]; then printf '%s' "$1"; else json_str_or_null "$1"; fi
}

file_mtime() {
  [[ -f "$1" ]] && date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ
}

cmd_status() {
  local commit="" branch="" dirty="null" porcelain now tmp
  commit="$(as_owner git -C "$HARDSHELL_HOME" rev-parse HEAD 2>/dev/null)" || commit=""
  [[ "$commit" =~ ^[0-9a-f]{40,64}$ ]] || commit=""
  branch="$(as_owner git -C "$HARDSHELL_HOME" rev-parse --abbrev-ref HEAD 2>/dev/null)" || branch=""
  if [[ -n "$commit" ]]; then
    if porcelain="$(as_owner env GIT_OPTIONAL_LOCKS=0 git -C "$HARDSHELL_HOME" status --porcelain --untracked-files=no 2>/dev/null)"; then
      if [[ -n "$porcelain" ]]; then dirty=true; else dirty=false; fi
    fi
  fi
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  tmp="$(mktemp "$SHARED_DIR/.version.json.XXXXXX")" || return 1
  {
    printf '{\n'
    printf '  "schema": "hardshell-shared-version/v1",\n'
    printf '  "written_at": "%s",\n' "$now"
    printf '  "source_dir": %s,\n' "$(json_str_or_null "$HARDSHELL_HOME")"
    printf '  "git_commit": %s,\n' "$(json_str_or_null "$commit")"
    printf '  "git_branch": %s,\n' "$(json_str_or_null "$branch")"
    printf '  "git_dirty": %s,\n' "$dirty"
    printf '  "watch": {\n'
    printf '    "finished_at": "%s",\n' "$now"
    printf '    "service_result": %s,\n' "$(json_str_or_null "${SERVICE_RESULT:-}")"
    printf '    "exit_code": %s,\n' "$(json_str_or_null "${EXIT_CODE:-}")"
    printf '    "exit_status": %s\n' "$(json_int_or_str "${EXIT_STATUS:-}")"
    printf '  },\n'
    printf '  "shared_files": {\n'
    printf '    "early-warning.json": %s,\n' "$(json_str_or_null "$(file_mtime "$SHARED_DIR/early-warning.json")")"
    printf '    "daily-latest.json": %s,\n' "$(json_str_or_null "$(file_mtime "$SHARED_DIR/daily-latest.json")")"
    printf '    "weekly-latest.json": %s\n' "$(json_str_or_null "$(file_mtime "$SHARED_DIR/weekly-latest.json")")"
    printf '  },\n'
    printf '  "report_sources": {\n'
    printf '    "daily": %s,\n' "$(json_str_or_null "$(cat "$SHARED_DIR/.daily-source" 2>/dev/null)")"
    printf '    "weekly": %s\n' "$(json_str_or_null "$(cat "$SHARED_DIR/.weekly-source" 2>/dev/null)")"
    printf '  }\n'
    printf '}\n'
  } >"$tmp"
  chmod 0640 "$tmp"
  if is_root; then chown "root:$SHARED_GROUP" "$tmp"; fi
  mv -f -- "$tmp" "$SHARED_DIR/version.json"
}

main() {
  if [[ ! -d "$SHARED_DIR" || -L "$SHARED_DIR" ]]; then
    log "shared dir $SHARED_DIR missing; run operations/grant-orca-readonly.sh"
    exit 0
  fi
  case "${1:-}" in
    publish) cmd_publish ;;
    status) cmd_status || log "status write failed" ;;
    *)
      echo "usage: $0 {publish|status}" >&2
      exit 64
      ;;
  esac
  exit 0
}

main "$@"
