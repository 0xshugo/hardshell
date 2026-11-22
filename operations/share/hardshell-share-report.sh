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
#   HARDSHELL_SHARE_MAX_BYTES  per-file size cap (default 128 MiB; daily reports
#                              are ~27 MB in production)
#
# publish records each file's outcome in $SHARED_DIR/.result-<name> and status
# copies them into version.json "share_results", so a skipped file is visible to
# orca-control without the journal:
#   {"status": "ok"} | {"status": "missing"}
#   {"status": "skipped", "reason": "too_large", "bytes": N}
#   {"status": "skipped", "reason": "not_regular_file" | "unreadable" | "forbidden" | "write_failed"}
set -uo pipefail
umask 077

HARDSHELL_HOME="${HARDSHELL_HOME:-/home/shugo/hardshell}"
REPORT_DIR="${HARDSHELL_REPORT_DIR:-$HARDSHELL_HOME/reports}"
SHARED_DIR="${HARDSHELL_SHARED_DIR:-/var/lib/hardshell-shared}"
OWNER="${HARDSHELL_OWNER:-$(stat -c %U "$HARDSHELL_HOME" 2>/dev/null || echo shugo)}"
SHARED_GROUP="${HARDSHELL_SHARED_GROUP:-orca-control}"
MAX_BYTES="${HARDSHELL_SHARE_MAX_BYTES:-134217728}"
[[ "$MAX_BYTES" =~ ^[0-9]+$ ]] || MAX_BYTES=134217728
SHARED_NAMES=(early-warning.json daily-latest.json weekly-latest.json)
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

# place_private <tmp> <dest>: make a 0640 root:<group> file and move it into place.
place_private() {
  chmod 0640 "$1"
  if is_root; then chown "root:$SHARED_GROUP" "$1"; fi
  mv -f -- "$1" "$2"
}

# record_result <name> <status> [reason] [bytes]: remember a publish outcome for status.
# Stored as one "status reason bytes" line; status re-validates it before emitting JSON.
record_result() {
  local name="$1" tmp
  tmp="$(mktemp "$SHARED_DIR/.result-${name}.XXXXXX")" || return 0
  printf '%s %s %s\n' "$2" "${3:--}" "${4:--}" >"$tmp"
  place_private "$tmp" "$SHARED_DIR/.result-${name}" || rm -f -- "$tmp"
}

# install_shared <source> <name>: atomically place a 0640 root:<group> copy in SHARED_DIR.
install_shared() {
  local src="$1" name="$2" tmp size
  if is_forbidden_source "$src"; then
    log "refusing forbidden source $src"
    record_result "$name" skipped forbidden
    return 1
  fi
  if [[ ! -e "$src" && ! -L "$src" ]]; then
    log "skip $name: $src is missing"
    record_result "$name" missing
    return 1
  fi
  if [[ -L "$src" || ! -f "$src" ]]; then
    log "skip $name: $src is not a regular file, or a symlink"
    record_result "$name" skipped not_regular_file
    return 1
  fi
  if ! tmp="$(mktemp "$SHARED_DIR/.${name}.XXXXXX")"; then
    record_result "$name" skipped write_failed
    return 1
  fi
  if ! as_owner head -c "$((MAX_BYTES + 1))" -- "$src" >"$tmp"; then
    log "skip $name: cannot read $src as $OWNER"
    rm -f -- "$tmp"
    record_result "$name" skipped unreadable
    return 1
  fi
  size="$(stat -c %s "$tmp")"
  if [[ "$size" -gt "$MAX_BYTES" ]]; then
    rm -f -- "$tmp"
    size="$(as_owner stat -c %s -- "$src" 2>/dev/null)" || size=""
    log "skip $name: ${size:-?} bytes is larger than $MAX_BYTES bytes (HARDSHELL_SHARE_MAX_BYTES)"
    record_result "$name" skipped too_large "$size"
    return 1
  fi
  touch -r "$src" "$tmp" 2>/dev/null || true
  if ! place_private "$tmp" "$SHARED_DIR/$name"; then
    rm -f -- "$tmp"
    record_result "$name" skipped write_failed
    return 1
  fi
  record_result "$name" ok
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
    if ! src="$(latest_report "$mode")"; then
      log "skip $mode-latest.json: no $mode-YYYY-MM-DD.json in $REPORT_DIR"
      record_result "$mode-latest.json" missing
      continue
    fi
    install_shared "$src" "$mode-latest.json" || continue
    # Record which dated report the stable name points to.
    printf '%s\n' "$(basename -- "$src")" >"$SHARED_DIR/.${mode}-source"
    chmod 0640 "$SHARED_DIR/.${mode}-source"
    if is_root; then chown "root:$SHARED_GROUP" "$SHARED_DIR/.${mode}-source"; fi
  done
}

# share_result_json <name>: emit the recorded publish outcome as a JSON object (or null).
# Every field is checked against a fixed vocabulary so version.json stays sanitized.
share_result_json() {
  local status="" reason="" bytes="" out
  read -r status reason bytes _ <"$SHARED_DIR/.result-$1" 2>/dev/null || true
  case "$status" in
    ok | missing) printf '{"status": "%s"}' "$status"; return ;;
    skipped) ;;
    *) printf 'null'; return ;;
  esac
  case "$reason" in
    too_large | not_regular_file | unreadable | forbidden | write_failed) ;;
    *) reason=unknown ;;
  esac
  out="{\"status\": \"skipped\", \"reason\": \"$reason\""
  if [[ "$reason" == too_large ]]; then
    if [[ "$bytes" =~ ^[0-9]{1,18}$ ]]; then out+=", \"bytes\": $((10#$bytes))"; else out+=', "bytes": null'; fi
    out+=", \"max_bytes\": $MAX_BYTES"
  fi
  printf '%s}' "$out"
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
    printf '  },\n'
    printf '  "share_results": {\n'
    local i last=$((${#SHARED_NAMES[@]} - 1))
    for i in "${!SHARED_NAMES[@]}"; do
      printf '    "%s": %s' "${SHARED_NAMES[$i]}" "$(share_result_json "${SHARED_NAMES[$i]}")"
      if [[ "$i" -lt "$last" ]]; then printf ',\n'; else printf '\n'; fi
    done
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
