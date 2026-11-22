#!/usr/bin/env bash
# host-health-push: push host and orca-server.service health to Prometheus Pushgateway.
#
# Fills the blind spots of the current monitoring stack (no node_exporter, and cadvisor
# runs with docker_only=true so systemd services are invisible). Runs every 60s from
# hardshell-host-health.timer as an unprivileged user. Reads only world-readable files
# (/sys/fs/cgroup, /proc/meminfo, /proc/loadavg), `df` and `systemctl is-active`.
# It never runs docker and never writes anything except the HTTP PUT to the Pushgateway.
#
# Usage:
#   host-health-push.sh            collect and PUT to $HOST_HEALTH_PUSHGATEWAY_URL
#   host-health-push.sh --print    collect and print the exposition text to stdout only
#
# Environment overrides (used by tests with fixture directories):
#   HOST_HEALTH_PUSHGATEWAY_URL  default http://127.0.0.1:9091
#   HOST_HEALTH_JOB              default host_health
#   HOST_HEALTH_CGROUP_DIR       default /sys/fs/cgroup/system.slice/orca-server.service
#   HOST_HEALTH_ROOTFS           default /
#   HOST_HEALTH_PROC_DIR         default /proc
#   HOST_HEALTH_UNITS            default "hardshell-watch.timer secfeed-monitor.timer
#                                         orca-server.service docker.service"
#   HOST_HEALTH_SYSTEMCTL        default systemctl
#   HOST_HEALTH_CURL             default curl
#
# Exit status is always 0. Problems are logged to stderr (journal) with a reason.

set -uo pipefail

PUSHGATEWAY_URL="${HOST_HEALTH_PUSHGATEWAY_URL:-http://127.0.0.1:9091}"
JOB="${HOST_HEALTH_JOB:-host_health}"
CGROUP_DIR="${HOST_HEALTH_CGROUP_DIR:-/sys/fs/cgroup/system.slice/orca-server.service}"
ROOTFS="${HOST_HEALTH_ROOTFS:-/}"
PROC_DIR="${HOST_HEALTH_PROC_DIR:-/proc}"
UNITS="${HOST_HEALTH_UNITS:-hardshell-watch.timer secfeed-monitor.timer orca-server.service docker.service}"
SYSTEMCTL="${HOST_HEALTH_SYSTEMCTL:-systemctl}"
CURL="${HOST_HEALTH_CURL:-curl}"

MODE="push"
case "${1:-}" in
  --print) MODE="print" ;;
  "") ;;
  -h|--help)
    sed -n '2,25p' "$0"
    exit 0
    ;;
  *)
    echo "host-health: unknown argument: $1 (use --print or no argument)" >&2
    exit 0
    ;;
esac

log() { echo "host-health: $*" >&2; }

OUT=""
emit() { OUT+="$1"$'\n'; }
meta() {
  # meta <name> <type> <help>
  emit "# HELP $1 $3"
  emit "# TYPE $1 $2"
}

# Read the first line of a file; prints nothing if unreadable.
read_line() {
  local f="$1" line=""
  [[ -r "$f" ]] || return 1
  IFS= read -r line < "$f" || [[ -n "$line" ]] || return 1
  printf '%s' "$line"
}

# Cgroup limits are either an integer or the literal "max".
limit_value() {
  if [[ "$1" == "max" ]]; then printf '+Inf'; else printf '%s' "$1"; fi
}

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

# Value of "<key> <n>" in a flat-keyed cgroup file (memory.events, memory.stat, pids.events).
keyed_value() {
  local f="$1" key="$2"
  [[ -r "$f" ]] || return 1
  awk -v k="$key" '$1 == k { print $2; found = 1; exit } END { if (!found) exit 1 }' "$f"
}

# --- orca-server.service cgroup -----------------------------------------------------------
collect_cgroup() {
  local pids_cur pids_max pids_ev mem_cur mem_max mem_anon mem_ev_max mem_ev_oom
  if [[ ! -d "$CGROUP_DIR" ]]; then
    log "cgroup dir missing: $CGROUP_DIR (orca-server.service not running?); skipping orca_server_* metrics"
    return 1
  fi
  pids_cur="$(read_line "$CGROUP_DIR/pids.current")"
  pids_max="$(read_line "$CGROUP_DIR/pids.max")"
  mem_cur="$(read_line "$CGROUP_DIR/memory.current")"
  mem_max="$(read_line "$CGROUP_DIR/memory.max")"
  if ! is_uint "$pids_cur" || ! is_uint "$mem_cur" || [[ -z "$pids_max" || -z "$mem_max" ]]; then
    log "cgroup files unreadable under $CGROUP_DIR; skipping orca_server_* metrics"
    return 1
  fi
  pids_ev="$(keyed_value "$CGROUP_DIR/pids.events" max)" || pids_ev=""
  mem_anon="$(keyed_value "$CGROUP_DIR/memory.stat" anon)" || mem_anon=""
  mem_ev_max="$(keyed_value "$CGROUP_DIR/memory.events" max)" || mem_ev_max=""
  mem_ev_oom="$(keyed_value "$CGROUP_DIR/memory.events" oom_kill)" || mem_ev_oom=""

  meta orca_server_pids_current gauge "Tasks (threads+processes) in orca-server.service cgroup"
  emit "orca_server_pids_current $pids_cur"
  meta orca_server_pids_max gauge "TasksMax of orca-server.service (+Inf when unlimited)"
  emit "orca_server_pids_max $(limit_value "$pids_max")"
  if is_uint "$pids_ev"; then
    meta orca_server_pids_events_max_total counter "Times orca-server.service hit TasksMax (pids.events max)"
    emit "orca_server_pids_events_max_total $pids_ev"
  fi
  meta orca_server_memory_current_bytes gauge "memory.current of orca-server.service (includes page cache)"
  emit "orca_server_memory_current_bytes $mem_cur"
  if is_uint "$mem_anon"; then
    meta orca_server_memory_anon_bytes gauge "Anonymous (non-reclaimable) memory of orca-server.service"
    emit "orca_server_memory_anon_bytes $mem_anon"
  fi
  meta orca_server_memory_max_bytes gauge "MemoryMax of orca-server.service (+Inf when unlimited)"
  emit "orca_server_memory_max_bytes $(limit_value "$mem_max")"
  if is_uint "$mem_ev_max"; then
    meta orca_server_memory_events_max_total counter "Times orca-server.service reached MemoryMax (memory.events max)"
    emit "orca_server_memory_events_max_total $mem_ev_max"
  fi
  if is_uint "$mem_ev_oom"; then
    meta orca_server_memory_events_oom_kill_total counter "OOM kills inside orca-server.service (memory.events oom_kill)"
    emit "orca_server_memory_events_oom_kill_total $mem_ev_oom"
  fi
  return 0
}

# --- host ---------------------------------------------------------------------------------
collect_rootfs() {
  local line used avail ratio
  # POSIX df: Filesystem 1024-blocks Used Available Capacity Mounted-on
  line="$(df -P "$ROOTFS" 2>/dev/null | awk 'NR == 2 { print $3, $4 }')"
  read -r used avail <<< "$line"
  if ! is_uint "${used:-}" || ! is_uint "${avail:-}" || (( used + avail == 0 )); then
    log "df failed for $ROOTFS; skipping host_rootfs_used_ratio"
    return 1
  fi
  # Same definition as df's Use%: used / (used + available); reserved blocks excluded.
  ratio="$(awk -v u="$used" -v a="$avail" 'BEGIN { printf "%.6f", u / (u + a) }')"
  meta host_rootfs_used_ratio gauge "Used ratio of the root filesystem (df Use%)"
  emit "host_rootfs_used_ratio $ratio"
}

collect_memory() {
  local ratio
  ratio="$(awk '
    $1 == "MemTotal:" { t = $2 }
    $1 == "MemAvailable:" { a = $2 }
    END { if (t > 0 && a != "") printf "%.6f", a / t; else exit 1 }
  ' "$PROC_DIR/meminfo" 2>/dev/null)" || ratio=""
  if [[ -z "$ratio" ]]; then
    log "cannot read MemTotal/MemAvailable from $PROC_DIR/meminfo; skipping host_memory_available_ratio"
    return 1
  fi
  meta host_memory_available_ratio gauge "MemAvailable / MemTotal of the host"
  emit "host_memory_available_ratio $ratio"
}

collect_load() {
  local load1 rest
  { read -r load1 rest < "$PROC_DIR/loadavg"; } 2>/dev/null || load1=""
  if [[ ! "$load1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    log "cannot read $PROC_DIR/loadavg; skipping host_load1"
    return 1
  fi
  meta host_load1 gauge "1-minute load average of the host"
  emit "host_load1 $load1"
}

collect_units() {
  local unit state value header=0
  for unit in $UNITS; do
    if [[ ! "$unit" =~ ^[A-Za-z0-9@._:-]+$ ]]; then
      log "ignoring invalid unit name: $unit"
      continue
    fi
    state="$("$SYSTEMCTL" is-active "$unit" 2>/dev/null)"
    case "$state" in
      active|reloading|refreshing) value=1 ;;
      inactive|failed|activating|deactivating|maintenance) value=0 ;;
      *)
        # Empty/unknown output means systemctl itself could not answer (no D-Bus, etc).
        # Skip instead of reporting a false "down"; HostHealthPushStale still covers us.
        log "systemctl is-active $unit returned '${state}'; skipping"
        continue
        ;;
    esac
    if (( header == 0 )); then
      meta systemd_unit_active gauge "1 if systemctl is-active reports active, else 0"
      header=1
    fi
    emit "systemd_unit_active{unit=\"$unit\"} $value"
  done
}

collect_cgroup
cgroup_ok=$?
meta host_health_orca_server_cgroup_readable gauge "1 if orca-server.service cgroup files were readable"
emit "host_health_orca_server_cgroup_readable $(( cgroup_ok == 0 ? 1 : 0 ))"
collect_rootfs
collect_memory
collect_load
collect_units

if [[ "$MODE" == "print" ]]; then
  printf '%s' "$OUT"
  exit 0
fi

if [[ ! "$PUSHGATEWAY_URL" =~ ^https?://[^/]+ ]]; then
  log "invalid HOST_HEALTH_PUSHGATEWAY_URL; not pushing"
  exit 0
fi

# PUT replaces the whole group, so metrics that disappear (e.g. cgroup gone) do not linger.
endpoint="${PUSHGATEWAY_URL%/}/metrics/job/${JOB}"
if ! printf '%s' "$OUT" | "$CURL" -fsS -m 10 -X PUT \
    -H 'Content-Type: text/plain; version=0.0.4; charset=utf-8' \
    --data-binary @- "$endpoint" >/dev/null; then
  log "push to $endpoint failed; HostHealthPushStale will fire if this persists"
fi
exit 0
