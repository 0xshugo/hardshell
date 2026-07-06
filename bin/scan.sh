#!/usr/bin/env bash
set -euo pipefail

# hardshell scan wrapper — daily / weekly modes
# Usage:
#   scan.sh daily [YYYY-MM-DD]
#   scan.sh weekly [YYYY-MM-DD]
# Optional environment:
#   HARDSHELL_SCAN_DATE=YYYY-MM-DD       Override report date for backfills/rescans.
#   HARDSHELL_DRY_RUN=1                  Print resolved actions without scanning.
#   HARDSHELL_AUTO_FIX=auto|true|false   Auto-remediation; auto=true only for today's report.
#   HARDSHELL_DELTA_NOTIFY=auto|true|false
#   HARDSHELL_STATUS_REPORT=auto|true|false
#   HARDSHELL_METRICS=auto|true|false
#   HARDSHELL_SCRATCH_SYNC=auto|true|false

MODE="${1:-daily}"

# インストール先はスクリプト位置から自動推定する。
# 注意: sudo/cron 実行では $HOME が /root になるため、$HOME 由来のパスに依存しない。
# 全パスは環境変数で上書き可能 (HARDSHELL_HOME, HARDSHELL_CONFIG, HERMES_CONFIG, HARDSHELL_ENV_FILE, HARDSHELL_BIN)。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARDSHELL_HOME="${HARDSHELL_HOME:-$(dirname "$SCRIPT_DIR")}"

# 運用ユーザー: 未指定時はリポジトリ所有者 (root cron でも所有者のホームを参照できる)
# ディレクトリ未存在時 (dry-run 等) は実行ユーザーにフォールバック
HARDSHELL_USER="${HARDSHELL_USER:-$(stat -c %U "$HARDSHELL_HOME" 2>/dev/null || stat -f %Su "$HARDSHELL_HOME" 2>/dev/null || id -un)}"
USER_HOME="$(getent passwd "$HARDSHELL_USER" 2>/dev/null | cut -d: -f6 || true)"
USER_HOME="${USER_HOME:-$HOME}"

CONFIG="${HARDSHELL_CONFIG:-$USER_HOME/.config/hardshell/config.toml}"
REPORT_DIR="$HARDSHELL_HOME/reports"
BIN_DIR="$HARDSHELL_HOME/bin"
BUILD_DIR="$HARDSHELL_HOME/build"
TODAY=$(date +%Y-%m-%d)
REPORT_DATE="${HARDSHELL_SCAN_DATE:-${2:-$TODAY}}"
HARDSHELL="${HARDSHELL_BIN:-/usr/local/bin/hardshell}"
HERMES_CONFIG="${HERMES_CONFIG:-$USER_HOME/.hermes/config.yaml}"
AGENT_REGISTRY_OUT="$BUILD_DIR/hardshell-agent-posture.json"
ENV_FILE="${HARDSHELL_ENV_FILE:-$USER_HOME/.env}"

usage() {
  echo "Usage: $0 {daily|weekly} [YYYY-MM-DD]" >&2
  exit 1
}

is_enabled() {
  local value="${1:-auto}"
  local auto_default="$2"
  # ${value,,} は bash 4+ 専用のため tr で小文字化 (macOS bash 3.2 互換)
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    auto|"") [[ "$auto_default" == "true" ]] ;;
    1|true|yes|on) return 0 ;;
    0|false|no|off) return 1 ;;
    *) echo "Invalid boolean/auto value: $1" >&2; exit 2 ;;
  esac
}

resolve_enabled() {
  if is_enabled "$1" "$2"; then
    echo true
  else
    echo false
  fi
}

[[ "$MODE" == "daily" || "$MODE" == "weekly" ]] || usage
[[ "$REPORT_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || {
  echo "Invalid report date: $REPORT_DATE (expected YYYY-MM-DD)" >&2
  exit 2
}

if [[ "$REPORT_DATE" == "$TODAY" ]]; then
  DEFAULT_CURRENT_RUN_MUTATIONS="true"
else
  DEFAULT_CURRENT_RUN_MUTATIONS="false"
fi

case "$MODE" in
  daily)
    SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy"
    OUTFILE="$REPORT_DIR/daily-${REPORT_DATE}.json"
    ANALYZE_ARGS=()
    ;;
  weekly)
    SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy,grype,lynis"
    OUTFILE="$REPORT_DIR/weekly-${REPORT_DATE}.json"
    ANALYZE_ARGS=(-a)
    ;;
esac

if [[ "${HARDSHELL_DRY_RUN:-}" =~ ^(1|true|yes|on)$ ]]; then
  echo "mode=$MODE"
  echo "today=$TODAY"
  echo "report_date=$REPORT_DATE"
  echo "outfile=$OUTFILE"
  echo "scanners=$SCANNERS"
  echo "current_run_mutations_default=$DEFAULT_CURRENT_RUN_MUTATIONS"
  echo "auto_fix=$(resolve_enabled "${HARDSHELL_AUTO_FIX:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS")"
  echo "delta_notify=$(resolve_enabled "${HARDSHELL_DELTA_NOTIFY:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS")"
  echo "status_report=$(resolve_enabled "${HARDSHELL_STATUS_REPORT:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS")"
  echo "metrics=$(resolve_enabled "${HARDSHELL_METRICS:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS")"
  echo "scratch_sync=$(resolve_enabled "${HARDSHELL_SCRATCH_SYNC:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS")"
  exit 0
fi

# 環境変数読み込み (cron 実行時は .env から通知設定を補完。値は出力しない)
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
fi

mkdir -p "$REPORT_DIR" "$BUILD_DIR"

# Hermes/MCP 実設定を secret 値なしの read-only registry JSON に正規化してから scan する
"$HARDSHELL" collect-hermes-registry \
  --hermes-config "$HERMES_CONFIG" \
  --env-file "$ENV_FILE" \
  --output "$AGENT_REGISTRY_OUT" || \
  echo "[$(date)] WARN: Hermes registry collection failed"

SUDO=()
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO=(sudo --preserve-env=PATH)
fi

echo "[$(date)] Starting $MODE scan for report_date=$REPORT_DATE..."
"${SUDO[@]}" "$HARDSHELL" scan \
  -s "$SCANNERS" -e "${ANALYZE_ARGS[@]}" -f json -o "$OUTFILE" -c "$CONFIG"

# 直前のレポート (今回生成分を除く) を特定して差分通知に使用
PREV_REPORT=$(ls -t "$REPORT_DIR"/${MODE}-*.json 2>/dev/null | grep -v "$OUTFILE" | head -1 || true)

if is_enabled "${HARDSHELL_AUTO_FIX:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS"; then
  echo "[$(date)] Running auto-remediation..."
  "${SUDO[@]}" "$HARDSHELL" fix \
    --execute --report "$OUTFILE" --tier auto -c "$CONFIG" || \
    echo "[$(date)] WARN: auto-remediation encountered errors"
else
  echo "[$(date)] Skipping auto-remediation for non-current/backfill report"
fi

# Discord 差分通知
if is_enabled "${HARDSHELL_DELTA_NOTIFY:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS"; then
  if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
    echo "[$(date)] Sending Discord notification..."
    "$HARDSHELL" notify "$OUTFILE" \
      ${PREV_REPORT:+--prev "$PREV_REPORT"} \
      --webhook "$DISCORD_WEBHOOK_URL" \
      -c "$CONFIG" || echo "[$(date)] WARN: Discord notify failed"
  else
    echo "[$(date)] DISCORD_WEBHOOK_URL not set — skipping notification"
  fi
else
  echo "[$(date)] Skipping delta notification for non-current/backfill report"
fi

# 毎回の状態サマリをDiscordへ送信（delta通知とは別。運用者向け定期レポート）
if is_enabled "${HARDSHELL_STATUS_REPORT:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS"; then
  "$BIN_DIR/discord-status.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: Discord status report failed"
else
  echo "[$(date)] Skipping status report for non-current/backfill report"
fi

# メトリクスを Pushgateway に送信
if is_enabled "${HARDSHELL_METRICS:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS"; then
  "$BIN_DIR/metrics.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: metrics push failed"
else
  echo "[$(date)] Skipping metrics push for non-current/backfill report"
fi

# project-scratch にサマリ反映
if is_enabled "${HARDSHELL_SCRATCH_SYNC:-auto}" "$DEFAULT_CURRENT_RUN_MUTATIONS"; then
  "$BIN_DIR/scratch-sync.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: scratch sync failed"
else
  echo "[$(date)] Skipping scratch sync for non-current/backfill report"
fi

# 90日超のレポートを自動削除（通常の当日実行時のみ）
if [[ "$DEFAULT_CURRENT_RUN_MUTATIONS" == "true" ]]; then
  find "$REPORT_DIR" -name "*.json" -mtime +90 -delete 2>/dev/null || true
  find "$REPORT_DIR" -name "*.md" -mtime +90 -delete 2>/dev/null || true
fi

echo "[$(date)] Scan complete: $OUTFILE"
