#!/usr/bin/env bash
set -euo pipefail

# hardshell scan wrapper — daily / weekly modes
# Usage: scan.sh daily | weekly

MODE="${1:-daily}"
HARDSHELL_HOME="/home/shugo/hardshell"
CONFIG="/home/shugo/.config/hardshell/config.toml"
REPORT_DIR="$HARDSHELL_HOME/reports"
BIN_DIR="$HARDSHELL_HOME/bin"
BUILD_DIR="$HARDSHELL_HOME/build"
DATE=$(date +%Y-%m-%d)
HARDSHELL="/usr/local/bin/hardshell"
HERMES_CONFIG="/home/shugo/.hermes/config.yaml"
AGENT_REGISTRY_OUT="$BUILD_DIR/hardshell-agent-posture.json"

# 環境変数読み込み (cron 実行時は .env から DISCORD_WEBHOOK_URL を補完)
ENV_FILE="/home/shugo/.env"
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

case "$MODE" in
  daily)
    SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy"
    OUTFILE="$REPORT_DIR/daily-${DATE}.json"
    echo "[$(date)] Starting daily scan..."
    sudo --preserve-env=PATH "$HARDSHELL" scan \
      -s "$SCANNERS" -e -f json -o "$OUTFILE" -c "$CONFIG"
    ;;
  weekly)
    SCANNERS="system,ssl,agent-registry,tool-mcp,secret-config,trivy,grype,lynis"
    OUTFILE="$REPORT_DIR/weekly-${DATE}.json"
    echo "[$(date)] Starting weekly scan (with LLM analysis)..."
    sudo --preserve-env=PATH "$HARDSHELL" scan \
      -s "$SCANNERS" -e -a -f json -o "$OUTFILE" -c "$CONFIG"
    ;;
  *)
    echo "Usage: $0 {daily|weekly}" >&2
    exit 1
    ;;
esac

# 直前のレポート (今回生成分を除く) を特定して差分通知に使用
PREV_REPORT=$(ls -t "$REPORT_DIR"/${MODE}-*.json 2>/dev/null | grep -v "$OUTFILE" | head -1 || true)

# AUTO ティアの自動修復を実行 (sudo 権限で)
echo "[$(date)] Running auto-remediation..."
sudo --preserve-env=PATH "$HARDSHELL" fix \
  --execute --report "$OUTFILE" --tier auto -c "$CONFIG" || \
  echo "[$(date)] WARN: auto-remediation encountered errors"

# Discord 差分通知
if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
  echo "[$(date)] Sending Discord notification..."
  "$HARDSHELL" notify "$OUTFILE" \
    ${PREV_REPORT:+--prev "$PREV_REPORT"} \
    --webhook "$DISCORD_WEBHOOK_URL" \
    -c "$CONFIG" || echo "[$(date)] WARN: Discord notify failed"
else
  echo "[$(date)] DISCORD_WEBHOOK_URL not set — skipping notification"
fi

# 毎回の状態サマリをDiscordへ送信（delta通知とは別。shugo向け定期レポート）
"$BIN_DIR/discord-status.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: Discord status report failed"

# メトリクスを Pushgateway に送信
"$BIN_DIR/metrics.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: metrics push failed"

# project-scratch にサマリ反映
"$BIN_DIR/scratch-sync.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: scratch sync failed"

# 90日超のレポートを自動削除
find "$REPORT_DIR" -name "*.json" -mtime +90 -delete 2>/dev/null || true
find "$REPORT_DIR" -name "*.md" -mtime +90 -delete 2>/dev/null || true

echo "[$(date)] Scan complete: $OUTFILE"
