#!/usr/bin/env bash
set -euo pipefail

# hardshell scan wrapper — daily / weekly modes
# Usage: scan.sh daily | weekly

MODE="${1:-daily}"
HARDSHELL_HOME="/home/shugo/hardshell"
CONFIG="/home/shugo/.config/hardshell/config.toml"
REPORT_DIR="$HARDSHELL_HOME/reports"
BIN_DIR="$HARDSHELL_HOME/bin"
DATE=$(date +%Y-%m-%d)
HARDSHELL="/usr/local/bin/hardshell"

mkdir -p "$REPORT_DIR"

case "$MODE" in
  daily)
    SCANNERS="system,trivy"
    OUTFILE="$REPORT_DIR/daily-${DATE}.json"
    echo "[$(date)] Starting daily scan..."
    sudo --preserve-env=PATH "$HARDSHELL" scan \
      -s "$SCANNERS" -e -f json -o "$OUTFILE" -c "$CONFIG"
    ;;
  weekly)
    SCANNERS="system,trivy,grype,lynis"
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

# メトリクスを Pushgateway に送信
"$BIN_DIR/metrics.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: metrics push failed"

# project-scratch にサマリ反映
"$BIN_DIR/scratch-sync.sh" "$OUTFILE" "$MODE" || echo "[$(date)] WARN: scratch sync failed"

# 90日超のレポートを自動削除
find "$REPORT_DIR" -name "*.json" -mtime +90 -delete 2>/dev/null || true
find "$REPORT_DIR" -name "*.md" -mtime +90 -delete 2>/dev/null || true

echo "[$(date)] Scan complete: $OUTFILE"
