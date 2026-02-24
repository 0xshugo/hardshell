#!/usr/bin/env bash
set -euo pipefail

JSON_FILE="$1"
MODE="${2:-daily}"
PUSHGATEWAY="http://localhost:9091"

if [[ ! -f "$JSON_FILE" ]]; then exit 1; fi

CRITICAL=$(jq '.summary.critical' "$JSON_FILE")
HIGH=$(jq '.summary.high' "$JSON_FILE")
MEDIUM=$(jq '.summary.medium' "$JSON_FILE")
LOW=$(jq '.summary.low' "$JSON_FILE")
INFO=$(jq '.summary.info' "$JSON_FILE")
TOTAL=$(jq '.summary.total' "$JSON_FILE")

# EPSS/KEV enrichment (if available)
EPSS_HIGH=$(jq -r '[.findings[] | select(.epss >= 0.1)] | length' "$JSON_FILE" 2>/dev/null || echo 0)
KEV_COUNT=$(jq -r '[.findings[] | select(.in_cisa_kev == true)] | length' "$JSON_FILE" 2>/dev/null || echo 0)

# Status フラグ: 0=OK, 1=NG
if [[ "$CRITICAL" -gt 0 || "$HIGH" -gt 0 ]]; then
  STATUS=1
else
  STATUS=0
fi

SCANNER_METRICS=$(jq -r '
  [.findings[].scanner] | group_by(.) | map({ scanner: .[0], count: length })[] |
  "hardshell_scanner_findings_total{scanner=\"\(.scanner)\"} \(.count)"
' "$JSON_FILE")

SCAN_TS=$(jq -r '.timestamp' "$JSON_FILE" | xargs -I{} date -d {} +%s 2>/dev/null || date +%s)

{
  # Status
  echo "# HELP hardshell_status 0=OK, 1=Critical/High found"
  echo "# TYPE hardshell_status gauge"
  echo "hardshell_status $STATUS"

  # Total findings
  echo "# HELP hardshell_findings_sum Total number of findings"
  echo "# TYPE hardshell_findings_sum gauge"
  echo "hardshell_findings_sum $TOTAL"

  # Findings by severity
  echo "# HELP hardshell_findings_total Findings by severity"
  echo "# TYPE hardshell_findings_total gauge"
  echo "hardshell_findings_total{severity=\"critical\"} $CRITICAL"
  echo "hardshell_findings_total{severity=\"high\"} $HIGH"
  echo "hardshell_findings_total{severity=\"medium\"} $MEDIUM"
  echo "hardshell_findings_total{severity=\"low\"} $LOW"
  echo "hardshell_findings_total{severity=\"info\"} $INFO"

  # CTI enrichment metrics
  echo "# HELP hardshell_epss_high_count Findings with EPSS >= 0.1"
  echo "# TYPE hardshell_epss_high_count gauge"
  echo "hardshell_epss_high_count $EPSS_HIGH"

  echo "# HELP hardshell_kev_count Findings in CISA KEV"
  echo "# TYPE hardshell_kev_count gauge"
  echo "hardshell_kev_count $KEV_COUNT"

  # Scanner breakdown
  echo "# HELP hardshell_scanner_findings_total Findings by scanner"
  echo "# TYPE hardshell_scanner_findings_total gauge"
  echo "$SCANNER_METRICS"

  # Scan timestamp
  echo "# HELP hardshell_scan_timestamp Unix timestamp of last scan"
  echo "# TYPE hardshell_scan_timestamp gauge"
  echo "hardshell_scan_timestamp $SCAN_TS"
} | curl -s --data-binary @- "$PUSHGATEWAY/metrics/job/hardshell/mode/$MODE"
