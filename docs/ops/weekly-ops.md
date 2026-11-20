# 週次運用（Solo VPS Guardian）

## 毎週（自動 + 人間レビュー）

1. **フルスキャン**（既存 timer / 手動）
   ```bash
   cd /home/shugo/hardshell
   ./bin/scan.sh --enrich
   ```
2. **Discord weekly** — `bin/discord-status.sh build/reports/<latest>.json weekly`
3. **early-warning / Discord 通知健全性**
   ```bash
   hardshell status
   hardshell ops-check
   jq '{status, notification, actionable:(.cases|map(select(.status=="actionable"))|length), potentially_affected:(.cases|map(select(.status=="potentially_affected"))|length), gaps:(.coverage_gaps|group_by(.reason)|map({reason:.[0].reason,count:length}))}' \
     build/early-warning.json
   ```
4. **残債レビュー**
   - Coolify 再作成で nginx が古いタグに戻っていないか
   - postiz 等の埋め込み nginx（local exposure）の更新方針
   - PHP 搭載コンテナ（`freshrss` / `coolify`）が最新セキュリティリリース・Debian バックポートに追従しているか
   - `coverage_gaps` / `feed_gaps` や Discord 通知失敗（`notification.status`）が増えていないか

## 月次

- Business 仕様（`RemediationIntent` / receipt）との差分レビュー
- Discord webhook・timer drop-in・Orca automation `hardshell-actionable-review` / `hardshell-ops-monitor` の生存確認
