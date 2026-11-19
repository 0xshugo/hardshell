# 週次運用（Solo VPS Guardian）

## 毎週（自動 + 人間レビュー）

1. **フルスキャン**（既存 timer / 手動）
   ```bash
   cd /home/shugo/hardshell
   ./bin/scan.sh --enrich
   ```
2. **Discord weekly** — `bin/discord-status.sh build/reports/<latest>.json weekly`
3. **early-warning 残債**
   ```bash
   hardshell status
   jq '{status, actionable:(.cases|map(select(.status=="actionable"))|length), gaps:(.coverage_gaps|group_by(.reason)|map({reason:.[0].reason,count:length}))}' \
     build/early-warning.json
   ```
4. **残債レビュー**
   - Coolify 再作成で nginx が古いタグに戻っていないか
   - postiz 等の埋め込み nginx（local exposure）の更新方針
   - `coverage_gaps` が増えていないか

## 月次

- Business 仕様（`RemediationIntent` / receipt）との差分レビュー
- Discord webhook・timer drop-in・Orca automation `hardshell-actionable-review` の生存確認
