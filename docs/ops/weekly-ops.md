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
   - Coolify 再作成で nginx が古いタグに戻っていないか（自動検知: `coverage_gaps[].reason=="coolify_recreate_reverts_nginx"` → `operations/playbooks/nginx-upgrade.md#coolify-pin`）
     ```bash
     jq '.coverage_gaps[] | select(.reason|startswith("coolify_recreate")) | {asset_id, reason, fixed, priority, blocks_status, exposure: .exposure_context.summary, networks: .exposure_context.networks, proxy: .exposure_context.proxy}' build/early-warning.json
     ```
     - `exposure_context.summary=="internal_only"`（ホストバインドなし・一致するプロキシなし）は `priority:"low"`, `blocks_status:false`。一覧には残るが watch exit 2 / `ops-check` follow-up にはならない。週次でタグ固定の要否だけ判断する（ルール: `nginx-upgrade.md` §4a）
     - `public_listener` / `proxy_routed` / その他は従来どおり follow-up 対象。follow-up 対象だけを見る:
       ```bash
       jq '[.coverage_gaps[] | select(.reason!="php_runtime_unverified" and .blocks_status!=false)] | length' build/early-warning.json
       ```
   - postiz 等の埋め込み nginx の更新方針（`packaging=="embedded"` の case。`exposure_context.summary` で `internal_only` / `local_only` / `local_bind_behind_tunnel` / `proxy_routed` / `public_listener` を確認）
     ```bash
     jq '.cases[] | select(.product=="nginx" and .packaging=="embedded") | {asset_id, installed, status, exposure_context}' build/early-warning.json
     ```
   - PHP 搭載コンテナ（`freshrss` / `coolify`）が最新セキュリティリリース・Debian バックポートに追従しているか
   - `coverage_gaps` / `feed_gaps` や Discord 通知失敗（`notification.status`）が増えていないか

## 月次

- Business 仕様（`RemediationIntent` / receipt）との差分レビュー
- Discord webhook・timer drop-in・Orca automation `hardshell-actionable-review` / `hardshell-ops-monitor` の生存確認
