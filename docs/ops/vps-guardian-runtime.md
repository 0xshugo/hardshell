# VPS Guardian ランタイム境界

この Workspace（`vps-security-hardshell`）は単一 VPS のセキュリティ専任面です。他プロダクト実装は扱いません。

## 役割分担

| 役割 | 実行主体 | できること | 禁止 |
|---|---|---|---|
| 観測 | `shugo` + `hardshell-watch.timer` | Docker 読み取り、`hardshell watch`、early-warning 出力 | 修復コマンドの自動実行 |
| 計画 | 本 Workspace のエージェント | actionable の整理、差分案、承認待ちプレイブック | `/home` への破壊的書き込み、docker recreate |
| 修復 | 明示承認後の `shugo` 実行枠 | プレイブック記載の docker/image 更新と検証 | `orca-control` サンドボックスからの直接修復 |
| 通知 | watch プロセス（ルールベース） | Discord HIGH / digest（`build/state/discord.env` + drop-in `20-discord.conf`） | webhook 未設定時はスキップ（失敗にしない） |

## パス

| 用途 | パス |
|---|---|
| 本番ソース / venv / timer cwd | `/home/shugo/hardshell` |
| 本 Workspace（実装・レビュー） | `/var/lib/orca-control/workspaces/hardshell-security` |
| early-warning 出力 | `/home/shugo/hardshell/build/early-warning.json` |
| 修復証跡 | `/home/shugo/hardshell/build/remediation/<date>-<cve>.json` |
| CTI feeds | `/home/shugo/services/secfeed`, `/home/shugo/services/secfeed-autonomous` |
| 公開エッジ | aoi-system `factory-nginx` |

## 制御モード

当面は `recommend` + `approve_then_apply` のみ。公開面の破壊的変更は人間承認必須。全体自動修復スイッチは持たない。

## AI

`hardshell-watch.service.d/10-x-hs-ai-less.conf` により `--ai` は無効。Typesafe 未整備の間はルールベースの深刻度判定と Discord 通知だけを使う。

## 残債（バックログ）

| 項目 | 状態 | 内容 |
|---|---|---|
| Coolify 再作成で埋め込み nginx が古いタグに戻る | **検知済み / 固定は人間作業待ち** | 原因: Coolify は再デプロイ時に DB 設定から compose を再生成する。`smoke-nginx` は Coolify 設定が浮動タグ `nginx:alpine`（ローカルキャッシュ = nginx 1.31.3）のまま。watch が `coverage_gaps` に `coolify_recreate_reverts_nginx` / `coolify_recreate_image_unverified` を出す。固定手順: `operations/playbooks/nginx-upgrade.md#coolify-pin`（Coolify UI でタグ固定 → 承認後 redeploy） |
| postiz など Debian 埋め込み nginx の追跡 | **対応済み** | 非 nginx イメージで `nginx -v` が応答した資産を `packaging: "embedded"` として case 化（`check_distro_security_tracker` 付き）。`exposure_context` に公開バインドと同一 compose project の cloudflared 有無を記録（postiz = `local_bind_behind_tunnel`, `127.0.0.1:8093`）。`nginx -v` が応答しないがイメージラベルが nginx 版を宣言する場合は `embedded_nginx_unverified` gap。追加の docker exec は無し。dpkg 版確認は playbook §4b で人間が行う |
| `orca-control` の docker.sock ACL は再起動で消える | **クローズ（ACL は冗長）** | 下記参照 |

### docker.sock アクセス（2026-11-21 確認）

- `/etc/group`: `docker:x:988:shugo,runner-user,orca-control` — `orca-control` は `docker` グループ所属（永続、再起動後も有効）。
- `getfacl /var/run/docker.sock`: `user:orca-control:rw-` — ACL は再起動で消えるが、ソケットは `root:docker 0660` で再作成されるためグループ経由のアクセスが残る。**ACL は冗長で、恒久化レシピは不要**。
- **注意: `docker` グループ所属は root 相当**（`docker run -v /:/host` 等で任意の root 操作が可能）。`orca-control` には本 Workspace の規約上、読み取り系（`docker ps` / `inspect` / `image inspect`）以外を許可しない。権限を絞りたい場合は `docker` グループから外し、読み取り専用の docker socket proxy（例: GET のみ許可）を検討する。
- グループ方式を避けて ACL を残す場合の恒久レシピ（参考、人間が root で設置）:
  ```ini
  # /etc/systemd/system/docker.socket.d/10-orca-control-acl.conf
  [Socket]
  ExecStartPost=/usr/bin/setfacl -m u:orca-control:rw /run/docker.sock
  ```
  `systemctl daemon-reload && systemctl restart docker.socket`。ACL 方式でも root 相当である点は同じ。
