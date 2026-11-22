# VPS Guardian ランタイム境界

この Workspace（`vps-security-hardshell`）は単一 VPS のセキュリティ専任面です。他プロダクト実装は扱いません。

## 役割分担

| 役割 | 実行主体 | できること | 禁止 |
|---|---|---|---|
| 観測 | `shugo` + `hardshell-watch.timer` | Docker 読み取り、`hardshell watch`、early-warning 出力 | 修復コマンドの自動実行 |
| 計画 | 本 Workspace のエージェント | actionable の整理、差分案、承認待ちプレイブック | `/home` への破壊的書き込み、docker recreate |
| 修復 | 明示承認後の `shugo` 実行枠 | プレイブック記載の docker/image 更新と検証 | `orca-control` サンドボックスからの直接修復 |
| 通知 | watch プロセス（ルールベース） | Discord HIGH / digest（`build/state/discord.env` + drop-in `20-discord.conf`） | webhook 未設定時はスキップ（失敗にしない） |
| 監視 | Prometheus / Alertmanager + `hardshell-host-health.timer`（`orca-control`） | ルール評価と Discord 通知、ホスト・orca-server の健全性 push（[`monitoring.md`](monitoring.md)） | 収集器からの docker 実行・root 実行 |

## パス

| 用途 | パス |
|---|---|
| 本番ソース / venv / timer cwd | `/home/shugo/hardshell` |
| 本 Workspace（実装・レビュー） | `/var/lib/orca-control/workspaces/hardshell-security` |
| early-warning 出力 | `/home/shugo/hardshell/build/early-warning.json` |
| scan レポート（`bin/scan.sh`） | `/home/shugo/hardshell/reports/{daily,weekly}-YYYY-MM-DD.json` |
| orca-control 向け読み取り専用コピー | `/var/lib/hardshell-shared/`（下記） |
| 共有ヘルパ（root 所有コピー） | `/usr/local/libexec/hardshell/share-report`（元: `operations/share/hardshell-share-report.sh`） |
| 共有 drop-in | `/etc/systemd/system/hardshell-watch.service.d/50-share-report.conf` |
| 監視ルール（統合先） | `/home/shugo/services/aoi-system/monitoring/prometheus-alerts.yml`（元: `operations/monitoring/rules/`、手順: [`monitoring.md`](monitoring.md)） |
| host-health 収集器（root 所有コピー） | `/usr/local/libexec/hardshell/host-health-push`（元: `operations/monitoring/host-health-push.sh`） |
| 修復証跡 | `/home/shugo/hardshell/build/remediation/<date>-<cve>.json` |
| CTI feeds | `/home/shugo/services/secfeed`, `/home/shugo/services/secfeed-autonomous` |
| 公開エッジ | aoi-system `factory-nginx` |

## orca-control 向け共有ディレクトリ `/var/lib/hardshell-shared`

`orca-control` は `/home/shugo` 配下を読めない（ACL も付けない）。Orca オートメーション
（`hardshell-actionable-review` など）が本番の状態を見るための唯一の窓口がこのディレクトリ。

| ファイル | 内容 | 更新タイミング |
|---|---|---|
| `early-warning.json` | `build/early-warning.json` のコピー | watch 成功後（exit 0/2）の `ExecStartPost=+` |
| `daily-latest.json` / `weekly-latest.json` | `reports/` の最新日付レポートのコピー（元ファイル名は `.daily-source` / `.weekly-source`） | 同上（scan は cron なので最大 1 watch 周期遅れ） |
| `version.json` | 本番ツリーの git commit / branch / dirty、最後の watch の `SERVICE_RESULT` / `EXIT_STATUS` と時刻、各ファイルの共有結果 `share_results` | watch 毎回（失敗時も）の `ExecStopPost=+` |

- 1 ファイルの上限は `HARDSHELL_SHARE_MAX_BYTES`（既定 128 MiB）。本番の daily レポートは約 27 MB。
- `share_results` は最後の publish の結果。journal を読めない orca-control でもスキップ理由が分かる:
  - `{"status": "ok"}` — コピー済み
  - `{"status": "missing"}` — 元ファイルなし（例: `reports/weekly-YYYY-MM-DD.json` がまだ無い）
  - `{"status": "skipped", "reason": "too_large", "bytes": N, "max_bytes": M}` — 上限超過。古いコピーが残る場合があるので `shared_files` の時刻も確認する
  - `{"status": "skipped", "reason": "not_regular_file" | "unreadable" | "forbidden" | "write_failed"}`
  - `null` — まだ publish されていない（ヘルパ更新直後など）
- ディレクトリ `root:orca-control 0750`、ファイル `root:orca-control 0640`。shugo も orca-control も書き込めない。
- ヘルパは root で起動されるが、元ファイルは `setpriv` で shugo 権限に落として読む。シンボリックリンクは追わない。
- コピーは allowlist のみ。`build/state/`（Discord webhook）と `.env` / `provider.env`（AI 認証情報）は絶対にコピーしない。
- ヘルパ失敗は watch ユニットを失敗させない（`-` 接頭辞、常に exit 0）。

### セットアップ（オーナーが一度だけ）

```sh
# shugo として本番ツリーを更新
cd /home/shugo/hardshell && git pull --ff-only
# 内容を確認してから root で実行（冪等）
sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh --dry-run
sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh --run-now
```

`--with-journal` は `orca-control` を `systemd-journal` に追加する。これは **システム全体の journal**
（sshd, sudo, 全ユニット）を読めるようにするため既定では付けない。ロールバック手順はスクリプトの最後に表示される。
ヘルパ（`operations/share/hardshell-share-report.sh`）を更新したら、スクリプトを再実行して root 所有コピーを更新する。

> **ヘルパ変更の PR をマージした後（オーナー作業）**: ヘルパは `/usr/local/libexec/hardshell/share-report`
> に **コピーとして** インストールされているため、`git pull` だけでは本番に反映されない。必ず両方を実行する:
>
> ```sh
> cd /home/shugo/hardshell && git pull --ff-only
> sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh --dry-run
> sudo /home/shugo/hardshell/operations/grant-orca-readonly.sh --run-now
> ```
>
> 反映後、`/var/lib/hardshell-shared/version.json` の `share_results` が `null` でなくなっていることを確認する。

### precheck の判断

`operations/automations/precheck-actionable.sh` は `$HARDSHELL_EARLY_WARNING` →
`/var/lib/hardshell-shared/early-warning.json` → `/home/shugo/hardshell/build/early-warning.json` の順に読む。
Workspace の `build/early-warning.json` はプレースホルダなので使わない。

- 新しい（2 時間以内）レポートに actionable あり → exit 0（レビュー起動）
- 新しいレポートに actionable なし → exit 1（スキップ）
- 読めない / 壊れている / 2 時間より古い → exit 0（エージェントが「本番が見えない」を報告）

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
