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
| scan レポート（`bin/scan.sh`） | `/home/shugo/hardshell/reports/{daily,weekly}-YYYY-MM-DD.json` |
| orca-control 向け読み取り専用コピー | `/var/lib/hardshell-shared/`（下記） |
| 共有ヘルパ（root 所有コピー） | `/usr/local/libexec/hardshell/share-report`（元: `operations/share/hardshell-share-report.sh`） |
| 共有 drop-in | `/etc/systemd/system/hardshell-watch.service.d/50-share-report.conf` |
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
| `version.json` | 本番ツリーの git commit / branch / dirty、最後の watch の `SERVICE_RESULT` / `EXIT_STATUS` と時刻 | watch 毎回（失敗時も）の `ExecStopPost=+` |

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

- Coolify 再作成で埋め込み nginx が古いタグに戻る
- postiz など Debian 埋め込み nginx の追跡
- `orca-control` の docker.sock ACL は再起動で消える（恒久レシピ未整備）
