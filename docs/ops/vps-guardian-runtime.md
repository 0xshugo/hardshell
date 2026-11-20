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

- Coolify 再作成で埋め込み nginx が古いタグに戻る
- postiz など Debian 埋め込み nginx の追跡
- `orca-control` の docker.sock ACL は再起動で消える（恒久レシピ未整備）
