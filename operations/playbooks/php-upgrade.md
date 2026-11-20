# Playbook: PHP ランタイム脆弱性対応（approve_then_apply）

対象: early-warning の `product=php` かつ `status=actionable` または `status=potentially_affected`（例: `PHP 8.4.27` → `8.4.28`）。

制御モード: **recommend → 人間承認 → apply → verify → receipt**。自動 recreate しない。

## 1. 対象特定

```bash
jq '.cases[] | select(.product=="php" and (.status=="actionable" or .status=="potentially_affected"))' \
  /home/shugo/hardshell/build/early-warning.json
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
docker exec <name> php -n -v
# Debian 系イメージの場合はバックポート版も確認
docker exec <name> dpkg-query -W -f='${Package} ${Version}\n' 'php*-cli' 'libapache2-mod-php*' 2>/dev/null || true
```

記録する項目: `asset_id`, `installed`, `fixed`, `image_ref`, `exposure`, `advisory_id`（または代表 CVE 群）。

## 2. 差分案（recommend）

| 種別 | 例 | 確認ポイント / 推奨操作 |
|---|---|---|
| Debian ベース公開アプリ | `freshrss` (`freshrss/freshrss:*`, `exposure=public`) | `freshrss/freshrss` の更新版（または Debian `php8.4` セキュリティパッチ `8.4.28-*` / `deb13u*` バックポート有無）を確認し、イメージタグ更新 → `docker compose pull && docker compose up -d --force-recreate` |
| 上流 PHP 同梱アプリ | `coolify` (`coollabsio/coolify:*`, `docker-library/php`) | Coolify 公式リリース / 更新手順で `8.4.28` 以降を含むイメージへ更新し、再作成後も維持されることを確認 |
| 公式 `php:*` | `image_ref` が `php:` で始まる | パッチタグ（例 `8.4.28-fpm-alpine`）へ更新し recreate |

注意:
- Debian ビルド（`Built by Debian`）は上流バージョン番号が `8.4.27` のまま Debian 側でバックポート修正される場合があるため、適用前に `dpkg-query` / Debian Security Tracker でバックポート有無を切り分ける。
- `freshrss`（`0.0.0.0:8081`）のように公開リスナを持つ資産を最優先とする。

## 3. 承認ゲート

人間が Orca / Discord で承認するまで apply しない。承認ログに残す内容:

- 承認者
- 対象 `asset_id` と `advisory_id`
- 予定コマンド（そのまま実行する文字列）

## 4. 適用（shugo 実行枠のみ）

```bash
# 例: compose 管理サービスの場合（事前に compose / アプリ設定のタグ・バージョンを更新してから）
docker compose pull <service>
docker compose up -d --force-recreate <service>
```

Coolify 管理コンテナやアプリ本体は、各サービス定義・公式アップグレード手順に従う（`orca-control` から docker recreate しない）。

## 5. 検証

```bash
docker exec <name> php -n -v
docker exec <name> dpkg-query -W -f='${Package} ${Version}\n' 'php*-cli' 2>/dev/null || true
# 公開サービスの場合は HTTP 疎通も確認
curl -sI http://127.0.0.1:8081/ | head -5
```

`php -n -v` が `fixed` 以上（または Debian バックポート修正済みパッケージ）であること、およびサービス応答が正常であることを確認する。

## 6. 証跡

`operations/remediation-receipt.schema.json` に従い次へ保存:

`/home/shugo/hardshell/build/remediation/<YYYYMMDD>-<advisory_id>.json`

Discord には `要承認` / `完了` / `失敗` のいずれかで短文通知する。
