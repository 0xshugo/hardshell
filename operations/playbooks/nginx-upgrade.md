# Playbook: nginx 公開面アップグレード（approve_then_apply）

対象: early-warning の `product=nginx` かつ `status=actionable`（例: CVE-2026-123007 / NGINX2Root）。

制御モード: **recommend → 人間承認 → apply → verify → receipt**。自動 recreate しない。

## 1. 対象特定

```bash
jq '.cases[] | select(.product=="nginx" and .status=="actionable")' \
  /home/shugo/hardshell/build/early-warning.json
docker ps --format '{{.Names}}\t{{.Image}}' | rg -i nginx
docker exec <name> nginx -v
```

記録する項目: `asset_id`, `installed`, `fixed` / `fixed_versions`, `image_ref`, `exposure`, `advisory_id`。

## 2. 差分案（recommend）

| 種別 | 判定 | 推奨操作 |
|---|---|---|
| 公式 `nginx:*` | `image_ref` が `nginx:` で始まる | パッチタグ（例 `1.31.9-alpine` / `1.30.7-alpine`）へ recreate |
| カスタムイメージ | アプリ Dockerfile の `FROM nginx:` | FROM 更新 → rebuild → recreate |
| Coolify 埋め込み | Coolify 管理コンテナ | イメージ/パッケージ更新 + **再作成耐性**（再デプロイで古いタグに戻らないか）を確認 |

推奨タグは case の `fixed_versions` から選ぶ。同一メジャー系があればそれを優先し、なければ stable（偶数目）または mainline（奇数目）の floor。

## 3. 承認ゲート

人間が Orca / Discord で承認するまで apply しない。承認ログに残す内容:

- 承認者
- 対象 `asset_id` と `advisory_id`
- 予定コマンド（そのまま実行する文字列）

## 4. 適用（shugo 実行枠のみ）

公式イメージ例:

```bash
# 事前に compose/Coolify のタグ定義を更新してから
docker pull nginx:1.31.9-alpine
# サービス定義に従い recreate（例）
docker compose up -d --force-recreate <service>
```

カスタムイメージはリポジトリ側の Dockerfile 更新とビルドパイプラインに従う。

## 5. 検証

```bash
docker exec <name> nginx -v
curl -sI https://<public-host>/ | head -5
```

`nginx -v` が fixed floor 以上であること。公開 HTTPS が 5xx 連続でないこと。

## 6. 証跡

`operations/remediation-receipt.schema.json` に従い次へ保存:

`/home/shugo/hardshell/build/remediation/<YYYYMMDD>-<advisory_id>.json`

Discord には `要承認` / `完了` / `失敗` のいずれかで短文通知する。
