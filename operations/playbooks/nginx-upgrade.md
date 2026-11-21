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

### 4a. Coolify 管理コンテナのタグ固定（coolify-pin） {#coolify-pin}

**なぜ戻るか（2026-11-21 調査、読み取り専用 `docker inspect` のみ）**:
Coolify は再デプロイのたびに自身の DB 設定から `docker-compose.yaml` を再生成する。
`smoke-nginx`（`bh33te0uq2mxqlh48wj9bey3-*`, project `my-first-project`）は手動で
`nginx:1.31.9-alpine` に recreate 済みだが、Coolify 側の設定は浮動タグ `nginx:alpine` のまま。
ラベル `com.docker.compose.image` が指す image（`sha256:f0ba77f7…`）はローカルキャッシュの
`nginx:alpine` = **nginx 1.31.3**（2026-07 ビルド）。Coolify から再デプロイすると
pull されない限りこの古い image に戻り、CVE-2026-123007 の脆弱範囲に再突入する。

**検知**: `hardshell watch` が `coverage_gaps` に次を出す（watch は exit 2、`ops-check` は follow-up）。

- `coolify_recreate_reverts_nginx` — 再作成時の image の nginx が advisory の floor 未満。`fixed` が固定すべき最小タグ
- `coolify_recreate_image_unverified` — Coolify 管理 nginx だが再作成 image を特定できない

**人間の手順（Coolify UI。エージェントは実行しない）**:

1. Coolify UI → 対象 Project → Resource（gap の `coolify_resource`）を開く。
2. Docker Image 型アプリ: **General → Docker Image** を `nginx`、**Docker Image Tag** を
   gap の `fixed` 以上の明示パッチタグ（例 `1.31.9-alpine`）に変更。`alpine` / `latest` など浮動タグは使わない。
   Docker Compose 型 / Service: **Edit Compose File** の `image:` を同じ明示タグに変更。
   Dockerfile / Nixpacks 型: リポジトリ側の `FROM nginx:<明示タグ>` を更新して push。
3. 保存 → 承認ゲート（§3）を通した上で Coolify から **Redeploy**。
4. 任意: 古いキャッシュの再利用防止のため、承認済み枠で `docker pull nginx:alpine` 相当の更新か
   不要イメージ削除を行う（Coolify 側でタグ固定済みなら必須ではない）。
5. 検証: §5 に加え、`docker inspect --format '{{index .Config.Labels "com.docker.compose.image"}} {{.Image}}' <name>`
   の 2 値が一致し、次回 watch で `coolify_recreate_*` gap が消えていること。

Coolify 本体（`coollabsio/coolify`）の内蔵 nginx はイメージラベル `io.coolify.nginx.version`
（4.7.6 時点 `1.31.9-r1`）で追える。Coolify 本体のアップグレードは Coolify 自身の更新手順に従う。

### 4b. 非 nginx イメージに埋め込まれた nginx（postiz 等）

early-warning は全コンテナに `nginx -v` を試し、イメージ名が nginx でないものを
`packaging: "embedded"` として扱う。case には `check_distro_security_tracker` が先頭に付く。

- Debian 系パッケージは upstream 版番号のまま backport されるため、まず Debian security tracker
  で該当 CVE が `nginx` パッケージ版で修正済みか確認する（人間が `docker exec <name> dpkg -l nginx` で版確認）。
- 修正はアプリのイメージ更新（例 postiz `ghcr.io/gitroomhq/postiz-app` の新タグ）を Coolify の
  Service compose で明示タグに固定して redeploy（§4a と同じ手順）。
- 優先度は `exposure_context.summary` を見る: `public_listener` > `local_bind_behind_tunnel`（例: postiz は
  `127.0.0.1:8093` のみ公開、同一 compose project の cloudflared 経由で到達）> `local_only`。

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
