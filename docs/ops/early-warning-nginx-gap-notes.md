# Early-warning: nginx 検知ギャップ修正計画 (NGINX2Root)

## 用語

- **NGINX2Root**: 公開境界の nginx を **コンテナ実体**（例: `factory-nginx`）と **ホスト root パッケージ**（存在すれば）の両面で棚卸しし、公式アドバイザリと突き合わせる残タスク群。PHP 専用の `watch` からの拡張。
- **GB-031 完了済み**: `collect_php()` の並列化・予算内完走（PR #39 @ `cd9cee4`）、`hardshell-watch` 15分間隔の安定稼働。

## 現状ギャップ（2026-11-19 実測）

| 領域 | 状態 |
|------|------|
| 公式取得 (`fetch_php`) | PHP のみ（`www.php.net`） |
| ランタイム棚卸し | `php -n` のみ。`factory-nginx` は `php_runtime_unverified` に埋没 |
| ケース生成 (`build_report`) | `product == "php"` 固定 |
| AI triage (`model_state`) | PHP 版・CVE 形式のみ外部送信可 |
| `PoliteSource.admit` | `www.php.net` ホストのみ許可 |
| ホスト nginx | Contabo 実機: バイナリなし（`factory-nginx` が 80/443 単独） |
| secfeed / trivy | 別経路（DB・イメージ CVE）。watch とは未連携 |

`build/early-warning.json` 例: `observed_runtimes` は coolify/freshrss の PHP のみ。`coverage_gaps` 51 件の大半は PHP 非搭載コンテナの想定内ギャップだが、**境界 nginx の版は一覧に出ない**。

## 目標（Green）

1. 公開反向き nginx（最低 `factory-nginx`）が `observed_runtimes` に `product: nginx` で載る。
2. nginx.org 公式アドバイザリと版比較で候補ケースを生成（承認待ち・非実行は PHP と同契約）。
3. 取得頻度・`PoliteSource` 予算を PHP と同等に nginx.org へ拡張。
4. 既存 PHP 経路の挙動・テストを退行させない。

## フェーズ

### Phase 1 — 棚卸し（本ブランチ着手）

- [x] `collect_nginx()` / `collect_runtime_inventory()`（コンテナ `nginx -v` + ホスト `nginx -v`）
- [x] `watch` のデフォルト inventory を統合コレクタへ切替
- [x] 単体テスト（モック docker）
- [ ] Contabo で `hardshell watch` 一回実行し `factory-nginx` 観測を確認（デプロイ後）

### Phase 2 — 公式 intel

- `intel/vendor_nginx.py`: `https://nginx.org/en/security_advisories.html` の bounded HTML 取得
  - CVE・Not vulnerable 版・影響範囲を構造化（公式に Atom/RSS なし）
  - `fetch_nginx()` → `advisories[]`（`product: nginx`）
- `PoliteSource`: 許可オリジンに `nginx.org`、日次/時間予算を PHP と同等に定義
- `watch`: `fetch_php` と `fetch_nginx` をマージした `intel`（`advisories` 結合、`gaps` 結合）

### Phase 3 — 突き合わせ・運用

- `build_report`: 製品ループ化（php + nginx）。nginx は mainline/stable の枝比較ルールを明文化
- `analysis/triage.model_state`: nginx 許可・外部送信は版と CVE のみ
- README / `hardshell-watch.service` コメント更新（対象製品に nginx を追記）
- Discord / secfeed 連携は **別タスク**（本ワースペース外の secfeed 実装に触れない）

### Phase 4 — 効率化（任意）

- コンテナごとの `docker inspect` を 1 回に集約（php+nginx プローブ共有）
- `coverage_gaps` の理由コードを製品別に整理（監視ノイズ低減）

## 非目標

- umwelt-mvp の `nginx2root` イメージタグやアプリ改修
- factory-nginx 設定変更・証明書・再起動
- nuclei/trivy スキャナ本体の差し替え

## 検証

```bash
cd /home/shugo/orca/workspaces/hardshell/vps-security-hardshell
uv run pytest tests/test_early_warning.py -q
uv run hardshell watch -o /tmp/early-warning-smoke.json
jq '.observed_runtimes[] | select(.product=="nginx")' /tmp/early-warning-smoke.json
```

成功条件: `factory-nginx`（または境界コンテナ）が `1.31.x` 等で観測され、PHP 観測が維持されること。