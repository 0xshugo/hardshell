# hardshell

VPS security hardening tool — scan, enrich with CTI, prioritize, remediate.

hardshell unifies multiple security scanners (Trivy, Grype, Lynis, Nuclei) with a built-in system checker, enriches findings using public threat intelligence (EPSS, CISA KEV), scores risks, and optionally generates AI-powered remediation plans.

## Security Control Adapters (HCAP)

Hardshell can coordinate external control planes through the Hardshell Control Adapter Protocol. The core stays fail-closed: observation does not grant mutation, provider changes return typed receipts, and queued/ambiguous effects require independent readback before they become verified success.

Built-in reference: Coolify REST adapter. The same contract is designed for Docker read-only verification, local firewall executors, Cloudflare/Kubernetes adapters and application-owned security APIs.

Third-party Python packages can register adapters through the `hardshell.adapters` entry-point group. See `docs/control-adapter-protocol.md` and `docs/application-security-contract.md`.

## Features

- **Built-in system scanner** — OS packages, SSH config, firewall, fail2ban, Docker audit (no external tools required)
- **AI agent registry scanner** — Read-only checks for agent kill switches and writable tool exposure
- **MCP/tool posture scanner** — Network egress allowlists and audit logging for MCP servers
- **Secret config scanner** — Plaintext and unscoped credential metadata checks
- **External scanner wrappers** — Trivy, Grype, Lynis, Nuclei (auto-detected, graceful skip if missing)
- **Safer scanner execution** — Argument-based subprocess execution to reduce command injection risk from scan targets
- **Input hardening for web scans** — Nuclei targets are validated (`http/https`) before execution
- **Resilient AI analysis** — LLM (`claude -p`) analysis has a timeout to avoid long hangs on low-resource VPS
- **CTI enrichment** — EPSS exploit probability + CISA KEV known exploited vulnerabilities
- **Risk scoring** — Severity × exploit factor, prioritized output
- **LLM analysis** — Optional `claude -p` integration for contextual remediation advice
- **Multiple output formats** — Rich terminal, JSON, Markdown

## Install

```bash
# With pip
pip install .

# With uv (application only)
uv pip install .
```

## Development

Uses the same lockfile workflow as [CI](.github/workflows/ci.yml):

```bash
uv sync --all-extras
uv run ruff check src/ tests/
uv run pytest -v
```

Optional editable install without the lockfile: `uv pip install -e ".[dev]"`.

## Usage

```bash
# Full scan with all available scanners
hardshell scan

# System checks only
hardshell scan --scanner system

# Multiple scanners
hardshell scan --scanner system,trivy

# With CTI enrichment (EPSS + CISA KEV)
hardshell scan --enrich

# With LLM analysis (requires claude CLI)
hardshell scan --analyze

# JSON report
hardshell scan --format json --output build/reports/report.json

# AI-agent posture JSON artifact for review/audit
hardshell scan --scanner agent-registry,tool-mcp,secret-config \
  --config hardshell.toml.example \
  --format json \
  --output build/hardshell-agent-posture.json

# Markdown report
hardshell scan --format markdown --output report.md

# Show available scanners
hardshell status

# Show config
hardshell config
```

## Configuration

Copy `hardshell.toml.example` to one of:
- `./hardshell.toml`
- `~/.config/hardshell/config.toml`
- `/etc/hardshell/config.toml`

```toml
[scan]
scanners = ["system", "trivy", "grype"]
enrich = true
analyze = false
format = "terminal"

# Optional AI-agent registry manifests for read-only posture checks.
# Run with: hardshell scan --scanner agent-registry,tool-mcp,secret-config --config hardshell.toml
agent_registry_paths = ["./examples/mythos-agent-registry.json"]
```

Minimal agent registry format (see [`docs/agent-registry-schema.md`](docs/agent-registry-schema.md) and [`docs/mythos-agent-security-template.md`](docs/mythos-agent-security-template.md) for the full Mythos-era posture workflow):

```json
{
  "agents": [
    {
      "id": "mythos/orchestrator",
      "kill_switch": true,
      "tools": [
        {"id": "mcp:filesystem", "permissions": ["read"]}
      ]
    }
  ]
}
```


## Operational Safety & Compatibility

Recent hardening changes improve reliability for personal VPS environments with limited resources:

- Scanner command execution avoids shell interpolation, reducing risk when handling user-provided targets.
- Nuclei runs only with valid `http/https` targets, preventing accidental malformed target execution.
- Optional LLM analysis now times out automatically, so scans do not block indefinitely.

These changes make rollout easier across a wider range of small VPS setups, including hosts with stricter runtime constraints or minimal operational buffers.

## Cron Wrapper Scripts (`bin/`)

The wrapper scripts under `bin/` (daily/weekly scan, Discord status, metrics push, scratch sync) auto-detect their install location and the owning user, so no per-user paths need to be edited. Everything is overridable via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `HARDSHELL_HOME` | repo root (derived from script location) | Install directory (reports/build live here) |
| `HARDSHELL_USER` | owner of `HARDSHELL_HOME` | Operating user; used to resolve home-dir paths and to drop privileges from root cron |
| `HARDSHELL_CONFIG` | `<user home>/.config/hardshell/config.toml` | Config file passed to `hardshell scan` |
| `HARDSHELL_ENV_FILE` | `<user home>/.env` | Env file sourced for webhook URLs etc. |
| `HERMES_CONFIG` | `<user home>/.hermes/config.yaml` | Hermes config for the agent registry collector |
| `HARDSHELL_BIN` | `/usr/local/bin/hardshell` | hardshell executable |
| `HARDSHELL_AGENT_REGISTRY` | `$HARDSHELL_HOME/build/hardshell-agent-posture.json` | Agent posture registry read by `discord-status.sh` |
| `HARDSHELL_STATUS_WEBHOOK_URL` | *(unset = skip)* | Discord webhook for the always-on status report |
| `DISCORD_WEBHOOK_URL` | *(unset = skip)* | Discord webhook for delta notifications |
| `HARDSHELL_PUSHGATEWAY_URL` | `http://localhost:9091` | Prometheus Pushgateway endpoint |
| `AI_SCRATCH_DIR` | `<user home>/project/scratch` | Git repo that receives the security-status summary |

Note: paths are resolved from the script location and the owning user — not from `$HOME` — so the wrappers behave identically under `sudo`/root cron (where `HOME=/root`).

## Docker

```bash
docker build -t hardshell .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock hardshell scan
```

## Scanners

| Scanner | Type | Requires |
|---------|------|----------|
| system | Built-in | Nothing (always available) |
| agent-registry | Built-in | JSON registry path in config |
| tool-mcp | Built-in | JSON registry path in config |
| secret-config | Built-in | JSON registry path in config |
| trivy | Wrapper | `trivy` binary |
| grype | Wrapper | `grype` binary |
| lynis | Wrapper | `lynis` binary |
| nuclei | Wrapper | `nuclei` binary + target URLs |

## Requirements

- Python 3.12+
- Linux (primary target) / macOS (partial support)

## License

MIT

## 公式速報からの早期確認（改修候補）

`hardshell watch` はPHP公式のリリース配信とニュース配信を直接読み、
実稼働のPHP版と照合して承認待ちの候補を保存します。重大な公開予告はCVE番号がなくても候補化します。
現在の対象はPHPです。他の製品を公式速報で網羅しているとは扱いません。

```sh
hardshell watch -o build/early-warning.json
# Dockerを照会せず、観測済みの正規化JSONで確認する場合
hardshell watch --inventory build/runtime-inventory.json -o build/early-warning.json
```

このコマンドは更新・再起動・外部通知を実行しません。コンテナの名前とイメージID、
`php -n -r 'echo PHP_VERSION;'` の出力だけを照会し、Envやラベルは取り込みません。
PHPがPATHにないコンテナ、ホスト側や埋込みランタイムは未確認として残ります。
公式の版比較だけでは配布元のバックポートやWeb経路を確定できないため、
`potentially_affected` / `needs_evidence` を使い、`affected` やサーバ全体の保護完了を断定しません。
候補IDは資産・イメージ・導入版・アドバイザリに紐づきます。

`operations/systemd/` はローカル確認15分間隔です。PHPへの外部取得は各URLで最低1時間空けます。
提供ユニットは `--ai` を使いますが、有効なローカル予算と提供元の実残高確認がなければ推論しません。通知は無効です。
日次フルスキャンを置き換えるものではありません。

### JevとローカルLLMの助言

`--ai` と明示的な予算ポリシーが揃った場合だけ、`TYPESAFE_API_KEY` があればJevへ関連性を問い合わせ、
`HARDSHELL_LLM_URL`（loopbackのOpenAI互換`/v1` URL）と`HARDSHELL_LLM_MODEL` があれば
LLMへ追加確認を依頼します。Jevモデルは `HARDSHELL_JEV_MODEL` で指定できます。
実運転前に提供元・送信範囲・費用上限を確認してください。

外部に送るのはPHPの版、公開アドバイザリと観測状態に限定します。
サーバ名・コンテナ名・イメージID・秘密・生ログは送りません。
モデルの応答は64KiBと時間で制限し、提案手順は固定の選択肢だけ受け付けます。
API異常、曖昧さ、非該当というモデル回答でも既存候補を消したり優先度を下げたりしません。
モデル出力からshellを実行する経路はありません。

### スキャンの証拠状態

スキャン結果には `status` と `scanner_status` を追加しています。
Trivyの異常終了・不正/空レポート、要求したscannerの欠落は `partial` と終了コード2で報告し、
検出0件の成功として扱いません。古いレポートの既定状態は `legacy_unverified` です。

### 取得負荷と費用の制限

外部取得は永続SQLiteで、PHP公式ホスト全体をローリング1時間4回・24時間60回に制限します。
通常の2フィードは各URLで最低1時間＋0〜5分のジッター、リリース詳細は最低24時間空けます。
ETag/Last-Modifiedが返る場合に条件付き取得し、304なら保存済みの本文を再利用します。
429とRetry-After、5xx/通信障害はホスト単位の待機・指数バックオフ、401/403は自動再取得停止です。
再起動・並行実行・出力先変更では制限をリセットしません。停止中の旧情報は確認不足として扱います。
これは配信元が許容する頻度を保証するものではなく、この監視の内部上限です。
正常時も外部の新情報確認は概ね1時間以上間隔となり、5分以内の検知は保証しません。

AIの既定予算はゼロです。`build/state/ai/policy.json` がない、無効、破損、期限切れ、
価格未確定、モデル不一致の場合は外部AIを呼び出しません。
`operations/ai-policy.example.json` は無効状態の設定例で、自動適用しません。
UTCの日次/月次で両者の回数、Jevの入力トークン・金額、ローカルLLMの入出力予約枠を制限します。
Jevの出力は無料のため課金予約の対象外ですが、応答本文は64KiB以内に制限します。
同一の入力・モデル・ポリシー版は保存応答を再利用し、入力や根拠が変わった場合だけ再判定します。
予算切れやAI停止でもスクリプトによる検知・案件表示は継続します。

送信前に予算を原子的に予約し、失敗・タイムアウトでも予約を戻さず、同一要求を自動再送しません。
Jevは未検証のトークナイザー推計を使わず、公表64kコンテキストを切り上げた65,536入力トークンを
1回分として全量予約します。実usageが不明でも予約を維持し、契約超過が返れば以後停止します。
Jevは固定モデルと有効期限のある価格確認が必要です。金額枠は確認済み単価での予約枠であり、
提供元の実課金に対する保証ではありません。厳密な金額制限には提供元側の残高・上限も併用します。
確認済みフラグは送信許可の根拠にしません。TypeSafeの認証・モデル利用可否、実残高と期限付きクレジットを読み取り確認します。
残高は月額枠以上、数えたクレジットの期限は24時間以上必要です。通常は1時間間隔、未キャッシュ推論前は5秒以内の確認を要求します。
不足・認証切れ・取得失敗は1時間待機し、既存案件を保持したまま停止します。
`ai_readiness` に理由を保存し、`watch --ai` はAI利用不可の場合に終了コード3を返します。
残高確認はAPIキーのみではできません。本運用ではMac miniの専用保護ファイルにだけ
承認済みTypeSafeセッションを保管し、VPSには渡しません。継続確認はMac miniの
ログイン済みChrome内で、TypeSafeの請求情報を読む処理だけを実行します。
既存のループバックDevTools接続をTypeSafeタブに限定して使用し、毎回ログインと組織一致を確認します。
通常のセッション更新は許容し、別組織・複数の異なるセッション・ログアウトは停止します。
Mac miniの読み取り専用ブローカーは
Tailscale上のVPSだけに、残高・期限・確認時刻・APIキーフィンガープリントを署名して返します。
VPSは固定公開鍵と要求ごとのnonceを検証します。署名用秘密鍵もMac miniから出しません。
`HARDSHELL_FUNDING_URL=http://100.80.158.82:18537` と `build/state/ai/funding-public.pem` が設定箇所です。
`provider.env` は所有者だけ読める600とし、推論用APIキーだけを含めます。請求画面用cookieは含めません。
Mac miniやChromeの停止、タブのログアウト、期限切れ、認証拒否、形式変更、署名不正、
古い確認結果では有料AIを止めます。元のHTTPクライアントの認証停止状態は保持します。
Chrome経由にも同じ取得回数枠を適用し、認証拒否後の解除には実際のセッション再取り込みが必要です。
請求画面の読み取り専用アクションは非公開インターフェースのため、変更時の継続動作は保証できません。
組織の対応付けは運用者による確認が必要で、残高の専用確保や他アプリによる消費の防止を保証しません。
旧直接接続アダプターは明示設定時だけ利用可能で、本VPS構成では使用しません。
ローカルLLMは非課金のローカル実行を明示した設定のみ対応し、8KiB入力・256出力トークンまでです。
予算台帳には保守的に8192入力・500出力トークンを予約します。専用Ollamaコンテナは
CPU 1コア・メモリ3GiB・スワップなし・同時1件・VPSループバック11436番だけに制限します。
`operations/compose.cpu-llm.yml` と `operations/Modelfile.cpu` が再現用の定義です。
モデルの一覧取得と残予算確認には推論を使いません。実推論の成功は別途canaryで確認します。
ローカル入力トークン枠は保守的な予約枠で、GPU時間や電力の厳密な上限ではありません。
従来の `scan --analyze` にあった無制限のClaude CLI呼出しは停止し、週次結果には解析保留と表示します。

試算（30日、取得先PHPのみ）:
旧5分案は通常17,280リクエスト/月、保存済みXML 1,503,200 bytesを毎回取得すると展開後約13.0GB/月。
改修案は通常最大1,440リクエスト/月、ホスト全体の上限は1,800回/月相当（各24時間60回）。
304・圧縮なしで毎回200の場合の展開後データは通常約1.08GB/月で、実転送量は圧縮・304で変わります。
これはVPSの転送課金額やCPU使用量の実測ではありません。既存Secfeedの他フィードは別集計です。
設定例のJev最大100回/月は、全コンテキスト予約で6,553,600入力トークン、
2026-10-22確認の$0.042/M単価で約$0.276/月を上限目安とし、回数/トークン/金額の先着上限で止めます。
単価根拠: https://docs.typesafe.ai/models 。例の価格確認期限は2026-10-29で、期限後は再確認するまで停止します。
残高ブローカーは通常1時間に1回、未キャッシュ推論前は5秒以内の新しい結果を要求します。
取得試行は12回/時・60回/日に制限し、429のRetry-Afterと段階的待機を守ります。
初回・12時間経過時は同一ホストの請求ページと最大40個のJSも確認するため、
60試行/日はHTTP要求全体の60回制限ではありません。認証拒否後はセッション更新まで停止します。
この確認は推論トークンを使いません。Jevの残高・期限と日次/月次残枠を
`ai_readiness` に記録し、価格確認期限切れも利用不可として表示します。
利用不可でも検知レポートを書き、終了コード3で監視異常を示します。
