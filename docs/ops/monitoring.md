# 監視とアラート（Prometheus / Alertmanager / Discord）

VPS 上の既存スタック（`task-prometheus` 127.0.0.1:9099、Alertmanager 127.0.0.1:9093、
Pushgateway 127.0.0.1:9091、Grafana、cadvisor）に対する HardShell 側のルールと収集器。
ファイルはすべて `operations/monitoring/` にある。

| ファイル | 役割 |
|---|---|
| `host-health-push.sh` | ホストと `orca-server.service` の状態を 60 秒ごとに Pushgateway へ PUT（job `host_health`） |
| `hardshell-host-health.service` / `.timer` | 上記を `User=orca-control`・ハードニング付きで 60 秒ごとに実行 |
| `rules/hardshell-alerts.yml` | `hardshell_alerts` グループ（既存グループを置換） |
| `rules/host-alerts.yml` | `host_health_alerts` グループ（追加） |
| `rules/tests/*.test.yml` | `promtool test rules` の単体テスト |
| `apply-monitoring.sh` | オーナーが sudo で実行するインストーラ（既定は dry-run） |
| `merge-alert-groups.py` | `--merge` 時に aoi-system のアラートファイルへグループを統合 |

## 通知先（Discord）

Alertmanager は `severity` ラベルだけでルーティングする。これ以外の値は Discord に届かない。

| severity | receiver | 再通知 |
|---|---|---|
| `critical` | `discord-critical` | 1 時間ごと |
| `warning` | `discord-warning` | 4 時間ごと |

ここにあるアラートはすべて `critical` か `warning` で、`summary` と、何をすればよいかと
このページへのリンクを書いた `description` を持つ（`tests/test_monitoring_rules.py` で強制）。

## 何を監視しているか

| 対象 | メトリクス | 出どころ |
|---|---|---|
| hardshell watch（25 分ごと） | `hardshell_watch_last_run_timestamp`, `hardshell_watch_cases_total{status}`, `hardshell_watch_feed_gaps_total`, `hardshell_watch_coverage_gaps_total`, `hardshell_watch_discord_failures` | `src/hardshell/watch_metrics.py`（job `hardshell_watch`） |
| スキャン（daily 06:00 / weekly 日曜 07:00） | `hardshell_findings_total{severity}`, `hardshell_kev_count`, `hardshell_epss_high_count`, `hardshell_scan_timestamp`（すべて `mode` ラベル付き） | `bin/metrics.sh`（job `hardshell`） |
| orca-server.service | `orca_server_pids_{current,max}`, `orca_server_pids_events_max_total`, `orca_server_memory_{current,anon,max}_bytes`, `orca_server_memory_events_{max,oom_kill}_total`, `host_health_orca_server_cgroup_readable` | `host-health-push.sh`（`/sys/fs/cgroup/system.slice/orca-server.service`） |
| ホスト | `host_rootfs_used_ratio`, `host_memory_available_ratio`, `host_load1` | `host-health-push.sh`（`df`, `/proc`） |
| systemd unit | `systemd_unit_active{unit}`（`hardshell-watch.timer`, `secfeed-monitor.timer`, `orca-server.service`, `docker.service`） | `host-health-push.sh`（`systemctl is-active`。timer は待機中も `active`） |
| 収集器自身 | `push_time_seconds{job="host_health"}` | Pushgateway が付与 |

### 廃止したアラート

`HardshellCriticalFindings` / `HardshellKEVExploit` / `HardshellHighEPSS` は件数の絶対値で
判定していた。本番は critical 約 376 件・KEV 7 件・EPSS-high 3〜8 件が恒常的にあるため常時発火し、
1 時間ごとに Discord を鳴らすだけで情報がなかった。24 時間前より増えたときだけ鳴る
`HardshellNewCriticalFindings` / `HardshellNewKEV` / `HardshellNewHighEPSS` に置き換えた。
件数そのものは Grafana と週次レビュー（`weekly-ops.md`）で見る。

## アラート一覧と対応

| アラート | 条件 | severity |
|---|---|---|
| HardshellWatchStale | `time() - hardshell_watch_last_run_timestamp > 5400`（または系列なし）5m | critical |
| HardshellActionableCase | `hardshell_watch_cases_total{status="actionable"} > 0` 1m | critical |
| HardshellDiscordNotifyFailing | `hardshell_watch_discord_failures > 0` 1m | warning |
| HardshellFeedGaps | `hardshell_watch_feed_gaps_total > 0` 1h | warning |
| HardshellCoverageGapsGrowing | coverage gaps が 24h 前より多い 30m | warning |
| HardshellScanStale | daily > 26h / weekly > 8d（mode ごとに判定） | warning |
| HardshellNewCriticalFindings | daily critical が 24h 前より 10 件超増加 | warning |
| HardshellNewKEV | daily KEV 件数が 24h 前より多い | critical |
| HardshellNewHighEPSS | daily EPSS-high 件数が 24h 前より多い | warning |
| HostHealthPushStale | `push_time_seconds{job="host_health"}` が 300s 超古い（または系列なし）2m | critical |
| OrcaServerCgroupUnreadable | cgroup ファイルを読めない 10m | warning |
| OrcaServerTasksNearLimit | pids / TasksMax > 0.8 5m（warning）、> 0.95 1m（critical） | warning / critical |
| OrcaServerTasksLimitHit | `increase(orca_server_pids_events_max_total[10m]) > 0` | warning |
| OrcaServerMemoryNearLimit | anon / MemoryMax > 0.85 10m | warning |
| OrcaServerOOMKill | `increase(orca_server_memory_events_oom_kill_total[10m]) > 0` | critical |
| OrcaServerMemoryNearHigh | anon / MemoryHigh > 0.9 10m | warning |
| OrcaServerMemoryThrottled | `increase(orca_server_memory_events_high_total[10m]) > 0` | warning |
| OrcaSessionsHigh | `orca_session_reaper_terminals > 12` 30m | warning |
| OrcaSessionReaperCloseFailures | `orca_session_reaper_close_failures > 0` | warning |
| OrcaSessionReaperStale | 最終実行から 1 時間超、またはメトリクス欠落 5m | warning |
| HostRootDiskHigh | / 使用率 > 0.85 10m（warning）、> 0.92 5m（critical） | warning / critical |
| HostMemoryAvailableLow | MemAvailable / MemTotal < 0.10 10m | warning |
| SystemdUnitInactive | `systemd_unit_active == 0` 5m（service は critical、timer は warning） | critical / warning |

### HardshellWatchStale

`hardshell-watch.timer` が 90 分（3 回分）報告していない。公式アドバイザリの照合が止まっている。

```bash
systemctl status hardshell-watch.timer hardshell-watch.service
journalctl -u hardshell-watch.service -n 50
```

`SystemdUnitInactive{unit="hardshell-watch.timer"}` も同時に出ていれば timer 停止、出ていなければ
サービスの失敗（タイムアウト・Pushgateway 到達不可）を疑う。

### HardshellActionableCase

公開資産が公式アドバイザリ対象のバージョンで動いている。`build/early-warning.json`
（orca-control からは `/var/lib/hardshell-shared/early-warning.json`）の `cases[] | select(.status=="actionable")`
を確認し、`operations/playbooks/` の該当プレイブックをオーナー承認のうえで実施する。
この Workspace から直接修復しない（`vps-guardian-runtime.md`）。

### HardshellDiscordNotifyFailing

watch 自身の Discord 通知（HIGH / digest）が失敗しているか webhook 未設定。Alertmanager 経由の
通知は別系統なので届いている。`jq .notification build/early-warning.json` と drop-in
`20-discord.conf` を確認する。

### HardshellFeedGaps

公式ベンダーフィードの取得失敗が 1 時間続いている。そのベンダーのアドバイザリは照合されていない。
`jq .feed_gaps build/early-warning.json` で対象と理由を確認する。一時的なネットワーク障害なら次回で消える。

### HardshellCoverageGapsGrowing

検証できない資産が 24 時間前より増えた（例: Coolify 再作成で nginx が古いタグに戻った）。
`jq '.coverage_gaps' build/early-warning.json` で一覧し、`weekly-ops.md` の残債レビュー手順に従う。

### HardshellScanStale

daily（26h 超）または weekly（8 日超）のスキャン結果が Pushgateway に届いていない。
mode ごとに括弧で独立判定しているので、ラベル `mode` を見ればどちらかわかる。root cron の
`bin/scan.sh` エントリと最新の `reports/<mode>-*.json` を確認する。

### HardshellNewCriticalFindings

daily スキャンの critical が前日より 10 件を超えて増えた（新イメージや CVE の一括公開が多い）。
今日と昨日の `reports/daily-*.json` を比較して新規分をトリアージする。閾値 10 は
`rules/hardshell-alerts.yml` で調整する。

### HardshellNewKEV

CISA KEV（悪用確認済み）に該当する finding が前日より増えた。最優先で確認する。

```bash
jq '.findings[] | select(.in_cisa_kev)' reports/daily-<date>.json
```

修正は `operations/playbooks/` 経由で計画する。

### HardshellNewHighEPSS

EPSS >= 0.7 の finding が前日より増えた。

```bash
jq '.findings[] | select((.epss_score // 0) >= 0.7)' reports/daily-<date>.json
```

### HostHealthPushStale

収集器のデッドマンスイッチ。これが出ている間は `host_health_alerts` の他のアラートはすべて盲目。

```bash
systemctl status hardshell-host-health.timer hardshell-host-health.service
journalctl -u hardshell-host-health.service -n 20
```

スクリプトは常に exit 0 で、失敗理由は journal に出る（`push to ... failed` なら Pushgateway 停止）。

### OrcaServerCgroupUnreadable

`/sys/fs/cgroup/system.slice/orca-server.service` を読めないので `OrcaServer*` が発火できない。
多くは orca-server.service の停止（その場合 `SystemdUnitInactive` も出る）。journal の理由を確認する。

### OrcaServerTasksNearLimit

orca-server.service のタスク（スレッド+プロセス）数が TasksMax に近い。上限に達すると新しい
スレッド・プロセスの生成が EAGAIN で失敗する（2026-11-23 に TasksMax=160 で 1070 回発生、当時は無警報）。
`systemctl status orca-server.service` で暴走しているエージェントを探し、正当な負荷なら drop-in で
TasksMax を上げる（現在 1024）。

### OrcaServerTasksLimitHit

`pids.events` の `max` が増えた。直近 10 分に fork/clone が実際に拒否された。原因を確認し、
TasksMax の引き上げを検討する。

### OrcaServerMemoryNearLimit

anon メモリが MemoryMax の 85% を超えている。page cache は回収可能なので `memory.current` ではなく
`memory.stat` の `anon` で判定する。MemoryMax に達するとサービス内で OOM kill が起きる。
大きいエージェントプロセスを特定し、MemoryMax（3G → 6G に引き上げ中）を検討する。

### OrcaServerOOMKill

`memory.events` の `oom_kill` が増えた。サービス内のプロセスがカーネルに kill された。
`journalctl -k | grep -i oom` と MemoryMax を確認する。

### OrcaServerMemoryNearHigh

anon メモリが MemoryHigh（drop-in `40-memoryhigh.conf`、5G）の 90% を超えた。超えるとカーネルがサービス内で
スロットリング・回収を始める。主因は開きっぱなしの Orca ターミナル。reaper の動作を確認し、不要なセッションを閉じる。

### OrcaServerMemoryThrottled

`memory.events` の `high` が増えた。MemoryHigh でスロットリングされている。MemoryMax（6G）で OOM kill される前に
アイドルなターミナルを閉じる。

### OrcaSessionsHigh

reaper 実行後も 12 を超えるターミナルが 30 分残っている。保護対象（`security-check-vps`、`aoi-broadcasting`）が多いか、
close が失敗している。

```bash
sudo journalctl -u orca-session-reaper.service -n 50
```

### OrcaSessionReaperCloseFailures

直近の reaper 実行で close に失敗したターミナルがある。上記ログと orca-server.service の状態を確認する。

### OrcaSessionReaperStale

reaper（`orca-session-reaper.timer`、15 分毎）が 1 時間以上 Pushgateway に push していない。古いセッションが閉じられず
メモリが増え続ける。

```bash
systemctl status orca-session-reaper.timer orca-session-reaper.service
```

### HostRootDiskHigh

ルートファイルシステムの使用率（`df` の Use% と同じ定義）が高い。92% を超えると critical。
`docker system df`、`/home/shugo/hardshell/reports` の古いレポート、`journalctl --vacuum-size` で空ける。
/ が埋まると Docker・Prometheus・journald が止まる。

### HostMemoryAvailableLow

ホスト全体の MemAvailable が 10% 未満。グローバル OOM killer が近い。`systemd-cgtop -m` と Grafana
の cadvisor ダッシュボードで大きい消費者を探す。

### SystemdUnitInactive

`systemctl is-active` が 5 分間 active でない。service（`orca-server.service`, `docker.service`）は
critical、timer（`hardshell-watch.timer`, `secfeed-monitor.timer`）は warning。
`systemctl status <unit>` と journal を見てから再起動する。timer は `systemctl list-timers` も確認する。

## インストール（オーナー、本番ツリーで）

```bash
cd /home/shugo/hardshell && git pull
sudo operations/monitoring/apply-monitoring.sh                  # 1. dry-run（何も変えない）
sudo operations/monitoring/apply-monitoring.sh --validate       # 2. promtool check + test
sudo operations/monitoring/apply-monitoring.sh --apply          # 3. 収集器 service/timer を導入
# 4a. ルール統合を手で行う場合: 3. の出力の "Manual merge" 手順に従う
# 4b. 自動で行う場合（差分確認 → 適用。YAML コメントは失われる、バックアップあり）
sudo operations/monitoring/apply-monitoring.sh --merge
sudo operations/monitoring/apply-monitoring.sh --apply --merge
curl -s http://127.0.0.1:9099/api/v1/rules | jq -r '.data.groups[].name'   # 5. 確認
```

注意:

- `prometheus-alerts.yml` は単一ファイルとして bind mount されている。`mv` や `sed -i` で置き換えると
  inode が変わり、コンテナは古い内容を見続ける。必ず同じファイルに書き込む（`cp new file`、vim/nano）。
  スクリプトの `--merge` は `cp` で上書きする。
- Prometheus は `web.enable-lifecycle=false` なので、リロードは `docker kill -s HUP task-prometheus`。
- ロールバック手順は `apply-monitoring.sh --rollback` で表示される。

## 既知のギャップ

- node_exporter がない。ディスク I/O、ネットワーク、ファイルシステム別の容量、inode、
  CPU steal は見ていない（host-health は / の使用率、MemAvailable、load1 のみ）。`host_load1` は
  記録だけでアラートはない（コア数に依存するため閾値未定）。
- cadvisor は `docker_only=true` なので、`orca-server.service` 以外の systemd サービスのリソースは見えない。
- 既存の `HighMemoryUsage`（container_alerts）はメモリ制限のあるコンテナにしか効かない。本 PR では
  aoi-system 側のグループは変更していない。
- MemoryMax / TasksMax が `max`（無制限）のときは `+Inf` を push するので、比率アラートは発火しない。
- 収集器の監視対象 unit は固定 4 つ。増やすときは `HOST_HEALTH_UNITS` を service の drop-in で設定する。
- `HardshellNew*` は 24h 前の値と比較するので、Prometheus 再起動直後や retention（15d）外の比較はできない。
  前日の値がないときは発火しない。

## 週次確認

`weekly-ops.md` の「アラート健全性」を参照（1 日以上発火し続けているアラートがないこと）。
