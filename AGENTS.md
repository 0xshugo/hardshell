# VPS security Workspace rules

- この Workspace 以外でセキュリティ修復を始めない。
- 修復は承認付きプレイブックのみ（`operations/playbooks/`）。`orca-control` から docker recreate しない。
- 本業タスク・他プロダクト実装を持ち込まない。
- 観測は `hardshell watch` / early-warning。本番ツリーは `/home/shugo/hardshell`。
- 詳細: `docs/ops/vps-guardian-runtime.md`
