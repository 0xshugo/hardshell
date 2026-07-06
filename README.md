# hardshell

VPS security hardening tool — scan, enrich with CTI, prioritize, remediate.

hardshell unifies multiple security scanners (Trivy, Grype, Lynis, Nuclei) with a built-in system checker, enriches findings using public threat intelligence (EPSS, CISA KEV), scores risks, and optionally generates AI-powered remediation plans.

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
# With uv (recommended)
uv pip install .

# With pip
pip install .

# Development
uv pip install -e ".[dev]"
```

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
