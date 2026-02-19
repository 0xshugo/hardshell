# hardshell

VPS security hardening tool — scan, enrich with CTI, prioritize, remediate.

hardshell unifies multiple security scanners (Trivy, Grype, Lynis, Nuclei) with a built-in system checker, enriches findings using public threat intelligence (EPSS, CISA KEV), scores risks, and optionally generates AI-powered remediation plans.

## Features

- **Built-in system scanner** — OS packages, SSH config, firewall, fail2ban, Docker audit (no external tools required)
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
hardshell scan --format json --output report.json

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
```


## Operational Safety & Compatibility

Recent hardening changes improve reliability for personal VPS environments with limited resources:

- Scanner command execution avoids shell interpolation, reducing risk when handling user-provided targets.
- Nuclei runs only with valid `http/https` targets, preventing accidental malformed target execution.
- Optional LLM analysis now times out automatically, so scans do not block indefinitely.

These changes make rollout easier across a wider range of small VPS setups, including hosts with stricter runtime constraints or minimal operational buffers.

## Docker

```bash
docker build -t hardshell .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock hardshell scan
```

## Scanners

| Scanner | Type | Requires |
|---------|------|----------|
| system | Built-in | Nothing (always available) |
| trivy | Wrapper | `trivy` binary |
| grype | Wrapper | `grype` binary |
| lynis | Wrapper | `lynis` binary |
| nuclei | Wrapper | `nuclei` binary + target URLs |

## Requirements

- Python 3.12+
- Linux (primary target) / macOS (partial support)

## License

MIT
