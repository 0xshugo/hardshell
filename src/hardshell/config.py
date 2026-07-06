"""TOML configuration loader."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


class AllowlistEntry(BaseModel):
    finding_id: str = Field(description="Finding id, e.g. SYS-DOCKER-PRIV")
    affected: list[str] = Field(default_factory=list)
    reason: str = Field(default="")


class NotifyConfig(BaseModel):
    discord_webhook_env: str = Field(default="DISCORD_WEBHOOK_URL")
    min_severity: str = Field(default="high")
    delta_only: bool = Field(default=True)


class RemediateConfig(BaseModel):
    auto_enabled: bool = Field(default=True)
    maintenance_window: str = Field(default="02:00-05:00", description="Local time HH:MM-HH:MM")


DEFAULT_CONFIG_PATHS = [
    Path("hardshell.toml"),
    Path.home() / ".config" / "hardshell" / "config.toml",
    Path("/etc/hardshell/config.toml"),
]


class ScanConfig(BaseModel):
    scanners: list[str] = Field(
        default_factory=lambda: ["system"],
        description=(
            "Scanners to run (system, ssl, agent-registry, tool-mcp, "
            "secret-config, trivy, grype, lynis, nuclei)"
        ),
    )
    enrich: bool = Field(default=False)
    analyze: bool = Field(default=False)
    format: str = Field(default="terminal")
    output: str | None = Field(default=None)

    trivy_target: str = Field(default="/")
    nuclei_targets: list[str] = Field(default_factory=list)
    docker_socket: str = Field(default="/var/run/docker.sock")
    ssl_cert_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit cert paths; if empty, auto-discovers "
            "/etc/letsencrypt/live/*/fullchain.pem"
        ),
    )
    agent_registry_paths: list[str] = Field(
        default_factory=list,
        description="Read-only JSON registry files describing AI agents, tools, and controls",
    )

    allowlist: list[AllowlistEntry] = Field(default_factory=list)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    remediate: RemediateConfig = Field(default_factory=RemediateConfig)


def load_config(config_path: Path | None = None) -> ScanConfig:
    if config_path and config_path.exists():
        return _parse_toml(config_path)
    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return _parse_toml(path)
    return ScanConfig()


def _parse_toml(path: Path) -> ScanConfig:
    data = tomllib.loads(path.read_text())
    scan_data = dict(data.get("scan", {}))
    if "allowlist" in data:
        scan_data["allowlist"] = data["allowlist"]
    if "notify" in data:
        scan_data["notify"] = data["notify"]
    if "remediate" in data:
        scan_data["remediate"] = data["remediate"]
    return ScanConfig(**scan_data)
