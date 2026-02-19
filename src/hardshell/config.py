"""TOML configuration loader."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATHS = [
    Path("hardshell.toml"),
    Path.home() / ".config" / "hardshell" / "config.toml",
    Path("/etc/hardshell/config.toml"),
]


class ScanConfig(BaseModel):
    """Configuration for a scan run."""

    scanners: list[str] = Field(
        default_factory=lambda: ["system"],
        description="Scanners to run (system, trivy, grype, lynis, nuclei)",
    )
    enrich: bool = Field(default=False, description="Enrich findings with CTI data")
    analyze: bool = Field(default=False, description="Run LLM analysis")
    format: str = Field(default="terminal", description="Output format")
    output: str | None = Field(default=None, description="Output file path")

    # Scanner-specific settings
    trivy_target: str = Field(default="/", description="Trivy scan target (rootfs or image)")
    nuclei_targets: list[str] = Field(
        default_factory=list,
        description="URLs for nuclei scanning",
    )
    docker_socket: str = Field(default="/var/run/docker.sock")


def load_config(config_path: Path | None = None) -> ScanConfig:
    """Load config from TOML file, falling back to defaults."""
    if config_path and config_path.exists():
        return _parse_toml(config_path)

    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return _parse_toml(path)

    return ScanConfig()


def _parse_toml(path: Path) -> ScanConfig:
    data = tomllib.loads(path.read_text())
    scan_data = data.get("scan", {})
    return ScanConfig(**scan_data)
