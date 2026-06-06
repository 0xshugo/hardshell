"""Collect a redacted, read-only hardshell agent registry from Hermes config."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

READ_ONLY_TOOLSETS = {"web", "search", "browser", "vision", "x_search", "session_search"}
WRITE_CAPABLE_TOOLSETS = {
    "terminal",
    "file",
    "computer_use",
    "cronjob",
    "discord",
    "discord_admin",
    "kanban",
    "todo",
    "skills",
    "github",
    "image_gen",
}
WRITE_TOOL_NAME_HINTS = (
    "write",
    "edit",
    "patch",
    "send",
    "create",
    "delete",
    "remove",
    "update",
    "execute",
)


def collect_hermes_registry(
    config_path: Path | None = None,
    env_path: Path | None = None,
    profile: str = "default",
) -> dict[str, Any]:
    """Return a vendor-neutral, secret-redacted registry for hardshell scanners.

    The collector only reads config metadata. It never includes header values, env
    values, API keys, or command arguments that may contain credentials.
    """
    config_path = config_path or Path.home() / ".hermes" / "config.yaml"
    payload = _read_yaml(config_path)
    toolsets = _collect_toolsets(payload)

    return {
        "schema_version": "hardshell.agent_registry.v1",
        "source": str(config_path.expanduser()),
        "agents": [_collect_agent(profile, toolsets, payload)],
        "mcp_servers": _collect_mcp_servers(payload),
        "secrets": _collect_env_secrets(env_path),
    }


def _read_yaml(path: Path) -> dict[str, Any]:
    path = path.expanduser()
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    return data if isinstance(data, dict) else {}


def _collect_agent(profile: str, toolsets: list[str], payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"hermes/{profile}",
        "kill_switch": True,
        "tools": [
            {"id": f"toolset:{name}", "permissions": _toolset_permissions(name)}
            for name in toolsets
        ],
        "approval_mode": _approval_mode(payload),
    }


def _collect_toolsets(payload: dict[str, Any]) -> list[str]:
    value = payload.get("toolsets") or payload.get("enabled_toolsets") or []
    if isinstance(value, dict):
        value = [name for name, enabled in value.items() if enabled]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _toolset_permissions(name: str) -> list[str]:
    normalized = name.lower()
    if normalized in READ_ONLY_TOOLSETS:
        return ["read"]
    if normalized in WRITE_CAPABLE_TOOLSETS:
        return ["read", "write"]
    return ["read"]


def _approval_mode(payload: dict[str, Any]) -> str:
    approvals = payload.get("approvals")
    if isinstance(approvals, dict):
        mode = approvals.get("mode")
        if mode:
            return str(mode)
    return "unknown"


def _collect_mcp_servers(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_servers = payload.get("mcp_servers", {})
    if not isinstance(raw_servers, dict):
        return []

    servers: list[dict[str, Any]] = []
    for server_id, server_config in raw_servers.items():
        if not isinstance(server_config, dict):
            continue
        servers.append(_collect_mcp_server(str(server_id), server_config))
    return servers


def _collect_mcp_server(server_id: str, server_config: dict[str, Any]) -> dict[str, Any]:
    url = str(server_config.get("url") or "")
    transport = _mcp_transport(server_config, url)
    permissions = _mcp_permissions(server_config)
    return {
        "id": server_id,
        "transport": transport,
        "network_access": transport in {"http", "sse", "streamable_http", "websocket"},
        "domain_allowlist": _domain_allowlist(server_config, url),
        "permissions": permissions,
        "audit_log": bool(server_config.get("audit_log", False)),
    }


def _mcp_transport(server_config: dict[str, Any], url: str) -> str:
    configured = server_config.get("transport")
    if configured:
        return str(configured)
    if url:
        return "streamable_http"
    return "stdio"


def _domain_allowlist(server_config: dict[str, Any], url: str) -> list[str]:
    configured = server_config.get("domain_allowlist")
    if isinstance(configured, list):
        return [str(item) for item in configured]
    if not url:
        return []
    host = urlparse(url).hostname
    return [host] if host else []


def _mcp_permissions(server_config: dict[str, Any]) -> list[str]:
    configured = server_config.get("permissions")
    if isinstance(configured, list):
        return sorted({str(item).lower() for item in configured})

    tools = server_config.get("tools")
    if isinstance(tools, dict):
        names = [str(name).lower() for name in tools]
        if any(any(hint in name for hint in WRITE_TOOL_NAME_HINTS) for name in names):
            return ["read", "write"]
    return ["read"]


def _collect_env_secrets(env_path: Path | None) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    if env_path is not None:
        candidates.append(env_path)
    else:
        candidates.extend([Path.home() / ".hermes" / ".env", Path.home() / ".env"])

    secrets: list[dict[str, Any]] = []
    for path in candidates:
        path = path.expanduser()
        if not path.exists() or not path.is_file():
            continue
        for name in _read_env_names(path):
            secrets.append(
                {
                    "id": name,
                    "storage": "env_file",
                    "scoped_to_agent": False,
                    "source": str(path),
                }
            )
        break
    return secrets


def _read_env_names(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name = stripped.split("=", 1)[0].removeprefix("export ").strip()
        if name and name.replace("_", "").isalnum():
            names.append(name)
    return names


def write_hermes_registry(
    output_path: Path,
    config_path: Path | None = None,
    env_path: Path | None = None,
    profile: str = "default",
) -> dict[str, Any]:
    registry = collect_hermes_registry(config_path=config_path, env_path=env_path, profile=profile)
    output_path = output_path.expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    import json

    output_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n")
    return registry
