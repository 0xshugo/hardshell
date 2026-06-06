import json
from pathlib import Path

from typer.testing import CliRunner

from hardshell.cli import app
from hardshell.collectors.hermes_registry import collect_hermes_registry


def test_collect_hermes_registry_maps_mcp_servers_without_secret_values(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    env_file = tmp_path / ".env"
    config.write_text(
        """
toolsets:
  - terminal
  - web
approvals:
  mode: manual
mcp_servers:
  secfeed:
    url: https://mcp.example.com/secfeed/mcp
    headers:
      Authorization: Bearer should-not-leak
  filesystem:
    command: npx
    args:
      - -y
      - '@modelcontextprotocol/server-filesystem'
    tools:
      write_file:
        enabled: true
""".strip()
    )
    env_file.write_text("DISCORD_WEBHOOK_URL=https://discord.example/webhook\nAPI_TOKEN=super-secret\n")

    registry = collect_hermes_registry(config_path=config, env_path=env_file)
    rendered = json.dumps(registry, sort_keys=True)

    assert "should-not-leak" not in rendered
    assert "super-secret" not in rendered
    assert registry["mcp_servers"][0] == {
        "id": "secfeed",
        "transport": "streamable_http",
        "network_access": True,
        "domain_allowlist": ["mcp.example.com"],
        "permissions": ["read"],
        "audit_log": False,
    }
    assert registry["mcp_servers"][1]["id"] == "filesystem"
    assert registry["mcp_servers"][1]["transport"] == "stdio"
    assert "write" in registry["mcp_servers"][1]["permissions"]
    assert {secret["id"] for secret in registry["secrets"]} == {"DISCORD_WEBHOOK_URL", "API_TOKEN"}
    assert all(secret["storage"] == "env_file" for secret in registry["secrets"])


def test_collect_hermes_registry_emits_agent_with_tool_permissions(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        """
toolsets:
  - terminal
  - file
approvals:
  mode: manual
""".strip()
    )

    registry = collect_hermes_registry(config_path=config)

    assert registry["schema_version"] == "hardshell.agent_registry.v1"
    assert registry["agents"][0]["id"] == "hermes/default"
    assert registry["agents"][0]["kill_switch"] is True
    tools = {tool["id"]: tool for tool in registry["agents"][0]["tools"]}
    assert tools["toolset:terminal"]["permissions"] == ["read", "write"]
    assert tools["toolset:file"]["permissions"] == ["read", "write"]


def test_collect_hermes_registry_cli_writes_json(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    output = tmp_path / "registry.json"
    config.write_text("toolsets:\n  - web\n")

    result = CliRunner().invoke(
        app,
        ["collect-hermes-registry", "--hermes-config", str(config), "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text())
    assert payload["agents"][0]["tools"] == [{"id": "toolset:web", "permissions": ["read"]}]
