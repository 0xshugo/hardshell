# AI Agent Registry Schema

`hardshell` uses a read-only JSON registry to evaluate AI-agent security posture. The schema is intentionally vendor-neutral so Mythos-era agent runtimes, MCP servers, tools, and secrets can be inventoried without connecting hardshell to live control planes.

## Top-level object

```json
{
  "agents": [],
  "mcp_servers": [],
  "secrets": []
}
```

All sections are optional. Missing files are skipped; invalid JSON is reported by `agent-registry` as `AGENT-REGISTRY-INVALID-JSON`.

## `agents[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | recommended | Stable agent identifier. |
| `kill_switch` | boolean | yes | Whether an operator-controlled runtime stop mechanism exists and is tested. |
| `tools` | array | optional | Tools exposed directly to the agent. |

### `agents[].tools[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | recommended | Stable tool identifier. |
| `permissions` | array[string] | yes | Capability list, e.g. `read`, `write`, `execute`. |
| `scope` | string/object | recommended | Human-readable or structured scope boundary. |
| `approval_required` | boolean | recommended for write | Whether a human or policy gate is required before side effects. |
| `rollback` | boolean | recommended for write | Whether side effects can be reverted. |
| `write_exception` | object | optional | Explicit exception record for a governed write-capable tool. |

`write_exception` is accepted only when it contains all of the following controls:

```json
{
  "approved": true,
  "risk_accepted": true,
  "audit_log": true,
  "rollback": true,
  "scope": "narrow operator-approved target boundary",
  "approver": "security-owner-or-change-record"
}
```

Scanner coverage:

- `agent-registry`: `REQ-RUNTIME-001` — every autonomous agent must have a kill switch.
- `agent-registry`: `REQ-TOOL-001` — writable tools require explicit scope, approval, audit, and rollback controls; incomplete exceptions are still findings.

## `mcp_servers[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | recommended | Stable MCP server identifier. |
| `transport` | string | recommended | `stdio`, `http`, `sse`, `websocket`, or `streamable_http`. |
| `network_access` | boolean | recommended | Whether the server can reach network resources. |
| `domain_allowlist` | array[string] | required for network-capable servers | Explicit egress destinations. |
| `permissions` | array[string] | recommended | Capability list exposed by the MCP server. |
| `audit_log` | boolean | required for write | Whether tamper-evident audit logging is enabled. |

Scanner coverage:

- `tool-mcp`: `REQ-MCP-001` — network-capable MCP servers must define a non-empty domain allowlist.
- `tool-mcp`: `REQ-MCP-002` — write-capable MCP servers must confirm audit logging.

## `secrets[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | recommended | Stable credential identifier; do not put secret values here. |
| `storage` | string | yes | `keychain`, `vault`, `managed_secret`, `short_lived_token`, `plaintext`, `plaintext_env`, or `env_file`. |
| `scoped_to_agent` | boolean | yes | Whether credential use is bound to a specific agent/tool/environment. |
| `rotation_days` | integer | recommended | Maximum rotation interval. |
| `least_privilege` | boolean | recommended | Whether the credential is known to have minimized permissions. |

Scanner coverage:

- `secret-config`: `REQ-SECRET-001` — plaintext, `.env`, or file-based secrets are critical findings.
- `secret-config`: `REQ-SECRET-002` — non-plaintext credentials must be scoped to a specific agent context.

## Example

See [`examples/mythos-agent-registry.json`](../examples/mythos-agent-registry.json).
