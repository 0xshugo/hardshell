# Mythos AI Agent Security Template

This template is a starting point for turning threat analysis into an auditable hardshell registry. Keep it free of secret values; record metadata, control decisions, and review evidence only.

## 1. Scope

- Runtime / project:
- Environment: `local` / `staging` / `production`
- Agents in scope:
- Human operators:
- External services and MCP servers:

## 2. Attack-side model

| Attack vector | Example | Primary asset | Expected control |
| --- | --- | --- | --- |
| Prompt / instruction injection | Malicious web page or RAG document changes agent goal | Agent, memory, tool call path | Source labeling, instruction hierarchy, tool approval |
| Tool abuse | Agent uses write-capable tool outside intent | Tool, MCP server, workspace | Least privilege, scope boundary, audit log, rollback |
| Credential theft | Token leaked through logs, prompt, browser, or file access | Credential | Secret store, scoped token, redaction, rotation |
| Runaway autonomy | Agent loops, spends budget, or executes unsafe plan | Runtime | Kill switch, budget limits, rate limits, human escalation |
| Supply-chain compromise | Plugin/MCP server/dependency is malicious | Tool, runtime | Version pinning, provenance, sandboxing, review |
| Data exfiltration | Agent sends sensitive local data to external service | Memory, files, network | Egress allowlist, data classification, DLP review |

## 3. Control requirements

| Requirement ID | Requirement | hardshell scanner |
| --- | --- | --- |
| `REQ-RUNTIME-001` | Every autonomous agent has an operator-controlled kill switch. | `agent-registry` |
| `REQ-TOOL-001` | Writable tools have explicit scope, approval, audit, and rollback controls. | `agent-registry` |
| `REQ-MCP-001` | Network-capable MCP servers have non-empty domain allowlists. | `tool-mcp` |
| `REQ-MCP-002` | Write-capable MCP servers have tamper-evident audit logging. | `tool-mcp` |
| `REQ-SECRET-001` | Agent credentials are not stored in plaintext or `.env` files. | `secret-config` |
| `REQ-SECRET-002` | Credentials are scoped to a specific agent/tool/environment context. | `secret-config` |

## 4. Registry workflow

1. Copy `examples/mythos-agent-registry.json` to a project-local registry file.
2. Add the path to `agent_registry_paths` in `hardshell.toml`.
3. Run:

```bash
hardshell scan --scanner agent-registry,tool-mcp,secret-config \
  --config hardshell.toml \
  --format json \
  --output build/hardshell-agent-posture.json
```

4. Review the JSON findings and update the registry or runtime controls.
5. Keep registry changes in code review with the same rigor as infrastructure changes.

## 5. Evidence checklist

- [ ] Kill switch has been tested and documented.
- [ ] Write-capable tools require approval or policy gates.
- [ ] MCP network egress has explicit domains and owners.
- [ ] Write-capable MCP calls include operator, agent, input, output, and approval context in logs.
- [ ] Credentials are stored in a managed secret store or OS keychain.
- [ ] Credentials are scoped and rotated.
- [ ] JSON scan output is stored as an immutable audit artifact for each review.
