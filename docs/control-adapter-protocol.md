# Hardshell Control Adapter Protocol (HCAP) v0.1

Status: draft implementation contract.

## Purpose

HCAP turns Hardshell into a security control plane that can coordinate with infrastructure owners without taking over their authority.

Core rule: Hardshell decides the required security state and preserves evidence; the system that owns the resource performs the change.

This allows Coolify, Docker, a host firewall, Cloudflare, Kubernetes, an application, or an AI-agent runtime to plug into Hardshell without giving Hardshell unrestricted root or platform-admin access.

## Control flow

Findings / CTI / policy -> RemediationIntent -> Adapter PLAN -> approval/policy gate -> provider-owned APPLY -> independent VERIFY -> evidence ledger.

Docker is a special case because control of a normal Docker daemon is root-equivalent. A Docker adapter should therefore be read-only by default. Mutating Docker state should normally be delegated to the owning platform such as Coolify or to a narrowly scoped local node agent.

## Contract objects

- ResourceRef: stable provider-owned resource identity.
- EvidenceRecord: observed state, source, time and optional digest/reference.
- RemediationIntent: provider-neutral desired security state; never an arbitrary shell command.
- ChangePlan: provider-specific steps, preconditions, risk, approval and rollback information.
- ExecutionReceipt: what the provider says happened. Queued is not automatically success.
- VerificationReceipt: independent readback after execution.

Timeout after a side effect begins must be represented as UNKNOWN until reconciled. It must not be converted to FAILED and blindly retried.

## Capabilities

Every adapter declares resource kinds and supported actions: OBSERVE, PLAN, APPLY, VERIFY, ROLLBACK. It also declares whether it can read secrets, change public exposure, change credentials, support idempotency keys or rollback.

Capabilities are descriptive, not authorization. Hardshell Business can further restrict them by RBAC, policy signature, environment, maintenance window and approval.

## Add-on packaging

Third-party packages register an adapter under the Python entry-point group hardshell.adapters. This creates an add-on ecosystem without modifying Hardshell Core.

Example package names:

- hardshell-adapter-coolify
- hardshell-adapter-docker
- hardshell-adapter-linux-firewall
- hardshell-adapter-cloudflare
- hardshell-adapter-kubernetes
- vendor-specific application adapters

## Security invariants

1. Observation access never implies write access.
2. APPLY is fail-closed unless explicitly implemented.
3. Secrets are referenced, not copied into Intent, Plan, Evidence or logs.
4. AI output never constitutes approval.
5. High-risk changes require fresh evidence and explicit approval.
6. Firewall, authentication, credential and public-exposure changes require independent readback.
7. Unknown external effects are reconciled before retry.
8. An adapter must not broaden its own privilege to satisfy an Intent.
9. Provider break-glass paths remain outside normal automation.
10. A clean scan is evidence of checks performed, not proof that a resource is secure.

## Initial adapter boundaries

### Coolify Adapter

Use the Coolify REST API with a team-scoped token and, for self-hosted Coolify, an API IP allowlist. Initial actions: observe application/service configuration and deployments, plan deploy/restart/config changes, apply only approved deploy/restart actions, then verify by resource/deployment readback. Secret values should not be returned merely because the token can technically access them.

### Docker Adapter

Initial mode: OBSERVE + PLAN + VERIFY. Observe daemon security options, daemon listeners, container privilege/namespace settings, docker.sock mounts, image digests/tags, networks, ports and mounts. Do not expose unrestricted APPLY through the normal Docker socket in the first product version.

### Linux Firewall Adapter

Runs locally on the workload host. It reads the current policy, renders a candidate delta, validates syntax, arms automatic rollback, applies atomically, verifies management-path reachability, then commits or rolls back. Firewall change risk is HIGH by default.

### Application Adapter

Applications opt in through a Hardshell Security Manifest and optionally a narrow application-owned security API. Examples include disabling Postiz registration, asserting an approved image digest, enforcing an expected hostname, disabling new agent dispatch, or reporting a security posture/version.

## Product split

### Hardshell Core / OSS

- HCAP schemas and SDK
- scanner framework
- local adapter discovery
- read-only observation
- local policy evaluation
- remediation plan generation
- evidence export
- community adapters

### Hardshell Business

- central multi-node inventory
- RBAC
- signed policy bundles
- approval workflows
- tamper-evident audit
- credential broker integration
- adapter allow/deny policy
- fail-closed execution orchestration
- maintenance windows
- staged/canary rollout
- fleet drift/compliance dashboards
- customer policy packs

The commercial value is governed, evidence-backed execution across heterogeneous infrastructure rather than proprietary scanner signatures alone.
