# HCAP v0.2 — Executor Security Contract

Status: reference verifier and bounded dispatcher implemented; not a production executor daemon.
Baseline: Hardshell Control Adapter Protocol v0.1.
Reference deployment: Coolify-owned AOIFUTURE Postiz.

## Assurance ownership

Hardshell does not certify itself. Each trust boundary has a separate owner:

| Requirement | Authority |
| --- | --- |
| Risk findings, proposed change | Hardshell Core and policy engine |
| Human/policy authorization | Hardshell Business, organization IdP |
| Plan signing | Business plan-signing key |
| Approval signing | Separate approval-authority key |
| Trusted keys, allowed operations | Executor operator / out-of-band provisioning |
| Process isolation and software provenance | Linux, systemd, package/image control |
| Actual provider mutation | Minimal platform-owned executor |
| Replay/crash safety | Executor-local durable ledger |
| Final verification | Provider readback and independent Docker/host observation |
| Evidence retention | External tamper-evident audit system |

Root or Docker daemon compromise cannot be contained by Hardshell alone.

## Signed request and protocol

Request format: SignedExecutorPlan = AuthorizedPlan + plan_signature + approval_signature.

The plan binds schema_version, tenant, environment, executor ID, plan ID, nonce,
adapter ID, resource kind, exact resource ID, typed operation, parameter values,
local policy SHA-256, observed-state SHA-256, approval ID, issuance and expiration.
Unknown fields and unexpected operations are refused.

Ed25519 is used for plan and approval signatures. Signatures use two different
public keys with separate key roles, enrolled locally. Both cover the entire
normalized plan. The normalized form is UTF-8 JSON produced by Pydantic's
model_dump(mode=json), sorted keys, compact separators, UTF-8 strings and NaN
rejection. Different domain-separator prefixes prevent purpose confusion.

This is VERSIONED deterministic JSON, not RFC 8785/JCS. Cross-language
implementations require conformance fixtures for the exact v0.2 encoding.

The approval_id is an audit reference, not approval evidence in isolation.
Business must verify RBAC, identity, approval scope, and separation of duties
BEFORE its independent approval authority signs. AI output is never approval.

## Local executor decision

1. Fetch fresh provider-owned evidence from inside the executor boundary.
2. Check plan target tenant, environment, executor ID and locally pinned policy digest.
3. Check time skew and expiration. Default maximum lifetime: 300 seconds.
4. Compare precondition evidence digest to fresh observed state; drift => deny.
5. Apply local exact allowlist for resource ID, adapter, operation and argument values.
6. Verify two valid unrevoked Ed25519 public keys with different trust roles.
7. Resolve a finite, locally installed typed operation handler (no arbitrary shell).
8. Reserve plan ID and nonce atomically in persistent SQLite BEFORE side effects.
9. Execute once. Persist ACCEPTED or UNKNOWN, never SUCCEEDED from API acceptance.
10. Require independent provider/container readback for final verification.

The replay DB directory must be mode 0700 and the DB file 0600, with durable
local storage. A process crash after replay claim means the plan is consumed
and the external effect UNKNOWN until reconciled. Never auto-retry.

If the ledger is unavailable, refuse mutation. A scanner failure does not
turn a denied request into an allowed one.

## Coolify reference

The previous CoolifyAdapter allow_apply=True direct mutation path is closed.
The observer can still read, plan, and verify.

The separate CoolifyWriteHandler owns the write token ONLY within the executor
process and supports a finite set of operations: deploy or restart an exact
enrolled application UUID, with exact parameter schema.

Default transport requires HTTPS. Private HTTP must be explicitly authorized
over an otherwise authenticated encrypted management network. API response
acceptance is not proof of deployed state, image digest, or health.

## Who protects the executor itself?

The host operator owns and secures the executor process; the security control
plane cannot grant itself root authority.

Production runtime requirements:
- reproducible provenance and image/binary digest pinning;
- OS operator-owned runtime and configuration, inaccessible to AI/writer identities;
- dedicated unprivileged identity and minimal privileged helper for host changes;
- systemd sandbox/no-new-privileges plus seccomp and AppArmor/SELinux as available;
- no generic Docker socket access;
- managed secret references with least-privilege provider tokens;
- locally pinned trust roots, key rotation and revocation;
- protected filesystem for replay ledger and local policies;
- private management ingress and restricted egress;
- remote audit replication, alerts and incident freeze;
- separate verifier readback after effect.

v0.2 DOES NOT YET IMPLEMENT TPM/vTPM attestation, IMA appraisal, secure boot
measurement validation, or a hardened network-facing executor daemon.
Software self-report is not attestation. Compromised host root can subvert a
local verifier; genuine runtime attestation needs a trust anchor outside the host.

## Deployment and SLA gates

Unit tests establish fail-closed behavior and replay semantics but do not
prove production safety. Do not deploy privileged Executor solely on this basis.

Go-live must additionally prove: exact resource enrollment, separated keys,
signed policy provisioning, executor sandbox, canary/rollback, audit delivery,
actual Coolify and Docker readback, firewall isolation, backup recovery, and
incident key-revocation handling.

Postiz G2 remains blocked by the separate upstream image vulnerability findings.
