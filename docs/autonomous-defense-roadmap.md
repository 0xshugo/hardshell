# Hardshell Autonomous Defense — Open-Core Roadmap (proposal)

Date: 2026-11-07  
Status: **Roadmap proposal; no new runtime capability is claimed or enabled by this document.**  
Scope: public Hardshell OSS. The companion commercial service is out of scope of this repository.

## 1. North star and non-goals

**North star:** shorten the interval between observable threats and **verified, safe containment** without requiring a human to authorize every routine event. Preserve human ownership of policy and high-impact exceptions.

This is not simply a CVE/CVSS/NVD scanner. Vulnerability and advisory feeds (including KEV and EPSS) are **context**, not proof of an ongoing attack; the runtime loop must use observations from the assets being protected.

Principles:
- **Fast loop:** low-latency, deterministic policy enforcement for predeclared agent/tool/resource actions, independent of LLM availability.
- **Adaptive loop:** correlate threat intelligence, local signals and outcomes; propose new detection rules/containment recipes; verify before activation.
- **Human governance:** no AI self-approval, no policy/capability escalation, and no unattended high-impact or unknown action.
- **Evidence-first:** prove what was observed, which decision was applied, what the provider actually did and what was independently verified. Lack of evidence is not success.
- **Useful OSS:** a single operator must be able to observe, test, enforce safe local controls and export evidence without a paid control plane.

Non-goals for the first release: replacing XDR/EDR; claiming zero-day prevention; general-purpose root execution; autonomous credential rotation/firewall modifications; production red-team/attack execution; mandatory cloud SaaS.

## 2. Baseline: implemented, design-only, and missing

| Domain | Baseline at 2026-11-07 | Gap |
| --- | --- | --- |
| Host/container and AI-agent posture | Built-in and wrapper scanners; read-only agent-registry, MCP and secret-config checks | Live agent/tool-call telemetry |
| Public CTI | CVE-related scanning, EPSS/CISA KEV enrichment; early-warning watch currently scoped to PHP | Event-level exposure/attack correlation, source freshness and unknown coverage |
| HCAP | Adapter contract; signed bounded executor **reference** with replay barrier and narrow Coolify handler | Independently deployed hardened executor, multi-resource concurrency and verified production effects |
| Policies/evidence | Local evidence export, local policy/receipt concepts | Common event schema, replayable validation, independent observation outside agent self-report |
| Red/Blue assurance | Research proposal (ASVF) | Reproducible defensive unit/integration/negative tests |

Existing production-safety work is tracked in [#23](https://github.com/0xshugo/hardshell/issues/23), [#24](https://github.com/0xshugo/hardshell/issues/24), [#25](https://github.com/0xshugo/hardshell/issues/25), [#26](https://github.com/0xshugo/hardshell/issues/26) and [#27](https://github.com/0xshugo/hardshell/issues/27). Do not duplicate or bypass those gates.

## 3. Architecture and trust boundaries

```text
Asset/runtime telemetry + feeds (CVE/KEV/EPSS) + posture
         │     observe + provenance + freshness
         ▼
Normalized events / asset references / evidence ledger
         │
         ├── FAST: local deterministic policy decision
         │          → agent/MCP tool-call guard → ALLOW/DENY/PAUSE
         │          → local auditable outcome
         │
         └── ADAPT: correlate/suggest response candidates
                    → typed HCAP RemediationIntent and ChangePlan
                    → approved mandate/capability/expiry/budget gate
                    → owner-operated narrow Executor (when qualified)
                    → independent readback and evidence
                    → ASVF-like regression/negative tests
                    → new policy ONLY after authorized rollout
```

Critical separation:
1. Sensors and LLMs are **untrusted evidence/proposal producers**, never authorization sources.
2. A tool-call policy enforcement point checks **before** effectful tools run; denying a log event after execution is not protection.
3. Core does not obtain implicit write access to the Docker daemon. Observation never implies APPLY.
4. No policy may delegate creation of new privileges or approval to the agent it governs.
5. Execution states are PROPOSED, DENIED, AUTHORIZED, ACCEPTED, UNKNOWN, VERIFIED, FAILED, ROLLED_BACK (not interchangeable); API HTTP success is not verified containment.
6. Fast loop stays functional without network, cloud AI or threat feeds for locally installed policies; missing feeds are marked stale/unknown.

## 4. OSS vs commercial boundary

| OSS (auditable and self-hosted) | Commercial control plane (separate product) |
| --- | --- |
| Scanner/CTI and single-environment posture | Multi-tenant, multi-node asset graph and cross-signal correlation |
| Event/evidence schemas; OpenTelemetry/OCSF mappings | Centralized evidence custody, retention and compliance/reporting |
| Deterministic policy and reference local guard | Organization-scoped policies, RBAC, separation of duties, delegated authority |
| HCAP models, SDK, limited adapters and narrow executor *reference* | Signed mandate distribution, approval and revocation workflow |
| Local scenario runner, defense-regression tests and signed/exportable receipts | Governed rollout, canary/rollback across fleets, support/SLA |
| Safe single-node opt-in examples when acceptance gates pass | Managed intelligence/update packs and licensed enterprise features |

The contract must remain portable: Business may orchestrate the OSS enforcement point, but it must never make an unsafe OSS enforcement point safe merely by adding a license.

## 5. Milestones and implementation tickets

Milestones are **ordered gates**, not calendar promises. Each feature is disabled for production until its release gate passes.

### O0 — Contract freeze and threat model (documentation only)

- Define assets, principals, signals, access boundaries, trust anchors and safe action classes.
- Version schemas for `SignalEvent`, `ThreatHypothesis`, `PolicyDecision`, `ContainmentIntent`, `ExecutionReceipt` and `VerificationReceipt`. Reuse HCAP structures, not an incompatible parallel action API.
- Tag event source, time, signer/observer identity, integrity, freshness, missing coverage and redaction status.
- Align fields with OpenTelemetry and OCSF where applicable; map AI agent tool controls to OWASP ACS as an optional, version-pinned adapter.

**Exit:** reviewed schema with backward-compatibility rules, abuse cases, source-freshness semantics, and a public OSS/commercial boundary.

### O1 — Observe-only live telemetry and trustworthy detection inputs

- Add opt-in adapters for agent lifecycle/tool-call requests and results (test harness first); normalized event ingestion from application security manifests.
- Join runtime signals to known assets and contextual CTI without treating CVE presence as live compromise.
- Support event deduplication, clock-skew tolerance, bounded queues/retention, backpressure and redaction.
- Emit explicit `unobserved`, `stale` and `partial` coverage states.

**Exit:** synthetic/replayed traces produce reproducible evidence; source drop and forged/untrusted event cases cannot become a clean safety verdict. No external data exfiltration, real credentials or live mutation.

### O2 — Fast deterministic guard for AI/MCP tools

- Implement reference `authorize_tool_call` / `deny` / `pause_dispatch` interfaces at a **pre-execution** enforcement point; use application-owned hooks, not an arbitrary shell.
- Exact tool/resource/argument allowlists, per-agent identity, local kill switch, immutable default-deny and authorized exception rules.
- No LLM calls, prompts or remote control plane in the critical authorization path. On policy failure, block effectful operations while retaining read-only logging.
- Separate observer from enforcement; collect externally verifiable tool outcomes.

**Exit:** scenario A (permitted operation continues), B (unapproved dummy file read is denied before the effect) and C (policy engine unavailable: fail closed) pass with evidence, plus bypass and concurrency negative tests; normal task impact is measured.

### O3 — HCAP bounded single-resource response reference

- Introduce a finite typed `pause_new_agent_dispatch` or equivalent app-owned reversible control with TTL, scope, explicit operator opt-in and independent restore/readback.
- Wire `RemediationIntent → PLAN → authority gate → executor → VERIFY` with current HCAP types and idempotency/UNKNOWN semantics.
- Do not use broad Docker socket/root/SSH from the planner. A lab reference is **not** approval for production.
- Reuse #23/#25 (executor hardening), #24/#26 (lease/TOCTOU/readback), #27 (provenance) as release dependencies.

**Exit:** fault injection (timeout, concurrent request, restart, stale state, revoked key, rollback failure) produces safe DENY/UNKNOWN/escalation; no unintended changes outside the exact target. Production APPLY remains disabled until executor gates pass.

### O4 — ASVF-compatible evidence and regression pack

- Establish versioned normal/adversarial/failure tests for control efficacy, false containment, recovery and independent readback.
- Package benchmark metadata (scenario, model/tool versions, seed, policy digest, action traces, verdict basis, limits) while keeping secrets out.
- Separate formal/policy invariants from statistical outcome estimates. Do not derive a universal safety score from zero observed failures.

**Exit:** reproducible offline CI with tamper/observer-failure tests; machine-readable output; independent reviewer can reconstruct why a response was allowed/denied/verified.

### O5 — OSS release readiness

- Document safe defaults, installation and opt-in, restricted privileges, runtime budgets, incident recovery, supported integrations and upgrade/migration.
- Lint/test/SBOM/lockfiles/code review, adversarial validation of public interfaces and clear published limitations.
- Maintain distinction between `reference`, `lab-validated`, `staging-validated` and `production-supported`.

**Exit:** a single-host user can reproduce observe → local guard → evidence and (only when gated) a narrow action without requiring Business.

## 6. Definition of done for every control

For each release candidate provide:
1. **Claim & boundary:** named asset, operation, authorized actor, prohibited behavior, environmental assumptions.
2. **Machine-checked invariants:** e.g. `not authorized → not executed` for paths in scope; exact parameter matching; deny on missing trust.
3. **Counterexample and failure tests:** missing telemetry, malicious event, permission bypass attempt, concurrent changes, outage, expired policy, failed readback.
4. **Observed impact:** legitimate work continues where authorized; false containment and recovery tested, with baseline measurements.
5. **Evidence:** reproducible scenario, policy/signature/digest versions, external readback, sanitized logs and explicit UNKNOWN.
6. **Release authority:** reviewed changes, no secrets/attack payloads, rollback and emergency stop; explicit customer consent for live containment.

## 7. Initial release slice and dependencies

**First vertical slice:** one dummy agent, one tool-call guard, one approved operation, one independent witness, three E0 scenarios. Only after O2 passes add an isolated O3 containment test. Do not start with a generic self-modifying AI or full SOAR.

**Parallel work permitted:** O0 schemas, threat model, read-only signal collector, ASVF test catalog. **Blocked work:** production Executor rollout until the existing HCAP G2/G3 security issues are resolved and independently reviewed.

Success measures (set actual numerical SLOs only after pilot measurement): detection-to-containment time for eligible events, correct-denial rate, verified containment rate, false containment rate, recovery success, observation coverage, unverified/unknown backlog, cost and resource overhead.

## 8. External references

- HCAP contract: [Hardshell Control Adapter Protocol](control-adapter-protocol.md)
- App-owned actions: [Application Security Contract](application-security-contract.md)
- NIST SP 800-61 Rev.3 (Respond/Recover/Improve): https://csrc.nist.gov/pubs/sp/800/61/r3/final
- OWASP Agent Control Standard (version-pin before implementing): https://owaspacs.org/docs/acs/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS: https://www.first.org/epss/
- Microsoft automatic attack disruption (existing market baseline, not a feature parity claim): https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption
