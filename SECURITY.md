# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes.

| Version | Supported |
| ------- | --------- |
| latest (`main`) | ✅ |
| older releases | ❌ |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's [Private Vulnerability Reporting](https://github.com/0xshugo/hardshell/security/advisories/new)
to report vulnerabilities privately. You will receive an initial response within 7 days.

When reporting, please include:

- Affected component (scanner, wrapper script, Dockerfile, CI, etc.)
- Reproduction steps or a proof of concept
- Impact assessment (what an attacker could achieve)

## Scope

hardshell is a security posture scanner that typically runs with elevated
privileges (sudo/cron) and sends notifications to external services.
Reports in the following areas are particularly appreciated:

- Command or argument injection via scan targets, config files, or registry JSON
- Secret leakage in reports, logs, or notification payloads
- Privilege escalation through wrapper scripts (`bin/*.sh`) or auto-remediation
- Supply-chain issues in dependencies or CI workflows
