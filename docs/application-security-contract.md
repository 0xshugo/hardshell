# Hardshell Application Security Contract v0.1

Applications can integrate with Hardshell without embedding Hardshell code by shipping a small security manifest, conventionally named hardshell-security.yaml.

## Required intent

The manifest declares intended security state. Hardshell still observes runtime state independently through platform and host adapters.

Recommended fields:

- schema_version
- application.id / owner / environment
- deployment.provider / resource_ref / canonical_url
- security.public_registration
- security.expected_public_ports
- security.forbidden container/runtime properties
- security.secret storage policy
- operations.kill_switch
- operations.security update SLA
- verification/readback requirements

## Optional application control API

An application may expose a narrow provider-owned API for a small set of security controls, for example:

- disable new dispatch
- enter maintenance mode
- invalidate application sessions
- report build/version/security posture
- request non-human token rotation through a secret broker

The API must use explicit operation names and typed inputs. It must not expose arbitrary shell execution or a generic configuration-write endpoint.

Every mutating operation should accept an Intent ID, Plan ID, idempotency key where supported, approval/evidence reference, and expected current version/digest. It should return a provider change ID and support independent readback.

## Security principle

This makes an application Hardshell-ready while preserving ownership. Hardshell supplies fleet-level detection, policy, evidence and governance; the application owns its safe control surface.
