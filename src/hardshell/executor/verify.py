"""Executor-side Ed25519 verification and local authorization. Never calls an LLM."""

from __future__ import annotations

import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hardshell.executor.contract import (
    AuthorizedPlan,
    ExecutorLocalPolicy,
    KeyPurpose,
    Signature,
    SignedExecutorPlan,
    TrustedPublicKey,
    signed_bytes,
)


class ExecutorDenied(PermissionError):
    """Reject unsafe execution without leaking credential material."""


def verify_ed25519(message: bytes, signature: Signature, key: TrustedPublicKey) -> bool:
    """Verify using OpenSSL EVP Ed25519; unavailable OpenSSL fails closed.

    Only trusted locally enrolled public keys are used. No shell or user-controlled
    CLI flags. Temporary files are private (0700 directory) and deleted after use.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="hcap-verify-") as temp:
            directory = Path(temp)
            pub = directory / "public.pem"
            msg = directory / "message.bin"
            sig = directory / "signature.bin"
            pub.write_text(key.public_key_pem, encoding="utf-8")
            msg.write_bytes(message)
            sig.write_bytes(signature.raw())
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                    "-rawin", "-in", str(msg), "-sigfile", str(sig),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
            )
            return result.returncode == 0
    except (FileNotFoundError, OSError, ValueError, subprocess.TimeoutExpired):
        return False


class ExecutorVerifier:
    def __init__(self, policy: ExecutorLocalPolicy) -> None:
        self.policy = policy

    def _verify_key(
        self, plan: AuthorizedPlan, signature: Signature, purpose: KeyPurpose, now: datetime
    ) -> None:
        key = self.policy.trusted_keys.get(signature.key_id)
        if key is None or key.purpose is not purpose or key.revoked:
            raise ExecutorDenied("untrusted or revoked signing key")
        if not key.valid_from <= now < key.valid_until:
            raise ExecutorDenied("signing key outside validity period")
        if not verify_ed25519(signed_bytes(plan, purpose), signature, key):
            raise ExecutorDenied("invalid execution signature")

    def authorize(
        self, request: SignedExecutorPlan, observed_evidence_digest: str,
        *, now: datetime | None = None,
    ) -> AuthorizedPlan:
        plan = request.plan
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            raise ExecutorDenied("clock must be timezone-aware")
        if (
            plan.tenant_id != self.policy.tenant_id
            or plan.environment != self.policy.environment
            or plan.executor_id != self.policy.executor_id
            or plan.policy_digest != self.policy.policy_digest
        ):
            raise ExecutorDenied("plan target or local policy mismatch")
        if plan.issued_at > now + timedelta(seconds=self.policy.clock_skew_seconds):
            raise ExecutorDenied("plan issued in the future")
        if plan.expires_at <= now:
            raise ExecutorDenied("expired execution plan")
        if (plan.expires_at - plan.issued_at).total_seconds() > self.policy.max_plan_age_seconds:
            raise ExecutorDenied("execution plan lifetime too long")
        if plan.evidence_digest != observed_evidence_digest:
            raise ExecutorDenied("observed state changed since plan approval")
        scope = self.policy.allowed_operations.get(plan.operation)
        if scope is None or scope.adapter_id != plan.adapter_id:
            raise ExecutorDenied("operation is not locally authorized")
        if scope.resource_kind != plan.resource_kind or plan.resource_id not in scope.resource_ids:
            raise ExecutorDenied("resource is outside locally authorized scope")
        if set(plan.parameters) != set(scope.permitted_parameters):
            raise ExecutorDenied("operation arguments are not locally authorized")
        for name, value in plan.parameters.items():
            if not isinstance(value, str) or value not in scope.permitted_parameters[name]:
                raise ExecutorDenied("operation arguments exceed local constraints")
        if request.plan_signature.key_id == request.approval_signature.key_id:
            raise ExecutorDenied("plan and approval must use distinct signing keys")
        self._verify_key(plan, request.plan_signature, KeyPurpose.PLAN, now)
        self._verify_key(plan, request.approval_signature, KeyPurpose.APPROVAL, now)
        return plan
