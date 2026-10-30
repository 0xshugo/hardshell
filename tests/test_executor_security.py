"""Executor security contract tests with ephemeral local OpenSSL keys."""

from __future__ import annotations

import base64
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from hardshell.adapters.base import ExecutionStatus
from hardshell.executor import (
    AuthorizedPlan,
    BoundedExecutor,
    CoolifyWriteHandler,
    ExecutorDenied,
    ExecutorLocalPolicy,
    ExecutorVerifier,
    KeyPurpose,
    OperationScope,
    PersistentReplayStore,
    Signature,
    SignedExecutorPlan,
    TrustedPublicKey,
    signed_bytes,
)


@pytest.fixture()
def keys(tmp_path: Path) -> dict[str, tuple[str, Path]]:
    found: dict[str, tuple[str, Path]] = {}
    for role in ("plan", "approval"):
        private = tmp_path / f"{role}.pem"
        public = tmp_path / f"{role}.pub.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        found[role] = (public.read_text(), private)
    return found


def signed_request(
    keys: dict[str, tuple[str, Path]], plan: AuthorizedPlan, tmp_path: Path,
) -> SignedExecutorPlan:
    signatures = {}
    for role in (KeyPurpose.PLAN, KeyPurpose.APPROVAL):
        msg = tmp_path / f"{role.value}-message"
        sig = tmp_path / f"{role.value}-signature"
        msg.write_bytes(signed_bytes(plan, role))
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-inkey", str(keys[role.value][1]),
                "-rawin", "-in", str(msg), "-out", str(sig),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        signatures[role.value] = Signature(
            key_id=f"{role.value}-key",
            value=base64.urlsafe_b64encode(sig.read_bytes()).rstrip(b"=").decode(),
        )
    return SignedExecutorPlan(
        plan=plan,
        plan_signature=signatures["plan"],
        approval_signature=signatures["approval"],
    )


@pytest.fixture()
def bundle(keys):
    now = datetime.now(UTC)
    policy_digest = "b" * 64
    observed = "a" * 64
    plan = AuthorizedPlan(
        tenant_id="tenant-a", environment="prod", executor_id="coolify-node-1",
        plan_id=uuid4(), nonce=uuid4(), adapter_id="coolify",
        resource_kind="application", resource_id="postiz-only",
        operation="coolify.deploy", parameters={"resource_type": "application"},
        policy_digest=policy_digest, evidence_digest=observed,
        approval_id="approval-123",
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(seconds=100),
    )
    trust = {}
    for role in (KeyPurpose.PLAN, KeyPurpose.APPROVAL):
        trust[f"{role.value}-key"] = TrustedPublicKey(
            key_id=f"{role.value}-key", purpose=role,
            public_key_pem=keys[role.value][0],
            valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=1),
        )
    policy = ExecutorLocalPolicy(
        tenant_id="tenant-a", environment="prod", executor_id="coolify-node-1",
        policy_digest=policy_digest, trusted_keys=trust,
        allowed_operations={
            "coolify.deploy": OperationScope(
                adapter_id="coolify", resource_kind="application",
                resource_ids=frozenset({"postiz-only"}),
                permitted_parameters={"resource_type": frozenset({"application"})},
            ),
        },
    )
    return keys, plan, policy


def test_valid_dual_signatures(bundle, tmp_path):
    keys, plan, policy = bundle
    assert ExecutorVerifier(policy).authorize(
        signed_request(keys, plan, tmp_path), plan.evidence_digest
    ) == plan


@pytest.mark.parametrize("change", [
    {"executor_id": "another-node"},
    {"tenant_id": "attacker"},
    {"environment": "dev"},
    {"resource_id": "not-postiz"},
    {"operation": "coolify.delete"},
    {"parameters": {"resource_type": "service"}},
    {"parameters": {"resource_type": "application", "shell": "rm -rf /"}},
    {"policy_digest": "0" * 64},
])
def test_rejects_wrong_target_or_scope_even_if_signed(bundle, tmp_path, change):
    keys, plan, policy = bundle
    altered = plan.model_copy(update=change)
    with pytest.raises(ExecutorDenied):
        ExecutorVerifier(policy).authorize(
            signed_request(keys, altered, tmp_path), altered.evidence_digest
        )


def test_rejects_signature_tampering(bundle, tmp_path):
    keys, plan, policy = bundle
    signed = signed_request(keys, plan, tmp_path)
    tampered = signed.model_copy(
        update={"plan": plan.model_copy(update={"approval_id": "not-approved"})}
    )
    with pytest.raises(ExecutorDenied, match="signature"):
        ExecutorVerifier(policy).authorize(tampered, plan.evidence_digest)


def test_rejects_stale_evidence_expiry_and_future(bundle, tmp_path):
    keys, plan, policy = bundle
    verifier = ExecutorVerifier(policy)
    with pytest.raises(ExecutorDenied, match="state changed"):
        verifier.authorize(signed_request(keys, plan, tmp_path), "c" * 64)

    expired = plan.model_copy(update={"expires_at": plan.issued_at + timedelta(seconds=1)})
    with pytest.raises(ExecutorDenied, match="expired"):
        verifier.authorize(signed_request(keys, expired, tmp_path), expired.evidence_digest)

    future = plan.model_copy(update={
        "issued_at": datetime.now(UTC) + timedelta(hours=1),
        "expires_at": datetime.now(UTC) + timedelta(hours=1, minutes=2),
    })
    with pytest.raises(ExecutorDenied, match="future"):
        verifier.authorize(signed_request(keys, future, tmp_path), future.evidence_digest)


def test_revocation_and_approval_key_separation(bundle, tmp_path):
    keys, plan, policy = bundle
    trust = dict(policy.trusted_keys)
    trust["plan-key"] = trust["plan-key"].model_copy(update={"revoked": True})
    revoked = policy.model_copy(update={"trusted_keys": trust})
    with pytest.raises(ExecutorDenied):
        ExecutorVerifier(revoked).authorize(
            signed_request(keys, plan, tmp_path), plan.evidence_digest
        )
    signed = signed_request(keys, plan, tmp_path)
    duplicate_key = signed.model_copy(update={
        "approval_signature": signed.plan_signature
    })
    with pytest.raises(ExecutorDenied):
        ExecutorVerifier(policy).authorize(duplicate_key, plan.evidence_digest)


def test_replay_persists_across_restart(tmp_path, bundle):
    _, plan, _ = bundle
    private = tmp_path / "replay"
    private.mkdir(mode=0o700)
    path = private / "ledger.db"
    PersistentReplayStore(path).claim(plan)
    with pytest.raises(ExecutorDenied, match="duplicate"):
        PersistentReplayStore(path).claim(plan)
    with pytest.raises(ExecutorDenied, match="duplicate"):
        PersistentReplayStore(path).claim(plan.model_copy(update={"nonce": uuid4()}))


@pytest.mark.asyncio
async def test_bounded_executor_and_timeout_are_not_retried(tmp_path, bundle):
    keys, plan, policy = bundle
    private = tmp_path / "replay"
    private.mkdir(mode=0o700)
    calls = []

    async def observe(_plan):
        return plan.evidence_digest

    async def deploy(_plan):
        calls.append("executed")
        return ["deployment-1"]

    executor = BoundedExecutor(
        ExecutorVerifier(policy), PersistentReplayStore(private / "ledger.db"),
        observe, {"coolify.deploy": deploy},
    )
    signed = signed_request(keys, plan, tmp_path)
    receipt = await executor.execute(signed)
    assert receipt.status == ExecutionStatus.ACCEPTED
    assert receipt.external_change_ids == ["deployment-1"]
    with pytest.raises(ExecutorDenied, match="duplicate"):
        await executor.execute(signed)
    assert calls == ["executed"]

    async def ambiguous(_plan):
        raise TimeoutError("provider response ambiguous")

    next_plan = plan.model_copy(update={"plan_id": uuid4(), "nonce": uuid4()})
    executor.handlers["coolify.deploy"] = ambiguous
    request = signed_request(keys, next_plan, tmp_path)
    assert (await executor.execute(request)).status == ExecutionStatus.UNKNOWN
    with pytest.raises(ExecutorDenied, match="duplicate"):
        await executor.execute(request)


@pytest.mark.asyncio
async def test_coolify_handler_is_narrowly_typed(bundle):
    def transport(request):
        assert request.method == "POST"
        assert request.url.path == "/api/v1/deploy"
        assert request.url.params.get("uuid") == "postiz-only"
        assert request.headers["Authorization"] == "Bearer test-token"
        return httpx.Response(200, json={"deployment_uuid": "dep-1"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        handler = CoolifyWriteHandler("https://coolify.example/api/v1", "test-token", client=client)
        _, plan, _ = bundle
        assert await handler(plan) == ["dep-1"]
        with pytest.raises(ExecutorDenied):
            await handler(plan.model_copy(update={"operation": "coolify.delete"}))


def test_extra_fields_denied(bundle):
    _, plan, _ = bundle
    value = plan.model_dump(mode="json")
    value["shell"] = "/bin/bash"
    with pytest.raises(ValidationError):
        AuthorizedPlan.model_validate(value)

@pytest.mark.parametrize("url", [
    "http://example.com/api/v1",
    "http://10.0.0.8:8300/api/v1",
    "http://coolify.internal/api/v1",
    "http://8.8.8.8/api/v1",
    "http://100.94.245.115:8300/api/v1?token=leak",
    "https://user:password@coolify.example/api/v1",
])
def test_coolify_rejects_untrusted_plaintext_or_embedded_credentials(url):
    with pytest.raises(ValueError):
        CoolifyWriteHandler(url, "test-token", allow_private_http=True)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8300/api/v1",
    "http://100.94.245.115:8300/api/v1",
])
def test_coolify_private_transport_requires_explicit_opt_in(url):
    with pytest.raises(ValueError):
        CoolifyWriteHandler(url, "test-token")
    # Local policy must STILL prove that a tailnet endpoint is actually owned.
    handler = CoolifyWriteHandler(url, "test-token", allow_private_http=True)
    assert handler.base_url == url

@pytest.mark.asyncio
async def test_coolify_rejects_path_injection_shape(bundle):
    _, plan, _ = bundle
    handler = CoolifyWriteHandler("https://coolify.example/api/v1", "test-token")
    with pytest.raises(ExecutorDenied, match="identifier"):
        await handler(plan.model_copy(update={"resource_id": "../api/v1/other"}))
