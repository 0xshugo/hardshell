from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from hardshell.adapters import (
    ControlAction,
    CoolifyAdapter,
    ExecutionReceipt,
    ExecutionStatus,
    RemediationIntent,
    ResourceKind,
    ResourceRef,
    RiskLevel,
)


def make_client() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-token"
        if request.method == "GET" and request.url.path.endswith("/applications/app-1"):
            return httpx.Response(
                200,
                json={
                    "uuid": "app-1",
                    "name": "postiz",
                    "fqdn": "https://social.aoifuture.com",
                    "http_basic_auth_password": "must-not-leak",
                    "settings": {"is_force_https_enabled": True},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/deploy"):
            return httpx.Response(
                200,
                json={"deployments": [{"deployment_uuid": "dep-1"}]},
            )
        if request.method == "GET" and request.url.path.endswith("/deployments/dep-1"):
            return httpx.Response(
                200,
                json={"deployment_uuid": "dep-1", "status": "finished", "commit": "abc"},
            )
        return httpx.Response(404, content=json.dumps({"message": "not found"}))

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_coolify_observation_redacts_unlisted_secrets() -> None:
    client = make_client()
    adapter = CoolifyAdapter("https://coolify.example/api/v1", "test-token", client=client)
    resource = ResourceRef(
        provider="coolify",
        kind=ResourceKind.APPLICATION,
        external_id="app-1",
        attributes={"coolify_resource_type": "application"},
    )

    evidence = await adapter.observe(resource)
    assert evidence[0].facts["fqdn"] == "https://social.aoifuture.com"
    assert "http_basic_auth_password" not in evidence[0].facts
    assert ControlAction.APPLY not in adapter.capabilities().actions
    await client.aclose()


@pytest.mark.asyncio
async def test_coolify_deploy_is_accepted_then_verified() -> None:
    client = make_client()
    adapter = CoolifyAdapter("https://coolify.example/api/v1", "test-token", client=client)
    resource = ResourceRef(
        provider="coolify",
        kind=ResourceKind.APPLICATION,
        external_id="app-1",
        attributes={"coolify_resource_type": "application"},
    )
    evidence = await adapter.observe(resource)
    intent = RemediationIntent(
        intent_id="i1",
        control_id="PATCH-POSTIZ",
        resource=resource,
        desired_state={"operation": "deploy"},
        reason="deploy reviewed security update",
        risk=RiskLevel.HIGH,
    )
    plan = await adapter.plan(intent, evidence)
    with pytest.raises(PermissionError, match="signed plan"):
        await adapter.apply(plan)
    with pytest.raises(ValueError, match="direct write"):
        CoolifyAdapter(
            "https://coolify.example/api/v1", "test-token", allow_apply=True, client=client
        )
    receipt = ExecutionReceipt(
        receipt_id="readback-example",
        adapter_id="coolify",
        plan_id=plan.plan_id,
        resource=resource,
        status=ExecutionStatus.ACCEPTED,
        started_at=datetime.now(UTC),
        external_change_ids=["dep-1"],
    )

    verified = await adapter.verify(plan, receipt)
    assert verified.verified is True
    assert verified.observed_status is ExecutionStatus.SUCCEEDED
    await client.aclose()
