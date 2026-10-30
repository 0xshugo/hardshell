from __future__ import annotations

from datetime import UTC, datetime

import pytest

from hardshell.adapters import (
    AdapterCapabilities,
    AdapterRegistry,
    ChangePlan,
    ChangeStep,
    ControlAction,
    ControlAdapter,
    EvidenceRecord,
    ExecutionReceipt,
    ExecutionStatus,
    RemediationIntent,
    ResourceKind,
    ResourceRef,
    RiskLevel,
    VerificationReceipt,
)


class ReadOnlyAdapter(ControlAdapter):
    @property
    def adapter_id(self) -> str:
        return "test-readonly"

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            adapter_id=self.adapter_id,
            resource_kinds={ResourceKind.APPLICATION},
            actions={ControlAction.OBSERVE, ControlAction.PLAN, ControlAction.VERIFY},
        )

    async def observe(self, resource: ResourceRef) -> list[EvidenceRecord]:
        return [
            EvidenceRecord(
                evidence_id="e1",
                resource=resource,
                source="test",
                facts={"registration": "enabled"},
            )
        ]

    async def plan(
        self,
        intent: RemediationIntent,
        evidence: list[EvidenceRecord],
    ) -> ChangePlan:
        return ChangePlan(
            plan_id="p1",
            intent_id=intent.intent_id,
            adapter_id=self.adapter_id,
            resource=intent.resource,
            risk=intent.risk,
            steps=[
                ChangeStep(
                    step_id="s1",
                    action="disable_registration",
                    expected_result={"registration": "disabled"},
                )
            ],
            verification_requirements=["registration=disabled"],
        )

    async def verify(
        self,
        plan: ChangePlan,
        receipt: ExecutionReceipt,
    ) -> VerificationReceipt:
        return VerificationReceipt(
            receipt_id="v1",
            adapter_id=self.adapter_id,
            plan_id=plan.plan_id,
            resource=plan.resource,
            verified=False,
            observed_status=receipt.status,
        )


@pytest.mark.asyncio
async def test_observe_does_not_grant_apply() -> None:
    adapter = ReadOnlyAdapter()
    resource = ResourceRef(
        provider="test",
        kind=ResourceKind.APPLICATION,
        external_id="app-1",
    )
    evidence = await adapter.observe(resource)
    intent = RemediationIntent(
        intent_id="i1",
        control_id="REGISTRATION-DISABLED",
        resource=resource,
        desired_state={"registration": "disabled"},
        reason="public registration should be closed after bootstrap",
        risk=RiskLevel.MEDIUM,
    )
    plan = await adapter.plan(intent, evidence)

    with pytest.raises(PermissionError):
        await adapter.apply(plan)


def test_registry_rejects_duplicate_adapter_id() -> None:
    registry = AdapterRegistry()
    registry.register(ReadOnlyAdapter())
    with pytest.raises(ValueError):
        registry.register(ReadOnlyAdapter())


def test_unknown_is_a_first_class_execution_status() -> None:
    resource = ResourceRef(
        provider="test",
        kind=ResourceKind.APPLICATION,
        external_id="app-1",
    )
    receipt = ExecutionReceipt(
        receipt_id="r1",
        adapter_id="test",
        plan_id="p1",
        resource=resource,
        status=ExecutionStatus.UNKNOWN,
        started_at=datetime.now(UTC),
    )
    assert receipt.status is ExecutionStatus.UNKNOWN
