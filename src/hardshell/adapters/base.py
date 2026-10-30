"""Typed contract for external security-control adapters.

Adapters keep authority at the system that owns a resource. Hardshell evaluates,
plans and verifies through this contract instead of assuming direct root access.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class ResourceKind(StrEnum):
    HOST = "host"
    CONTROL_PLANE = "control_plane"
    CONTAINER_RUNTIME = "container_runtime"
    WORKLOAD = "workload"
    NETWORK_POLICY = "network_policy"
    EDGE = "edge"
    SECRET_STORE = "secret_store"
    APPLICATION = "application"
    AGENT_RUNTIME = "agent_runtime"


class ControlAction(StrEnum):
    OBSERVE = "observe"
    PLAN = "plan"
    APPLY = "apply"
    VERIFY = "verify"
    ROLLBACK = "rollback"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(StrEnum):
    ACCEPTED = "accepted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    REJECTED = "rejected"
    NOT_APPLIED = "not_applied"


class ResourceRef(BaseModel):
    provider: str
    kind: ResourceKind
    external_id: str
    environment: str | None = None
    display_name: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class EvidenceRecord(BaseModel):
    evidence_id: str
    resource: ResourceRef
    source: str
    observed_at: datetime = Field(default_factory=utcnow)
    facts: dict[str, Any] = Field(default_factory=dict)
    evidence_digest: str | None = None
    raw_ref: str | None = None


class AdapterCapabilities(BaseModel):
    adapter_id: str
    resource_kinds: set[ResourceKind]
    actions: set[ControlAction]
    can_read_secrets: bool = False
    can_change_public_exposure: bool = False
    can_change_credentials: bool = False
    supports_idempotency_key: bool = False
    supports_rollback: bool = False
    notes: list[str] = Field(default_factory=list)


class RemediationIntent(BaseModel):
    intent_id: str
    control_id: str
    resource: ResourceRef
    desired_state: dict[str, Any]
    reason: str
    risk: RiskLevel
    approval_required: bool = True
    expected_evidence_digest: str | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChangeStep(BaseModel):
    step_id: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_result: dict[str, Any] = Field(default_factory=dict)


class ChangePlan(BaseModel):
    plan_id: str
    intent_id: str
    adapter_id: str
    resource: ResourceRef
    risk: RiskLevel
    steps: list[ChangeStep]
    preconditions: list[str] = Field(default_factory=list)
    verification_requirements: list[str] = Field(default_factory=list)
    rollback_steps: list[ChangeStep] = Field(default_factory=list)
    requires_approval: bool = True
    irreversible: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None


class ExecutionReceipt(BaseModel):
    receipt_id: str
    adapter_id: str
    plan_id: str
    resource: ResourceRef
    status: ExecutionStatus
    started_at: datetime
    finished_at: datetime = Field(default_factory=utcnow)
    external_change_ids: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    error_code: str | None = None
    message: str | None = None


class VerificationReceipt(BaseModel):
    receipt_id: str
    adapter_id: str
    plan_id: str
    resource: ResourceRef
    verified: bool
    observed_status: ExecutionStatus
    observed_at: datetime = Field(default_factory=utcnow)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    residual_risks: list[str] = Field(default_factory=list)


class ControlAdapter(ABC):
    """Provider adapter with fail-closed mutation semantics."""

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        raise NotImplementedError

    @abstractmethod
    async def observe(self, resource: ResourceRef) -> list[EvidenceRecord]:
        raise NotImplementedError

    @abstractmethod
    async def plan(
        self,
        intent: RemediationIntent,
        evidence: list[EvidenceRecord],
    ) -> ChangePlan:
        raise NotImplementedError

    async def apply(self, plan: ChangePlan) -> ExecutionReceipt:
        raise PermissionError(
            f"adapter {self.adapter_id!r} does not implement APPLY; "
            "use a provider-owned executor or an adapter that explicitly supports it"
        )

    @abstractmethod
    async def verify(
        self,
        plan: ChangePlan,
        receipt: ExecutionReceipt,
    ) -> VerificationReceipt:
        raise NotImplementedError

    async def rollback(
        self,
        plan: ChangePlan,
        receipt: ExecutionReceipt,
    ) -> ExecutionReceipt:
        raise PermissionError(f"adapter {self.adapter_id!r} does not implement ROLLBACK")
