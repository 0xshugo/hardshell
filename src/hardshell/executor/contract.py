"""HCAP v0.2 signed executor plans and independently pinned local permissions.

Wire format: normalized UTF-8 JSON signed with Ed25519 and a domain separator.
Version 0.2 does not claim RFC 8785 JSON canonicalization or TPM attestation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from hardshell.adapters.base import ResourceKind

PLAN_DOMAIN = b"HCAP-v0.2/plan\x00"
APPROVAL_DOMAIN = b"HCAP-v0.2/approval\x00"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[a-z][a-z0-9_.-]{2,95}$")


class KeyPurpose(StrEnum):
    PLAN = "plan"
    APPROVAL = "approval"


class AuthorizedPlan(BaseModel):
    """Everything that could change execution is covered by BOTH signatures."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["hcap.executor/v0.2"] = "hcap.executor/v0.2"
    tenant_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=80)
    executor_id: str = Field(min_length=1, max_length=128)
    plan_id: UUID
    nonce: UUID
    adapter_id: str = Field(min_length=1, max_length=128)
    resource_kind: ResourceKind
    resource_id: str = Field(min_length=1, max_length=256)
    operation: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    policy_digest: str  # SHA-256 of locally installed, signed policy bundle
    evidence_digest: str  # SHA-256 of fresh provider-owned observed state
    approval_id: str = Field(min_length=1, max_length=128)
    issued_at: datetime
    expires_at: datetime

    @field_validator("policy_digest", "evidence_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _DIGEST.fullmatch(value):
            raise ValueError("digest must be 64 lowercase hex characters")
        return value

    @field_validator("operation")
    @classmethod
    def validate_operation(cls, value: str) -> str:
        if not _OPERATION.fullmatch(value):
            raise ValueError("invalid operation identifier")
        return value

    @model_validator(mode="after")
    def check_expiry(self) -> AuthorizedPlan:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("issued_at and expires_at must have timezone offsets")
        if self.expires_at <= self.issued_at:
            raise ValueError("expiration must follow issuance")
        return self


def payload_bytes(plan: AuthorizedPlan) -> bytes:
    """Versioned, deterministic wire encoding; reject NaN and non-JSON data."""
    data = plan.model_dump(mode="json")
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def signed_bytes(plan: AuthorizedPlan, purpose: KeyPurpose) -> bytes:
    return (PLAN_DOMAIN if purpose is KeyPurpose.PLAN else APPROVAL_DOMAIN) + payload_bytes(plan)


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str = Field(min_length=1, max_length=128)
    algorithm: Literal["Ed25519"] = "Ed25519"
    value: str

    def raw(self) -> bytes:
        try:
            if not re.fullmatch(r"[A-Za-z0-9_-]{86}", self.value):
                raise ValueError("invalid base64url encoding")
            value = base64.urlsafe_b64decode(self.value + "==")
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("invalid signature encoding") from exc
        if len(value) != 64 or base64.urlsafe_b64encode(value).rstrip(b"=").decode() != self.value:
            raise ValueError("invalid Ed25519 signature")
        return value


class SignedExecutorPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan: AuthorizedPlan
    plan_signature: Signature
    approval_signature: Signature


class TrustedPublicKey(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: str
    purpose: KeyPurpose
    public_key_pem: str
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False

    @model_validator(mode="after")
    def validity_window(self) -> TrustedPublicKey:
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("signing key dates must have timezone offsets")
        if self.valid_from >= self.valid_until:
            raise ValueError("invalid signing key validity window")
        return self


class OperationScope(BaseModel):
    """A capability allowlist installed locally; no wildcard target or command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str
    resource_kind: ResourceKind
    resource_ids: frozenset[str] = Field(min_length=1)
    # All supplied parameter keys must be explicitly allowed, with exact scalar values.
    permitted_parameters: dict[str, frozenset[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scopes(self) -> OperationScope:
        if "*" in self.resource_ids:
            raise ValueError("wildcard resources are prohibited")
        for name, values in self.permitted_parameters.items():
            if not name or not values or "*" in values:
                raise ValueError("empty or wildcard parameter constraints are prohibited")
        return self


class ExecutorLocalPolicy(BaseModel):
    """Provisioned out-of-band on the executor; never supplied by a plan sender."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    environment: str
    executor_id: str
    policy_digest: str
    max_plan_age_seconds: int = Field(default=300, ge=1, le=900)
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    allowed_operations: dict[str, OperationScope]
    trusted_keys: dict[str, TrustedPublicKey]

    @field_validator("policy_digest")
    @classmethod
    def validate_policy_digest(cls, value: str) -> str:
        if not _DIGEST.fullmatch(value):
            raise ValueError("invalid policy digest")
        return value

    @model_validator(mode="after")
    def validate_key_bindings(self) -> ExecutorLocalPolicy:
        if not self.allowed_operations or not self.trusted_keys:
            raise ValueError("default-deny policy requires explicit operations and trusted keys")
        for key_id, key in self.trusted_keys.items():
            if key_id != key.key_id:
                raise ValueError("keyring key/id mismatch")
        return self


def evidence_digest(facts: dict[str, Any]) -> str:
    """Digest ONLY sanitized, source-controlled observations, never model output."""
    data = json.dumps(
        facts, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
