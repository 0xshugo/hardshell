"""Hardshell control-adapter extension API."""

from hardshell.adapters.base import (
    AdapterCapabilities,
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
from hardshell.adapters.registry import AdapterRegistry, discover_adapters

__all__ = [
    "AdapterCapabilities",
    "AdapterRegistry",
    "ChangePlan",
    "ChangeStep",
    "ControlAction",
    "ControlAdapter",
    "EvidenceRecord",
    "ExecutionReceipt",
    "ExecutionStatus",
    "RemediationIntent",
    "ResourceKind",
    "ResourceRef",
    "RiskLevel",
    "VerificationReceipt",
    "discover_adapters",
]
