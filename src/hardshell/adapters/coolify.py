"""Reference HCAP adapter for Coolify.

The adapter is read/plan/verify by default. Mutation must be explicitly enabled
and all writes belong in the separately sandboxed HCAP v0.2 executor.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx

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
    VerificationReceipt,
)


class CoolifyAdapter(ControlAdapter):
    """Read-only Coolify REST adapter; write tokens belong to the executor."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        allow_apply: bool = False,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        if allow_apply:
            raise ValueError("direct write access removed; use HCAP v0.2 BoundedExecutor")
        self._client = client

    @property
    def adapter_id(self) -> str:
        return "coolify"

    def capabilities(self) -> AdapterCapabilities:
        actions = {ControlAction.OBSERVE, ControlAction.PLAN, ControlAction.VERIFY}
        return AdapterCapabilities(
            adapter_id=self.adapter_id,
            resource_kinds={ResourceKind.APPLICATION, ResourceKind.CONTROL_PLANE},
            actions=actions,
            can_read_secrets=False,
            can_change_public_exposure=False,
            can_change_credentials=False,
            supports_idempotency_key=False,
            supports_rollback=False,
            notes=[
                "Use a team-scoped Coolify token and self-hosted API IP allowlist.",
                "Secret values are intentionally excluded from evidence.",
            ],
        )

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {self.token}"
        client = self._client
        if client is not None:
            response = await client.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                **kwargs,
            )
            response.raise_for_status()
            return response
        async with httpx.AsyncClient(timeout=20.0) as owned:
            response = await owned.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                **kwargs,
            )
            response.raise_for_status()
            return response

    @staticmethod
    def _resource_type(resource: ResourceRef) -> str:
        resource_type = str(resource.attributes.get("coolify_resource_type", ""))
        if resource_type not in {"application", "service"}:
            raise ValueError(
                "resource.attributes.coolify_resource_type must be application or service"
            )
        return resource_type

    @staticmethod
    def _safe_facts(resource_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if resource_type == "application":
            allowed = {
                "uuid",
                "name",
                "fqdn",
                "config_hash",
                "git_repository",
                "git_branch",
                "git_commit_sha",
                "docker_registry_image_name",
                "docker_registry_image_tag",
                "ports_exposes",
                "ports_mappings",
                "health_check_enabled",
                "updated_at",
            }
            facts = {key: payload.get(key) for key in allowed if key in payload}
            settings = payload.get("settings")
            if isinstance(settings, dict):
                setting_keys = {
                    "is_auto_deploy_enabled",
                    "is_force_https_enabled",
                    "is_preview_deployments_enabled",
                    "is_gpu_enabled",
                    "connect_to_docker_network",
                    "is_container_label_readonly_enabled",
                    "use_build_secrets",
                }
                facts["settings"] = {
                    key: settings.get(key) for key in setting_keys if key in settings
                }
            return facts

        allowed = {
            "uuid",
            "name",
            "description",
            "config_hash",
            "service_type",
            "connect_to_docker_network",
            "redact_all_env_values_in_logs",
            "updated_at",
        }
        return {key: payload.get(key) for key in allowed if key in payload}

    async def observe(self, resource: ResourceRef) -> list[EvidenceRecord]:
        resource_type = self._resource_type(resource)
        collection = "applications" if resource_type == "application" else "services"
        response = await self._request("GET", f"/{collection}/{resource.external_id}")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Coolify response is not an object")
        return [
            EvidenceRecord(
                evidence_id=f"coolify-{uuid4()}",
                resource=resource,
                source=f"coolify.api.{resource_type}",
                facts=self._safe_facts(resource_type, payload),
            )
        ]

    async def plan(
        self,
        intent: RemediationIntent,
        evidence: list[EvidenceRecord],
    ) -> ChangePlan:
        resource_type = self._resource_type(intent.resource)
        operation = str(intent.desired_state.get("operation", ""))
        if operation not in {"deploy", "restart"}:
            raise ValueError("Coolify reference adapter supports deploy or restart only")

        step = ChangeStep(
            step_id="coolify-1",
            action=f"coolify.{operation}",
            parameters={
                "resource_type": resource_type,
                "resource_uuid": intent.resource.external_id,
            },
            expected_result={"provider_accepts_request": True},
        )
        preconditions = []
        if intent.expected_evidence_digest:
            preconditions.append(
                f"evidence_digest={intent.expected_evidence_digest}"
            )
        if evidence:
            preconditions.append("fresh_coolify_readback")

        return ChangePlan(
            plan_id=f"coolify-plan-{uuid4()}",
            intent_id=intent.intent_id,
            adapter_id=self.adapter_id,
            resource=intent.resource,
            risk=intent.risk,
            steps=[step],
            preconditions=preconditions,
            verification_requirements=["provider readback after queued operation"],
            requires_approval=intent.approval_required,
            expires_at=intent.expires_at,
        )

    async def apply(self, plan: ChangePlan) -> ExecutionReceipt:
        """Direct provider mutation is forbidden outside the v0.2 executor."""
        raise PermissionError("Coolify mutations require a verified HCAP v0.2 signed plan")

    async def verify(
        self,
        plan: ChangePlan,
        receipt: ExecutionReceipt,
    ) -> VerificationReceipt:
        evidence: list[EvidenceRecord] = []
        observed = ExecutionStatus.UNKNOWN
        verified = False

        for deployment_uuid in receipt.external_change_ids:
            response = await self._request("GET", f"/deployments/{deployment_uuid}")
            payload = response.json()
            if not isinstance(payload, dict):
                continue
            status = str(payload.get("status", "")).lower()
            evidence.append(
                EvidenceRecord(
                    evidence_id=f"coolify-deployment-{uuid4()}",
                    resource=plan.resource,
                    source="coolify.api.deployment",
                    facts={
                        "deployment_uuid": deployment_uuid,
                        "status": status,
                        "commit": payload.get("commit"),
                        "rollback": payload.get("rollback"),
                    },
                )
            )
            if status in {"finished", "success", "completed"}:
                observed = ExecutionStatus.SUCCEEDED
                verified = True
            elif status in {"failed", "cancelled", "canceled"}:
                observed = ExecutionStatus.FAILED
                verified = True
            else:
                observed = ExecutionStatus.ACCEPTED

        if not receipt.external_change_ids:
            evidence.extend(await self.observe(plan.resource))

        return VerificationReceipt(
            receipt_id=f"coolify-verify-{uuid4()}",
            adapter_id=self.adapter_id,
            plan_id=plan.plan_id,
            resource=plan.resource,
            verified=verified,
            observed_status=observed,
            evidence=evidence,
            residual_risks=[] if verified else ["operation not yet conclusively verified"],
        )
