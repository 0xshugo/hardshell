"""Typed Coolify executor-side handler. Keep the write token in this process only."""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from hardshell.executor.contract import AuthorizedPlan
from hardshell.executor.verify import ExecutorDenied


class CoolifyWriteHandler:
    """Finite operation set, not a generic HTTP proxy or shell facility.

    This handler must only be installed in BoundedExecutor after verification.
    A team-scoped API token is injected into the isolated executor process.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        client: httpx.AsyncClient | None = None,
        allow_private_http: bool = False,
    ) -> None:
        base_url = base_url.rstrip("/")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" and not (
            allow_private_http and parsed.scheme == "http"
        ):
            raise ValueError("Coolify executor requires HTTPS by default")
        if not parsed.netloc or not parsed.path.endswith("/api/v1"):
            raise ValueError("expected a fixed Coolify /api/v1 URL")
        if not token:
            raise ValueError("empty Coolify token")
        self.base_url = base_url
        self.token = token
        self.client = client

    async def __call__(self, plan: AuthorizedPlan) -> list[str]:
        if plan.adapter_id != "coolify" or plan.resource_kind != "application":
            raise ExecutorDenied("unsupported resource for Coolify reference executor")
        if plan.operation not in {"coolify.deploy", "coolify.restart"}:
            raise ExecutorDenied("unsupported Coolify write operation")
        if plan.parameters != {"resource_type": "application"}:
            raise ExecutorDenied("unexpected Coolify operation parameters")

        if plan.operation == "coolify.deploy":
            path = "/deploy"
            params = {"uuid": plan.resource_id}
        else:
            path = f"/applications/{plan.resource_id}/restart"
            params = None

        headers = {"Authorization": f"Bearer {self.token}"}
        if self.client is not None:
            response = await self.client.post(
                self.base_url + path, params=params, headers=headers, timeout=20.0
            )
        else:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    self.base_url + path, params=params, headers=headers
                )
        response.raise_for_status()
        payload = response.json() if response.content else {}
        if not isinstance(payload, dict):
            return []
        identifiers = []
        if isinstance(payload.get("deployment_uuid"), str):
            identifiers.append(payload["deployment_uuid"])
        if isinstance(payload.get("deployments"), list):
            for item in payload["deployments"]:
                if isinstance(item, dict) and isinstance(item.get("deployment_uuid"), str):
                    identifiers.append(item["deployment_uuid"])
        return identifiers
