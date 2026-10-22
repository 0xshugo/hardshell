"""Budget capacity and bounded, non-inference local model availability checks."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse

import httpx


async def local_readiness(budget, url, model, *, client=None):
    limits = budget.readiness("llm")
    if limits["status"] != "ready":
        return limits
    parsed = urlparse(url or "")
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "localhost", "::1")
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/v1"
        or model != limits["model"]
    ):
        return {"status": "unavailable", "reason": "invalid_local_model_config"}
    if client is None:
        async with httpx.AsyncClient() as owned:
            return await local_readiness(budget, url, model, client=owned)
    try:
        async with asyncio.timeout(5):
            async with client.stream(
                "GET", url.rstrip("/") + "/models", timeout=3, follow_redirects=False
            ) as response:
                response.raise_for_status()
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise ValueError("response_limit")
        if model not in {entry["id"] for entry in json.loads(raw)["data"]}:
            raise ValueError("model_missing")
        limits["verification"] = "model_available_not_inference_proof"
        return limits
    except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError):
        return {"status": "unavailable", "reason": "local_model_unavailable"}
