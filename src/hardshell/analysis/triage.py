"""Jev relevance judgment followed by bounded local LLM review; advice only."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
from urllib.parse import urlparse

import httpx

from hardshell.analysis.budget import BudgetDeniedError

STEPS = {
    "verify_vendor_patch",
    "prepare_image_update",
    "request_service_approval",
    "verify_runtime_after_update",
    "collect_runtime_evidence",
}


def model_state(case):
    # Only normalized product/version and public advisory IDs leave the host.
    # Never pass host/container identities, digests, scanner prose, secrets or logs.
    if (
        case.get("product") != "php"
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", case.get("installed", ""))
        or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", case.get("advisory_id", ""))
        or (
            case.get("fixed") is not None
            and not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", case["fixed"])
        )
    ):
        raise ValueError("untrusted_model_state")
    return {
        "product": case["product"],
        "installed": case["installed"],
        "fixed": case["fixed"],
        "advisory_id": case["advisory_id"],
        "evidence_status": case["status"],
        "vendor_backport_verified": False,
        "web_exposure": "unknown",
        "public_advisory": str(case.get("public_summary", ""))[:2000],
    }


async def post_json(client, url, *, deadline=25, **kwargs):
    async with asyncio.timeout(deadline):
        async with client.stream("POST", url, **kwargs) as response:
            response.raise_for_status()
            body = bytearray()
            async for part in response.aiter_bytes():
                body.extend(part)
                if len(body) > 64 * 1024:
                    raise ValueError("model_response_too_large")
    return json.loads(body)


async def metered_json(client, url, *, budget, provider, **kwargs):
    if budget is None:
        raise BudgetDeniedError("budget_not_configured")
    try:
        ticket = budget.admit(provider, kwargs["json"]["model"], kwargs["json"], url)
    except BudgetDeniedError as exc:
        if provider != "jev" or exc.code != "provider_funds_unverified":
            raise
        from hardshell.analysis.funding import check_funding

        proof = await check_funding(
            budget,
            api_key=kwargs.get("headers", {}).get("Authorization", "").removeprefix("Bearer "),
            cookie=os.environ.get("HARDSHELL_TYPESAFE_BILLING_COOKIE"),
            client=client,
            for_request=True,
        )
        if proof["status"] != "ready":
            raise BudgetDeniedError(proof["reason"])
        ticket = budget.admit(provider, kwargs["json"]["model"], kwargs["json"], url)
    if "cached" in ticket:
        return ticket["cached"]
    try:
        body = await post_json(client, url, deadline=60 if provider == "llm" else 25, **kwargs)
    except Exception:
        budget.finish(ticket)
        raise
    budget.finish(ticket, body)
    return body


async def review(
    case,
    *,
    jev_key=None,
    jev_model="jev-1.13.0",
    llm_url=None,
    llm_model=None,
    client=None,
    budget=None,
):
    if client is None:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as owned:
            return await review(
                case,
                jev_key=jev_key,
                jev_model=jev_model,
                llm_url=llm_url,
                llm_model=llm_model,
                client=owned,
                budget=budget,
            )
    state = model_state(case)
    decision = {
        "status": "needs_review",
        "jev": "not_configured",
        "llm": "not_configured",
        "executable": False,
        "requires_approval": True,
    }
    if jev_key:
        try:
            body = await metered_json(
                client,
                "https://api.typesafe.ai/v1/systemone",
                budget=budget,
                provider="jev",
                headers={"Authorization": "Bearer " + jev_key},
                json={
                    "model": jev_model,
                    "state": state,
                    "questions": {
                        "relevance": {
                            "type": "choice",
                            "instructions": "Does this PHP advisory require runtime review? "
                            "Version evidence does not establish vendor patch status.",
                            "criteria": {
                                "review": "An older or uncertain PHP runtime needs review",
                                "unrelated": "Evidence explicitly excludes this product",
                                "uncertain": "Evidence is incomplete or ambiguous",
                            },
                        }
                    },
                },
                timeout=10,
            )
            answer = body["answers"]["relevance"]
            choice, confidence = answer["choice"], answer["confidence"]
            probs = answer["probabilities"]
            if (
                answer["type"] != "choice"
                or choice not in ("review", "unrelated", "uncertain")
                or type(confidence) not in (int, float)
                or not math.isfinite(confidence)
                or not 0 <= confidence <= 1
                or set(probs) != {"review", "unrelated", "uncertain"}
                or any(
                    type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1
                    for p in probs.values()
                )
                or abs(sum(probs.values()) - 1) > 0.02
            ):
                raise ValueError("invalid_model_answer")
            decision["jev"] = {
                "choice": choice,
                "confidence": confidence,
                "model": body.get("model"),
                "usage": body.get("usage", {}),
            }
        except BudgetDeniedError as exc:
            decision["jev"] = {"status": "deferred", "reason": exc.code}
        except (httpx.HTTPError, TimeoutError, KeyError, TypeError, ValueError):
            decision["jev"] = "failed"
    # Critical vendor matches and uncertain decisions always reach reasoning review.
    # No Jev output may discard, downgrade or execute a deterministic case.
    if llm_url and llm_model:
        parsed = urlparse(llm_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("local_llm_endpoint_required")
        try:
            schema = {
                "type": "object",
                "properties": {
                    "advisory_id": {"type": "string", "const": case["advisory_id"]},
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 5,
                        "items": {"type": "string", "enum": sorted(STEPS)},
                    },
                    "summary": {"type": "string", "maxLength": 2000},
                },
                "required": ["advisory_id", "steps", "summary"],
                "additionalProperties": False,
            }
            reasoning = (
                budget.policy.get("providers", {}).get("llm", {}).get("reasoning_effort")
                if budget is not None
                else None
            )
            body = await metered_json(
                client,
                llm_url.rstrip("/") + "/chat/completions",
                budget=budget,
                provider="llm",
                json={
                    "model": llm_model,
                    "max_tokens": 256,
                    "temperature": 0,
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {"name": "security_plan", "strict": True, "schema": schema},
                    },
                    **({"reasoning_effort": reasoning} if reasoning else {}),
                    "messages": [
                        {
                            "role": "system",
                            "content": "Review security evidence. Return JSON with "
                            "advisory_id, steps (array), and summary. Allowed steps: "
                            + ", ".join(sorted(STEPS))
                            + ". Keep summary to one short sentence. "
                            "No execution. No claim of safety. "
                            "Account for vendor backports and unknown web exposure.",
                        },
                        {
                            "role": "user",
                            "content": json.dumps({"evidence": state, "jev": decision["jev"]}),
                        },
                    ],
                },
                timeout=55,
            )
            content = body["choices"][0]["message"]["content"]
            if len(content) > 8000:
                raise ValueError("model_output_too_large")
            plan = json.loads(content)
            if (
                set(plan) != {"advisory_id", "steps", "summary"}
                or plan["advisory_id"] != case["advisory_id"]
                or not isinstance(plan["steps"], list)
                or not 1 <= len(plan["steps"]) <= 5
                or any(not isinstance(s, str) or s not in STEPS for s in plan["steps"])
                or not isinstance(plan["summary"], str)
                or len(plan["summary"]) > 2000
            ):
                raise ValueError("invalid_plan")
            # Free model prose is not a trusted instruction or approval artifact.
            decision["llm"] = {
                "status": "advice_ready",
                "steps": plan["steps"],
                "model": body.get("model"),
                "usage": body.get("usage", {}),
            }
        except BudgetDeniedError as exc:
            decision["llm"] = {"status": "deferred", "reason": exc.code}
        except (httpx.HTTPError, TimeoutError, KeyError, IndexError, TypeError, ValueError):
            decision["llm"] = "failed"
    if (
        isinstance(decision["jev"], dict)
        and "choice" in decision["jev"]
        and isinstance(decision["llm"], dict)
        and decision["llm"].get("status") == "advice_ready"
    ):
        decision["pipeline_status"] = "advice_ready"
    return decision
