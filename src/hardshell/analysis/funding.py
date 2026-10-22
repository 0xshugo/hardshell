"""Read-only TypeSafe console funding preflight; never import browser credentials.

The console interface is not a documented billing API. Fail closed if it changes.
An operator must provision an API key and console session for the same organization.
No raw console body, cookie, key, or account identity is persisted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime
from decimal import Decimal
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import httpx

BILLING = "https://console.typesafe.ai/settings/billing"
ORIGIN = "https://console.typesafe.ai"


class FundingUnavailableError(ValueError):
    def __init__(self, code, retry_after=3600):
        self.retry_after = retry_after
        super().__init__(code)


def nano(value):
    if type(value) not in (int, float) or value < 0:
        raise FundingUnavailableError("invalid_funding_response")
    decimal = Decimal(str(value))
    if not decimal.is_finite():
        raise FundingUnavailableError("invalid_funding_response")
    return int(decimal * 1_000_000_000)


def parse_billing(text, now):
    for line in text.splitlines():
        try:
            result = json.loads(line.split(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if not isinstance(result, dict) or "ok" not in result:
            continue
        if result.get("ok") is not True:
            raise FundingUnavailableError("funding_request_rejected")
        try:
            billing = result["data"]["billing"]
            balance = nano(billing["balance"])
            # Only dated, non-expired credit grants are counted as funding evidence.
            # Unknown grants/pay-as-you-go credit lines cannot establish usable funds.
            credits = []
            for grant in billing["credits"]:
                remaining = nano(grant["remaining"])
                expires = datetime.fromisoformat(grant["expiresAt"].replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    raise ValueError("undated_credit")
                if remaining > 0 and expires.timestamp() > now:
                    credits.append((remaining, expires.timestamp()))
            return {
                "balance_nano_usd": balance,
                "usable_nano_usd": min(balance, sum(c[0] for c in credits)),
                "expires_at": min((c[1] for c in credits), default=now),
            }
        except (KeyError, TypeError, ValueError, AttributeError):
            raise FundingUnavailableError("invalid_funding_response") from None
    raise FundingUnavailableError("invalid_funding_response")


async def bounded_text(client, method, url, **kwargs):
    async with client.stream(method, url, timeout=8, follow_redirects=False, **kwargs) as response:
        if response.status_code in (401, 403) or 300 <= response.status_code < 400:
            raise FundingUnavailableError("funding_authentication_required")
        if response.status_code == 429:
            value = response.headers.get("Retry-After", "3600")
            try:
                wait = float(value)
            except ValueError:
                try:
                    from datetime import UTC

                    wait = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
                except (TypeError, ValueError):
                    wait = 3600
            raise FundingUnavailableError("funding_rate_limited", max(3600, wait))
        if response.status_code != 200:
            raise FundingUnavailableError("funding_provider_unavailable")
        data = bytearray()
        async for part in response.aiter_bytes():
            data.extend(part)
            if len(data) > 2 * 1024 * 1024:
                raise FundingUnavailableError("funding_response_limit")
        return data.decode("utf-8")


async def check_funding(budget, **kwargs):
    try:
        async with asyncio.timeout(45):
            bridge = os.environ.get("HARDSHELL_FUNDING_URL")
            if bridge:
                from hardshell.analysis.funding_bridge import check_bridge

                arguments = dict(
                    api_key=kwargs.get("api_key"),
                    url=bridge,
                    for_request=kwargs.get("for_request", False),
                )
                if kwargs.get("client") is not None:
                    return await check_bridge(budget, client=kwargs["client"], **arguments)
                async with httpx.AsyncClient() as client:
                    return await check_bridge(budget, client=client, **arguments)
            return await _check_funding(budget, **kwargs)
    except (sqlite3.Error, OSError, TimeoutError, ValueError, TypeError):
        budget.funding = None
        return {"status": "unavailable", "reason": "funding_check_unavailable"}


async def _check_funding(budget, *, api_key=None, cookie=None, client=None, for_request=False):
    """Hourly idle preflight, fresh before every uncached request; failures last an hour.

    Separate read-only console authorization is required. API model access alone does
    not prove a positive balance. An unauthenticated/missing check never authorizes AI.
    """
    if client is None:
        async with httpx.AsyncClient() as owned:
            return await _check_funding(
                budget, api_key=api_key, cookie=cookie, client=owned, for_request=for_request
            )
    now = budget.clock()
    if not api_key or not cookie:
        return {"status": "unavailable", "reason": "provider_funding_credentials_missing"}
    identity = hashlib.sha256((api_key + "\0" + cookie).encode()).hexdigest()
    with budget.connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS funding (key TEXT PRIMARY KEY, at REAL, body TEXT)")
        db.execute(
            "CREATE TABLE IF NOT EXISTS funding_actions "
            "(key TEXT PRIMARY KEY, at REAL, action TEXT)"
        )
        old = db.execute("SELECT at,body FROM funding WHERE key=?", (identity,)).fetchone()
        cached_action = db.execute(
            "SELECT at,action FROM funding_actions WHERE key=?", (identity,)
        ).fetchone()
    if old:
        body = json.loads(old["body"])
        if body.get("reason") == "funding_authentication_required":
            return body  # Same credential must not keep retrying an expired session.
        if now < body.get("retry_at", 0):
            return body
        ttl = 5 if for_request and body.get("status") == "ready" else 3600
        if 0 <= now - old["at"] < ttl:
            if body.get("status") == "ready":
                budget.funding = body
            return body
    # Reserve the check before network I/O; concurrent processes and crashes wait
    # for an hour rather than flooding the console or reusing an old positive check.
    with budget.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        newer = db.execute("SELECT at FROM funding WHERE key=?", (identity,)).fetchone()
        if newer and (not old or newer["at"] != old["at"]):
            return {"status": "unavailable", "reason": "funding_check_in_progress"}
        pending = {
            "status": "unavailable",
            "reason": "funding_check_in_progress",
            "checked_at": now,
        }
        db.execute(
            "INSERT OR REPLACE INTO funding VALUES (?,?,?)", (identity, now, json.dumps(pending))
        )
    try:
        # Check the inference credential too, without spending inference tokens.
        models = json.loads(
            await bounded_text(
                client,
                "GET",
                "https://api.typesafe.ai/v1/models",
                headers={"Authorization": "Bearer " + api_key},
            )
        )
        model = budget.policy["providers"]["jev"]["model"]
        names = {m["name"] for m in models["models"]}
        # Official /models currently lists aliases only. Fixed IDs are accepted
        # even when absent from that list (docs.typesafe.ai/models#listing-models).
        documented_alias = {"jev-1.13.0": "jev-latest", "jev-1.14.0": "jev-preview"}.get(model)
        if model not in names and documented_alias not in names:
            raise FundingUnavailableError("funded_model_unavailable")
        headers = {"User-Agent": "Hardshell/0.1 funding-monitor", "Cookie": cookie}
        action = (
            cached_action["action"] if cached_action and now - cached_action["at"] < 43200 else None
        )
        page = "" if action else await bounded_text(client, "GET", BILLING, headers=headers)
        # At most 12 static chunks; no third-party script or cookie forwarding.
        for source in list(dict.fromkeys(re.findall(r'<script\b[^>]*\bsrc=["\']([^"\']+)', page)))[
            :12
        ]:
            url = urljoin(ORIGIN, source)
            parsed = urlparse(url)
            if (
                parsed.scheme != "https"
                or parsed.netloc != "console.typesafe.ai"
                or not parsed.path.endswith(".js")
            ):
                continue
            chunk = await bounded_text(client, "GET", url)
            found = re.search(r'"([0-9a-f]{40,})"[^)]{0,150}"getBillingOverviewResult"', chunk)
            if found:
                action = found[1]
                with budget.connect() as db:
                    db.execute(
                        "INSERT OR REPLACE INTO funding_actions VALUES (?,?,?)",
                        (identity, now, action),
                    )
                break
        if not action:
            raise FundingUnavailableError("funding_interface_unavailable")
        text = await bounded_text(
            client,
            "POST",
            BILLING,
            headers={
                **headers,
                "Origin": ORIGIN,
                "Next-Action": action,
                "Accept": "text/x-component",
                "Content-Type": "application/json",
            },
            content="[]",
        )
        funds = parse_billing(text, now)
        required = int(
            Decimal(str(budget.policy["providers"]["jev"]["monthly"]["usd"])) * 1_000_000_000
        )
        if funds["usable_nano_usd"] < max(required, 1):
            raise FundingUnavailableError("provider_funds_insufficient")
        if funds["expires_at"] < now + 86400:
            raise FundingUnavailableError("provider_funds_expiring")
        body = {"status": "ready", "checked_at": now, **funds}
    except FundingUnavailableError as exc:
        body = {
            "status": "unavailable",
            "reason": str(exc),
            "checked_at": now,
            "retry_at": now + exc.retry_after,
        }
    except (httpx.HTTPError, ValueError, KeyError, TypeError, UnicodeError):
        body = {"status": "unavailable", "reason": "funding_check_failed", "checked_at": now}
    with budget.connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO funding VALUES (?,?,?)", (identity, now, json.dumps(body))
        )
    budget.funding = body
    return body
