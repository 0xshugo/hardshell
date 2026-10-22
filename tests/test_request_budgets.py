from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
import pytest

from hardshell.analysis.budget import BudgetDeniedError
from hardshell.analysis.budget import BudgetLedger as RealBudgetLedger
from hardshell.analysis.triage import review
from hardshell.intel.polite import PoliteSource, SourceDeferredError


def funded_ledger(*args, **kwargs):
    ledger = RealBudgetLedger(*args, **kwargs)
    ledger.funding = {
        "status": "ready",
        "checked_at": ledger.clock(),
        "usable_nano_usd": 10_000_000_000,
        "expires_at": ledger.clock() + 86400 * 30,
    }
    return ledger


def policy(calls=10, monthly_calls=100, inputs=655360):
    return {
        "providers": {
            "jev": {
                "enabled": True,
                "model": "jev-1.13.0",
                "price_valid_until": "2026-10-29T00:00:00Z",
                "daily": {
                    "calls": calls,
                    "input_tokens": inputs,
                    "output_tokens": 0,
                    "usd": "0.10",
                },
                "monthly": {
                    "calls": monthly_calls,
                    "input_tokens": 6553600,
                    "output_tokens": 0,
                    "usd": "1.00",
                },
            },
            "llm": {
                "enabled": True,
                "model": "local-test",
                "cost_mode": "local_nonbillable",
                "daily": {"calls": 10, "input_tokens": 81920, "output_tokens": 5000, "usd": "0"},
                "monthly": {
                    "calls": 100,
                    "input_tokens": 819200,
                    "output_tokens": 50000,
                    "usd": "0",
                },
            },
        }
    }


def clock():
    return datetime(2026, 10, 22, tzinfo=UTC).timestamp()


def payload(i=0):
    return {"model": "jev-1.13.0", "state": str(i)}


@pytest.mark.asyncio
async def test_missing_budget_never_calls_paid_api():
    calls = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: calls.append(request) or httpx.Response(500))
    ) as client:
        decision = await review(
            {
                "product": "php",
                "installed": "8.4.21",
                "fixed": "8.4.27",
                "advisory_id": "CVE-2026-109618",
                "status": "potentially_affected",
            },
            client=client,
            jev_key="test",
        )
    assert calls == []
    assert decision["jev"]["reason"] == "budget_not_configured"


def test_reservations_survive_restart_and_failure_without_refund(tmp_path):
    ledger = funded_ledger(tmp_path, policy(calls=1), clock=clock)
    ticket = ledger.admit("jev", "jev-1.13.0", payload(), "https://api.typesafe.ai/v1/systemone")
    ledger.finish(ticket)
    restarted = funded_ledger(tmp_path, policy(calls=1), clock=clock)
    with pytest.raises(BudgetDeniedError, match="daily_budget_exhausted"):
        restarted.admit("jev", "jev-1.13.0", payload(1), "https://api.typesafe.ai/v1/systemone")
    assert restarted.totals()[0]["input_reserved"] == 65536


def test_monthly_and_input_and_dollar_limits_apply_before_request(tmp_path):
    for kind in ("month", "input", "dollar"):
        config = policy()
        cap = config["providers"]["jev"]
        if kind == "month":
            cap["monthly"]["calls"] = 0
        elif kind == "input":
            cap["daily"]["input_tokens"] = 65535
        else:
            cap["monthly"]["usd"] = "0.001"
        ledger = funded_ledger(tmp_path / kind, config, clock=clock)
        with pytest.raises(BudgetDeniedError, match="budget_exhausted"):
            ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
        assert ledger.totals() == []


def test_same_input_is_cached_across_restart_without_new_reservation(tmp_path):
    ledger = funded_ledger(tmp_path, policy(calls=1), clock=clock)
    ticket = ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
    ledger.finish(ticket, {"answers": {}, "usage": {"input_tokens": 100}})
    result = funded_ledger(tmp_path, policy(calls=1), clock=clock).admit(
        "jev", "jev-1.13.0", payload(), "endpoint"
    )
    assert result["cached"]["usage"]["input_tokens"] == 100
    assert ledger.totals()[0]["calls"] == 1


def test_parallel_admission_does_not_overspend(tmp_path):
    config = policy(calls=1)
    funded_ledger(tmp_path, config, clock=clock)

    def attempt(i):
        try:
            return funded_ledger(tmp_path, config, clock=clock).admit(
                "jev", "jev-1.13.0", payload(i), "endpoint"
            )
        except BudgetDeniedError:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        result = list(executor.map(attempt, range(4)))
    assert sum(item is not None for item in result) == 1


def test_price_expiry_unknown_model_and_usage_violation_fail_closed(tmp_path):
    ledger = funded_ledger(tmp_path, policy(), clock=clock)
    with pytest.raises(BudgetDeniedError):
        ledger.admit("jev", "jev-latest", {"model": "jev-latest"}, "endpoint")
    ticket = ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
    with pytest.raises(BudgetDeniedError, match="usage_contract_violation"):
        ledger.finish(ticket, {"usage": {"input_tokens": 65537}})
    with pytest.raises(BudgetDeniedError, match="usage_contract_violation"):
        funded_ledger(tmp_path, policy(), clock=clock).admit(
            "jev", "jev-1.13.0", payload(1), "endpoint"
        )
    expired = funded_ledger(tmp_path / "expired", policy(), clock=lambda: clock() + 10 * 86400)
    with pytest.raises(BudgetDeniedError, match="price_quote_expired"):
        expired.admit("jev", "jev-1.13.0", payload(), "endpoint")


@pytest.mark.asyncio
async def test_etag_304_and_persistent_minimum_interval(tmp_path):
    at = [clock()]
    seen = []

    def handle(request):
        seen.append(request)
        if len(seen) > 1:
            assert request.headers["if-none-match"] == "version-one"
            assert "if-modified-since" in request.headers
            return httpx.Response(304)
        return httpx.Response(
            200,
            text="public-feed",
            headers={"ETag": "version-one", "Last-Modified": "Wed, 21 Oct 2026 00:00:00 GMT"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        source = PoliteSource(client, tmp_path, clock=lambda: at[0], jitter=lambda: 0)
        assert await source.text("https://www.php.net/feed.atom") == "public-feed"
        at[0] += 1800
        restarted = PoliteSource(client, tmp_path, clock=lambda: at[0], jitter=lambda: 0)
        assert await restarted.text("https://www.php.net/feed.atom") == "public-feed"
        assert len(seen) == 1
        at[0] += 1800
        assert await restarted.text("https://www.php.net/feed.atom") == "public-feed"
    assert len(seen) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 429, 503])
async def test_origin_error_does_not_retry_or_switch_urls_immediately(tmp_path, status):
    seen = []
    at = [clock()]
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: seen.append(r) or httpx.Response(status, headers={"Retry-After": "7200"})
        )
    ) as client:
        source = PoliteSource(client, tmp_path, clock=lambda: at[0], jitter=lambda: 0)
        with pytest.raises(SourceDeferredError):
            await source.text("https://www.php.net/feed.atom")
        at[0] += 3601
        if status == 403:
            at[0] += 100 * 86400
        with pytest.raises(SourceDeferredError):
            await PoliteSource(client, tmp_path, clock=lambda: at[0], jitter=lambda: 0).text(
                "https://www.php.net/releases/feed.php"
            )
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_origin_hour_and_rolling_daily_caps(tmp_path):
    at = [clock()]
    seen = []
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: seen.append(r) or httpx.Response(200, text="public")
        )
    ) as client:
        source = PoliteSource(client, tmp_path, clock=lambda: at[0], jitter=lambda: 0)
        for i in range(60):
            if i and i % 4 == 0:
                at[0] += 3601
            await source.text(f"https://www.php.net/releases/{i}.php")
            if i == 3:
                with pytest.raises(SourceDeferredError):
                    await source.text("https://www.php.net/releases/excess-hour.php")
        at[0] += 3601
        with pytest.raises(SourceDeferredError):
            await source.text("https://www.php.net/releases/excess-day.php")
    assert len(seen) == 60


@pytest.mark.asyncio
async def test_legacy_weekly_analysis_cannot_bypass_budgets(monkeypatch):
    import asyncio

    from hardshell.analysis.llm import analyze
    from hardshell.models import ScanResult

    def forbidden(*args, **kwargs):
        raise AssertionError("unmetered external CLI execution")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    assert "deferred" in await analyze(ScanResult())


@pytest.mark.asyncio
async def test_same_case_twice_makes_one_paid_request(tmp_path):
    calls = []
    case = {
        "product": "php",
        "installed": "8.4.21",
        "fixed": "8.4.27",
        "advisory_id": "CVE-2026-109618",
        "status": "potentially_affected",
    }
    answer = {
        "answers": {
            "relevance": {
                "type": "choice",
                "choice": "review",
                "confidence": 1,
                "probabilities": {"review": 1, "unrelated": 0, "uncertain": 0},
            }
        },
        "usage": {"input_tokens": 1000, "output_tokens": 20},
    }
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200, json=answer))
    ) as client:
        for _ in range(2):
            result = await review(
                case,
                jev_key="test",
                client=client,
                budget=funded_ledger(tmp_path, policy(), clock=clock),
            )
            assert result["jev"]["choice"] == "review"
    assert len(calls) == 1


def test_unconfirmed_provider_billing_cap_blocks_external_ai(tmp_path):
    config = policy()
    config["providers"]["jev"]["provider_budget_confirmed"] = False
    ledger = RealBudgetLedger(tmp_path, config, clock=clock)
    with pytest.raises(BudgetDeniedError, match="provider_funds_unverified"):
        ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
    assert ledger.totals() == []


@pytest.mark.asyncio
async def test_full_php_fetch_reuses_cache_without_extra_network_requests(tmp_path):
    from hardshell.intel.vendor import fetch_php

    feed = """<feed xmlns="http://www.w3.org/2005/Atom" xmlns:php="http://php.net/ns/releases">
    <entry><php:version>8.4.27</php:version><php:tag>security</php:tag>
    <published>2026-10-21T00:00:00Z</published></entry></feed>"""
    news = """<feed xmlns="http://www.w3.org/2005/Atom"><entry>
    <title>Security advisory: Critical PHP vulnerabilities</title>
    <id>https://www.php.net/archive/2026.php#2026-10-21-5</id>
    <published>2026-10-21T00:35:00Z</published>
    <content>PHP 8.4.27 fixes CVE-2026-109618 and CVE-2026-109619</content>
    </entry></feed>"""
    seen = []

    def handle(request):
        seen.append(request.url.path)
        return httpx.Response(200, text=feed if request.url.path.endswith("feed.php") else news)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        one = await fetch_php(client, cache_dir=tmp_path)
        two = await fetch_php(client, cache_dir=tmp_path)
    assert len(one["advisories"]) == len(two["advisories"]) == 2
    assert one["observed_at"] == two["observed_at"]
    assert seen == ["/releases/feed.php", "/feed.atom"]
    assert all(item["mode"] == "cached" for item in two["source_requests"])
