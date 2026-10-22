import json

import httpx
import pytest

from hardshell.analysis.budget import BudgetDeniedError, BudgetLedger
from hardshell.analysis.funding import check_funding
from tests.test_request_budgets import clock, payload, policy


def transport(
    *, balance=10, expires="2026-12-01T00:00:00Z", status=200, calls=None, retry_after="3600"
):
    def handle(request):
        calls.append(request)
        if request.url.host == "api.typesafe.ai":
            assert request.url.path == "/v1/models"
            return httpx.Response(200, json={"models": [{"name": "jev-latest"}]})
        assert request.url.host == "console.typesafe.ai"
        if request.url.path.endswith(".js"):
            assert "cookie" not in request.headers
            return httpx.Response(200, text='"' + "a" * 40 + '","getBillingOverviewResult"')
        if request.method == "GET":
            return httpx.Response(200, text='<script src="/billing.js"></script>')
        assert request.content == b"[]"
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": retry_after})
        billing = {
            "balance": balance,
            "credits": [{"remaining": balance, "expiresAt": expires}],
        }
        return httpx.Response(
            200, text="1:" + json.dumps({"ok": True, "data": {"billing": billing}})
        )

    return httpx.MockTransport(handle)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "balance,expires,status,reason",
    [
        (0, "2026-12-01T00:00:00Z", 200, "provider_funds_insufficient"),
        (10, "2026-10-21T00:00:00Z", 200, "provider_funds_insufficient"),
        (10, "2026-10-22T01:00:00Z", 200, "provider_funds_expiring"),
        (10, "2026-12-01T00:00:00Z", 403, "funding_authentication_required"),
        (10, "2026-12-01T00:00:00Z", 429, "funding_rate_limited"),
    ],
)
async def test_insufficient_expired_or_unavailable_funds_never_admit(
    tmp_path, balance, expires, status, reason
):
    calls = []
    ledger = BudgetLedger(tmp_path, policy(), clock=clock)
    async with httpx.AsyncClient(
        transport=transport(balance=balance, expires=expires, status=status, calls=calls)
    ) as client:
        result = await check_funding(
            ledger, api_key="test-key", cookie="test-session", client=client
        )
        assert result["reason"] == reason
        with pytest.raises(BudgetDeniedError, match="provider_funds_unverified"):
            ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
        count = len(calls)
        restarted = BudgetLedger(tmp_path, policy(), clock=clock)
        assert (
            await check_funding(
                restarted,
                api_key="test-key",
                cookie="test-session",
                client=client,
                for_request=True,
            )
        )["reason"] == reason
        assert len(calls) == count
    assert ledger.totals() == []


@pytest.mark.asyncio
async def test_live_balance_is_rechecked_before_new_paid_request_and_expired_proof_blocks(tmp_path):
    at = [clock()]
    calls = []
    ledger = BudgetLedger(tmp_path, policy(), clock=lambda: at[0])
    async with httpx.AsyncClient(transport=transport(calls=calls)) as client:
        result = await check_funding(
            ledger, api_key="test-key", cookie="test-session", client=client
        )
        assert result["usable_nano_usd"] == 10_000_000_000
        ledger.finish(
            ledger.admit("jev", "jev-1.13.0", payload(), "endpoint"),
            {"usage": {"input_tokens": 10}},
        )
        at[0] += 6
        with pytest.raises(BudgetDeniedError, match="provider_funds_unverified"):
            ledger.admit("jev", "jev-1.13.0", payload(1), "endpoint")
        await check_funding(
            ledger, api_key="test-key", cookie="test-session", client=client, for_request=True
        )
        assert len(calls) == 6  # First discovery 4, subsequent model+balance check 2.
        ledger.admit("jev", "jev-1.13.0", payload(1), "endpoint")
    assert ledger.totals()[0]["calls"] == 2
    assert "test-key" not in ledger.path.read_bytes().decode(errors="ignore")
    assert "test-session" not in ledger.path.read_bytes().decode(errors="ignore")


@pytest.mark.asyncio
async def test_missing_credentials_and_policy_boolean_cannot_authorize_paid_requests(tmp_path):
    calls = []
    config = policy()
    config["providers"]["jev"]["provider_budget_confirmed"] = True
    ledger = BudgetLedger(tmp_path, config, clock=clock)
    async with httpx.AsyncClient(transport=transport(calls=calls)) as client:
        assert (await check_funding(ledger, client=client))["status"] == "unavailable"
    with pytest.raises(BudgetDeniedError, match="provider_funds_unverified"):
        ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status,elapsed", [(403, 86400 * 30), (429, 7201)])
async def test_expired_session_stops_until_credentials_change_and_retry_after_is_honored(
    tmp_path, status, elapsed
):
    at = [clock()]
    calls = []
    ledger = BudgetLedger(tmp_path, policy(), clock=lambda: at[0])
    async with httpx.AsyncClient(
        transport=transport(status=status, calls=calls, retry_after="10800")
    ) as client:
        await check_funding(ledger, api_key="test-key", cookie="test-session", client=client)
        count = len(calls)
        at[0] += elapsed
        await check_funding(ledger, api_key="test-key", cookie="test-session", client=client)
        assert len(calls) == count


def test_watch_writes_budget_failure_and_keeps_detection_report(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import hardshell.early_warning as warning
    from hardshell.cli import app
    from hardshell.intel import vendor

    async def intel(**kwargs):
        return {"advisories": [], "gaps": []}

    monkeypatch.setattr(vendor, "fetch_php", intel)
    monkeypatch.setattr(warning, "collect_php", lambda: {"runtimes": [], "gaps": []})
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["watch", "--ai", "-o", str(output)])
    assert result.exit_code == 3
    report = json.loads(output.read_text())
    assert report["ai_readiness"]["jev"]["reason"] == "provider_funding_credentials_missing"
    assert "cases" in report
