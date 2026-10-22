import httpx
import pytest

from hardshell.analysis.budget import BudgetLedger
from hardshell.analysis.readiness import local_readiness
from tests.test_request_budgets import clock, funded_ledger, payload, policy


def test_budget_health_is_readonly_and_detects_exhaustion_and_quote_expiry(tmp_path):
    ledger = funded_ledger(tmp_path, policy(calls=1), clock=clock)
    assert ledger.readiness("jev")["status"] == "ready"
    assert ledger.totals() == []
    ticket = ledger.admit("jev", "jev-1.13.0", payload(), "endpoint")
    ledger.finish(ticket)
    assert ledger.readiness("jev")["reason"] == "daily_budget_exhausted"
    ledger.clock = lambda: clock() + 31 * 86400
    assert ledger.readiness("jev")["reason"] == "price_quote_expired"


@pytest.mark.asyncio
@pytest.mark.parametrize("present", [True, False])
async def test_local_health_has_no_inference_or_budget_reservation(tmp_path, present):
    ledger = BudgetLedger(tmp_path, policy(), clock=clock)

    def handle(request):
        assert request.method == "GET" and request.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "local-test" if present else "other"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await local_readiness(
            ledger, "http://127.0.0.1:11436/v1", "local-test", client=client
        )
    assert result["status"] == ("ready" if present else "unavailable")
    assert ledger.totals() == []
