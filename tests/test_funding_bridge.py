import base64
import hashlib
import json
import subprocess

import httpx
import pytest

from hardshell.analysis.budget import BudgetLedger
from hardshell.analysis.funding import check_funding
from tests.test_request_budgets import clock, policy


@pytest.fixture(scope="module")
def rsa(tmp_path_factory):
    path = tmp_path_factory.mktemp("rsa")
    private = path / "private.pem"
    subprocess.run(
        ["openssl", "genrsa", "-out", str(private), "2048"], check=True, capture_output=True
    )
    public = subprocess.run(
        ["openssl", "rsa", "-in", str(private), "-pubout"], check=True, capture_output=True
    ).stdout
    return private, public


def setup(tmp_path, monkeypatch, rsa):
    monkeypatch.setenv("HARDSHELL_FUNDING_URL", "http://100.80.158.82:18537")
    ledger = BudgetLedger(tmp_path, policy(), clock=clock)
    (tmp_path / "funding-public.pem").write_bytes(rsa[1])
    return ledger


def signed(rsa, request, **changes):
    # Neither an inference key nor a console credential is sent to the bridge.
    assert "authorization" not in request.headers and "cookie" not in request.headers
    assert "test-api-key" not in str(request.url)
    proof = dict(
        status="ready",
        source="typesafe_console",
        checked_at=clock(),
        usable_nano_usd=5_000_000_000,
        balance_nano_usd=5_000_000_000,
        expires_at=clock() + 30 * 86400,
        api_key_sha256=hashlib.sha256(b"test-api-key").hexdigest(),
        request_nonce=request.url.params["nonce"],
    )
    proof.update(changes)
    data = json.dumps(proof, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(rsa[0])],
        input=data,
        check=True,
        capture_output=True,
    ).stdout
    return dict(payload=proof, signature=base64.b64encode(signature).decode())


@pytest.mark.asyncio
async def test_real_signature_and_cache_preserve_observation(tmp_path, monkeypatch, rsa):
    ledger = setup(tmp_path, monkeypatch, rsa)
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(200, json=signed(rsa, request))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        first = await check_funding(ledger, api_key="test-api-key", client=client)
        ledger.clock = lambda: clock() + 60
        cached = await check_funding(ledger, api_key="test-api-key", client=client)
        assert first == cached and len(calls) == 1
        fresh = await check_funding(ledger, api_key="test-api-key", client=client, for_request=True)
        assert fresh["status"] == "unavailable"  # signed old observation cannot authorize a send
        assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change,reason",
    [
        ({"request_nonce": "wrong"}, "funding_bridge_unavailable"),
        ({"api_key_sha256": "0" * 64}, "funding_bridge_unavailable"),
        ({"checked_at": clock() - 6}, "funding_bridge_unavailable"),
        ({"checked_at": clock() + 10}, "funding_bridge_unavailable"),
        ({"usable_nano_usd": 0}, "provider_funds_insufficient"),
        ({"expires_at": clock() + 100}, "provider_funds_expiring"),
        ({"expires_at": float("inf")}, "funding_bridge_unavailable"),
        ({"usable_nano_usd": True}, "funding_bridge_unavailable"),
        ({"source": "manual"}, "funding_bridge_unavailable"),
        ({"status": "unavailable", "reason": "auth_required"}, "auth_required"),
    ],
)
async def test_signed_bad_evidence_cannot_enable_paid_calls(
    tmp_path, monkeypatch, rsa, change, reason
):
    ledger = setup(tmp_path, monkeypatch, rsa)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=signed(rsa, request, **change))
        )
    ) as client:
        result = await check_funding(
            ledger, api_key="test-api-key", client=client, for_request=True
        )
    assert result["status"] == "unavailable" and result["reason"] == reason
    assert ledger.totals() == []


@pytest.mark.asyncio
async def test_tamper_and_transport_failure_fail_closed(tmp_path, monkeypatch, rsa):
    ledger = setup(tmp_path, monkeypatch, rsa)

    def handle(request):
        data = signed(rsa, request)
        data["payload"]["usable_nano_usd"] *= 2
        return httpx.Response(200, json=data)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        result = await check_funding(ledger, api_key="test-api-key", client=client)
    assert result["status"] == "unavailable"
    ledger.clock = lambda: clock() + 61

    def offline(request):
        raise httpx.ConnectError("offline", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(offline)) as client:
        assert (await check_funding(ledger, api_key="test-api-key", client=client))[
            "status"
        ] == "unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:18537",
        "https://100.80.158.82:18537",
        "http://100.80.158.82:18537/?cookie=x",
        "http://100.80.158.82:80",
    ],
)
async def test_foreign_or_credential_bearing_url_never_contacted(tmp_path, monkeypatch, rsa, url):
    ledger = setup(tmp_path, monkeypatch, rsa)
    monkeypatch.setenv("HARDSHELL_FUNDING_URL", url)

    def unexpected(request):
        pytest.fail("invalid endpoint contacted")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
        assert (await check_funding(ledger, api_key="test-api-key", client=client))[
            "status"
        ] == "unavailable"
