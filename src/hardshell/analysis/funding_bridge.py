"""Nonce-bound signed funding evidence from the Mac mini; no console session on VPS."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import secrets
import subprocess
import tempfile
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse

import httpx


def verify_signature(payload, signature, public_key):
    raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    signed = base64.b64decode(signature, validate=True)
    if len(signed) != 256:
        raise ValueError("invalid_signature_size")
    with tempfile.TemporaryDirectory(prefix="hardshell-funding-") as directory:
        path = Path(directory)
        (path / "public.pem").write_bytes(public_key)
        (path / "signature").write_bytes(signed)
        check = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(path / "public.pem"),
                "-signature",
                str(path / "signature"),
            ],
            input=raw,
            capture_output=True,
            timeout=3,
        )
        if check.returncode:
            raise ValueError("invalid_funding_signature")


async def check_bridge(budget, *, api_key, url, client, for_request=False):
    if not api_key:
        return {"status": "unavailable", "reason": "provider_funding_credentials_missing"}
    parsed = urlparse(url)
    address = ipaddress.ip_address(parsed.hostname or "")
    if (
        parsed.scheme != "http"
        or address not in ipaddress.ip_network("100.64.0.0/10")
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.port != 18537
    ):
        raise ValueError("invalid_funding_bridge_url")
    key_path = budget.path.parent / "funding-public.pem"
    if key_path.stat().st_mode & 0o022 or key_path.stat().st_size > 8192:
        raise ValueError("unsafe_funding_public_key")
    public = key_path.read_bytes()
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    identity = hashlib.sha256((url + key_hash).encode() + public).hexdigest()
    now = budget.clock()
    with budget.connect() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS bridge_checks (key TEXT PRIMARY KEY, at REAL, body TEXT)"
        )
        old = db.execute("SELECT at,body FROM bridge_checks WHERE key=?", (identity,)).fetchone()
    if old:
        cached = json.loads(old["body"])
        age = now - cached.get("checked_at", old["at"])
        ttl = 5 if for_request else 3600
        if cached["status"] != "ready":
            ttl = 60 if cached.get("reason") == "funding_bridge_unavailable" else 3600
        if 0 <= age < ttl:
            budget.funding = cached
            return cached
    nonce = secrets.token_hex(16)
    try:
        async with client.stream(
            "GET",
            url.rstrip("/") + "/v1/funding/jev",
            params={"nonce": nonce, "fresh": "1" if for_request else "0"},
            timeout=40,
            follow_redirects=False,
        ) as response:
            response.raise_for_status()
            body = bytearray()
            async for part in response.aiter_bytes():
                body.extend(part)
                if len(body) > 64 * 1024:
                    raise ValueError("funding_bridge_response_limit")
        envelope = json.loads(body)
        proof = envelope["payload"]
        verify_signature(proof, envelope["signature"], public)
        checked = proof.get("checked_at")
        if (
            proof.get("request_nonce") != nonce
            or proof.get("source") != "typesafe_console"
            or proof.get("api_key_sha256") != key_hash
            or type(checked) not in (int, float)
            or not math.isfinite(checked)
            or proof.get("status") not in ("ready", "unavailable")
        ):
            raise ValueError("unbound_funding_evidence")
        if proof["status"] == "ready":
            now = budget.clock()
            if not 0 <= now - checked <= (5 if for_request else 3600):
                raise ValueError("stale_funding_evidence")
            if any(
                type(proof.get(k)) is not int or proof[k] < 0
                for k in ("usable_nano_usd", "balance_nano_usd")
            ):
                raise ValueError("invalid_funding_amount")
            expires = proof.get("expires_at")
            if type(expires) not in (int, float) or not math.isfinite(expires):
                raise ValueError("invalid_credit_expiry")
            required = int(
                Decimal(str(budget.policy["providers"]["jev"]["monthly"]["usd"])) * 1_000_000_000
            )
            if proof["usable_nano_usd"] < max(required, 1):
                proof = {
                    "status": "unavailable",
                    "reason": "provider_funds_insufficient",
                    "checked_at": checked,
                }
            elif expires < now + 86400:
                proof = {
                    "status": "unavailable",
                    "reason": "provider_funds_expiring",
                    "checked_at": checked,
                }
        else:
            reason = proof.get("reason", "funding_provider_unavailable")
            if (
                not isinstance(reason, str)
                or not reason.replace("_", "").isalnum()
                or len(reason) > 100
            ):
                raise ValueError("invalid_failure_reason")
    except (
        httpx.HTTPError,
        TimeoutError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ):
        proof = {
            "status": "unavailable",
            "reason": "funding_bridge_unavailable",
            "checked_at": budget.clock(),
        }
    with budget.connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO bridge_checks VALUES (?,?,?)",
            (identity, now, json.dumps(proof)),
        )
    budget.funding = proof
    return proof
