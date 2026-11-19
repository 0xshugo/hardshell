"""Unit tests for bounded OSV.dev / GHSA advisory lookup & matching."""

from __future__ import annotations

import json

import httpx
import pytest

from hardshell.intel.osv import (
    MAX_OSV_BYTES,
    SOLO_STACK_PACKAGES,
    fetch_osv_advisories,
    match_osv_advisories,
    parse_osv_response,
)


def test_parse_osv_response_handles_cve_less_ghsa_and_filters_refs():
    payload = {
        "vulns": [
            {
                "id": "GHSA-9999-xxxx-yyyy",
                "aliases": [],
                "published": "2026-01-10T00:00:00Z",
                "summary": "Critical RCE in workflow expression evaluation",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "n8n"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "1.121.0"}],
                            }
                        ],
                    }
                ],
                "references": [
                    {"url": "https://github.com/n8n-io/n8n/security/advisories/GHSA-9999-xxxx-yyyy"},
                    {"url": "http://insecure.example.invalid/advisory"},
                ],
            }
        ]
    }
    advisories = parse_osv_response(
        payload, product="n8n", package_name="n8n", observed_at="2026-01-11T00:00:00Z"
    )
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv["id"] == "GHSA-9999-xxxx-yyyy"
    assert adv["cves"] == []
    assert adv["severity"] == "critical"
    assert adv["fixed_versions"] == ["1.121.0"]
    assert adv["references"] == [
        "https://github.com/n8n-io/n8n/security/advisories/GHSA-9999-xxxx-yyyy"
    ]
    assert "n8n" in SOLO_STACK_PACKAGES
    assert "coolify" in SOLO_STACK_PACKAGES


def test_match_osv_advisories_fail_closed_states():
    advisories = [
        {
            "id": "GHSA-crit-0001",
            "cves": [],
            "product": "n8n",
            "severity": "critical",
            "fixed_versions": ["1.121.0"],
            "references": ["https://github.com/n8n-io/n8n/security/advisories/GHSA-crit-0001"],
            "public_summary": "Expression RCE",
        },
        {
            "id": "GHSA-nofix-0002",
            "cves": ["CVE-2026-0001"],
            "product": "n8n",
            "severity": "high",
            "fixed_versions": [],
            "references": [],
            "public_summary": "Unfixed issue",
        },
    ]

    public_old = {
        "asset_id": "container:n8n",
        "product": "n8n",
        "version": "1.120.4",
        "image_digest": "sha256:abc",
        "exposure": "public",
    }
    cases = match_osv_advisories(public_old, advisories)
    by_id = {c["advisory_id"]: c for c in cases}
    assert by_id["GHSA-crit-0001"]["status"] == "actionable"
    assert by_id["GHSA-crit-0001"]["priority"] == "P0"
    assert by_id["GHSA-crit-0001"]["requires_approval"] is True
    assert by_id["GHSA-crit-0001"]["executable"] is False
    assert by_id["GHSA-nofix-0002"]["status"] == "needs_evidence"
    assert by_id["GHSA-nofix-0002"]["priority"] == "P2"

    local_old = {**public_old, "exposure": "local"}
    local_cases = {c["advisory_id"]: c for c in match_osv_advisories(local_old, advisories)}
    assert local_cases["GHSA-crit-0001"]["status"] == "potentially_affected"
    assert local_cases["GHSA-crit-0001"]["priority"] == "P1"

    patched = {**public_old, "version": "1.121.0"}
    patched_ids = {c["advisory_id"] for c in match_osv_advisories(patched, advisories)}
    assert "GHSA-crit-0001" not in patched_ids
    assert "GHSA-nofix-0002" in patched_ids


async def test_fetch_osv_advisories_success_and_bounds():
    sample = {
        "vulns": [
            {
                "id": "GHSA-test-1234",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "Packagist", "name": "coollabsio/coolify"},
                        "ranges": [{"events": [{"fixed": "4.0.0-beta.460"}]}],
                    }
                ],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        assert body["package"]["name"] == "coollabsio/coolify"
        return httpx.Response(200, json=sample)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        res = await fetch_osv_advisories(
            product="coolify",
            ecosystem="Packagist",
            package_name="coollabsio/coolify",
            client=client,
        )
    assert len(res) == 1
    assert res[0]["id"] == "GHSA-test-1234"
    assert res[0]["severity"] == "high"

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(503, text="unavailable"))
    ) as client:
        with pytest.raises(RuntimeError, match="osv_http_503"):
            await fetch_osv_advisories(
                product="n8n", ecosystem="npm", package_name="n8n", client=client
            )

    oversized = b"x" * (MAX_OSV_BYTES + 10)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=oversized))
    ) as client:
        with pytest.raises(ValueError, match="osv_response_too_large"):
            await fetch_osv_advisories(
                product="n8n", ecosystem="npm", package_name="n8n", client=client
            )
