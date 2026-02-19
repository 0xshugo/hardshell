"""CISA Known Exploited Vulnerabilities (KEV) catalog client."""

from __future__ import annotations

import httpx

from hardshell.models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def enrich_kev(findings: list[Finding]) -> None:
    """Mark findings that appear in the CISA KEV catalog."""
    cve_findings = [f for f in findings if f.is_cve]
    if not cve_findings:
        return

    try:
        kev_cves = await _fetch_kev_cves()
    except (httpx.HTTPError, KeyError, ValueError):
        return  # Graceful degradation

    for finding in cve_findings:
        if finding.id in kev_cves:
            finding.in_cisa_kev = True
            finding.has_public_exploit = True  # KEV implies active exploitation


async def _fetch_kev_cves() -> set[str]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(KEV_URL)
        resp.raise_for_status()
        data = resp.json()

    return {v["cveID"] for v in data.get("vulnerabilities", [])}
