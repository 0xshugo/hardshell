"""FIRST.org EPSS (Exploit Prediction Scoring System) API client."""

from __future__ import annotations

import httpx

from hardshell.models import Finding

EPSS_API = "https://api.first.org/data/v1/epss"


async def enrich_epss(findings: list[Finding]) -> None:
    """Enrich findings that have CVE IDs with EPSS scores."""
    cve_findings = [f for f in findings if f.is_cve]
    if not cve_findings:
        return

    # Batch CVEs (API limit ~100 per request)
    for batch in _chunks(cve_findings, 100):
        cve_ids = [f.id for f in batch]
        cve_map = {f.id: f for f in batch}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(EPSS_API, params={"cve": ",".join(cve_ids)})
                resp.raise_for_status()
                data = resp.json()

                for entry in data.get("data", []):
                    cve_id = entry.get("cve")
                    if cve_id in cve_map:
                        cve_map[cve_id].epss_score = float(entry.get("epss", 0))
                        cve_map[cve_id].epss_percentile = float(entry.get("percentile", 0))
        except (httpx.HTTPError, KeyError, ValueError):
            pass  # Graceful degradation — enrichment is best-effort


def _chunks(lst: list, n: int):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
