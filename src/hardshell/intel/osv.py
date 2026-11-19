"""Bounded OSV.dev / GHSA advisory lookup & matching for CVE-less advisories.

Covers GitHub Security Advisories (GHSA-*) that may not have CVE identifiers
(e.g., n8n, Coolify, Traefik, Caddy, and ecosystem packages). Never claims
complete coverage when upstream data or version ranges are unavailable.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_OSV_BYTES = 512 * 1024  # 512 KiB bounded response
SEMVER_CORE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")

# Default OSV ecosystem/package targets for common self-hosted VPS stacks.
SOLO_STACK_PACKAGES: dict[str, dict[str, str]] = {
    "n8n": {"ecosystem": "npm", "name": "n8n"},
    "coolify": {"ecosystem": "Packagist", "name": "coollabsio/coolify"},
    "traefik": {"ecosystem": "Go", "name": "github.com/traefik/traefik/v3"},
    "caddy": {"ecosystem": "Go", "name": "github.com/caddyserver/caddy/v2"},
}


def parse_semver_tuple(version: str) -> tuple[int, int, int] | None:
    if not isinstance(version, str):
        return None
    match = SEMVER_CORE.match(version.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _extract_severity(vuln: dict) -> str:
    db_spec = vuln.get("database_specific")
    if isinstance(db_spec, dict):
        sev = str(db_spec.get("severity") or "").lower()
        if sev in {"critical", "high", "moderate", "medium", "low"}:
            return "medium" if sev == "moderate" else sev
    return "unknown"


def _extract_fixed_versions(vuln: dict, package_name: str) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if package_name and pkg.get("name") and pkg.get("name") != package_name:
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                    fixed.append(ev["fixed"])
    return sorted(set(fixed))


def parse_osv_response(
    raw_payload: dict,
    *,
    product: str,
    package_name: str = "",
    observed_at: str | None = None,
) -> list[dict]:
    """Normalize an OSV /v1/query JSON payload into Hardshell advisory records."""
    if not isinstance(raw_payload, dict):
        raise ValueError("invalid_osv_payload")
    vulns = raw_payload.get("vulns")
    if vulns is None:
        return []
    if not isinstance(vulns, list):
        raise ValueError("invalid_osv_vulns")

    stamp = observed_at or datetime.now(UTC).isoformat()
    advisories: list[dict] = []
    for vuln in vulns[:100]:
        if not isinstance(vuln, dict):
            continue
        adv_id = str(vuln.get("id") or "").strip()
        if not adv_id:
            continue
        aliases = [a for a in (vuln.get("aliases") or []) if isinstance(a, str)]
        cves = sorted(a for a in aliases if a.startswith("CVE-"))
        refs = [
            r["url"]
            for r in (vuln.get("references") or [])
            if isinstance(r, dict)
            and isinstance(r.get("url"), str)
            and r["url"].startswith("https://")
        ][:8]
        fixed_versions = _extract_fixed_versions(vuln, package_name)
        summary = str(vuln.get("summary") or vuln.get("details") or "")[:2000]
        advisories.append(
            {
                "id": adv_id,
                "aliases": aliases,
                "cves": cves,
                "product": product,
                "source": "osv.dev",
                "severity": _extract_severity(vuln),
                "published_at": vuln.get("published") or "",
                "observed_at": stamp,
                "fixed_versions": fixed_versions,
                "references": refs,
                "public_summary": summary,
            }
        )
    return advisories


def match_osv_advisories(
    asset: dict,
    advisories: list[dict],
) -> list[dict]:
    """Match a runtime asset against normalized OSV/GHSA advisories (fail-closed)."""
    installed = str(asset.get("version") or "").strip()
    installed_tuple = parse_semver_tuple(installed)
    product = str(asset.get("product") or "").strip()
    exposure = str(asset.get("exposure") or "unknown").strip()
    asset_id = str(asset.get("asset_id") or "").strip()

    cases: list[dict] = []
    for advisory in advisories:
        if advisory.get("product") != product:
            continue
        fixed_versions = [
            v for v in (advisory.get("fixed_versions") or []) if parse_semver_tuple(v) is not None
        ]
        if installed_tuple is not None and fixed_versions:
            threshold = min(fixed_versions, key=lambda v: parse_semver_tuple(v) or (0, 0, 0))
            threshold_tuple = parse_semver_tuple(threshold)
            if threshold_tuple is not None and installed_tuple >= threshold_tuple:
                continue
        else:
            threshold = None

        sev = str(advisory.get("severity") or "unknown").lower()
        is_high = sev in {"critical", "high"}
        if threshold is None or installed_tuple is None:
            status = "needs_evidence"
            priority = "P2"
        elif exposure == "public" and is_high:
            status = "actionable"
            priority = "P0" if sev == "critical" else "P1"
        else:
            status = "potentially_affected"
            priority = "P1" if is_high else "P2"

        case_id = hashlib.sha256(
            json.dumps(
                [asset_id, asset.get("image_digest"), installed, advisory["id"]],
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        cases.append(
            {
                "case_id": case_id,
                "advisory_id": advisory["id"],
                "cves": advisory.get("cves", []),
                "asset_id": asset_id,
                "product": product,
                "installed": installed,
                "image_digest": asset.get("image_digest"),
                "exposure": exposure,
                "severity": sev,
                "fixed": threshold,
                "fixed_versions": fixed_versions,
                "status": status,
                "priority": priority,
                "references": advisory.get("references", []),
                "public_summary": advisory.get("public_summary", ""),
                "requires_approval": True,
                "executable": False,
            }
        )
    return cases


async def fetch_osv_advisories(
    *,
    product: str,
    ecosystem: str,
    package_name: str,
    version: str | None = None,
    client: httpx.AsyncClient | None = None,
    timeout_seconds: float = 10.0,
) -> list[dict]:
    """Query OSV.dev over bounded HTTPS for a single product/package."""
    body: dict[str, object] = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False)
    try:
        resp = await http.post(OSV_QUERY_URL, json=body, headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise RuntimeError(f"osv_http_{resp.status_code}")
        raw = resp.content
        if len(raw) > MAX_OSV_BYTES:
            raise ValueError("osv_response_too_large")
        data = json.loads(raw.decode("utf-8"))
        return parse_osv_response(data, product=product, package_name=package_name)
    finally:
        if owns_client:
            await http.aclose()
