"""Bounded official vendor acquisition, independent of scanner database lag."""

from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from hardshell.intel.polite import PoliteSource, SourceDeferredError

PHP_FEED = "https://www.php.net/releases/feed.php"
NGINX_ADVISORIES = "https://nginx.org/en/security_advisories.html"
ATOM = "{http://www.w3.org/2005/Atom}"
PHP = "{http://php.net/ns/releases}"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b")
VERSION = re.compile(r"\d+\.\d+\.\d+")
NGINX_RANGE = re.compile(r"(\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+)")
NGINX_FLOOR = re.compile(r"(\d+\.\d+\.\d+)\+")
NGINX_SEVERITY = re.compile(r"Severity:\s*(?:<b>)?(critical|major|medium|minor|low)(?:</b>)?", re.I)


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def plain(raw):
    parser = Text()
    parser.feed(raw)
    return " ".join(parser.parts)


def releases(raw):
    if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    root = ET.fromstring(raw)
    if root.tag != ATOM + "feed":
        raise ValueError("invalid_vendor_feed")
    output = []
    for entry in root.findall(ATOM + "entry")[:80]:
        version = entry.findtext(PHP + "version", "")
        if not VERSION.fullmatch(version) or entry.findtext(PHP + "tag") != "security":
            continue
        # Construct official URLs from validated versions; never follow feed-controlled hosts.
        output.append(
            {
                "version": version,
                "published_at": entry.findtext(ATOM + "published"),
                "url": "https://www.php.net/releases/" + version.replace(".", "_") + ".php",
            }
        )
    if not output:
        raise ValueError("missing_security_releases")
    # One current security release per maintained branch, not every historic release.
    latest = {}
    for item in output:
        branch = ".".join(item["version"].split(".")[:2])
        if branch not in latest or tuple(map(int, item["version"].split("."))) > tuple(
            map(int, latest[branch]["version"].split("."))
        ):
            latest[branch] = item
    return list(latest.values())[:8]


def preannouncements(raw, now=None):
    """Preserve CVE-less urgent notices until a later release notice supersedes them."""
    if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    root = ET.fromstring(raw)
    if root.tag != ATOM + "feed":
        raise ValueError("invalid_vendor_feed")
    now = now or datetime.now(UTC)
    pending, released = [], []
    for entry in root.findall(ATOM + "entry")[:80]:
        title = entry.findtext(ATOM + "title", "")
        date = entry.findtext(ATOM + "published", "")
        try:
            stamp = datetime.fromisoformat(date.replace("Z", "+00:00"))
        except ValueError:
            continue
        if stamp.tzinfo is None or stamp > now + timedelta(minutes=5):
            continue
        if now - stamp > timedelta(days=7):
            continue
        text = " ".join(entry.itertext())
        if "security" in title.lower() and CVE.search(text):
            released.append(stamp)
        if "upcoming" not in title.lower() or "critical" not in title.lower():
            continue
        url = entry.findtext(ATOM + "id", "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "www.php.net":
            continue
        pending.append(
            (
                stamp,
                {
                    "id": "PHP-NOTICE-" + stamp.date().isoformat(),
                    "product": "php",
                    "source": "php.net",
                    "published_at": date,
                    "fixed_versions": [],
                    "references": [url],
                    "public_summary": text[:2000],
                },
            )
        )
    return [notice for stamp, notice in pending if not any(date >= stamp for date in released)]


def _parse_iso_stamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo is not None else None


def _atom_release_info(raw: str) -> tuple[dict[str, str], set[str]]:
    """Extract exact release timestamps and ChangeLog-pointing versions from feed.atom."""
    if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    root = ET.fromstring(raw)
    if root.tag != ATOM + "feed":
        raise ValueError("invalid_vendor_feed")
    release_stamps: dict[str, str] = {}
    changelog_versions: set[str] = set()
    for entry in root.findall(ATOM + "entry")[:80]:
        title = entry.findtext(ATOM + "title", "")
        match = re.search(r"\bPHP\s+(\d+\.\d+\.\d+)\s+Released\b", title, re.I)
        if not match:
            continue
        version = match.group(1)
        published = entry.findtext(ATOM + "published", "")
        if published:
            release_stamps[version] = published
        text = " ".join(entry.itertext())
        if "changelog" in text.lower() and not CVE.search(text):
            changelog_versions.add(version)
    return release_stamps, changelog_versions


def _extract_changelog_section(raw: str, version: str) -> str:
    pattern = re.compile(
        rf'<section\b[^>]*\bid=["\']{re.escape(version)}["\'][^>]*>(.*?)</section>',
        re.I | re.S,
    )
    match = pattern.search(raw)
    if match:
        return plain(match.group(1))
    text = plain(raw)
    heading = re.search(rf"\bVersion\s+{re.escape(version)}\b", text)
    if not heading:
        return ""
    next_heading = re.search(r"\bVersion\s+\d+\.\d+\.\d+\b", text[heading.end() :])
    end = heading.end() + next_heading.start() if next_heading else len(text)
    return text[heading.start() : end]


def _cve_context_snippet(section_text: str, cve: str) -> str:
    compact = re.sub(r"\s+", " ", section_text).strip()
    idx = compact.find(cve)
    if idx == -1:
        return compact[:2000]
    prefix = compact[: idx + len(cve) + 2]
    start = max(prefix.rfind("Fixed GHSA-"), prefix.rfind("Fixed bug "), prefix.rfind("Fix "))
    if start == -1:
        start = max(0, idx - 200)
    end = min(len(compact), idx + len(cve) + 2)
    return compact[start:end].strip()[:2000]


def changelog_advisories(
    raw: str,
    entries: list[dict],
    *,
    changelog_url: str = "https://www.php.net/ChangeLog-8.php",
    published_overrides: dict[str, str] | None = None,
) -> dict[str, dict]:
    """Extract PHP CVEs for specific release versions from php.net ChangeLog-<major>.php."""
    if "<!DOCTYPE" in raw[:200].upper() and "<!ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    output: dict[str, dict] = {}
    published_overrides = published_overrides or {}
    for entry in entries:
        version = entry["version"]
        section_text = _extract_changelog_section(raw, version)
        if not section_text:
            continue
        cves = sorted(set(CVE.findall(section_text)))
        if not cves:
            continue
        published_at = published_overrides.get(version) or entry.get("published_at")
        ref = f"{changelog_url}#{version}"
        for cve in cves:
            item = output.setdefault(
                cve,
                {
                    "id": cve,
                    "product": "php",
                    "source": "php.net",
                    "published_at": published_at,
                    "fixed_versions": [],
                    "references": [],
                    "public_summary": _cve_context_snippet(section_text, cve),
                },
            )
            if version not in item["fixed_versions"]:
                item["fixed_versions"].append(version)
            if ref not in item["references"]:
                item["references"].append(ref)
    return output


def _merge_advisory(advisories: dict[str, dict], cve: str, incoming: dict) -> None:
    existing = advisories.get(cve)
    if existing is None:
        advisories[cve] = incoming
        return
    for ver in incoming.get("fixed_versions", []):
        if ver not in existing["fixed_versions"]:
            existing["fixed_versions"].append(ver)
    for ref in incoming.get("references", []):
        if ref not in existing["references"]:
            existing["references"].append(ref)
    if not existing.get("public_summary") and incoming.get("public_summary"):
        existing["public_summary"] = incoming["public_summary"]


def news_advisories(raw, entries):
    if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    root = ET.fromstring(raw)
    if root.tag != ATOM + "feed":
        raise ValueError("invalid_vendor_feed")
    output = {}
    for entry in root.findall(ATOM + "entry")[:80]:
        title = entry.findtext(ATOM + "title", "")
        if not title.lower().startswith("security advisory"):
            continue
        text = " ".join(entry.itertext())
        date = entry.findtext(ATOM + "published", "")
        url = entry.findtext(ATOM + "id", "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "www.php.net":
            continue
        fixes = [
            e["version"]
            for e in entries
            if date[:10] == (e["published_at"] or "")[:10]
            and re.search(r"(?<![0-9.])" + re.escape(e["version"]) + r"(?![0-9.])", text)
        ]
        for cve in sorted(set(CVE.findall(text))):
            if fixes:
                output[cve] = {
                    "id": cve,
                    "product": "php",
                    "source": "php.net",
                    "published_at": date,
                    "fixed_versions": fixes,
                    "references": [url],
                    "public_summary": text[:2000],
                }
    return output


async def bounded_text(client, url):
    if isinstance(client, PoliteSource):
        return await client.text(url)
    async with (
        asyncio.timeout(20),
        client.stream("GET", url, timeout=15, follow_redirects=False) as response,
    ):
        response.raise_for_status()
        body = bytearray()
        async for part in response.aiter_bytes():
            body.extend(part)
            if len(body) > 2 * 1024 * 1024:
                raise ValueError("vendor_body_too_large")
        return body.decode("utf-8", errors="replace")


def nginx_advisories(raw: str) -> list[dict]:
    """Parse nginx.org/en/security_advisories.html into normalized advisories."""
    if "<!DOCTYPE" in raw[:200].upper() and "ENTITY" in raw.upper():
        raise ValueError("unsafe_xml")
    output = []
    for block in re.findall(r"<li>\s*<p>(.*?)</p>\s*</li>", raw, flags=re.I | re.S):
        text = re.sub(r"<br\s*/?>", "\n", block, flags=re.I)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"[ \t]+", " ", text)
        cves = sorted(set(CVE.findall(text)))
        if not cves:
            continue
        floors = NGINX_FLOOR.findall(text)
        ranges = NGINX_RANGE.findall(text)
        if not floors or not ranges:
            continue
        sev = NGINX_SEVERITY.search(block) or NGINX_SEVERITY.search(text)
        severity = (sev.group(1).lower() if sev else "medium")
        title = text.strip().split("\n", 1)[0].strip()[:200]
        refs = ["https://nginx.org/en/security_advisories.html"]
        for match in re.findall(r'href="(https://(?:www\.cve\.org|my\.f5\.com)[^"]+)"', block):
            refs.append(match)
        for cve in cves:
            output.append(
                {
                    "id": cve,
                    "product": "nginx",
                    "source": "nginx.org",
                    "severity": severity,
                    "fixed_versions": floors,
                    "vulnerable_ranges": [list(pair) for pair in ranges],
                    "references": refs,
                    "public_summary": title,
                }
            )
    if not output:
        raise ValueError("missing_nginx_advisories")
    return output[:80]


def nginx_version_affected(
    installed: str, fixed_versions: list[str], vulnerable_ranges: list
) -> bool:
    """True when installed version falls in a vulnerable range and misses same-branch floors."""
    if not VERSION.fullmatch(installed):
        return False
    current = tuple(map(int, installed.split(".")))
    in_range = False
    for pair in vulnerable_ranges:
        if len(pair) != 2 or not all(VERSION.fullmatch(part) for part in pair):
            continue
        low, high = (tuple(map(int, part.split("."))) for part in pair)
        if low <= current <= high:
            in_range = True
            break
    if not in_range:
        return False
    for floor in fixed_versions:
        if not VERSION.fullmatch(floor):
            continue
        target = tuple(map(int, floor.split(".")))
        if current[:2] == target[:2] and current >= target:
            return False
    return True


async def fetch_nginx(client=None, *, cache_dir=None):
    if client is None:
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as owned:
            return await fetch_nginx(owned, cache_dir=cache_dir)
    if cache_dir is not None:
        client = PoliteSource(client, cache_dir)
    gaps = []
    advisories = []
    try:
        advisories = nginx_advisories(await bounded_text(client, NGINX_ADVISORIES))
    except (httpx.HTTPError, TimeoutError, ValueError, SourceDeferredError):
        gaps.append({"source": NGINX_ADVISORIES, "reason": "nginx_advisories_unavailable"})
    if isinstance(client, PoliteSource):
        gaps.extend(
            {"source": o["url"], "reason": o["deferred_reason"]}
            for o in client.snapshot()
            if o.get("deferred_reason")
        )
    return {
        "observed_at": (
            client.verified_at()
            if isinstance(client, PoliteSource)
            else datetime.now(UTC).isoformat()
        ),
        "source_requests": client.snapshot() if isinstance(client, PoliteSource) else [],
        "advisories": advisories,
        "gaps": gaps,
    }


async def fetch_php(client=None, *, cache_dir=None):
    if client is None:
        async with httpx.AsyncClient(follow_redirects=False, trust_env=False) as owned:
            return await fetch_php(owned, cache_dir=cache_dir)
    if cache_dir is not None:
        client = PoliteSource(client, cache_dir)
    entries = releases(await bounded_text(client, PHP_FEED))
    advisories = {}
    gaps = []
    notices = []
    release_stamps: dict[str, str] = {}
    changelog_versions: set[str] = set()
    try:
        news = await bounded_text(client, "https://www.php.net/feed.atom")
        notices = preannouncements(news)
        advisories.update(news_advisories(news, entries))
        release_stamps, changelog_versions = _atom_release_info(news)
    except (httpx.HTTPError, TimeoutError, ValueError, ET.ParseError, SourceDeferredError):
        gaps.append({"source": "php.net/feed.atom", "reason": "preannouncement_feed_unavailable"})
    needs_changelog: list[dict] = []
    for entry in entries:
        if any(entry["version"] in a["fixed_versions"] for a in advisories.values()):
            continue
        if entry["version"] in changelog_versions:
            needs_changelog.append(entry)
            continue
        try:
            text = plain(await bounded_text(client, entry["url"]))
            cves = sorted(set(CVE.findall(text)))
            if not cves:
                needs_changelog.append(entry)
                continue
            published_at = release_stamps.get(entry["version"]) or entry["published_at"]
            for cve in cves:
                _merge_advisory(
                    advisories,
                    cve,
                    {
                        "id": cve,
                        "product": "php",
                        "source": "php.net",
                        "published_at": published_at,
                        "fixed_versions": [entry["version"]],
                        "references": [entry["url"]],
                        "public_summary": text[:2000],
                    },
                )
        except (httpx.HTTPError, TimeoutError, ValueError, SourceDeferredError):
            gaps.append({"source": entry["url"], "reason": "vendor_details_unavailable"})
    if needs_changelog:
        by_major: dict[str, list[dict]] = {}
        for entry in needs_changelog:
            major = entry["version"].split(".", 1)[0]
            if major.isdigit():
                by_major.setdefault(major, []).append(entry)
            else:
                gaps.append({"source": entry["url"], "reason": "vendor_details_unavailable"})
        for major, group in by_major.items():
            changelog_url = f"https://www.php.net/ChangeLog-{major}.php"
            try:
                cl_raw = await bounded_text(client, changelog_url)
                parsed = changelog_advisories(
                    cl_raw,
                    group,
                    changelog_url=changelog_url,
                    published_overrides=release_stamps,
                )
                for cve, item in parsed.items():
                    _merge_advisory(advisories, cve, item)
                for entry in group:
                    resolved = any(
                        entry["version"] in a["fixed_versions"] for a in advisories.values()
                    )
                    if not resolved:
                        gaps.append(
                            {"source": entry["url"], "reason": "vendor_details_unavailable"}
                        )
            except (httpx.HTTPError, TimeoutError, ValueError, SourceDeferredError):
                gaps.append({"source": changelog_url, "reason": "vendor_details_unavailable"})
    if notices and advisories:
        resolved_exact = [
            stamp
            for a in advisories.values()
            if (
                a.get("published_at") in release_stamps.values()
                or any("/archive/" in ref for ref in a.get("references", []))
            )
            for stamp in [_parse_iso_stamp(a.get("published_at"))]
            if stamp is not None
        ]
        resolved_versions = {v for a in advisories.values() for v in a.get("fixed_versions", [])}
        resolved_dates = [
            stamp.date()
            for entry in entries
            if entry["version"] in resolved_versions
            for stamp in [_parse_iso_stamp(entry.get("published_at"))]
            if stamp is not None
        ]
        kept_notices = []
        for notice in notices:
            nstamp = _parse_iso_stamp(notice.get("published_at"))
            if nstamp is not None and (
                any(rstamp >= nstamp for rstamp in resolved_exact)
                or any(rdate > nstamp.date() for rdate in resolved_dates)
            ):
                continue
            kept_notices.append(notice)
        notices = kept_notices
    if isinstance(client, PoliteSource):
        gaps.extend(
            {"source": o["url"], "reason": o["deferred_reason"]}
            for o in client.snapshot()
            if o.get("deferred_reason")
        )
    return {
        "observed_at": (
            client.verified_at()
            if isinstance(client, PoliteSource)
            else datetime.now(UTC).isoformat()
        ),
        "source_requests": client.snapshot() if isinstance(client, PoliteSource) else [],
        "advisories": list(advisories.values()) + notices,
        "gaps": gaps,
    }
