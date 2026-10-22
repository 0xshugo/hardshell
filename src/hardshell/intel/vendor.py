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
ATOM = "{http://www.w3.org/2005/Atom}"
PHP = "{http://php.net/ns/releases}"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b")
VERSION = re.compile(r"\d+\.\d+\.\d+")


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
    try:
        news = await bounded_text(client, "https://www.php.net/feed.atom")
        notices = preannouncements(news)
        advisories.update(news_advisories(news, entries))
    except (httpx.HTTPError, TimeoutError, ValueError, ET.ParseError, SourceDeferredError):
        gaps.append({"source": "php.net/feed.atom", "reason": "preannouncement_feed_unavailable"})
    for entry in entries:
        if any(entry["version"] in a["fixed_versions"] for a in advisories.values()):
            continue
        try:
            text = plain(await bounded_text(client, entry["url"]))
            cves = sorted(set(CVE.findall(text)))
            if not cves:
                raise ValueError("missing_cve_details")
            for cve in cves:
                item = advisories.setdefault(
                    cve,
                    {
                        "id": cve,
                        "product": "php",
                        "source": "php.net",
                        "published_at": entry["published_at"],
                        "fixed_versions": [],
                        "references": [],
                        "public_summary": text[:2000],
                    },
                )
                item["fixed_versions"].append(entry["version"])
                item["references"].append(entry["url"])
        except (httpx.HTTPError, TimeoutError, ValueError, SourceDeferredError):
            gaps.append({"source": entry["url"], "reason": "vendor_details_unavailable"})
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
