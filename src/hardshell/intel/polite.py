"""Persistent per-origin request admission and conditional public-feed acquisition."""

from __future__ import annotations

import asyncio
import json
import random
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx


class SourceDeferredError(RuntimeError):
    pass


class PoliteSource:
    def __init__(
        self, client, directory, *, clock=time.time, jitter=lambda: random.uniform(0, 300)
    ):
        self.client, self.clock, self.jitter = client, clock, jitter
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / "source-cache.sqlite3"
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS urls (
                    url TEXT PRIMARY KEY, body TEXT, etag TEXT, modified TEXT,
                    verified REAL, next_at REAL NOT NULL, failures INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS attempts (origin TEXT, at REAL);
                CREATE TABLE IF NOT EXISTS origins (
                    origin TEXT PRIMARY KEY, blocked INTEGER NOT NULL DEFAULT 0,
                    next_at REAL NOT NULL DEFAULT 0);
            """)
        self.path.chmod(0o600)
        self.observations = []

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def admit(self, url):
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "www.php.net":
            raise ValueError("unapproved_source")
        origin, now = parsed.netloc, self.clock()
        interval = 3600 if parsed.path in ("/feed.atom", "/releases/feed.php") else 86400
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM urls WHERE url=?", (url,)).fetchone()
            gate = db.execute("SELECT * FROM origins WHERE origin=?", (origin,)).fetchone()
            if gate and (gate["blocked"] or gate["next_at"] > now):
                if row and row["body"] is not None:
                    return {**dict(row), "deferred_reason": "origin_blocked_or_cooling_down"}, False
                raise SourceDeferredError("origin_blocked_or_cooling_down")
            if row and row["next_at"] > now:
                if row["body"] is not None:
                    return {
                        **dict(row),
                        "deferred_reason": "source_cooling_down" if row["failures"] else None,
                    }, False
                raise SourceDeferredError("source_cooling_down")
            day, hour = db.execute(
                "SELECT SUM(at>?),SUM(at>?) FROM attempts WHERE origin=?",
                (now - 86400, now - 3600, origin),
            ).fetchone()
            if (day or 0) >= 60 or (hour or 0) >= 4:
                if row and row["body"] is not None:
                    return {
                        **dict(row),
                        "deferred_reason": "origin_request_budget_exhausted",
                    }, False
                raise SourceDeferredError("origin_request_budget_exhausted")
            # Reserve before I/O: parallel processes and crashes cannot bypass admission.
            db.execute("INSERT INTO attempts VALUES (?,?)", (origin, now))
            db.execute(
                "INSERT INTO urls(url,next_at) VALUES (?,?) ON CONFLICT(url) "
                "DO UPDATE SET next_at=excluded.next_at",
                (url, now + interval + max(0, self.jitter())),
            )
            db.execute("DELETE FROM attempts WHERE at<?", (now - 2 * 86400,))
            return dict(row) if row else {}, True

    def fail(self, url, status=None, retry_after=None):
        now = self.clock()
        retry_at = now
        if retry_after:
            try:
                retry_at = now + max(0, int(retry_after))
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after).timestamp()
                except (ValueError, TypeError, OverflowError):
                    pass
        with self.connect() as db:
            row = db.execute("SELECT failures FROM urls WHERE url=?", (url,)).fetchone()
            failures = (row["failures"] if row else 0) + 1
            next_at = max(retry_at, now + min(86400, 3600 * 2 ** min(failures - 1, 5)))
            db.execute(
                "UPDATE urls SET failures=?,next_at=? WHERE url=?",
                (failures, next_at + max(0, self.jitter()), url),
            )
            db.execute(
                "INSERT INTO origins VALUES (?,?,?) ON CONFLICT(origin) DO UPDATE SET "
                "blocked=MAX(blocked,excluded.blocked),next_at=MAX(next_at,excluded.next_at)",
                (urlparse(url).netloc, int(status in (401, 403)), next_at),
            )

    async def text(self, url):
        row, admitted = self.admit(url)
        if not admitted:
            self.observations.append(
                {
                    "url": url,
                    "mode": "cached",
                    "verified": row["verified"],
                    "deferred_reason": row.get("deferred_reason"),
                }
            )
            return row["body"]
        headers = {"User-Agent": "Hardshell/0.1 (+https://github.com/0xshugo/hardshell)"}
        if row.get("body") is not None and row.get("etag"):
            headers["If-None-Match"] = row["etag"]
        if row.get("body") is not None and row.get("modified"):
            headers["If-Modified-Since"] = row["modified"]
        try:
            async with (
                asyncio.timeout(20),
                self.client.stream(
                    "GET", url, headers=headers, timeout=15, follow_redirects=False
                ) as response,
            ):
                if response.status_code != 304:
                    response.raise_for_status()
                if response.status_code == 304:
                    if row.get("body") is None:
                        raise ValueError("not_modified_without_cache")
                    body = row["body"]
                else:
                    raw = bytearray()
                    async for part in response.aiter_bytes():
                        raw.extend(part)
                        if len(raw) > 2 * 1024 * 1024:
                            raise ValueError("vendor_body_too_large")
                    body = raw.decode("utf-8", errors="replace")
                no_store = "no-store" in response.headers.get("cache-control", "").lower()
                verified = self.clock()
                with self.connect() as db:
                    db.execute(
                        "UPDATE urls SET body=?,etag=?,modified=?,verified=?,failures=0 "
                        "WHERE url=?",
                        (
                            None if no_store else body,
                            response.headers.get("etag", row.get("etag")),
                            response.headers.get("last-modified", row.get("modified")),
                            verified,
                            url,
                        ),
                    )
                self.observations.append(
                    {"url": url, "mode": str(response.status_code), "verified": verified}
                )
                return body
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            response = getattr(exc, "response", None)
            self.fail(
                url,
                response.status_code if response is not None else None,
                response.headers.get("retry-after") if response is not None else None,
            )
            if row.get("body") is not None:
                self.observations.append(
                    {
                        "url": url,
                        "mode": "cached",
                        "verified": row.get("verified"),
                        "deferred_reason": "source_request_failed",
                    }
                )
                return row["body"]
            raise SourceDeferredError("source_request_failed") from None

    def verified_at(self):
        stamps = [
            o["verified"]
            for o in self.observations
            if o["verified"] is not None
            and urlparse(o["url"]).path in ("/feed.atom", "/releases/feed.php")
        ]
        return datetime.fromtimestamp(min(stamps), UTC).isoformat() if stamps else None

    def snapshot(self):
        return json.loads(json.dumps(self.observations))
