"""Fail-closed persistent reservations. No refunds after ambiguous or failed requests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

# Documented 64k input context, rounded up to 65,536 tokens per paid request.
# Reserve the entire context, not an unverified tokenizer estimate.
JEV_INPUT_CEILING = 65536
JEV_INPUT_NANO_USD = 42  # $0.042/M input tokens; no long-context header is sent.
JEV_MODELS = {"jev-1.13.0", "jev-1.14.0"}


class BudgetDeniedError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class BudgetLedger:
    def __init__(self, directory, policy=None, *, clock=time.time):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path, self.clock = directory / "usage.sqlite3", clock
        if policy is None:
            try:
                policy = json.loads((directory / "policy.json").read_text())
            except (OSError, ValueError):
                policy = {}
        self.policy = policy
        self.funding = None
        try:
            with self.connect() as db:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS requests (
                      id INTEGER PRIMARY KEY, provider TEXT, model TEXT, key TEXT,
                      at REAL, day TEXT, month TEXT, input_reserved INTEGER,
                      output_reserved INTEGER, nano_usd_reserved INTEGER,
                      status TEXT, response TEXT, actual_input INTEGER, actual_output INTEGER);
                    CREATE TABLE IF NOT EXISTS blocked (provider TEXT PRIMARY KEY);
                """)
            self.path.chmod(0o600)
        except sqlite3.Error:
            raise BudgetDeniedError("budget_store_unavailable") from None

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

    def admit(self, provider, model, payload, endpoint):
        try:
            return self._admit(provider, model, payload, endpoint)
        except BudgetDeniedError:
            raise
        except (sqlite3.Error, KeyError, TypeError, AttributeError, ArithmeticError, ValueError):
            raise BudgetDeniedError("invalid_or_unavailable_budget") from None

    def _admit(self, provider, model, payload, endpoint):
        config = self.policy.get("providers", {}).get(provider, {})
        if config.get("enabled") is not True or config.get("model") != model:
            raise BudgetDeniedError("budget_not_configured")
        data = json.dumps(payload, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if len(data.encode()) > 8192:
            raise BudgetDeniedError("request_input_limit")
        if provider == "jev":
            if model not in JEV_MODELS:
                raise BudgetDeniedError("unpriced_or_unpinned_model")
            quote = datetime.fromisoformat(config["price_valid_until"].replace("Z", "+00:00"))
            if quote.tzinfo is None or quote.timestamp() < self.clock():
                raise BudgetDeniedError("price_quote_expired")
            inputs, outputs = JEV_INPUT_CEILING, 0
            cost = inputs * JEV_INPUT_NANO_USD
        elif provider == "llm" and config.get("cost_mode") == "local_nonbillable":
            # Local inputs are bounded by request bytes; output is enforced in the request.
            inputs, outputs, cost = 8192, 500, 0
            requested = payload.get("max_tokens")
            if type(requested) is not int or not 1 <= requested <= outputs:
                raise BudgetDeniedError("output_limit_missing")
        else:
            raise BudgetDeniedError("unpriced_provider")
        key = hashlib.sha256(
            json.dumps([provider, model, endpoint, data, config.get("cache_revision", 1)]).encode()
        ).hexdigest()
        now = self.clock()
        stamp = datetime.fromtimestamp(now, UTC)
        day, month = stamp.strftime("%Y-%m-%d"), stamp.strftime("%Y-%m")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM blocked WHERE provider=?", (provider,)).fetchone():
                raise BudgetDeniedError("usage_contract_violation")
            old = db.execute(
                "SELECT * FROM requests WHERE provider=? AND key=? ORDER BY id DESC LIMIT 1",
                (provider, key),
            ).fetchone()
            if old:
                if old["status"] == "complete":
                    return {"cached": json.loads(old["response"])}
                # No automatic charged retries, including timeouts/crashes and invalid replies.
                raise BudgetDeniedError("previous_attempt_requires_review")
            if db.execute(
                "SELECT 1 FROM requests WHERE provider=? AND status=? AND at>?",
                (provider, "reserved", now - 60),
            ).fetchone():
                raise BudgetDeniedError("provider_busy")
            for field, value in [("day", day), ("month", month)]:
                period = "daily" if field == "day" else "monthly"
                limits = config[period]
                if any(
                    type(limits[k]) is not int or limits[k] < 0
                    for k in ("calls", "input_tokens", "output_tokens")
                ):
                    raise BudgetDeniedError("invalid_budget")
                used = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(input_reserved),0),"
                    "COALESCE(SUM(output_reserved),0),COALESCE(SUM(nano_usd_reserved),0) "
                    f"FROM requests WHERE provider=? AND {field}=?",
                    (provider, value),
                ).fetchone()
                cap = int(Decimal(str(limits["usd"])) * 1_000_000_000)
                if (
                    used[0] + 1 > limits["calls"]
                    or used[1] + inputs > limits["input_tokens"]
                    or used[2] + outputs > limits["output_tokens"]
                    or used[3] + cost > cap
                ):
                    raise BudgetDeniedError(period + "_budget_exhausted")
            if provider == "jev":
                proof = self.funding or {}
                checked = proof.get("checked_at", 0)
                if proof.get("status") != "ready" or not 0 <= now - checked <= 5:
                    raise BudgetDeniedError("provider_funds_unverified")
                if proof.get("expires_at", 0) < now + 86400:
                    raise BudgetDeniedError("provider_funds_expiring")
                reserved = db.execute(
                    "SELECT COALESCE(SUM(nano_usd_reserved),0) FROM requests "
                    "WHERE provider=? AND at>=?",
                    (provider, checked),
                ).fetchone()[0]
                if proof.get("usable_nano_usd", 0) < reserved + cost:
                    raise BudgetDeniedError("provider_funds_insufficient")
            cursor = db.execute(
                "INSERT INTO requests(provider,model,key,at,day,month,"
                "input_reserved,output_reserved,nano_usd_reserved,status) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (provider, model, key, now, day, month, inputs, outputs, cost, "reserved"),
            )
            return {"id": cursor.lastrowid, "input_reserved": inputs, "output_reserved": outputs}

    def finish(self, ticket, body=None):
        try:
            with self.connect() as db:
                record = db.execute("SELECT * FROM requests WHERE id=?", (ticket["id"],)).fetchone()
                usage = body.get("usage", {}) if isinstance(body, dict) else {}
                usage_valid = isinstance(usage, dict)
                if not usage_valid:
                    usage = {}
                inp = usage.get("input_tokens", usage.get("prompt_tokens"))
                out = usage.get("output_tokens", usage.get("completion_tokens"))
                valid = all(v is None or (type(v) is int and v >= 0) for v in (inp, out))
                violation = (
                    not usage_valid
                    or not valid
                    or (inp is not None and inp > record["input_reserved"])
                    or (
                        record["provider"] == "llm"
                        and out is not None
                        and out > record["output_reserved"]
                    )
                )
                if violation:
                    db.execute("INSERT OR IGNORE INTO blocked VALUES (?)", (record["provider"],))
                db.execute(
                    "UPDATE requests SET status=?,response=?,actual_input=?,actual_output=? "
                    "WHERE id=?",
                    (
                        "complete" if body is not None and not violation else "failed",
                        json.dumps(body) if body is not None and not violation else None,
                        inp if valid else None,
                        out if valid else None,
                        ticket["id"],
                    ),
                )
            if violation:
                raise BudgetDeniedError("usage_contract_violation")
        except sqlite3.Error:
            raise BudgetDeniedError("budget_store_unavailable") from None

    def readiness(self, provider):
        """Read-only capacity for one new request; does not reserve or contact providers."""
        try:
            config = self.policy.get("providers", {}).get(provider, {})
            if config.get("enabled") is not True or not config.get("model"):
                raise BudgetDeniedError("budget_not_configured")
            if provider == "jev":
                if config["model"] not in JEV_MODELS:
                    raise BudgetDeniedError("unpriced_or_unpinned_model")
                quote = datetime.fromisoformat(config["price_valid_until"].replace("Z", "+00:00"))
                if quote.tzinfo is None or quote.timestamp() < self.clock():
                    raise BudgetDeniedError("price_quote_expired")
                inputs, outputs, cost = JEV_INPUT_CEILING, 0, JEV_INPUT_CEILING * JEV_INPUT_NANO_USD
            elif provider == "llm" and config.get("cost_mode") == "local_nonbillable":
                inputs, outputs, cost = 8192, 500, 0
            else:
                raise BudgetDeniedError("unpriced_provider")
            stamp = datetime.fromtimestamp(self.clock(), UTC)
            remaining = {}
            with self.connect() as db:
                if db.execute("SELECT 1 FROM blocked WHERE provider=?", (provider,)).fetchone():
                    raise BudgetDeniedError("usage_contract_violation")
                for column, period, value in (
                    ("day", "daily", stamp.strftime("%Y-%m-%d")),
                    ("month", "monthly", stamp.strftime("%Y-%m")),
                ):
                    limits = config[period]
                    if any(
                        type(limits[k]) is not int or limits[k] < 0
                        for k in ("calls", "input_tokens", "output_tokens")
                    ):
                        raise BudgetDeniedError("invalid_budget")
                    used = db.execute(
                        "SELECT COUNT(*),COALESCE(SUM(input_reserved),0),"
                        "COALESCE(SUM(output_reserved),0),COALESCE(SUM(nano_usd_reserved),0) "
                        f"FROM requests WHERE provider=? AND {column}=?",
                        (provider, value),
                    ).fetchone()
                    cap = int(Decimal(str(limits["usd"])) * 1_000_000_000)
                    left = [
                        limits["calls"] - used[0],
                        limits["input_tokens"] - used[1],
                        limits["output_tokens"] - used[2],
                        cap - used[3],
                    ]
                    if any(a < b for a, b in zip(left, (1, inputs, outputs, cost), strict=True)):
                        raise BudgetDeniedError(period + "_budget_exhausted")
                    remaining[period] = dict(
                        zip(
                            ("calls", "input_tokens", "output_tokens", "nano_usd"),
                            left,
                            strict=True,
                        )
                    )
            return {"status": "ready", "remaining": remaining, "model": config["model"]}
        except BudgetDeniedError as exc:
            return {"status": "unavailable", "reason": exc.code}
        except (sqlite3.Error, KeyError, TypeError, AttributeError, ArithmeticError, ValueError):
            return {"status": "unavailable", "reason": "invalid_or_unavailable_budget"}

    def totals(self):
        try:
            with self.connect() as db:
                rows = db.execute(
                    "SELECT provider,COUNT(*) AS calls,SUM(input_reserved) AS input_reserved,"
                    "SUM(output_reserved) AS output_reserved,"
                    "SUM(nano_usd_reserved) AS nano_usd_reserved "
                    "FROM requests GROUP BY provider"
                ).fetchall()
                result = [dict(row) for row in rows]
                stamp = datetime.fromtimestamp(self.clock(), UTC)
                for row in result:
                    row["period"] = "all_time"
                    for column, period, value in (
                        ("day", "daily", stamp.strftime("%Y-%m-%d")),
                        ("month", "monthly", stamp.strftime("%Y-%m")),
                    ):
                        used = db.execute(
                            "SELECT COUNT(*),COALESCE(SUM(input_reserved),0),"
                            "COALESCE(SUM(output_reserved),0),COALESCE(SUM(nano_usd_reserved),0) "
                            f"FROM requests WHERE provider=? AND {column}=?",
                            (row["provider"], value),
                        ).fetchone()
                        row[period] = dict(
                            zip(
                                ("calls", "input_reserved", "output_reserved", "nano_usd_reserved"),
                                used,
                                strict=True,
                            )
                        )
                return result
        except sqlite3.Error:
            raise BudgetDeniedError("budget_store_unavailable") from None
