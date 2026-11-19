"""Deterministic local AI Agent Runaway & Cost Circuit Breaker / Kill Switch.

Protects self-hosted AI workflows (OpenClaw, n8n, Hermes, Ollama, API proxies)
entirely locally and offline (no external SaaS required):
- Sliding-window request rate limit (retry-storm protection).
- Duplicate request/tool fingerprint loop detector (infinite agent loop breaker).
- Exact integer nano-USD daily and monthly hard spend caps (zero float drift).
- Consecutive error breaker (429/500 runaway retry loop protection).
- Instant manual emergency Kill Switch (never auto-resets).
- Append-only SQLite audit trail (never stores prompt text or API secrets).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

NANO_USD_SCALE = 1_000_000_000


class CircuitOpenError(RuntimeError):
    """Raised when an AI agent call is denied by the local circuit breaker or kill switch."""

    def __init__(self, code: str, *, agent: str, detail: str = ""):
        self.code = code
        self.agent = agent
        self.detail = detail
        super().__init__(f"{agent}: {code}" + (f" ({detail})" if detail else ""))


@dataclass(frozen=True)
class AgentGuardPolicy:
    """Hard deterministic bounds for a single AI agent or API proxy."""

    max_requests_per_minute: int = 30
    max_daily_usd: str = "5.00"
    max_monthly_usd: str = "50.00"
    max_consecutive_errors: int = 5
    max_duplicate_calls_in_window: int = 5
    duplicate_window_seconds: int = 60

    def daily_cap_nano_usd(self) -> int:
        return parse_usd_to_nano(self.max_daily_usd)

    def monthly_cap_nano_usd(self) -> int:
        return parse_usd_to_nano(self.max_monthly_usd)


def parse_usd_to_nano(amount: str | int | float | Decimal) -> int:
    """Convert a non-negative USD amount cleanly into integer nano-USD."""
    try:
        dec = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid_usd_amount") from exc
    if not dec.is_finite() or dec < 0:
        raise ValueError("usd_amount_must_be_non_negative")
    return int(dec * NANO_USD_SCALE)


def fingerprint_action(action: str) -> str:
    """Return a non-reversible SHA-256 fingerprint of a prompt or tool invocation."""
    return hashlib.sha256(action.encode("utf-8")).hexdigest()


class CircuitBreakerStore:
    """SQLite-backed local AI runaway & spend circuit breaker (0600 private DB)."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        policies: dict[str, AgentGuardPolicy] | None = None,
        default_policy: AgentGuardPolicy | None = None,
        clock=time.time,
    ) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.policies = dict(policies or {})
        self.default_policy = default_policy or AgentGuardPolicy()
        self.clock = clock
        self._init_db()

    @contextmanager
    def _connect(self):
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

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS agent_state (
                  agent TEXT PRIMARY KEY,
                  state TEXT NOT NULL CHECK(state IN ('closed', 'tripped', 'killed')),
                  reason TEXT NOT NULL DEFAULT '',
                  consecutive_errors INTEGER NOT NULL DEFAULT 0,
                  updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS call_ledger (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent TEXT NOT NULL,
                  at REAL NOT NULL,
                  day TEXT NOT NULL,
                  month TEXT NOT NULL,
                  nano_usd INTEGER NOT NULL CHECK(nano_usd >= 0),
                  fingerprint TEXT NOT NULL DEFAULT '',
                  outcome TEXT NOT NULL DEFAULT 'admitted'
                );
                CREATE INDEX IF NOT EXISTS idx_call_ledger_agent_at
                  ON call_ledger(agent, at);
                CREATE INDEX IF NOT EXISTS idx_call_ledger_agent_day
                  ON call_ledger(agent, day);
                CREATE INDEX IF NOT EXISTS idx_call_ledger_agent_month
                  ON call_ledger(agent, month);
                CREATE TABLE IF NOT EXISTS breaker_audit (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent TEXT NOT NULL,
                  action TEXT NOT NULL,
                  at REAL NOT NULL,
                  detail TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS breaker_audit_no_update
                  BEFORE UPDATE ON breaker_audit
                  BEGIN SELECT RAISE(ABORT, 'append only'); END;
                CREATE TRIGGER IF NOT EXISTS breaker_audit_no_delete
                  BEFORE DELETE ON breaker_audit
                  BEGIN SELECT RAISE(ABORT, 'append only'); END;
                """
            )
        self.path.chmod(0o600)

    def _policy_for(self, agent: str) -> AgentGuardPolicy:
        return self.policies.get(agent, self.default_policy)

    @staticmethod
    def _audit(db: sqlite3.Connection, agent: str, action: str, now: float, detail: dict) -> None:
        db.execute(
            "INSERT INTO breaker_audit(agent, action, at, detail) VALUES(?,?,?,?)",
            (agent, action, now, json.dumps(detail, sort_keys=True, separators=(",", ":"))),
        )

    def _trip(
        self,
        db: sqlite3.Connection,
        agent: str,
        *,
        state: str,
        reason: str,
        now: float,
        detail: dict | None = None,
    ) -> None:
        db.execute(
            """
            INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
            VALUES(?, ?, ?, 0, ?)
            ON CONFLICT(agent) DO UPDATE SET
              state = CASE WHEN agent_state.state = 'killed' THEN 'killed' ELSE excluded.state END,
              reason = CASE WHEN agent_state.state = 'killed' THEN agent_state.reason
                            ELSE excluded.reason END,
              updated_at = excluded.updated_at
            """,
            (agent, state, reason, now),
        )
        self._audit(db, agent, f"state.{state}", now, {"reason": reason, **(detail or {})})

    def admit(
        self,
        agent: str,
        *,
        cost_usd: str | int | float | Decimal = "0",
        fingerprint: str = "",
    ) -> dict:
        """Atomically evaluate rate, loop, spend, and kill-switch bounds before an AI call."""
        if not agent or len(agent) > 128:
            raise ValueError("invalid_agent_name")
        nano_cost = parse_usd_to_nano(cost_usd)
        policy = self._policy_for(agent)
        now = float(self.clock())
        stamp = datetime.fromtimestamp(now, UTC)
        day = stamp.strftime("%Y-%m-%d")
        month = stamp.strftime("%Y-%m")
        fp = fingerprint[:64] if fingerprint else ""

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM agent_state WHERE agent=?", (agent,)).fetchone()
            if row is not None and row["state"] in {"killed", "tripped"}:
                raise CircuitOpenError(
                    f"circuit_{row['state']}", agent=agent, detail=str(row["reason"])
                )

            # 1. Sliding 60-second request rate check
            rpm = db.execute(
                "SELECT COUNT(*) FROM call_ledger WHERE agent=? AND at > ?",
                (agent, now - 60.0),
            ).fetchone()[0]
            if rpm + 1 > policy.max_requests_per_minute:
                self._trip(
                    db,
                    agent,
                    state="tripped",
                    reason="rate_limit_exceeded",
                    now=now,
                    detail={"rpm": rpm + 1, "limit": policy.max_requests_per_minute},
                )
                db.commit()
                raise CircuitOpenError(
                    "rate_limit_exceeded",
                    agent=agent,
                    detail=f"{rpm + 1}/{policy.max_requests_per_minute} rpm",
                )

            # 2. Duplicate-action runaway loop detection
            if fp:
                dups = db.execute(
                    "SELECT COUNT(*) FROM call_ledger WHERE agent=? AND fingerprint=? AND at > ?",
                    (agent, fp, now - float(policy.duplicate_window_seconds)),
                ).fetchone()[0]
                if dups + 1 > policy.max_duplicate_calls_in_window:
                    self._trip(
                        db,
                        agent,
                        state="tripped",
                        reason="runaway_loop_detected",
                        now=now,
                        detail={
                            "duplicates": dups + 1,
                            "limit": policy.max_duplicate_calls_in_window,
                        },
                    )
                    db.commit()
                    raise CircuitOpenError(
                        "runaway_loop_detected",
                        agent=agent,
                        detail=f"fingerprint repeated {dups + 1}x",
                    )

            # 3. Exact nano-USD daily and monthly spend caps
            day_spent = db.execute(
                "SELECT COALESCE(SUM(nano_usd), 0) FROM call_ledger WHERE agent=? AND day=?",
                (agent, day),
            ).fetchone()[0]
            daily_cap = policy.daily_cap_nano_usd()
            if day_spent + nano_cost > daily_cap:
                self._trip(
                    db,
                    agent,
                    state="tripped",
                    reason="daily_cost_cap_exceeded",
                    now=now,
                    detail={"projected_nano_usd": day_spent + nano_cost, "cap_nano_usd": daily_cap},
                )
                db.commit()
                raise CircuitOpenError("daily_cost_cap_exceeded", agent=agent)

            month_spent = db.execute(
                "SELECT COALESCE(SUM(nano_usd), 0) FROM call_ledger WHERE agent=? AND month=?",
                (agent, month),
            ).fetchone()[0]
            monthly_cap = policy.monthly_cap_nano_usd()
            if month_spent + nano_cost > monthly_cap:
                self._trip(
                    db,
                    agent,
                    state="tripped",
                    reason="monthly_cost_cap_exceeded",
                    now=now,
                    detail={
                        "projected_nano_usd": month_spent + nano_cost,
                        "cap_nano_usd": monthly_cap,
                    },
                )
                db.commit()
                raise CircuitOpenError("monthly_cost_cap_exceeded", agent=agent)

            cursor = db.execute(
                "INSERT INTO call_ledger(agent, at, day, month, nano_usd, fingerprint, outcome) "
                "VALUES(?,?,?,?,?,?,?)",
                (agent, now, day, month, nano_cost, fp, "admitted"),
            )
            db.execute(
                """
                INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
                VALUES(?, 'closed', '', 0, ?)
                ON CONFLICT(agent) DO UPDATE SET updated_at=excluded.updated_at
                """,
                (agent, now),
            )
            return {
                "call_id": cursor.lastrowid,
                "agent": agent,
                "state": "closed",
                "daily_spent_usd": f"{Decimal(day_spent + nano_cost) / NANO_USD_SCALE:.6f}",
                "monthly_spent_usd": f"{Decimal(month_spent + nano_cost) / NANO_USD_SCALE:.6f}",
            }

    def record_outcome(self, agent: str, *, success: bool, error_code: str = "") -> dict:
        """Record call success/error; trips breaker on consecutive error storms."""
        policy = self._policy_for(agent)
        now = float(self.clock())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM agent_state WHERE agent=?", (agent,)).fetchone()
            current_state = row["state"] if row is not None else "closed"
            if current_state == "killed":
                return {"agent": agent, "state": "killed", "reason": row["reason"]}

            if success:
                db.execute(
                    """
                    INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
                    VALUES(?, 'closed', '', 0, ?)
                    ON CONFLICT(agent) DO UPDATE SET
                      consecutive_errors=0, updated_at=excluded.updated_at
                    """,
                    (agent, now),
                )
                return {"agent": agent, "state": current_state, "consecutive_errors": 0}

            errors = (row["consecutive_errors"] if row is not None else 0) + 1
            if errors >= policy.max_consecutive_errors:
                self._trip(
                    db,
                    agent,
                    state="tripped",
                    reason="consecutive_errors_exceeded",
                    now=now,
                    detail={"consecutive_errors": errors, "error_code": error_code[:64]},
                )
                return {
                    "agent": agent,
                    "state": "tripped",
                    "reason": "consecutive_errors_exceeded",
                    "consecutive_errors": errors,
                }

            db.execute(
                """
                INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
                VALUES(?, 'closed', '', ?, ?)
                ON CONFLICT(agent) DO UPDATE SET
                  consecutive_errors=excluded.consecutive_errors,
                  updated_at=excluded.updated_at
                """,
                (agent, errors, now),
            )
            return {"agent": agent, "state": current_state, "consecutive_errors": errors}

    def kill(self, agent: str, *, reason: str = "manual_kill_switch") -> dict:
        """Activate immediate emergency Kill Switch for an agent (never auto-resets)."""
        now = float(self.clock())
        clean_reason = (reason or "manual_kill_switch")[:128]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
                VALUES(?, 'killed', ?, 0, ?)
                ON CONFLICT(agent) DO UPDATE SET
                  state='killed', reason=excluded.reason, updated_at=excluded.updated_at
                """,
                (agent, clean_reason, now),
            )
            self._audit(db, agent, "kill_switch.engaged", now, {"reason": clean_reason})
        return {"agent": agent, "state": "killed", "reason": clean_reason}

    def reset(self, agent: str, *, reason: str = "operator_reset") -> dict:
        """Explicitly re-arm a tripped or killed agent after operator investigation."""
        now = float(self.clock())
        clean_reason = (reason or "operator_reset")[:128]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO agent_state(agent, state, reason, consecutive_errors, updated_at)
                VALUES(?, 'closed', '', 0, ?)
                ON CONFLICT(agent) DO UPDATE SET
                  state='closed', reason='', consecutive_errors=0, updated_at=excluded.updated_at
                """,
                (agent, now),
            )
            self._audit(db, agent, "circuit.reset", now, {"reason": clean_reason})
        return {"agent": agent, "state": "closed", "reason": clean_reason}

    def status(self, agent: str | None = None) -> list[dict]:
        """Return current state and daily/monthly spend summary for monitored agents."""
        now = float(self.clock())
        stamp = datetime.fromtimestamp(now, UTC)
        day = stamp.strftime("%Y-%m-%d")
        month = stamp.strftime("%Y-%m")
        with self._connect() as db:
            if agent is not None:
                rows = db.execute(
                    "SELECT * FROM agent_state WHERE agent=?", (agent,)
                ).fetchall()
            else:
                rows = db.execute("SELECT * FROM agent_state ORDER BY agent").fetchall()
            out: list[dict] = []
            for row in rows:
                name = row["agent"]
                policy = self._policy_for(name)
                day_nano = db.execute(
                    "SELECT COALESCE(SUM(nano_usd), 0) FROM call_ledger WHERE agent=? AND day=?",
                    (name, day),
                ).fetchone()[0]
                month_nano = db.execute(
                    "SELECT COALESCE(SUM(nano_usd), 0) FROM call_ledger WHERE agent=? AND month=?",
                    (name, month),
                ).fetchone()[0]
                out.append(
                    {
                        "agent": name,
                        "state": row["state"],
                        "reason": row["reason"],
                        "consecutive_errors": row["consecutive_errors"],
                        "daily_spent_usd": f"{Decimal(day_nano) / NANO_USD_SCALE:.6f}",
                        "daily_cap_usd": policy.max_daily_usd,
                        "monthly_spent_usd": f"{Decimal(month_nano) / NANO_USD_SCALE:.6f}",
                        "monthly_cap_usd": policy.max_monthly_usd,
                        "updated_at": datetime.fromtimestamp(row["updated_at"], UTC).isoformat(),
                    }
                )
            return out
