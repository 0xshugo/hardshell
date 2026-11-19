"""Unit tests for local AI Agent Runaway & Billing Circuit Breaker / Kill Switch."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hardshell.circuit_breaker import (
    AgentGuardPolicy,
    CircuitBreakerStore,
    CircuitOpenError,
    fingerprint_action,
)
from hardshell.cli import app


def test_rate_limit_and_operator_reset(tmp_path: Path):
    now = 1_800_000_000.0
    store = CircuitBreakerStore(
        tmp_path / "guard.sqlite3",
        policies={"n8n": AgentGuardPolicy(max_requests_per_minute=2)},
        clock=lambda: now,
    )
    assert store.admit("n8n", cost_usd="0.01")["state"] == "closed"
    assert store.admit("n8n", cost_usd="0.01")["state"] == "closed"

    with pytest.raises(CircuitOpenError) as exc:
        store.admit("n8n", cost_usd="0.01")
    assert exc.value.code == "rate_limit_exceeded"

    # Once tripped, remains fail-closed even after the 60s window passes until reset
    now += 120.0
    with pytest.raises(CircuitOpenError) as still_tripped:
        store.admit("n8n", cost_usd="0.01")
    assert still_tripped.value.code == "circuit_tripped"

    store.reset("n8n", reason="fixed_webhook_loop")
    assert store.admit("n8n", cost_usd="0.01")["state"] == "closed"


def test_runaway_duplicate_loop_detection(tmp_path: Path):
    now = 1_800_000_000.0
    store = CircuitBreakerStore(
        tmp_path / "guard.sqlite3",
        policies={
            "openclaw": AgentGuardPolicy(
                max_requests_per_minute=50,
                max_duplicate_calls_in_window=3,
                duplicate_window_seconds=60,
            )
        },
        clock=lambda: now,
    )
    fp = fingerprint_action("tool:send_email:customer@example.com")
    for _ in range(3):
        store.admit("openclaw", fingerprint=fp)

    with pytest.raises(CircuitOpenError) as exc:
        store.admit("openclaw", fingerprint=fp)
    assert exc.value.code == "runaway_loop_detected"


def test_exact_nano_usd_daily_and_monthly_caps(tmp_path: Path):
    now = 1_800_000_000.0
    store = CircuitBreakerStore(
        tmp_path / "guard.sqlite3",
        policies={
            "hermes": AgentGuardPolicy(
                max_requests_per_minute=100,
                max_daily_usd="1.00",
                max_monthly_usd="1.50",
            )
        },
        clock=lambda: now,
    )
    store.admit("hermes", cost_usd="0.60")
    store.admit("hermes", cost_usd="0.40")  # Exactly $1.00 daily cap
    with pytest.raises(CircuitOpenError) as exc_day:
        store.admit("hermes", cost_usd="0.000001")
    assert exc_day.value.code == "daily_cost_cap_exceeded"

    # Next day + operator reset -> daily resets, monthly ($1.00 already spent) enforces $1.50 cap
    now += 86400.0
    store.reset("hermes", reason="next_day")
    store.admit("hermes", cost_usd="0.50")  # Exactly $1.50 monthly cap
    with pytest.raises(CircuitOpenError) as exc_month:
        store.admit("hermes", cost_usd="0.01")
    assert exc_month.value.code == "monthly_cost_cap_exceeded"


def test_consecutive_errors_and_manual_kill_switch_and_append_only_audit(tmp_path: Path):
    db_file = tmp_path / "guard.sqlite3"
    store = CircuitBreakerStore(
        db_file,
        policies={"ollama": AgentGuardPolicy(max_consecutive_errors=2)},
        clock=lambda: 1_800_000_000.0,
    )
    assert store.record_outcome("ollama", success=False, error_code="http_429")["state"] == "closed"
    res = store.record_outcome("ollama", success=False, error_code="http_429")
    assert res["state"] == "tripped"

    # Engage manual Kill Switch -> cannot be cleared by record_outcome(success=True)
    killed = store.kill("ollama", reason="suspected_prompt_injection")
    assert killed["state"] == "killed"
    assert store.record_outcome("ollama", success=True)["state"] == "killed"
    with pytest.raises(CircuitOpenError) as exc:
        store.admit("ollama")
    assert exc.value.code == "circuit_killed"

    # Audit table is strictly append-only
    conn = sqlite3.connect(db_file)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM breaker_audit")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE breaker_audit SET action='tampered'")
    finally:
        conn.close()


def test_guard_cli_check_kill_status_reset(tmp_path: Path):
    runner = CliRunner()
    db_file = tmp_path / "cli-guard.sqlite3"

    ok = runner.invoke(
        app,
        [
            "guard",
            "check",
            "openclaw",
            "--cost-usd",
            "0.25",
            "--daily-cap",
            "1.00",
            "--db",
            str(db_file),
        ],
    )
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.output)["allowed"] is True

    killed = runner.invoke(
        app, ["guard", "kill", "openclaw", "--reason", "emergency", "--db", str(db_file)]
    )
    assert killed.exit_code == 0

    blocked = runner.invoke(
        app, ["guard", "check", "openclaw", "--cost-usd", "0.01", "--db", str(db_file)]
    )
    assert blocked.exit_code == 4
    assert json.loads(blocked.output)["code"] == "circuit_killed"

    st = runner.invoke(app, ["guard", "status", "--agent", "openclaw", "--db", str(db_file)])
    assert st.exit_code == 0
    rows = json.loads(st.output)
    assert len(rows) == 1
    assert rows[0]["state"] == "killed"

    rearmed = runner.invoke(app, ["guard", "reset", "openclaw", "--db", str(db_file)])
    assert rearmed.exit_code == 0
    ok_again = runner.invoke(
        app, ["guard", "check", "openclaw", "--cost-usd", "0.10", "--db", str(db_file)]
    )
    assert ok_again.exit_code == 0
