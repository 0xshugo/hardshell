import json
from datetime import UTC, datetime, timedelta

from typer.testing import CliRunner

from hardshell.cli import app
from hardshell.ops_health import evaluate_ops_health


def _seed_healthy_root(root, now):
    (root / "build" / "state").mkdir(parents=True)
    (root / "build" / "remediation").mkdir(parents=True)
    (root / "reports").mkdir(parents=True)
    (root / "reports" / "daily-2026-11-20.json").write_text("{}")
    (root / "build" / "early-warning.json").write_text(
        json.dumps(
            {
                "generated_at": now.isoformat(),
                "status": "insufficient_evidence",
                "cases": [],
                "feed_gaps": [],
                "coverage_gaps": [{"asset_id": "redis", "reason": "php_runtime_unverified"}],
                "notification": {
                    "channel": "discord",
                    "status": "idle",
                    "consecutive_failures": 0,
                    "checked_at": now.isoformat(),
                },
            }
        )
    )
    (root / "build" / "state" / "early-warning-alerts.json").write_text(
        json.dumps({"case_ids": [], "last_delivery": {"status": "idle", "consecutive_failures": 0}})
    )


def test_ops_health_ok_when_report_discord_and_scans_healthy(tmp_path):
    now = datetime(2026, 11, 20, 5, 0, tzinfo=UTC)
    _seed_healthy_root(tmp_path, now)
    res = evaluate_ops_health(tmp_path, check_systemd=False, now=now)
    assert res["overall_status"] == "ok"
    assert res["follow_up_needed"] is False
    assert res["checks"]["discord_alerting"]["status"] == "ok"
    assert res["checks"]["scan_reports"]["status"] == "ok"


def test_ops_health_flags_discord_failure_and_feed_gaps(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    _seed_healthy_root(tmp_path, now)
    (tmp_path / "build" / "early-warning.json").write_text(
        json.dumps(
            {
                "generated_at": (now - timedelta(minutes=5)).isoformat(),
                "status": "actionable",
                "cases": [
                    {
                        "case_id": "php-1",
                        "advisory_id": "CVE-2026-129496",
                        "product": "php",
                        "asset_id": "freshrss",
                        "installed": "8.4.27",
                        "fixed": "8.4.28",
                        "status": "actionable",
                        "exposure": "public",
                    }
                ],
                "feed_gaps": [
                    {
                        "source": "https://www.php.net/releases/8_4_28.php",
                        "reason": "vendor_details_unavailable",
                    }
                ],
                "coverage_gaps": [],
                "notification": {
                    "channel": "discord",
                    "status": "failed",
                    "consecutive_failures": 2,
                    "last_error": "discord_webhook_post_failed",
                },
            }
        )
    )
    monkeypatch.setenv("HARDSHELL_HOME", str(tmp_path))
    cli_res = CliRunner().invoke(app, ["ops-check", "--no-systemd", "--json"])
    assert cli_res.exit_code == 2
    payload = json.loads(cli_res.stdout)
    assert payload["follow_up_needed"] is True
    assert payload["checks"]["discord_alerting"]["status"] == "follow_up_needed"
    assert payload["checks"]["early_warning"]["status"] == "follow_up_needed"
    assert payload["checks"]["remediation"]["pending_actionable_count"] == 1


def test_status_surfaces_potentially_affected_feed_gaps_and_discord(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    _seed_healthy_root(tmp_path, now)
    (tmp_path / "build" / "early-warning.json").write_text(
        json.dumps(
            {
                "generated_at": now.isoformat(),
                "status": "needs_review",
                "cases": [
                    {
                        "case_id": "php-local",
                        "advisory_id": "CVE-2026-129496",
                        "product": "php",
                        "asset_id": "coolify",
                        "installed": "8.4.27",
                        "fixed": "8.4.28",
                        "status": "potentially_affected",
                    }
                ],
                "observed_runtimes": [{"product": "php", "asset_id": "coolify"}],
                "feed_gaps": [{"source": "php.net", "reason": "vendor_details_unavailable"}],
                "coverage_gaps": [],
                "notification": {
                    "status": "skipped_unconfigured",
                    "consecutive_failures": 1,
                    "last_error": "discord_webhook_unconfigured",
                },
            }
        )
    )
    monkeypatch.setenv("HARDSHELL_HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["status"])
    assert result.exit_code == 0
    assert "potentially_affected=1" in result.stdout
    assert "coolify" in result.stdout
    assert "vendor_details_unavailable=1" in result.stdout
    assert "skipped_unconfigured" in result.stdout
