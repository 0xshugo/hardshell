import json
from datetime import UTC, datetime

from typer.testing import CliRunner

from hardshell.cli import app


def test_status_shows_actionable_and_coverage(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    rem = build / "remediation"
    rem.mkdir()
    now = datetime.now(UTC).isoformat()
    (build / "early-warning.json").write_text(
        json.dumps(
            {
                "generated_at": now,
                "status": "actionable",
                "cases": [
                    {
                        "status": "actionable",
                        "advisory_id": "CVE-2026-123007",
                        "product": "nginx",
                        "asset_id": "factory-nginx",
                        "installed": "1.29.3",
                        "fixed": "1.30.7",
                    }
                ],
                "observed_runtimes": [{"product": "nginx", "asset_id": "factory-nginx"}],
                "coverage_gaps": [{"reason": "php_runtime_unverified"}],
                "feed_gaps": [],
            }
        )
    )
    (rem / "20261119-CVE-2026-123007.json").write_text(
        json.dumps(
            {
                "status": "completed",
                "advisory_id": "CVE-2026-123007",
                "asset_id": "factory-nginx",
                "control_mode": "approve_then_apply",
            }
        )
    )
    monkeypatch.setenv("HARDSHELL_HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["status"])
    assert result.exit_code == 0
    assert "actionable=1" in result.stdout
    assert "CVE-2026-123007" in result.stdout
    assert "php_runtime_unverified=1" in result.stdout
    assert "approve_then_apply" in result.stdout
