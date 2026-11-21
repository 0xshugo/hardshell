"""Tests for hardshell-watch Pushgateway metrics and bin/metrics.sh."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import httpx
import pytest

from hardshell.watch_metrics import format_watch_metrics, push_watch_metrics


def test_format_watch_metrics_counts_cases_gaps_and_discord():
    report = {
        "generated_at": "2026-11-21T01:10:38+00:00",
        "cases": [
            {"status": "actionable"},
            {"status": "potentially_affected"},
            {"status": "potentially_affected"},
            {"status": "needs_evidence"},
        ],
        "feed_gaps": [{"source": "php.net", "reason": "acquisition_failed"}],
        "coverage_gaps": [{"asset_id": "a"}, {"asset_id": "b"}],
        "notification": {"status": "failed", "consecutive_failures": 0},
    }
    text = format_watch_metrics(report, now=1795223438.0)
    assert 'hardshell_watch_cases_total{status="actionable"} 1' in text
    assert 'hardshell_watch_cases_total{status="potentially_affected"} 2' in text
    assert 'hardshell_watch_cases_total{status="needs_evidence"} 1' in text
    assert "hardshell_watch_feed_gaps_total 1" in text
    assert "hardshell_watch_coverage_gaps_total 2" in text
    assert "hardshell_watch_discord_failures 1" in text
    assert "hardshell_watch_last_run_timestamp 1795223438" in text


@pytest.mark.asyncio
async def test_push_watch_metrics_posts_and_handles_errors(monkeypatch):
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append((str(request.url), request.content.decode()))
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient

    class FakeClient(orig_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)

    ok = await push_watch_metrics(
        {"generated_at": "2026-11-21T01:10:38+00:00", "cases": []},
        "http://127.0.0.1:9091",
    )
    assert ok is True
    assert posted[0][0] == "http://127.0.0.1:9091/metrics/job/hardshell_watch"
    assert "hardshell_watch_cases_total" in posted[0][1]

    assert await push_watch_metrics({}, "file:///etc/passwd") is False


def test_metrics_sh_uses_07_threshold_for_high_epss(tmp_path):
    report = tmp_path / "daily.json"
    report.write_text(
        json.dumps(
            {
                "timestamp": "2026-11-21T06:00:00+09:00",
                "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 2},
                "findings": [
                    {"scanner": "trivy", "epss_score": 0.75, "in_cisa_kev": False},
                    {"scanner": "trivy", "epss_score": 0.35, "in_cisa_kev": False},
                ],
            }
        )
    )
    out_file = tmp_path / "pushed.txt"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text(f"#!/bin/sh\ncat > {out_file}\n")
    curl.chmod(0o700)

    env = os.environ.copy()
    env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
    script = Path(__file__).resolve().parents[1] / "bin" / "metrics.sh"
    res = subprocess.run(["bash", str(script), str(report), "daily"], env=env, capture_output=True)
    assert res.returncode == 0, res.stderr.decode()
    pushed = out_file.read_text()
    assert "hardshell_epss_high_count 1" in pushed
    assert "hardshell_epss_elevated_count 2" in pushed
