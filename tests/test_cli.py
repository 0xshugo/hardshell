"""Tests for CLI output behavior."""

import json

from hardshell.cli import _output_report
from hardshell.config import ScanConfig
from hardshell.models import ScanResult


def test_json_output_creates_parent_directories(tmp_path):
    output = tmp_path / "build" / "reports" / "hardshell.json"
    cfg = ScanConfig(format="json", output=str(output))
    result = ScanResult(hostname="test-host", os_info="test-os")

    _output_report(result, cfg)

    payload = json.loads(output.read_text())
    assert payload["hostname"] == "test-host"
    assert payload["summary"]["total"] == 0
