import json
from unittest.mock import AsyncMock, patch

import pytest
import typer

from hardshell.cli import _run_scan
from hardshell.config import ScanConfig
from hardshell.scanners.trivy import TrivyScanner


@pytest.mark.asyncio
async def test_nonzero_is_not_clean():
    proc = AsyncMock(returncode=1)
    proc.communicate.return_value = (b"", b"private credentials should not escape")
    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(RuntimeError, match="scanner_nonzero"):
            await TrivyScanner().scan(ScanConfig())


@pytest.mark.parametrize("raw", ["invalid", "{}", '{"Results": null}', '{"Results": []}', "[]"])
def test_malformed_is_not_clean(raw):
    with pytest.raises(RuntimeError, match="scanner_invalid_report"):
        TrivyScanner()._parse(raw)


@pytest.mark.asyncio
async def test_partial_report_persisted_and_exit_nonzero(tmp_path):
    class Failed:
        name = "trivy"

        async def scan(self, cfg):
            raise RuntimeError("scanner_nonzero")

    output = tmp_path / "scan.json"
    with (
        patch("hardshell.scanners.list_available_scanners", return_value=["trivy"]),
        patch("hardshell.scanners.get_scanner", return_value=Failed()),
    ):
        with pytest.raises(typer.Exit) as exc:
            await _run_scan(ScanConfig(scanners=["trivy"], format="json", output=str(output)))
    assert exc.value.exit_code == 2
    report = json.loads(output.read_text())
    assert report["status"] == "partial"
    assert report["scanner_status"]["trivy"] == "failed"
    assert report["summary"]["total"] == 0


@pytest.mark.asyncio
async def test_missing_requested_scanner_is_partial(tmp_path):
    class Clean:
        name = "system"

        async def scan(self, cfg):
            return []

    output = tmp_path / "scan.json"
    with (
        patch("hardshell.scanners.list_available_scanners", return_value=["system"]),
        patch("hardshell.scanners.get_scanner", return_value=Clean()),
    ):
        with pytest.raises(typer.Exit):
            await _run_scan(
                ScanConfig(scanners=["system", "trivy"], format="json", output=str(output))
            )
    assert json.loads(output.read_text())["scanner_status"]["trivy"] == "unavailable"


@pytest.mark.asyncio
async def test_all_requested_scanners_missing_still_writes_failure_report(tmp_path):
    output = tmp_path / "missing.json"
    with patch("hardshell.scanners.list_available_scanners", return_value=[]):
        with pytest.raises(typer.Exit):
            await _run_scan(ScanConfig(scanners=["trivy"], format="json", output=str(output)))
    assert json.loads(output.read_text())["status"] == "partial"


@pytest.mark.asyncio
async def test_system_subcheck_exception_is_not_silently_clean():
    from hardshell.scanners.system import SystemScanner

    scanner = SystemScanner()

    async def failed():
        raise RuntimeError("private details")

    async def clean(*args):
        return []

    with (
        patch.object(scanner, "_check_os_packages", failed),
        patch.object(scanner, "_check_listening_ports", clean),
        patch.object(scanner, "_check_ssh_config", clean),
        patch.object(scanner, "_check_firewall", clean),
        patch.object(scanner, "_check_fail2ban", clean),
        patch.object(scanner, "_check_unattended_upgrades", clean),
        patch.object(scanner, "_check_docker", clean),
    ):
        with pytest.raises(RuntimeError, match="scanner_incomplete"):
            await scanner.scan(ScanConfig())


@pytest.mark.asyncio
async def test_lynis_nonzero_never_reuses_previous_report():
    from hardshell.scanners.lynis import LynisScanner

    proc = AsyncMock(returncode=1)
    proc.communicate.return_value = (b"", None)
    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(RuntimeError, match="scanner_nonzero"):
            await LynisScanner().scan(ScanConfig())
