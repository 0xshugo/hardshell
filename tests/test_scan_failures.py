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


# --- failure evidence (stderr tail, redacted) ---

from hardshell.scanners.trivy import STDERR_TAIL_BYTES, redact, stderr_tail  # noqa: E402


@pytest.mark.asyncio
async def test_nonzero_records_redacted_stderr_tail():
    # Fake values are assembled at runtime so the source holds no secret-shaped literal.
    fake_token = "gh" + "p_" + "a1" * 18
    fake_pw = "hun" + "ter2"
    fake_jwt = "eyJ" + "hbGciOiJIUzI1NiJ9"
    fake_userinfo = "pa" + "55"
    stderr = (
        "2026-11-10T06:01:00Z FATAL walk error: open /var/lib/x: permission denied\n"
        f"GITHUB_TOKEN={fake_token} pass" + f"word: {fake_pw}\n"
        f"Authorization: Bearer {fake_jwt}.payload.sig\n"
        f"fetch https://user:{fake_userinfo}@example.com/db\n"
    ).encode()
    proc = AsyncMock(returncode=1)
    proc.communicate.return_value = (b"", stderr)
    scanner = TrivyScanner()
    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(RuntimeError, match="scanner_nonzero"):
            await scanner.scan(ScanConfig())
    ev = scanner.evidence
    assert ev["failure"] == "scanner_nonzero"
    assert ev["returncode"] == 1
    tail = ev["stderr_tail"]
    assert "permission denied" in tail
    assert "/var/lib/x" in tail
    secrets = (fake_token, fake_pw, fake_jwt, fake_userinfo)
    for secret in secrets:
        assert secret not in tail


def test_stderr_tail_is_bounded():
    raw = (b"x " * 5000) + b"LAST-LINE fatal"
    tail = stderr_tail(raw)
    assert len(tail.encode()) <= STDERR_TAIL_BYTES
    assert tail.endswith("LAST-LINE fatal")


def test_redact_keeps_plain_paths():
    line = "open /usr/lib/python3/dist-packages/foo.py: no such file"
    assert redact(line) == line


@pytest.mark.asyncio
async def test_invalid_report_records_failure_kind():
    proc = AsyncMock(returncode=0)
    proc.communicate.return_value = (b'{"Results": []}', b"")
    scanner = TrivyScanner()
    with patch("asyncio.create_subprocess_exec", return_value=proc):
        with pytest.raises(RuntimeError, match="scanner_invalid_report"):
            await scanner.scan(ScanConfig())
    assert scanner.evidence["failure"] == "scanner_invalid_report"
    assert scanner.evidence["returncode"] == 0
    assert scanner.evidence["stdout_bytes"] == len(b'{"Results": []}')


@pytest.mark.asyncio
async def test_failed_scanner_evidence_lands_in_report(tmp_path):
    class Failed:
        name = "trivy"
        evidence = None

        async def scan(self, cfg):
            self.evidence = {
                "failure": "scanner_nonzero",
                "returncode": 1,
                "stdout_bytes": 0,
                "stderr_tail": "boom",
            }
            raise RuntimeError("scanner_nonzero")

    output = tmp_path / "scan.json"
    with (
        patch("hardshell.scanners.list_available_scanners", return_value=["trivy"]),
        patch("hardshell.scanners.get_scanner", return_value=Failed()),
    ):
        with pytest.raises(typer.Exit):
            await _run_scan(ScanConfig(scanners=["trivy"], format="json", output=str(output)))
    report = json.loads(output.read_text())
    assert report["scanner_status"]["trivy"] == "failed"
    assert report["scanner_evidence"]["trivy"]["stderr_tail"] == "boom"
