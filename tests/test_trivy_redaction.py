"""Regression coverage for secrets in diagnostics that leave the scanner process."""

import json
from unittest.mock import AsyncMock, patch

import pytest
import typer

from hardshell.cli import _run_scan
from hardshell.config import ScanConfig
from hardshell.scanners.trivy import TrivyScanner, redact, stderr_tail


@pytest.mark.parametrize(
    "key",
    ["password", "api_key", "API-KEY", "access_token", "client_secret", "credentials"],
)
@pytest.mark.parametrize("value", ["short", 'has"quote', "has\\slash", "has\nnewline", "秘密"])
def test_json_secret_fields_are_redacted(key, value):
    raw = json.dumps({key: value, "error": "permission denied", "path": "/var/lib/db"})
    result = json.loads(redact(raw))
    assert result[key] == "<REDACTED>"
    assert result["error"] == "permission denied"
    assert result["path"] == "/var/lib/db"


@pytest.mark.parametrize(
    "raw",
    [
        '{"pass\\u0077ord":"short"}',
        "{'password': 'short'}",
        'password="short"',
        "password='short'",
        "password=short",
        'FATAL response: {"password":"short"} permission denied',
        'FATAL response: {"credentials":{"value":"short"}} permission denied',
        '{"tokens":["short","other"]}',
        '{"password":"escaped\\\"short"}',
        "{'password': 'escaped\\'short'}",
        '{"password":"short',
        '{"credentials":{"value":"short"\nshort',
    ],
)
def test_structured_and_malformed_secret_values_do_not_escape(raw):
    assert "short" not in stderr_tail(raw.encode())


def test_redaction_precedes_byte_truncation():
    raw = ('{"password":"' + "short" * 1000 + '"}').encode()
    result = stderr_tail(raw, limit=20)
    assert "short" not in result
    assert len(result.encode()) <= 20


@pytest.mark.parametrize("phase", ["startup", "communicate"])
@pytest.mark.asyncio
async def test_failed_subprocess_does_not_reuse_old_evidence(phase):
    scanner = TrivyScanner()
    previous = AsyncMock(returncode=1)
    previous.communicate.return_value = (b"", b"previous scan")
    with patch("asyncio.create_subprocess_exec", return_value=previous):
        with pytest.raises(RuntimeError, match="scanner_nonzero"):
            await scanner.scan(ScanConfig())
    assert scanner.evidence is not None

    process = AsyncMock()
    process.communicate.side_effect = OSError("failed to communicate")
    kwargs = (
        {"side_effect": FileNotFoundError()} if phase == "startup" else {"return_value": process}
    )
    with patch("asyncio.create_subprocess_exec", **kwargs):
        with pytest.raises(OSError):
            await scanner.scan(ScanConfig())
    assert scanner.evidence is None


@pytest.mark.parametrize("returncode,stdout", [(1, b""), (0, b'{"Results": []}')])
@pytest.mark.asyncio
async def test_real_failed_scanner_never_persists_json_secrets(tmp_path, returncode, stdout):
    raw = json.dumps({"password": "short", "api_key": "small-value", "path": "/var/lib/db"})
    process = AsyncMock(returncode=returncode)
    process.communicate.return_value = (stdout, raw.encode())
    output = tmp_path / "report.json"
    with (
        patch("asyncio.create_subprocess_exec", return_value=process),
        patch("hardshell.scanners.list_available_scanners", return_value=["trivy"]),
        patch("hardshell.scanners.get_scanner", return_value=TrivyScanner()),
    ):
        with pytest.raises(typer.Exit) as result:
            await _run_scan(ScanConfig(scanners=["trivy"], format="json", output=str(output)))
    assert result.value.exit_code == 2
    serialized = output.read_text()
    assert "short" not in serialized
    assert "small-value" not in serialized
    report = json.loads(serialized)
    assert report["status"] == "partial"
    assert report["scanner_status"]["trivy"] == "failed"
    assert "/var/lib/db" in report["scanner_evidence"]["trivy"]["stderr_tail"]
