"""Unit tests for sanitized posture export, OpenSSL Ed25519 signing, and CLI."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hardshell.cli import app
from hardshell.posture_export import build_posture_summary, verify_posture_summary


@pytest.fixture()
def ed25519_keypair(tmp_path: Path) -> tuple[str, str, Path]:
    priv = tmp_path / "posture.pem"
    pub = tmp_path / "posture.pub.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return priv.read_text(encoding="utf-8"), pub.read_text(encoding="utf-8"), priv


def test_posture_summary_states_and_secret_redaction(tmp_path: Path):
    # 1. Missing sources -> unverified
    empty = build_posture_summary(
        scan_report_path=tmp_path / "missing-scan.json",
        early_warning_path=tmp_path / "missing-ew.json",
        remediation_dir=tmp_path / "missing-rem",
    )
    assert empty["payload"]["overall_status"] == "unverified"
    assert verify_posture_summary(empty) is True

    # 2. Clean scan + early-warning with coverage gap -> partial_verified
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(
        json.dumps(
            {
                "status": "complete",
                "timestamp": "2026-11-19T00:00:00Z",
                "scanner_status": {"system": {"status": "ok"}},
                "findings": [{"id": "SYS-SSH-PORT", "severity": "info"}],
            }
        ),
        encoding="utf-8",
    )
    ew_path = tmp_path / "early-warning.json"
    ew_path.write_text(
        json.dumps(
            {
                "status": "monitoring",
                "generated_at": "2026-11-19T00:10:00Z",
                "cases": [],
                "coverage_gaps": [{"reason": "php_runtime_unverified"}],
                "observed_runtimes": [{"product": "nginx"}],
            }
        ),
        encoding="utf-8",
    )
    rem_dir = tmp_path / "remediation"
    rem_dir.mkdir()
    (rem_dir / "receipt-1.json").write_text(
        json.dumps(
            {
                "advisory_id": "CVE-2026-1234",
                "product": "nginx",
                "control_mode": "approve_then_apply",
                "status": "completed",
                "verified_at": "2026-11-19T00:15:00Z",
                "command": "SECRET_TOKEN=supersecret123 apt upgrade -y",
                "hostname": "internal-secret-host.local",
            }
        ),
        encoding="utf-8",
    )

    partial = build_posture_summary(
        scan_report_path=scan_path,
        early_warning_path=ew_path,
        remediation_dir=rem_dir,
        subject_label="prod-eu-1",
    )
    assert partial["payload"]["overall_status"] == "partial_verified"
    assert partial["payload"]["early_warning"]["coverage_gaps_by_reason"] == {
        "php_runtime_unverified": 1
    }
    assert partial["payload"]["remediation_receipts"]["verified_completed"] == 1
    serialized = json.dumps(partial)
    assert "supersecret123" not in serialized
    assert "internal-secret-host.local" not in serialized
    assert verify_posture_summary(partial) is True

    # 3. No gaps and no critical/actionable -> verified
    ew_clean = json.loads(ew_path.read_text(encoding="utf-8"))
    ew_clean["coverage_gaps"] = []
    ew_path.write_text(json.dumps(ew_clean), encoding="utf-8")
    verified = build_posture_summary(
        scan_report_path=scan_path, early_warning_path=ew_path, remediation_dir=rem_dir
    )
    assert verified["payload"]["overall_status"] == "verified"

    # 4. Critical finding -> attention_required
    scan_crit = json.loads(scan_path.read_text(encoding="utf-8"))
    scan_crit["findings"].append({"id": "SYS-DOCKER-UFW-BYPASS", "severity": "critical"})
    scan_path.write_text(json.dumps(scan_crit), encoding="utf-8")
    attention = build_posture_summary(
        scan_report_path=scan_path, early_warning_path=ew_path, remediation_dir=rem_dir
    )
    assert attention["payload"]["overall_status"] == "attention_required"


def test_posture_summary_ed25519_signing_and_tamper_rejection(
    tmp_path: Path, ed25519_keypair: tuple[str, str, Path]
):
    priv_pem, pub_pem, _ = ed25519_keypair
    envelope = build_posture_summary(
        scan_report_path=tmp_path / "none.json",
        early_warning_path=tmp_path / "none-ew.json",
        subject_label="solo-vps-1",
        signing_private_key_pem=priv_pem,
        signing_key_id="vps-key-2026",
    )
    assert envelope["signature"]["algorithm"] == "Ed25519"
    assert verify_posture_summary(envelope, trusted_public_keys_pem={"vps-key-2026": pub_pem})

    # Tampering with payload must fail both digest and signature checks
    tampered = copy.deepcopy(envelope)
    tampered["payload"]["overall_status"] = "verified"
    assert not verify_posture_summary(tampered, trusted_public_keys_pem={"vps-key-2026": pub_pem})

    # Unknown key id must fail closed
    assert not verify_posture_summary(envelope, trusted_public_keys_pem={"other-key": pub_pem})


def test_posture_export_cli_smoke(tmp_path: Path, ed25519_keypair: tuple[str, str, Path]):
    _, pub_pem, priv_path = ed25519_keypair
    runner = CliRunner()
    out_file = tmp_path / "posture.json"

    result = runner.invoke(
        app,
        [
            "posture-export",
            "--early-warning",
            str(tmp_path / "missing-ew.json"),
            "--remediation-dir",
            str(tmp_path / "missing-rem"),
            "--subject",
            "solo-demo",
            "--sign-key",
            str(priv_path),
            "--sign-key-id",
            "cli-key-1",
            "--output",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output
    exported = json.loads(out_file.read_text(encoding="utf-8"))
    assert exported["payload"]["subject"] == "solo-demo"
    assert verify_posture_summary(exported, trusted_public_keys_pem={"cli-key-1": pub_pem})

    # Missing --sign-key-id with --sign-key must exit 2
    bad = runner.invoke(app, ["posture-export", "--sign-key", str(priv_path)])
    assert bad.exit_code == 2
