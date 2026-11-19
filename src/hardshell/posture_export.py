"""Sanitized, verifiable Posture & Receipt Summary exporter.

Produces a secret-free, canonical-hashed JSON posture summary suitable for
independent verification or publishing on a public security status page:
- Explicitly preserves ``coverage_gaps`` and ``unknown`` counts (never fakes
  completeness).
- Summarizes verified remediation receipts by SHA-256 digest without leaking
  raw shell commands, secrets, or sensitive host paths.
- Optionally signs the canonical payload with an Ed25519 PEM key via OpenSSL
  EVP (matching ``hardshell.executor.verify`` with zero extra Python deps).
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

POSTURE_SCHEMA_VERSION = 1
POSTURE_PURPOSE = "hardshell.posture_summary.v1"
POSTURE_DOMAIN_PREFIX = b"hardshell.posture_summary.v1\n"


def _canonical_bytes(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign_ed25519_pem(message: bytes, private_key_pem: str) -> bytes:
    """Sign raw bytes with an Ed25519 private key PEM via OpenSSL EVP."""
    with tempfile.TemporaryDirectory(prefix="hardshell-posture-sign-") as temp:
        directory = Path(temp)
        key_path = directory / "private.pem"
        msg_path = directory / "message.bin"
        sig_path = directory / "signature.bin"
        key_path.write_text(private_key_pem, encoding="utf-8")
        key_path.chmod(0o600)
        msg_path.write_bytes(message)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(msg_path),
                "-out",
                str(sig_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
        )
        if result.returncode != 0 or not sig_path.exists():
            raise ValueError("ed25519_sign_failed")
        sig = sig_path.read_bytes()
        if len(sig) != 64:
            raise ValueError("invalid_ed25519_signature_length")
        return sig


def _verify_ed25519_pem(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    """Verify an Ed25519 signature via OpenSSL EVP; unavailable OpenSSL fails closed."""
    if len(signature) != 64:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="hardshell-posture-verify-") as temp:
            directory = Path(temp)
            pub_path = directory / "public.pem"
            msg_path = directory / "message.bin"
            sig_path = directory / "signature.bin"
            pub_path.write_text(public_key_pem, encoding="utf-8")
            msg_path.write_bytes(message)
            sig_path.write_bytes(signature)
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub_path),
                    "-rawin",
                    "-in",
                    str(msg_path),
                    "-sigfile",
                    str(sig_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
            )
            return result.returncode == 0
    except (FileNotFoundError, OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _summarize_scan_report(scan_path: Path | None) -> dict:
    if scan_path is None or not scan_path.exists():
        return {"present": False, "status": "unverified", "counts": {}}
    try:
        data = json.loads(scan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"present": False, "status": "unreadable", "counts": {}}

    findings = data.get("findings") or []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    kev_open = 0
    for item in findings:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
        if item.get("kev") is True:
            kev_open += 1

    scanner_status = data.get("scanner_status") or {}
    failed_scanners = sorted(
        name
        for name, info in scanner_status.items()
        if isinstance(info, dict) and info.get("status") not in {"ok", "success"}
    )
    return {
        "present": True,
        "status": str(data.get("status") or "legacy_unverified"),
        "scanned_at": data.get("timestamp") or data.get("scanned_at"),
        "counts": counts,
        "kev_open": kev_open,
        "failed_scanners": failed_scanners,
    }


def _summarize_early_warning(ew_path: Path | None) -> dict:
    if ew_path is None or not ew_path.exists():
        return {
            "present": False,
            "status": "unverified",
            "actionable": 0,
            "potentially_affected": 0,
            "needs_evidence": 0,
            "coverage_gaps_total": 0,
            "coverage_gaps_by_reason": {},
            "observed_products": [],
        }
    try:
        data = json.loads(ew_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {
            "present": False,
            "status": "unreadable",
            "actionable": 0,
            "potentially_affected": 0,
            "needs_evidence": 0,
            "coverage_gaps_total": 0,
            "coverage_gaps_by_reason": {},
            "observed_products": [],
        }

    cases = data.get("cases") or []
    actionable = sum(1 for c in cases if isinstance(c, dict) and c.get("status") == "actionable")
    potentially = sum(
        1 for c in cases if isinstance(c, dict) and c.get("status") == "potentially_affected"
    )
    needs_ev = sum(1 for c in cases if isinstance(c, dict) and c.get("status") == "needs_evidence")

    gaps = data.get("coverage_gaps") or []
    by_reason: dict[str, int] = {}
    for gap in gaps:
        if isinstance(gap, dict):
            reason = str(gap.get("reason") or "unknown")
            by_reason[reason] = by_reason.get(reason, 0) + 1

    products = sorted(
        {
            str(r.get("product"))
            for r in (data.get("observed_runtimes") or [])
            if isinstance(r, dict) and r.get("product")
        }
    )
    return {
        "present": True,
        "status": str(data.get("status") or "unknown"),
        "observed_at": data.get("generated_at") or data.get("observed_at"),
        "actionable": actionable,
        "potentially_affected": potentially,
        "needs_evidence": needs_ev,
        "coverage_gaps_total": len(gaps),
        "coverage_gaps_by_reason": dict(sorted(by_reason.items())),
        "observed_products": products,
    }


def _summarize_receipts(receipts_dir: Path | None) -> dict:
    if receipts_dir is None or not receipts_dir.is_dir():
        return {"count": 0, "verified_completed": 0, "latest_verified_at": None, "digests": []}

    entries: list[dict] = []
    completed = 0
    latest_at: str | None = None
    for path in sorted(receipts_dir.glob("*.json")):
        try:
            raw = path.read_bytes()
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        status = str(data.get("status") or "unknown")
        verified_at = data.get("verified_at")
        if status == "completed":
            completed += 1
        if isinstance(verified_at, str) and (latest_at is None or verified_at > latest_at):
            latest_at = verified_at
        # Public-safe receipt digest only (never exposes commands, hostnames, or raw versions).
        entries.append(
            {
                "advisory_id": str(data.get("advisory_id") or "unknown"),
                "product": str(data.get("product") or "unknown"),
                "control_mode": str(data.get("control_mode") or "unknown"),
                "status": status,
                "verified_at": verified_at,
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    return {
        "count": len(entries),
        "verified_completed": completed,
        "latest_verified_at": latest_at,
        "digests": entries[-25:],
    }


def build_posture_summary(
    *,
    scan_report_path: Path | None = None,
    early_warning_path: Path | None = None,
    remediation_dir: Path | None = None,
    subject_label: str = "self-hosted-vps",
    generated_at: str | None = None,
    signing_private_key_pem: str | None = None,
    signing_key_id: str = "",
) -> dict:
    """Build a sanitized, canonical-hashed (and optionally Ed25519-signed) posture summary."""
    scan_summary = _summarize_scan_report(scan_report_path)
    ew_summary = _summarize_early_warning(early_warning_path)
    receipts_summary = _summarize_receipts(remediation_dir)

    has_verified_source = scan_summary["present"] or ew_summary["present"]
    has_gaps = (
        ew_summary["coverage_gaps_total"] > 0
        or bool(scan_summary.get("failed_scanners"))
        or not scan_summary["present"]
        or not ew_summary["present"]
    )
    if not has_verified_source:
        overall = "unverified"
    elif (
        scan_summary["counts"].get("critical", 0) > 0
        or scan_summary.get("kev_open", 0) > 0
        or ew_summary["actionable"] > 0
    ):
        overall = "attention_required"
    elif has_gaps:
        overall = "partial_verified"
    else:
        overall = "verified"

    payload = {
        "schema_version": POSTURE_SCHEMA_VERSION,
        "purpose": POSTURE_PURPOSE,
        "subject": subject_label,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "overall_status": overall,
        "disclaimer": (
            "Machine-observed security posture summary. "
            "Coverage gaps and unverified components are explicitly reported; "
            "this is not a third-party compliance certification."
        ),
        "scan": scan_summary,
        "early_warning": ew_summary,
        "remediation_receipts": receipts_summary,
    }
    canonical = _canonical_bytes(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    envelope: dict[str, object] = {
        "payload": payload,
        "content_sha256": digest,
    }

    if signing_private_key_pem is not None:
        if not signing_key_id:
            raise ValueError("signing_key_id required when signing")
        sig = _sign_ed25519_pem(POSTURE_DOMAIN_PREFIX + canonical, signing_private_key_pem)
        envelope["signature"] = {
            "algorithm": "Ed25519",
            "key_id": signing_key_id,
            "value": _b64u_encode(sig),
        }

    return envelope


def verify_posture_summary(
    envelope: dict,
    *,
    trusted_public_keys_pem: dict[str, str] | None = None,
) -> bool:
    """Verify content SHA-256 digest and (if keys supplied) Ed25519 signature."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), dict):
        return False
    canonical = _canonical_bytes(envelope["payload"])
    expected_digest = hashlib.sha256(canonical).hexdigest()
    if envelope.get("content_sha256") != expected_digest:
        return False

    if trusted_public_keys_pem is not None:
        sig_block = envelope.get("signature")
        if not isinstance(sig_block, dict) or sig_block.get("algorithm") != "Ed25519":
            return False
        kid = sig_block.get("key_id")
        pub_pem = trusted_public_keys_pem.get(kid) if isinstance(kid, str) else None
        if not pub_pem:
            return False
        try:
            sig_bytes = _b64u_decode(str(sig_block.get("value") or ""))
        except (ValueError, TypeError):
            return False
        return _verify_ed25519_pem(POSTURE_DOMAIN_PREFIX + canonical, sig_bytes, pub_pem)
    return True
