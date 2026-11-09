"""Trivy vulnerability scanner wrapper."""

from __future__ import annotations

import asyncio
import json
import re
import shutil

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


STDERR_TAIL_BYTES = 2048

_SECRET_KEY = (
    r"[\w.-]*(?:token|secret|passw(?:or)?d|api[_-]?key"
    r"|auth\w*|credential\w*|private[_-]?key)[\w.-]*"
)
_KNOWN_TOKENS = (
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}"
)
# Order matters: bearer/basic values first so "Authorization: Bearer x" loses x.
_REDACTIONS = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), r"\1 <REDACTED>"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]*)?@"), r"\1<REDACTED>@"),
    (
        re.compile(
            r"(?i)\b("
            + _SECRET_KEY
            + r")(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|(?!<REDACTED>|bearer\b|basic\b)\S+)"
        ),
        r"\1\2<REDACTED>",
    ),
    (re.compile(r"\b(?:" + _KNOWN_TOKENS + r")\b"), "<REDACTED>"),
    (re.compile(r"\b[A-Za-z0-9+_=-]{32,}\b"), "<REDACTED>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def stderr_tail(raw: bytes, limit: int = STDERR_TAIL_BYTES) -> str:
    """Return the redacted tail of stderr, at most ``limit`` bytes of UTF-8."""
    text = redact(raw.decode(errors="replace"))
    encoded = text.encode()
    if len(encoded) <= limit:
        return text
    return encoded[-limit:].decode(errors="ignore")


class TrivyScanner:
    name = "trivy"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("trivy") is not None

    def _build_cmd(self, target: str) -> list[str]:
        subcommand = "rootfs"
        if target.startswith("/") and target != "/":
            subcommand = "fs"

        return [
            "trivy",
            subcommand,
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            "--timeout",
            "10m",
            target,
        ]

    async def scan(self, config: ScanConfig) -> list[Finding]:
        cmd = self._build_cmd(config.trivy_target)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        self.evidence = None

        if proc.returncode != 0:
            self.evidence = {
                "failure": "scanner_nonzero",
                "returncode": proc.returncode,
                "stdout_bytes": len(stdout or b""),
                "stderr_tail": stderr_tail(stderr or b""),
            }
            raise RuntimeError("scanner_nonzero")

        try:
            return self._parse(stdout.decode(errors="replace"))
        except RuntimeError as exc:
            self.evidence = {
                "failure": str(exc),
                "returncode": proc.returncode,
                "stdout_bytes": len(stdout or b""),
                "stderr_tail": stderr_tail(stderr or b""),
            }
            raise

    def _parse(self, raw: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError("scanner_invalid_report") from None

        if (
            not isinstance(data, dict)
            or not isinstance(data.get("Results"), list)
            or not data["Results"]
        ):
            raise RuntimeError("scanner_invalid_report")
        results = data["Results"]
        for result in results:
            if not isinstance(result, dict):
                raise RuntimeError("scanner_invalid_report")
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities") or []:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                sev = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO)
                findings.append(
                    Finding(
                        id=cve_id,
                        scanner=self.name,
                        severity=sev,
                        title=vuln.get("Title", cve_id),
                        description=vuln.get("Description", "")[:500],
                        affected=f"{vuln.get('PkgName', target)}",
                        current_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                    )
                )

        return findings
