"""Trivy vulnerability scanner wrapper."""

from __future__ import annotations

import asyncio
import json
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


class TrivyScanner:
    name = "trivy"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("trivy") is not None

    async def scan(self, config: ScanConfig) -> list[Finding]:
        target = config.trivy_target
        cmd = f"trivy rootfs --format json --quiet {target}"
        if target.startswith("/") and target != "/":
            cmd = f"trivy fs --format json --quiet {target}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        if proc.returncode != 0:
            return []

        return self._parse(stdout.decode(errors="replace"))

    def _parse(self, raw: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                sev = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO)
                findings.append(Finding(
                    id=cve_id,
                    scanner=self.name,
                    severity=sev,
                    title=vuln.get("Title", cve_id),
                    description=vuln.get("Description", "")[:500],
                    affected=f"{vuln.get('PkgName', target)}",
                    current_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                ))

        return findings
