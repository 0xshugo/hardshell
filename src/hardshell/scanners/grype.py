"""Grype vulnerability scanner wrapper."""

from __future__ import annotations

import asyncio
import json
import shutil

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity

SEVERITY_MAP = {
    "Critical": Severity.CRITICAL,
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Negligible": Severity.INFO,
    "Unknown": Severity.INFO,
}


class GrypeScanner:
    name = "grype"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("grype") is not None

    async def scan(self, config: ScanConfig) -> list[Finding]:
        target = config.trivy_target  # Reuse same target path
        cmd = f"grype dir:{target} -o json --quiet"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        if proc.returncode not in (0, 1):  # grype returns 1 when vulns found
            return []

        return self._parse(stdout.decode(errors="replace"))

    def _parse(self, raw: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            cve_id = vuln.get("id", "UNKNOWN")
            sev = SEVERITY_MAP.get(vuln.get("severity", "Unknown"), Severity.INFO)

            fixed_versions = vuln.get("fix", {}).get("versions", [])
            findings.append(Finding(
                id=cve_id,
                scanner=self.name,
                severity=sev,
                title=vuln.get("description", cve_id)[:200],
                description=vuln.get("description", "")[:500],
                affected=artifact.get("name", ""),
                current_version=artifact.get("version"),
                fixed_version=", ".join(fixed_versions) if fixed_versions else None,
            ))

        return findings
