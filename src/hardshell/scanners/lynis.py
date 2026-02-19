"""Lynis security auditing wrapper."""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity


class LynisScanner:
    name = "lynis"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("lynis") is not None

    async def scan(self, config: ScanConfig) -> list[Finding]:
        log_path = Path("/var/log/lynis-report.dat")

        proc = await asyncio.create_subprocess_shell(
            "lynis audit system --no-colors --quick --quiet 2>/dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        if not log_path.exists():
            return []

        return self._parse(log_path.read_text(errors="replace"))

    def _parse(self, report: str) -> list[Finding]:
        findings: list[Finding] = []

        for line in report.splitlines():
            line = line.strip()

            # Parse warnings: warning[]=<id>|<text>|<details>|<severity>
            if line.startswith("warning[]="):
                parts = line[len("warning[]="):].split("|")
                if len(parts) >= 2:
                    test_id = parts[0]
                    text = parts[1]
                    details = parts[2] if len(parts) > 2 else ""
                    findings.append(Finding(
                        id=f"LYNIS-{test_id}",
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=text,
                        description=details,
                        affected=test_id,
                    ))

            # Parse suggestions: suggestion[]=<id>|<text>|<details>|<severity>
            elif line.startswith("suggestion[]="):
                parts = line[len("suggestion[]="):].split("|")
                if len(parts) >= 2:
                    test_id = parts[0]
                    text = parts[1]
                    details = parts[2] if len(parts) > 2 else ""
                    findings.append(Finding(
                        id=f"LYNIS-{test_id}",
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title=text,
                        description=details,
                        affected=test_id,
                        remediation=details if details else None,
                    ))

        # Parse hardening index
        match = re.search(r"hardening_index=(\d+)", report)
        if match:
            index = int(match.group(1))
            severity = Severity.INFO
            if index < 50:
                severity = Severity.HIGH
            elif index < 70:
                severity = Severity.MEDIUM

            findings.append(Finding(
                id="LYNIS-HARDENING-INDEX",
                scanner=self.name,
                severity=severity,
                title=f"Lynis hardening index: {index}/100",
                affected="system",
            ))

        return findings
