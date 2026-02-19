"""Nuclei vulnerability scanner wrapper (external scan)."""

from __future__ import annotations

import asyncio
import json
import shutil
from urllib.parse import urlparse

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiScanner:
    name = "nuclei"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("nuclei") is not None

    async def scan(self, config: ScanConfig) -> list[Finding]:
        if not config.nuclei_targets:
            return []

        args = self._build_cmd(config.nuclei_targets)
        if "-u" not in args:
            return []

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()

        return self._parse(stdout.decode(errors="replace"))

    def _build_cmd(self, targets: list[str]) -> list[str]:
        args = [
            "nuclei",
            "-jsonl",
            "-silent",
            "-severity",
            "medium,high,critical",
            "-timeout",
            "10",
        ]

        for target in targets:
            parsed = urlparse(target)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            args.extend(["-u", target])

        return args

    def _parse(self, raw: str) -> list[Finding]:
        findings: list[Finding] = []

        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            template_id = data.get("template-id", "unknown")
            sev = SEVERITY_MAP.get(
                info.get("severity", "unknown"), Severity.INFO
            )

            # Extract CVE references if available
            refs = info.get("reference", [])
            cve_ids = [r for r in (refs or []) if r.startswith("CVE-")]
            finding_id = cve_ids[0] if cve_ids else f"NUCLEI-{template_id}"

            findings.append(Finding(
                id=finding_id,
                scanner=self.name,
                severity=sev,
                title=info.get("name", template_id),
                description=info.get("description", "")[:500],
                affected=data.get("matched-at", data.get("host", "")),
                remediation=info.get("remediation"),
            ))

        return findings
