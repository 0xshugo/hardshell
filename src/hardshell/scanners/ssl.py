"""SSL certificate expiry scanner — reads Let's Encrypt certs directly."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity


def _days_until_expiry(cert_path: Path) -> tuple[str, int] | None:
    """Return (domain, days_remaining) or None on error."""
    try:
        import subprocess
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-subject", "-in", str(cert_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        expiry_str = ""
        domain = cert_path.parent.name  # fallback: directory name

        for line in result.stdout.splitlines():
            if line.startswith("notAfter="):
                expiry_str = line.removeprefix("notAfter=").strip()
            elif line.startswith("subject="):
                for part in line.split(","):
                    if "CN" in part and "=" in part:
                        domain = part.split("=", 1)[1].strip()

        if not expiry_str:
            return None

        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        days = (expiry_dt - datetime.now(UTC)).days
        return domain, days
    except Exception:
        return None


class SslScanner:
    name = "ssl"

    @staticmethod
    def is_available() -> bool:
        import shutil
        return shutil.which("openssl") is not None

    async def scan(self, config: ScanConfig) -> list[Finding]:
        cert_paths = self._discover_certs(config)
        findings: list[Finding] = []

        for cert_path in cert_paths:
            result = await asyncio.to_thread(_days_until_expiry, cert_path)
            if result is None:
                continue
            domain, days = result
            finding = self._make_finding(domain, days, cert_path)
            if finding:
                findings.append(finding)

        return findings

    def _discover_certs(self, config: ScanConfig) -> list[Path]:
        paths: list[Path] = []

        # Explicit config first
        for p in config.ssl_cert_paths:
            cp = Path(p)
            if cp.exists():
                paths.append(cp)

        # Auto-discover Let's Encrypt
        if not paths:
            le_base = Path("/etc/letsencrypt/live")
            if le_base.exists():
                for cert in sorted(le_base.glob("*/fullchain.pem")):
                    paths.append(cert)

        return paths

    def _make_finding(self, domain: str, days: int, cert_path: Path) -> Finding | None:
        if days > 30:
            severity = Severity.INFO
            title = f"SSL cert '{domain}' valid for {days} days"
        elif days > 14:
            severity = Severity.MEDIUM
            title = f"SSL cert '{domain}' expires in {days} days"
        elif days > 7:
            severity = Severity.HIGH
            title = f"SSL cert '{domain}' expires in {days} days — renew soon"
        elif days >= 0:
            severity = Severity.CRITICAL
            title = f"SSL cert '{domain}' expires in {days} days — URGENT"
        else:
            severity = Severity.CRITICAL
            title = f"SSL cert '{domain}' EXPIRED {abs(days)} days ago"

        return Finding(
            id=f"SSL-EXPIRY-{domain.replace('.', '-').replace('*', 'wildcard')}",
            scanner=self.name,
            severity=severity,
            title=title,
            description=f"Certificate path: {cert_path}",
            affected=domain,
            remediation="certbot renew --quiet",
        )
