"""Built-in system scanner — no external tools required."""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path

from hardshell.config import ScanConfig
from hardshell.models import Finding, Severity


class SystemScanner:
    name = "system"

    @staticmethod
    def is_available() -> bool:
        return True  # Always available — built-in checks only

    async def scan(self, config: ScanConfig) -> list[Finding]:
        checks = [
            self._check_os_packages(),
            self._check_listening_ports(),
            self._check_ssh_config(),
            self._check_firewall(),
            self._check_fail2ban(),
            self._check_unattended_upgrades(),
            self._check_docker(config),
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        return findings

    async def _run(self, cmd: str) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return (
            proc.returncode or 0,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )

    # --- OS Packages ---

    async def _check_os_packages(self) -> list[Finding]:
        findings: list[Finding] = []

        if shutil.which("apt"):
            rc, out, _ = await self._run("apt list --upgradable 2>/dev/null")
            if rc == 0:
                lines = [
                    ln for ln in out.strip().splitlines()
                    if "/" in ln and "Listing" not in ln
                ]
                security_lines = [
                    ln for ln in lines if "security" in ln.lower()
                ]

                if security_lines:
                    desc_lines = "\n".join(
                        f"  - {ln.split('/')[0]}" for ln in security_lines[:20]
                    )
                    findings.append(Finding(
                        id="SYS-PKG-SEC",
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"{len(security_lines)} security update(s) pending",
                        description=f"Pending security updates:\n{desc_lines}",
                        affected="system packages",
                        remediation="apt update && apt upgrade -y",
                    ))
                elif lines:
                    findings.append(Finding(
                        id="SYS-PKG-UPD",
                        scanner=self.name,
                        severity=Severity.LOW,
                        title=f"{len(lines)} package update(s) available",
                        affected="system packages",
                        remediation="apt update && apt upgrade -y",
                    ))

        elif shutil.which("dnf"):
            rc, out, _ = await self._run(
                "dnf check-update --security -q 2>/dev/null"
            )
            if rc == 100:  # dnf returns 100 when updates are available
                lines = [
                    ln for ln in out.strip().splitlines() if ln.strip()
                ]
                if lines:
                    findings.append(Finding(
                        id="SYS-PKG-SEC",
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title=f"{len(lines)} security update(s) pending",
                        affected="system packages",
                        remediation="dnf update --security -y",
                    ))

        return findings

    # --- Listening Ports ---

    async def _check_listening_ports(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("ss"):
            return findings

        rc, out, _ = await self._run("ss -tlnp 2>/dev/null")
        if rc != 0:
            return findings

        for line in out.strip().splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[3]

            # Flag services bound to 0.0.0.0 or ::
            is_wildcard = (
                local_addr.startswith("0.0.0.0:")
                or local_addr.startswith("*:")
                or local_addr.startswith(":::")
            )
            if is_wildcard:
                port = local_addr.rsplit(":", 1)[-1]
                process = parts[-1] if len(parts) > 5 else "unknown"

                # Extract process name from users:(("sshd",pid=...))
                proc_name = "unknown"
                match = re.search(r'\("([^"]+)"', process)
                if match:
                    proc_name = match.group(1)

                well_known = {"22", "80", "443", "53"}
                sev = Severity.INFO if port in well_known else Severity.MEDIUM

                findings.append(Finding(
                    id=f"SYS-PORT-{port}",
                    scanner=self.name,
                    severity=sev,
                    title=f"Port {port} ({proc_name}) bound to all interfaces",
                    description=(
                        f"Service on 0.0.0.0:{port} is reachable "
                        f"from any network interface."
                    ),
                    affected=f"port {port} ({proc_name})",
                    remediation=(
                        f"Bind to 127.0.0.1:{port} if internal only, "
                        f"or restrict via firewall."
                    ),
                ))

        return findings

    # --- SSH Config ---

    async def _check_ssh_config(self) -> list[Finding]:
        findings: list[Finding] = []

        config_paths = [Path("/etc/ssh/sshd_config")]
        # Include drop-in configs
        dropin = Path("/etc/ssh/sshd_config.d")
        if dropin.is_dir():
            config_paths.extend(sorted(dropin.glob("*.conf")))

        combined = ""
        for p in config_paths:
            if p.exists():
                try:
                    combined += p.read_text()
                except PermissionError:
                    pass

        if not combined:
            return findings

        def _get_setting(key: str) -> str | None:
            for line in reversed(combined.splitlines()):
                line = line.strip()
                if line.lower().startswith(key.lower()):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        return parts[1].strip()
            return None

        # Password authentication
        pw_auth = _get_setting("PasswordAuthentication")
        if pw_auth and pw_auth.lower() == "yes":
            findings.append(Finding(
                id="SYS-SSH-PASSWD",
                scanner=self.name,
                severity=Severity.HIGH,
                title="SSH password authentication enabled",
                description=(
                    "Password authentication is enabled, "
                    "making the server vulnerable to brute-force."
                ),
                affected="sshd_config",
                remediation=(
                    "Set 'PasswordAuthentication no' in sshd_config "
                    "and restart sshd."
                ),
            ))

        # Root login
        root_login = _get_setting("PermitRootLogin")
        if root_login and root_login.lower() not in (
            "no", "prohibit-password", "without-password"
        ):
            findings.append(Finding(
                id="SYS-SSH-ROOT",
                scanner=self.name,
                severity=Severity.HIGH,
                title="SSH root login permitted",
                description=f"PermitRootLogin is set to '{root_login}'.",
                affected="sshd_config",
                remediation=(
                    "Set 'PermitRootLogin no' or "
                    "'PermitRootLogin prohibit-password'."
                ),
            ))

        # Default port
        port = _get_setting("Port")
        if port == "22" or port is None:
            findings.append(Finding(
                id="SYS-SSH-PORT",
                scanner=self.name,
                severity=Severity.INFO,
                title="SSH running on default port 22",
                affected="sshd_config",
                remediation="Consider changing SSH port to reduce scan noise.",
            ))

        return findings

    # --- Firewall ---

    async def _check_firewall(self) -> list[Finding]:
        findings: list[Finding] = []

        if shutil.which("ufw"):
            rc, out, _ = await self._run("ufw status 2>/dev/null")
            if rc == 0 and "inactive" in out.lower():
                findings.append(Finding(
                    id="SYS-FW-INACTIVE",
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="Firewall (ufw) is inactive",
                    affected="ufw",
                    remediation="ufw enable",
                ))
            elif rc == 0 and "active" in out.lower():
                findings.append(Finding(
                    id="SYS-FW-ACTIVE",
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="Firewall (ufw) is active",
                    affected="ufw",
                ))
        elif shutil.which("firewall-cmd"):
            rc, out, _ = await self._run("firewall-cmd --state 2>/dev/null")
            if rc != 0 or "not running" in out.lower():
                findings.append(Finding(
                    id="SYS-FW-INACTIVE",
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="Firewall (firewalld) is not running",
                    affected="firewalld",
                    remediation="systemctl enable --now firewalld",
                ))
        elif shutil.which("iptables"):
            rc, out, _ = await self._run("iptables -L -n 2>/dev/null")
            if rc == 0:
                if out.count("ACCEPT") >= 3 and out.count("\n") < 12:
                    findings.append(Finding(
                        id="SYS-FW-OPEN",
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title="iptables: permissive defaults, no custom rules",
                        affected="iptables",
                        remediation="Configure iptables or install ufw/firewalld.",
                    ))
        else:
            findings.append(Finding(
                id="SYS-FW-NONE",
                scanner=self.name,
                severity=Severity.MEDIUM,
                title="No firewall tool detected",
                affected="firewall",
                remediation="Install and configure ufw or firewalld.",
            ))

        return findings

    # --- fail2ban ---

    async def _check_fail2ban(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("fail2ban-client"):
            findings.append(Finding(
                id="SYS-F2B-MISSING",
                scanner=self.name,
                severity=Severity.MEDIUM,
                title="fail2ban is not installed",
                affected="fail2ban",
                remediation=(
                    "apt install fail2ban && "
                    "systemctl enable --now fail2ban"
                ),
            ))
            return findings

        rc, out, _ = await self._run("fail2ban-client status 2>/dev/null")
        if rc != 0:
            findings.append(Finding(
                id="SYS-F2B-DOWN",
                scanner=self.name,
                severity=Severity.MEDIUM,
                title="fail2ban is installed but not running",
                affected="fail2ban",
                remediation="systemctl enable --now fail2ban",
            ))
        else:
            if "sshd" not in out:
                findings.append(Finding(
                    id="SYS-F2B-NOSSH",
                    scanner=self.name,
                    severity=Severity.LOW,
                    title="fail2ban sshd jail is not active",
                    affected="fail2ban",
                    remediation="Enable sshd jail in /etc/fail2ban/jail.local.",
                ))

        return findings

    # --- Unattended Upgrades ---

    async def _check_unattended_upgrades(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("apt"):
            return findings  # Only relevant for Debian/Ubuntu

        auto_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if not auto_conf.exists():
            findings.append(Finding(
                id="SYS-AUTOUPD-OFF",
                scanner=self.name,
                severity=Severity.MEDIUM,
                title="Automatic security updates not configured",
                affected="unattended-upgrades",
                remediation=(
                    "apt install unattended-upgrades && "
                    "dpkg-reconfigure -plow unattended-upgrades"
                ),
            ))
        else:
            try:
                content = auto_conf.read_text()
                if '"1"' not in content and '"true"' not in content.lower():
                    findings.append(Finding(
                        id="SYS-AUTOUPD-OFF",
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title="Automatic security updates appear disabled",
                        affected="unattended-upgrades",
                        remediation="Enable in /etc/apt/apt.conf.d/20auto-upgrades.",
                    ))
            except PermissionError:
                pass

        return findings

    # --- Docker ---

    async def _check_docker(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("docker"):
            return findings

        # Check for images using :latest tag
        docker_fmt = "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}"
        rc, out, _ = await self._run(
            f"docker images --format '{docker_fmt}' 2>/dev/null"
        )
        if rc == 0:
            for line in out.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split(None, 2)
                image = parts[0] if parts else ""
                if image.endswith(":latest") or ":<none>" in image:
                    findings.append(Finding(
                        id="SYS-DOCKER-LATEST",
                        scanner=self.name,
                        severity=Severity.LOW,
                        title=f"Docker image '{image}' uses mutable tag",
                        affected=image,
                        remediation="Pin images to specific version tags or digests.",
                    ))

        # Check for privileged or host network containers
        rc, out, _ = await self._run(
            "docker ps --format '{{.Names}}' 2>/dev/null"
        )
        if rc == 0:
            for container in out.strip().splitlines():
                if not container.strip():
                    continue
                inspect_fmt = (
                    "{{.HostConfig.Privileged}} "
                    "{{.HostConfig.NetworkMode}}"
                )
                rc2, inspect_out, _ = await self._run(
                    f"docker inspect --format '{inspect_fmt}' "
                    f"{container} 2>/dev/null"
                )
                if rc2 == 0:
                    parts = inspect_out.strip().split()
                    privileged = parts[0] if parts else "false"
                    net_mode = parts[1] if len(parts) > 1 else ""

                    if privileged.lower() == "true":
                        findings.append(Finding(
                            id="SYS-DOCKER-PRIV",
                            scanner=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Container '{container}' runs privileged",
                            affected=container,
                            remediation=(
                                "Remove 'privileged: true' and use "
                                "specific capabilities instead."
                            ),
                        ))

                    if net_mode == "host":
                        findings.append(Finding(
                            id="SYS-DOCKER-HOSTNET",
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            title=f"Container '{container}' uses host network",
                            affected=container,
                            remediation="Use bridge networking with port mappings.",
                        ))

        return findings
