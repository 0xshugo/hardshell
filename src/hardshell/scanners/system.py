"""Built-in system scanner — no external tools required."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
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
            self._check_linux_lsm(),
            self._check_docker(config),
        ]
        results = await asyncio.gather(*checks, return_exceptions=True)
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        if any(isinstance(result, BaseException) for result in results):
            raise RuntimeError("scanner_incomplete")
        return findings

    async def _run(self, *argv: str) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, stderr = await proc.communicate()
        expected = {"dnf": {0, 100}, "firewall-cmd": {0, 1}, "fail2ban-client": {0, 1}}
        if proc.returncode not in expected.get(argv[0], {0}):
            raise RuntimeError("scanner_command_failed")
        return (
            proc.returncode or 0,
            stdout.decode(errors="replace"),
            (stderr or b"").decode(errors="replace"),
        )

    # --- OS Packages ---

    async def _check_os_packages(self) -> list[Finding]:
        findings: list[Finding] = []

        if shutil.which("apt"):
            rc, out, _ = await self._run("apt", "list", "--upgradable")
            if rc == 0:
                lines = [ln for ln in out.strip().splitlines() if "/" in ln and "Listing" not in ln]
                security_lines = [ln for ln in lines if "security" in ln.lower()]

                if security_lines:
                    desc_lines = "\n".join(f"  - {ln.split('/')[0]}" for ln in security_lines[:20])
                    findings.append(
                        Finding(
                            id="SYS-PKG-SEC",
                            scanner=self.name,
                            severity=Severity.HIGH,
                            title=f"{len(security_lines)} security update(s) pending",
                            description=f"Pending security updates:\n{desc_lines}",
                            affected="system packages",
                            remediation="apt update && apt upgrade -y",
                        )
                    )
                elif lines:
                    findings.append(
                        Finding(
                            id="SYS-PKG-UPD",
                            scanner=self.name,
                            severity=Severity.LOW,
                            title=f"{len(lines)} package update(s) available",
                            affected="system packages",
                            remediation="apt update && apt upgrade -y",
                        )
                    )

        elif shutil.which("dnf"):
            rc, out, _ = await self._run("dnf", "check-update", "--security", "-q")
            if rc == 100:  # dnf returns 100 when updates are available
                lines = [ln for ln in out.strip().splitlines() if ln.strip()]
                if lines:
                    findings.append(
                        Finding(
                            id="SYS-PKG-SEC",
                            scanner=self.name,
                            severity=Severity.HIGH,
                            title=f"{len(lines)} security update(s) pending",
                            affected="system packages",
                            remediation="dnf update --security -y",
                        )
                    )

        return findings

    # --- Listening Ports ---

    async def _check_listening_ports(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("ss"):
            return findings

        rc, out, _ = await self._run("ss", "-tlnp")
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

                findings.append(
                    Finding(
                        id=f"SYS-PORT-{port}",
                        scanner=self.name,
                        severity=sev,
                        title=f"Port {port} ({proc_name}) bound to all interfaces",
                        description=(
                            f"Service on 0.0.0.0:{port} is reachable from any network interface."
                        ),
                        affected=f"port {port} ({proc_name})",
                        remediation=(
                            f"Bind to 127.0.0.1:{port} if internal only, or restrict via firewall."
                        ),
                    )
                )

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
            findings.append(
                Finding(
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
                        "Set 'PasswordAuthentication no' in sshd_config and restart sshd."
                    ),
                )
            )

        # Root login
        root_login = _get_setting("PermitRootLogin")
        if root_login and root_login.lower() not in ("no", "prohibit-password", "without-password"):
            findings.append(
                Finding(
                    id="SYS-SSH-ROOT",
                    scanner=self.name,
                    severity=Severity.HIGH,
                    title="SSH root login permitted",
                    description=f"PermitRootLogin is set to '{root_login}'.",
                    affected="sshd_config",
                    remediation=(
                        "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password'."
                    ),
                )
            )

        # Default port
        port = _get_setting("Port")
        if port == "22" or port is None:
            findings.append(
                Finding(
                    id="SYS-SSH-PORT",
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="SSH running on default port 22",
                    affected="sshd_config",
                    remediation="Consider changing SSH port to reduce scan noise.",
                )
            )

        return findings

    # --- Firewall ---

    async def _check_firewall(self) -> list[Finding]:
        findings: list[Finding] = []

        if shutil.which("ufw"):
            rc, out, _ = await self._run("ufw", "status")
            if rc == 0 and "inactive" in out.lower():
                findings.append(
                    Finding(
                        id="SYS-FW-INACTIVE",
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title="Firewall (ufw) is inactive",
                        affected="ufw",
                        remediation="ufw enable",
                    )
                )
            elif rc == 0 and "active" in out.lower():
                findings.append(
                    Finding(
                        id="SYS-FW-ACTIVE",
                        scanner=self.name,
                        severity=Severity.INFO,
                        title="Firewall (ufw) is active",
                        affected="ufw",
                    )
                )
        elif shutil.which("firewall-cmd"):
            rc, out, _ = await self._run("firewall-cmd", "--state")
            if rc != 0 or "not running" in out.lower():
                findings.append(
                    Finding(
                        id="SYS-FW-INACTIVE",
                        scanner=self.name,
                        severity=Severity.HIGH,
                        title="Firewall (firewalld) is not running",
                        affected="firewalld",
                        remediation="systemctl enable --now firewalld",
                    )
                )
        elif shutil.which("iptables"):
            rc, out, _ = await self._run("iptables", "-L", "-n")
            if rc == 0:
                if out.count("ACCEPT") >= 3 and out.count("\n") < 12:
                    findings.append(
                        Finding(
                            id="SYS-FW-OPEN",
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            title="iptables: permissive defaults, no custom rules",
                            affected="iptables",
                            remediation="Configure iptables or install ufw/firewalld.",
                        )
                    )
        else:
            findings.append(
                Finding(
                    id="SYS-FW-NONE",
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="No firewall tool detected",
                    affected="firewall",
                    remediation="Install and configure ufw or firewalld.",
                )
            )

        return findings

    # --- fail2ban ---

    async def _check_fail2ban(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("fail2ban-client"):
            findings.append(
                Finding(
                    id="SYS-F2B-MISSING",
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="fail2ban is not installed",
                    affected="fail2ban",
                    remediation=("apt install fail2ban && systemctl enable --now fail2ban"),
                )
            )
            return findings

        rc, out, _ = await self._run("fail2ban-client", "status")
        if rc != 0:
            findings.append(
                Finding(
                    id="SYS-F2B-DOWN",
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="fail2ban is installed but not running",
                    affected="fail2ban",
                    remediation="systemctl enable --now fail2ban",
                )
            )
        else:
            if "sshd" not in out:
                findings.append(
                    Finding(
                        id="SYS-F2B-NOSSH",
                        scanner=self.name,
                        severity=Severity.LOW,
                        title="fail2ban sshd jail is not active",
                        affected="fail2ban",
                        remediation="Enable sshd jail in /etc/fail2ban/jail.local.",
                    )
                )

        return findings

    # --- Unattended Upgrades ---

    async def _check_unattended_upgrades(self) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("apt"):
            return findings  # Only relevant for Debian/Ubuntu

        auto_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if not auto_conf.exists():
            findings.append(
                Finding(
                    id="SYS-AUTOUPD-OFF",
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="Automatic security updates not configured",
                    affected="unattended-upgrades",
                    remediation=(
                        "apt install unattended-upgrades && "
                        "dpkg-reconfigure -plow unattended-upgrades"
                    ),
                )
            )
        else:
            try:
                content = auto_conf.read_text()
                if '"1"' not in content and '"true"' not in content.lower():
                    findings.append(
                        Finding(
                            id="SYS-AUTOUPD-OFF",
                            scanner=self.name,
                            severity=Severity.MEDIUM,
                            title="Automatic security updates appear disabled",
                            affected="unattended-upgrades",
                            remediation="Enable in /etc/apt/apt.conf.d/20auto-upgrades.",
                        )
                    )
            except PermissionError:
                pass

        return findings

    # --- Linux Security Modules ---

    async def _check_linux_lsm(self) -> list[Finding]:
        findings: list[Finding] = []
        if not sys.platform.startswith("linux"):
            return findings

        apparmor_enabled = False
        selinux_enforcing = False

        apparmor_flag = Path("/sys/module/apparmor/parameters/enabled")
        if apparmor_flag.exists():
            try:
                apparmor_enabled = apparmor_flag.read_text().strip().lower() in {"y", "yes", "1"}
            except (OSError, PermissionError):
                pass

        selinux_flag = Path("/sys/fs/selinux/enforce")
        if selinux_flag.exists():
            try:
                selinux_enforcing = selinux_flag.read_text().strip() == "1"
            except (OSError, PermissionError):
                pass

        if apparmor_enabled:
            findings.append(
                Finding(
                    id="SYS-LSM-APPARMOR",
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="AppArmor is enabled",
                    affected="kernel LSM",
                )
            )
        if selinux_enforcing:
            findings.append(
                Finding(
                    id="SYS-LSM-SELINUX",
                    scanner=self.name,
                    severity=Severity.INFO,
                    title="SELinux is enforcing",
                    affected="kernel LSM",
                )
            )

        # Only flag absence when Linux exposes the LSM control paths but neither
        # of the common mandatory-access-control systems is active.
        if Path("/sys/module").exists() and not apparmor_enabled and not selinux_enforcing:
            findings.append(
                Finding(
                    id="SYS-LSM-NONE",
                    scanner=self.name,
                    severity=Severity.MEDIUM,
                    title="No enforcing AppArmor or SELinux detected",
                    description=(
                        "Container and host compromise have less mandatory-access-control "
                        "containment when neither AppArmor nor SELinux is enforcing."
                    ),
                    affected="kernel LSM",
                    remediation=(
                        "Enable and enforce AppArmor or SELinux where supported by "
                        "the distribution."
                    ),
                )
            )

        return findings

    # --- Docker ---

    @staticmethod
    def _docker_container_findings(
        container: str,
        host_config: dict[str, object],
        mounts: list[dict[str, object]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        if bool(host_config.get("Privileged")):
            findings.append(
                Finding(
                    id="SYS-DOCKER-PRIV",
                    scanner="system",
                    severity=Severity.CRITICAL,
                    title=f"Container '{container}' runs privileged",
                    affected=container,
                    remediation="Remove privileged mode and grant only required capabilities.",
                )
            )

        network_mode = str(host_config.get("NetworkMode") or "")
        if network_mode == "host":
            findings.append(
                Finding(
                    id="SYS-DOCKER-HOSTNET",
                    scanner="system",
                    severity=Severity.MEDIUM,
                    title=f"Container '{container}' uses host network",
                    affected=container,
                    remediation="Use bridge networking with explicit port mappings.",
                )
            )

        if str(host_config.get("PidMode") or "") == "host":
            findings.append(
                Finding(
                    id="SYS-DOCKER-HOSTPID",
                    scanner="system",
                    severity=Severity.HIGH,
                    title=f"Container '{container}' shares the host PID namespace",
                    affected=container,
                    remediation=(
                        "Remove pid: host unless a reviewed operational exception "
                        "requires it."
                    ),
                )
            )

        if str(host_config.get("IpcMode") or "") == "host":
            findings.append(
                Finding(
                    id="SYS-DOCKER-HOSTIPC",
                    scanner="system",
                    severity=Severity.HIGH,
                    title=f"Container '{container}' shares the host IPC namespace",
                    affected=container,
                    remediation="Remove ipc: host unless a reviewed exception requires it.",
                )
            )

        dangerous_caps = {
            "SYS_ADMIN": Severity.CRITICAL,
            "SYS_MODULE": Severity.CRITICAL,
            "SYS_PTRACE": Severity.HIGH,
            "NET_ADMIN": Severity.HIGH,
        }
        for cap in host_config.get("CapAdd") or []:
            normalized = str(cap).upper()
            if normalized in dangerous_caps:
                findings.append(
                    Finding(
                        id=f"SYS-DOCKER-CAP-{normalized}",
                        scanner="system",
                        severity=dangerous_caps[normalized],
                        title=f"Container '{container}' adds dangerous capability {normalized}",
                        affected=container,
                        remediation=f"Remove {normalized} or document a narrowly scoped exception.",
                    )
                )

        for opt in host_config.get("SecurityOpt") or []:
            lowered = str(opt).lower()
            if "seccomp=unconfined" in lowered:
                findings.append(
                    Finding(
                        id="SYS-DOCKER-SECCOMP-UNCONFINED",
                        scanner="system",
                        severity=Severity.HIGH,
                        title=f"Container '{container}' disables seccomp confinement",
                        affected=container,
                        remediation=(
                            "Use Docker's default seccomp profile or a reviewed "
                            "stricter profile."
                        ),
                    )
                )
            if "apparmor=unconfined" in lowered:
                findings.append(
                    Finding(
                        id="SYS-DOCKER-APPARMOR-UNCONFINED",
                        scanner="system",
                        severity=Severity.HIGH,
                        title=f"Container '{container}' disables AppArmor confinement",
                        affected=container,
                        remediation="Use the default or a service-specific AppArmor profile.",
                    )
                )

        devices = host_config.get("Devices") or []
        if devices:
            findings.append(
                Finding(
                    id="SYS-DOCKER-DEVICES",
                    scanner="system",
                    severity=Severity.MEDIUM,
                    title=f"Container '{container}' has host device passthrough",
                    affected=container,
                    remediation=(
                        "Remove device passthrough or document and constrain the "
                        "required device."
                    ),
                )
            )

        for mount in mounts:
            source = str(mount.get("Source") or "")
            destination = str(mount.get("Destination") or "")
            if source == "/var/run/docker.sock" or destination == "/var/run/docker.sock":
                findings.append(
                    Finding(
                        id="SYS-DOCKER-SOCKET-MOUNT",
                        scanner="system",
                        severity=Severity.CRITICAL,
                        title=f"Container '{container}' can access the Docker socket",
                        description=(
                            "Docker daemon control is effectively root-equivalent "
                            "on a rootful host."
                        ),
                        affected=container,
                        remediation=(
                            "Remove the Docker socket mount; use a narrowly scoped "
                            "control-plane adapter "
                            "if container management is required."
                        ),
                    )
                )
            if source == "/" and destination != "/":
                findings.append(
                    Finding(
                        id="SYS-DOCKER-HOSTROOT-MOUNT",
                        scanner="system",
                        severity=Severity.CRITICAL,
                        title=f"Container '{container}' bind-mounts the host root filesystem",
                        affected=container,
                        remediation=(
                            "Remove the host root bind mount and mount only required "
                            "paths."
                        ),
                    )
                )

        return findings

    async def _check_docker(self, config: ScanConfig) -> list[Finding]:
        findings: list[Finding] = []

        if not shutil.which("docker"):
            return findings

        # Docker daemon remote API exposure. Port 2375 is plaintext; 2376 is
        # conventionally TLS but is still a high-value management surface.
        if shutil.which("ss"):
            rc, out, _ = await self._run("ss", "-tlnp")
            if rc == 0:
                for line in out.splitlines():
                    if re.search(r"(?:0\.0\.0\.0|\*|\[?::\]?):2375\b", line):
                        findings.append(
                            Finding(
                                id="SYS-DOCKER-API-2375",
                                scanner=self.name,
                                severity=Severity.CRITICAL,
                                title="Docker daemon API exposed on TCP 2375",
                                affected="docker daemon",
                                remediation=(
                                    "Disable the TCP listener and use the local Unix socket or a "
                                    "strongly authenticated private management path."
                                ),
                            )
                        )
                    if re.search(r"(?:0\.0\.0\.0|\*|\[?::\]?):2376\b", line):
                        findings.append(
                            Finding(
                                id="SYS-DOCKER-API-2376",
                                scanner=self.name,
                                severity=Severity.HIGH,
                                title="Docker daemon API listens on all interfaces on TCP 2376",
                                affected="docker daemon",
                                remediation=(
                                    "Restrict the Docker management API to a private "
                                    "management plane; "
                                    "verify mutual TLS if TCP access is required."
                                ),
                            )
                        )

        # Check daemon security mode (rootless / user namespaces / seccomp).
        info_fmt = "{{json .SecurityOptions}}"
        rc, out, _ = await self._run("docker", "info", "--format", info_fmt)
        if rc == 0:
            lowered = out.lower()
            rootless = "rootless" in lowered
            userns = "userns" in lowered
            seccomp = "seccomp" in lowered
            if not rootless and not userns:
                findings.append(
                    Finding(
                        id="SYS-DOCKER-ROOTFUL",
                        scanner=self.name,
                        severity=Severity.LOW,
                        title="Docker daemon is rootful without user-namespace isolation",
                        description=(
                            "This is a common deployment mode, but daemon compromise has a larger "
                            "host blast radius than rootless or user-namespace-isolated operation."
                        ),
                        affected="docker daemon",
                        remediation=(
                            "Evaluate rootless Docker or userns-remap in a "
                            "compatibility-tested pilot."
                        ),
                    )
                )
            if not seccomp:
                findings.append(
                    Finding(
                        id="SYS-DOCKER-SECCOMP-MISSING",
                        scanner=self.name,
                        severity=Severity.MEDIUM,
                        title="Docker daemon does not report seccomp security options",
                        affected="docker daemon",
                        remediation=(
                            "Enable Docker's default seccomp profile unless "
                            "explicitly incompatible."
                        ),
                    )
                )

        socket_path = Path("/var/run/docker.sock")
        if socket_path.exists():
            try:
                mode = socket_path.stat().st_mode
                if mode & 0o002:
                    findings.append(
                        Finding(
                            id="SYS-DOCKER-SOCKET-WORLD-WRITABLE",
                            scanner=self.name,
                            severity=Severity.CRITICAL,
                            title="Docker socket is world-writable",
                            affected=str(socket_path),
                            remediation=(
                                "Remove world write permissions and restrict daemon "
                                "access."
                            ),
                        )
                    )
            except (OSError, PermissionError):
                pass

        # Check for images using mutable tags.
        docker_fmt = "{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedSince}}"
        rc, out, _ = await self._run("docker", "images", "--format", docker_fmt)
        if rc == 0:
            for line in out.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split(None, 2)
                image = parts[0] if parts else ""
                if image.endswith(":latest") or ":<none>" in image:
                    findings.append(
                        Finding(
                            id="SYS-DOCKER-LATEST",
                            scanner=self.name,
                            severity=Severity.LOW,
                            title=f"Docker image '{image}' uses mutable tag",
                            affected=image,
                            remediation="Pin images to specific version tags or digests.",
                        )
                    )

        # Inspect running containers without exposing their environment variables.
        rc, out, _ = await self._run("docker", "ps", "--format", "{{.Names}}")
        if rc == 0:
            for container in out.strip().splitlines():
                container = container.strip()
                if not container:
                    continue
                inspect_fmt = "{{json .HostConfig}}|||{{json .Mounts}}"
                rc2, inspect_out, _ = await self._run(
                    "docker", "inspect", "--format", inspect_fmt, container
                )
                if rc2 != 0 or "|||" not in inspect_out:
                    continue
                host_raw, mounts_raw = inspect_out.strip().split("|||", 1)
                try:
                    host_config = json.loads(host_raw)
                    mounts = json.loads(mounts_raw)
                except json.JSONDecodeError as exc:
                    raise RuntimeError("docker_inspect_parse_failed") from exc
                if not isinstance(host_config, dict) or not isinstance(mounts, list):
                    raise RuntimeError("docker_inspect_shape_invalid")
                findings.extend(
                    self._docker_container_findings(container, host_config, mounts)
                )

        return findings
