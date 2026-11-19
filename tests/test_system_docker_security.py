"""Docker host/container security checks for the built-in system scanner."""

from hardshell.models import Severity
from hardshell.scanners.system import SystemScanner


def _ids(findings):
    return {finding.id for finding in findings}


def test_docker_container_findings_detect_high_risk_isolation_breaks():
    scanner = SystemScanner()
    host_config = {
        "Privileged": True,
        "NetworkMode": "host",
        "PidMode": "host",
        "IpcMode": "host",
        "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
        "SecurityOpt": ["seccomp=unconfined", "apparmor=unconfined"],
        "Devices": [{"PathOnHost": "/dev/kvm"}],
    }
    mounts = [
        {
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "RW": True,
        },
        {"Source": "/", "Destination": "/host", "RW": False},
    ]

    findings = scanner._docker_container_findings("dangerous", host_config, mounts)
    ids = _ids(findings)

    assert "SYS-DOCKER-PRIV" in ids
    assert "SYS-DOCKER-HOSTNET" in ids
    assert "SYS-DOCKER-HOSTPID" in ids
    assert "SYS-DOCKER-HOSTIPC" in ids
    assert "SYS-DOCKER-CAP-SYS_ADMIN" in ids
    assert "SYS-DOCKER-CAP-NET_ADMIN" in ids
    assert "SYS-DOCKER-SECCOMP-UNCONFINED" in ids
    assert "SYS-DOCKER-APPARMOR-UNCONFINED" in ids
    assert "SYS-DOCKER-DEVICES" in ids
    assert "SYS-DOCKER-SOCKET-MOUNT" in ids
    assert "SYS-DOCKER-HOSTROOT-MOUNT" in ids

    by_id = {finding.id: finding for finding in findings}
    assert by_id["SYS-DOCKER-SOCKET-MOUNT"].severity == Severity.CRITICAL
    assert by_id["SYS-DOCKER-HOSTPID"].severity == Severity.HIGH


def test_docker_container_findings_accept_default_isolation():
    scanner = SystemScanner()
    host_config = {
        "Privileged": False,
        "NetworkMode": "bridge",
        "PidMode": "",
        "IpcMode": "private",
        "CapAdd": None,
        "SecurityOpt": ["no-new-privileges:true"],
        "Devices": [],
    }
    mounts = [
        {
            "Source": "/var/lib/docker/volumes/app-data/_data",
            "Destination": "/data",
            "RW": True,
        }
    ]

    assert scanner._docker_container_findings("safe", host_config, mounts) == []


def test_docker_ufw_bypass_flags_wildcard_non_web_ports():
    scanner = SystemScanner()
    container_ports = {
        "postgres": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]},
        "n8n": {"5678/tcp": [{"HostIp": "::", "HostPort": "5678"}]},
        "nginx": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]},
    }
    findings = scanner._docker_ufw_bypass_findings(
        ufw_active=True,
        docker_user_rules="-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n",
        container_ports=container_ports,
    )
    assert len(findings) == 1
    assert findings[0].id == "SYS-DOCKER-UFW-BYPASS"
    assert findings[0].severity == Severity.CRITICAL
    assert "postgres:5432" in findings[0].affected
    assert "n8n:5678" in findings[0].affected
    assert "nginx:443" not in findings[0].affected


def test_docker_ufw_bypass_respects_docker_user_drop_and_loopback():
    scanner = SystemScanner()
    wildcard_ports = {"postgres": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}}
    mitigated = scanner._docker_ufw_bypass_findings(
        ufw_active=True,
        docker_user_rules="-N DOCKER-USER\n-A DOCKER-USER -i eth0 -j DROP\n",
        container_ports=wildcard_ports,
    )
    assert mitigated == []

    loopback_only = {
        "postgres": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
        "caddy": {
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}],
            "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}],
        },
    }
    assert (
        scanner._docker_ufw_bypass_findings(
            ufw_active=True,
            docker_user_rules="-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n",
            container_ports=loopback_only,
        )
        == []
    )


def test_docker_ufw_bypass_unreadable_iptables_fails_closed():
    scanner = SystemScanner()
    findings = scanner._docker_ufw_bypass_findings(
        ufw_active=True,
        docker_user_rules=None,
        container_ports={"redis": {"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "6379"}]}},
    )
    assert len(findings) == 1
    assert findings[0].id == "SYS-DOCKER-UFW-BYPASS"
    assert findings[0].severity == Severity.CRITICAL
    assert "unverified" in findings[0].description.lower()


async def test_listening_ports_elevates_database_and_solo_stack_ports(monkeypatch):
    scanner = SystemScanner()
    ss_output = "\n".join(
        [
            "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
            'LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=10,fd=5))',
            'LISTEN 0 4096 :::6379 :::* users:(("redis-server",pid=11,fd=5))',
            'LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:* users:(("coolify",pid=12,fd=5))',
            'LISTEN 0 4096 0.0.0.0:5678 0.0.0.0:* users:(("node",pid=13,fd=5))',
            'LISTEN 0 4096 0.0.0.0:11434 0.0.0.0:* users:(("ollama",pid=14,fd=5))',
            'LISTEN 0 4096 0.0.0.0:18789 0.0.0.0:* users:(("openclaw",pid=15,fd=5))',
            'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=16,fd=5))',
            'LISTEN 0 4096 0.0.0.0:9090 0.0.0.0:* users:(("prom",pid=17,fd=5))',
            'LISTEN 0 4096 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=18,fd=5))',
        ]
    )

    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/ss" if cmd == "ss" else None)

    async def fake_run(*argv: str):
        return (0, ss_output, "")

    monkeypatch.setattr(scanner, "_run", fake_run)
    findings = await scanner._check_listening_ports()
    by_id = {f.id: f for f in findings}

    assert by_id["SYS-PORT-5432"].severity == Severity.CRITICAL
    assert by_id["SYS-PORT-6379"].severity == Severity.CRITICAL
    assert by_id["SYS-PORT-8000"].severity == Severity.HIGH
    assert by_id["SYS-PORT-5678"].severity == Severity.HIGH
    assert by_id["SYS-PORT-11434"].severity == Severity.HIGH
    assert by_id["SYS-PORT-18789"].severity == Severity.HIGH
    assert by_id["SYS-PORT-443"].severity == Severity.INFO
    assert by_id["SYS-PORT-9090"].severity == Severity.MEDIUM
    assert "SYS-PORT-3306" not in by_id
