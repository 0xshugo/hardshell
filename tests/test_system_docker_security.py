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
