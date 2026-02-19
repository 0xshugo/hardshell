"""Tests for scanner implementations."""

import json

from hardshell.models import Severity
from hardshell.scanners.grype import GrypeScanner
from hardshell.scanners.lynis import LynisScanner
from hardshell.scanners.nuclei import NucleiScanner
from hardshell.scanners.system import SystemScanner
from hardshell.scanners.trivy import TrivyScanner


def test_system_scanner_always_available():
    assert SystemScanner.is_available() is True


def test_trivy_parse():
    scanner = TrivyScanner()
    raw = json.dumps({
        "Results": [{
            "Target": "ubuntu (ubuntu 22.04)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.2-0ubuntu1.12",
                    "FixedVersion": "3.0.2-0ubuntu1.15",
                    "Severity": "HIGH",
                    "Title": "OpenSSL: Buffer overflow",
                    "Description": "A buffer overflow in OpenSSL...",
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "curl",
                    "InstalledVersion": "7.81.0",
                    "Severity": "CRITICAL",
                    "Title": "curl: Use-after-free",
                    "Description": "A use-after-free in curl...",
                },
            ],
        }]
    })

    findings = scanner._parse(raw)
    assert len(findings) == 2
    assert findings[0].id == "CVE-2024-1234"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].fixed_version == "3.0.2-0ubuntu1.15"
    assert findings[1].severity == Severity.CRITICAL


def test_trivy_parse_empty():
    scanner = TrivyScanner()
    assert scanner._parse("{}") == []
    assert scanner._parse("invalid json") == []


def test_grype_parse():
    scanner = GrypeScanner()
    raw = json.dumps({
        "matches": [{
            "vulnerability": {
                "id": "CVE-2024-9999",
                "severity": "Medium",
                "description": "Test vulnerability in libfoo",
                "fix": {"versions": ["1.2.3"]},
            },
            "artifact": {
                "name": "libfoo",
                "version": "1.0.0",
            },
        }]
    })

    findings = scanner._parse(raw)
    assert len(findings) == 1
    assert findings[0].id == "CVE-2024-9999"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].current_version == "1.0.0"
    assert findings[0].fixed_version == "1.2.3"


def test_lynis_parse():
    scanner = LynisScanner()
    report = (
        "warning[]=AUTH-9262|No password set for single mode||\n"
        "suggestion[]=FILE-6310|Consider hardening /tmp mount|Add noexec option|\n"
        "hardening_index=65\n"
    )

    findings = scanner._parse(report)
    assert len(findings) == 3

    warnings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(warnings) == 1
    assert "AUTH-9262" in warnings[0].id

    suggestions = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(suggestions) == 2  # suggestion + hardening index < 70


def test_nuclei_parse():
    scanner = NucleiScanner()
    raw = json.dumps({
        "template-id": "cve-2024-1234",
        "info": {
            "name": "Test Template",
            "severity": "high",
            "description": "Test nuclei finding",
            "reference": ["CVE-2024-1234", "https://example.com"],
        },
        "matched-at": "https://target.com/path",
        "host": "target.com",
    })

    findings = scanner._parse(raw)
    assert len(findings) == 1
    assert findings[0].id == "CVE-2024-1234"
    assert findings[0].severity == Severity.HIGH
