from hardshell.models import Finding, Severity


def test_epss_percentile_stays_in_json_contract():
    finding = Finding(id="CVE-2026-1234", scanner="trivy", title="example",
                      severity=Severity.HIGH, affected="example", epss_percentile=0.9)
    assert finding.model_dump(mode="json")["epss_percentile"] == 0.9
