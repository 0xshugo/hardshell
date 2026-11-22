"""Static checks for operations/monitoring (rules, collector, merge helper).

No docker and no network: promtool itself runs via apply-monitoring.sh --validate.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from hardshell.watch_metrics import format_watch_metrics

ROOT = Path(__file__).resolve().parents[1]
MON = ROOT / "operations" / "monitoring"
RULES = MON / "rules"
HARDSHELL_RULES = RULES / "hardshell-alerts.yml"
HOST_RULES = RULES / "host-alerts.yml"
RULE_FILES = [HARDSHELL_RULES, HOST_RULES]
TEST_FILES = sorted((RULES / "tests").glob("*.test.yml"))
COLLECTOR = MON / "host-health-push.sh"
MERGE = MON / "merge-alert-groups.py"
APPLY = MON / "apply-monitoring.sh"
DOC = ROOT / "docs" / "ops" / "monitoring.md"

PROMQL_WORDS = {
    "absent", "and", "bool", "by", "increase", "offset", "or", "rate", "time", "unless",
    "without", "on", "ignoring", "group_left", "group_right", "max", "min", "sum", "d", "h",
    "m", "s",
}  # fmt: skip


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _alerts(path: Path) -> list[dict[str, Any]]:
    return [r for g in _load(path)["groups"] for r in g["rules"] if "alert" in r]


def _metric_names(expr: str) -> set[str]:
    expr = re.sub(r'"[^"]*"', "", expr)
    expr = re.sub(r"\{[^}]*\}", "", expr)
    expr = re.sub(r"\[[^\]]*\]", "", expr)
    names = set(re.findall(r"[A-Za-z_:][A-Za-z0-9_:]*", expr))
    return {n for n in names if n not in PROMQL_WORDS and not re.fullmatch(r"\d+[smhd]", n)}


# --- rule files ---------------------------------------------------------------------------


def test_rule_files_have_expected_groups() -> None:
    assert [g["name"] for g in _load(HARDSHELL_RULES)["groups"]] == ["hardshell_alerts"]
    assert [g["name"] for g in _load(HOST_RULES)["groups"]] == ["host_health_alerts"]


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_every_alert_has_severity_and_actionable_annotations(path: Path) -> None:
    doc = DOC.read_text(encoding="utf-8")
    alerts = _alerts(path)
    assert alerts
    for rule in alerts:
        name = rule["alert"]
        assert rule["labels"]["severity"] in {"critical", "warning"}, name
        ann = rule["annotations"]
        assert ann.get("summary"), name
        desc = ann.get("description") or ""
        anchor = f"docs/ops/monitoring.md#{name.lower()}"
        assert anchor in desc, f"{name}: description must link {anchor}"
        assert re.search(rf"^#+ {name}\s*$", doc, re.M), f"{name}: missing heading in {DOC.name}"
        assert "$value" not in desc + ann["summary"], f"{name}: $value breaks promtool tests"


def test_no_absolute_count_alerts_remain() -> None:
    names = {r["alert"] for r in _alerts(HARDSHELL_RULES)}
    assert not names & {"HardshellCriticalFindings", "HardshellKEVExploit", "HardshellHighEPSS"}
    for rule in _alerts(HARDSHELL_RULES):
        expr = rule["expr"]
        for metric in (
            "hardshell_findings_total",
            "hardshell_kev_count",
            "hardshell_epss_high_count",
        ):
            if metric in expr:
                assert "offset 1d" in expr, f"{rule['alert']} must compare with 24h earlier"


def test_scan_stale_checks_each_mode_in_parentheses() -> None:
    (rule,) = [r for r in _alerts(HARDSHELL_RULES) if r["alert"] == "HardshellScanStale"]
    expr = " ".join(rule["expr"].split())
    assert '(time() - hardshell_scan_timestamp{mode="daily"} > 93600)' in expr
    assert '(time() - hardshell_scan_timestamp{mode="weekly"} > 691200)' in expr


def test_hardshell_rule_metrics_are_emitted_by_hardshell() -> None:
    emitted = set(re.findall(r"^([a-z_]+)[{ ]", format_watch_metrics({}, now=0), re.M))
    metrics_sh = (ROOT / "bin" / "metrics.sh").read_text(encoding="utf-8")
    emitted |= set(re.findall(r'echo "(hardshell_[a-z_]+)[{ ]', metrics_sh))
    assert "/metrics/job/hardshell/mode/$MODE" in metrics_sh  # source of the mode label
    used: set[str] = set()
    for rule in _alerts(HARDSHELL_RULES):
        used |= _metric_names(rule["expr"])
    assert used
    assert used <= emitted, f"not emitted by watch_metrics.py/metrics.sh: {sorted(used - emitted)}"


# --- promtool unit tests stay in sync with the rules --------------------------------------


def _render(template: str, labels: dict[str, str]) -> str:
    out = re.sub(r"\{\{\s*\$labels\.(\w+)\s*\}\}", lambda m: labels.get(m.group(1), ""), template)
    return " ".join(out.split())


def test_promtool_tests_cover_every_alert_and_match_annotations() -> None:
    assert {p.name for p in TEST_FILES} == {"hardshell-alerts.test.yml", "host-alerts.test.yml"}
    for test_path in TEST_FILES:
        data = _load(test_path)
        (rule_ref,) = data["rule_files"]
        rule_path = (test_path.parent / rule_ref).resolve()
        assert rule_path in {p.resolve() for p in RULE_FILES}
        by_name: dict[str, list[dict[str, Any]]] = {}
        for rule in _alerts(rule_path):
            by_name.setdefault(rule["alert"], []).append(rule)
        tested: set[str] = set()
        fired: set[str] = set()
        for case in data["tests"]:
            for check in case["alert_rule_test"]:
                name = check["alertname"]
                assert name in by_name, f"{test_path.name}: unknown alert {name}"
                tested.add(name)
                for exp in check.get("exp_alerts") or []:
                    fired.add(name)
                    labels = exp["exp_labels"]
                    candidates = [
                        r for r in by_name[name] if r["labels"]["severity"] == labels["severity"]
                    ]
                    assert candidates, f"{name}: no rule with severity {labels['severity']}"
                    want = {k: _render(v, labels) for k, v in candidates[0]["annotations"].items()}
                    got = {k: " ".join(str(v).split()) for k, v in exp["exp_annotations"].items()}
                    assert got == want, f"{test_path.name}: {name} annotations drifted"
        assert tested == set(by_name), f"untested alerts: {sorted(set(by_name) - tested)}"
        assert fired == set(by_name), f"alerts never shown firing: {sorted(set(by_name) - fired)}"


# --- host-health collector ----------------------------------------------------------------


def _write(path: Path, text: str, mode: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)
    return path


@pytest.fixture
def fixture_env(tmp_path: Path) -> dict[str, str]:
    cg = tmp_path / "cgroup"
    _write(cg / "pids.current", "150\n")
    _write(cg / "pids.max", "1024\n")
    _write(cg / "pids.events", "max 1070\n")
    _write(cg / "memory.current", "4000000000\n")
    _write(cg / "memory.max", "max\n")
    _write(cg / "memory.events", "low 0\nhigh 0\nmax 3\noom 0\noom_kill 1\n")
    _write(cg / "memory.stat", "anon 2500000000\nfile 1400000000\n")
    proc = tmp_path / "proc"
    _write(
        proc / "meminfo",
        "MemTotal:       16000000 kB\nMemFree: 1 kB\nMemAvailable:    4000000 kB\n",
    )
    _write(proc / "loadavg", "1.25 0.90 0.70 2/900 12345\n")
    systemctl = _write(
        tmp_path / "bin" / "systemctl",
        "#!/usr/bin/env bash\n"
        'case "$2" in\n'
        "  orca-server.service|docker.service) echo active ;;\n"
        "  hardshell-watch.timer) echo inactive; exit 3 ;;\n"
        "  secfeed-monitor.timer) echo failed; exit 3 ;;\n"
        "  *) exit 4 ;;\n"
        "esac\n",
        0o755,
    )
    curl_log = tmp_path / "curl.log"
    curl = _write(
        tmp_path / "bin" / "curl",
        f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{curl_log}.args"\ncat > "{curl_log}"\n',
        0o755,
    )
    env = dict(os.environ)
    env.update(
        HOST_HEALTH_CGROUP_DIR=str(cg),
        HOST_HEALTH_PROC_DIR=str(proc),
        HOST_HEALTH_ROOTFS=str(tmp_path),
        HOST_HEALTH_SYSTEMCTL=str(systemctl),
        HOST_HEALTH_CURL=str(curl),
        HOST_HEALTH_PUSHGATEWAY_URL="http://pushgateway.invalid:9091/",
        CURL_LOG=str(curl_log),
    )
    return env


def _run_collector(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(COLLECTOR), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _samples(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            name, value = line.rsplit(" ", 1)
            out[name] = float(value)
    return out


def test_collector_print_produces_expected_metrics(fixture_env: dict[str, str]) -> None:
    result = _run_collector(fixture_env, "--print")
    assert result.returncode == 0, result.stderr
    s = _samples(result.stdout)
    assert s["orca_server_pids_current"] == 150
    assert s["orca_server_pids_max"] == 1024
    assert s["orca_server_pids_events_max_total"] == 1070
    assert s["orca_server_memory_current_bytes"] == 4_000_000_000
    assert s["orca_server_memory_anon_bytes"] == 2_500_000_000
    assert s["orca_server_memory_max_bytes"] == float("inf")
    assert s["orca_server_memory_events_max_total"] == 3
    assert s["orca_server_memory_events_oom_kill_total"] == 1
    assert s["host_health_orca_server_cgroup_readable"] == 1
    assert s["host_memory_available_ratio"] == pytest.approx(0.25)
    assert s["host_load1"] == 1.25
    assert 0 <= s["host_rootfs_used_ratio"] <= 1
    assert s['systemd_unit_active{unit="orca-server.service"}'] == 1
    assert s['systemd_unit_active{unit="docker.service"}'] == 1
    assert s['systemd_unit_active{unit="hardshell-watch.timer"}'] == 0
    assert s['systemd_unit_active{unit="secfeed-monitor.timer"}'] == 0
    assert "# TYPE orca_server_pids_events_max_total counter" in result.stdout
    assert not Path(fixture_env["CURL_LOG"]).exists(), "--print must not push"


def test_collector_pushes_with_put_to_host_health_job(fixture_env: dict[str, str]) -> None:
    result = _run_collector(fixture_env)
    assert result.returncode == 0, result.stderr
    args = Path(fixture_env["CURL_LOG"] + ".args").read_text().splitlines()
    assert args[args.index("-X") + 1] == "PUT"
    assert args[-1] == "http://pushgateway.invalid:9091/metrics/job/host_health"
    body = Path(fixture_env["CURL_LOG"]).read_text()
    assert "orca_server_pids_current 150" in body


def test_collector_missing_cgroup_exits_zero_with_reason(
    fixture_env: dict[str, str], tmp_path: Path
) -> None:
    fixture_env["HOST_HEALTH_CGROUP_DIR"] = str(tmp_path / "nope")
    result = _run_collector(fixture_env, "--print")
    assert result.returncode == 0
    assert "cgroup dir missing" in result.stderr
    s = _samples(result.stdout)
    assert s["host_health_orca_server_cgroup_readable"] == 0
    assert not any(k.startswith("orca_server_") for k in s)
    assert "host_load1" in s


def test_collector_push_failure_still_exits_zero(fixture_env: dict[str, str]) -> None:
    fixture_env["HOST_HEALTH_CURL"] = "false"
    result = _run_collector(fixture_env)
    assert result.returncode == 0
    assert "push to" in result.stderr


def test_host_rule_metrics_are_emitted_by_collector(fixture_env: dict[str, str]) -> None:
    printed = _run_collector(fixture_env, "--print").stdout
    emitted = set(re.findall(r"^([a-z_]+)[{ ]", printed, re.M)) | {"push_time_seconds"}
    used: set[str] = set()
    for rule in _alerts(HOST_RULES):
        used |= _metric_names(rule["expr"])
    assert used <= emitted, f"not emitted by host-health-push.sh: {sorted(used - emitted)}"


def test_collector_never_runs_docker_and_unit_is_unprivileged() -> None:
    code = [ln for ln in COLLECTOR.read_text().splitlines() if not ln.lstrip().startswith("#")]
    # `docker.service` is a monitored unit name; only a docker command invocation is forbidden.
    assert not any(re.search(r"(^|[\s;|&(\"'])docker(\s|$)", ln) for ln in code)
    unit = (MON / "hardshell-host-health.service").read_text()
    for line in (
        "User=orca-control",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=",
    ):
        assert line in unit
    timer = (MON / "hardshell-host-health.timer").read_text()
    assert "OnUnitActiveSec=60s" in timer


@pytest.mark.parametrize("script", [COLLECTOR, APPLY], ids=lambda p: p.name)
def test_shell_scripts_parse_and_are_executable(script: Path) -> None:
    subprocess.run(["bash", "-n", str(script)], check=True)
    assert script.stat().st_mode & stat.S_IXUSR


def test_apply_script_defaults_to_dry_run_and_avoids_secrets() -> None:
    text = APPLY.read_text()
    assert 'MODE="dry-run"' in text
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    for secret in ("docker/secrets", "build/state", ".env"):
        assert secret not in code


# --- merge helper -------------------------------------------------------------------------

AOI_FIXTURE = """\
groups:
  - name: app_alerts
    rules:
      - alert: AppDown
        expr: up{job="app"} == 0
        labels: {severity: critical}
  - name: container_alerts
    rules:
      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.9
        labels: {severity: warning}
  - name: hardshell_alerts
    rules:
      - alert: HardshellKEVExploit
        expr: hardshell_kev_count > 0
        labels: {severity: critical}
  - name: resource_alerts
    rules:
      - alert: HighCPU
        expr: rate(container_cpu_usage_seconds_total[5m]) > 0.9
        labels: {severity: warning}
"""


def _merge(target: Path, out: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(MERGE), str(target), str(out), str(HARDSHELL_RULES), str(HOST_RULES)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_merge_replaces_hardshell_group_and_keeps_others(tmp_path: Path) -> None:
    target = _write(tmp_path / "prometheus-alerts.yml", AOI_FIXTURE)
    out = tmp_path / "merged.yml"
    result = _merge(target, out)
    assert result.returncode == 0, result.stderr
    assert "replaced: hardshell_alerts" in result.stdout
    assert "appended: host_health_alerts" in result.stdout
    assert target.read_text() == AOI_FIXTURE, "target must not be modified"
    groups = _load(out)["groups"]
    assert [g["name"] for g in groups] == [
        "app_alerts",
        "container_alerts",
        "hardshell_alerts",
        "resource_alerts",
        "host_health_alerts",
    ]
    original = _load(target)["groups"]
    for i in (0, 1, 3):
        assert groups[i] == original[i]
    assert groups[2] == _load(HARDSHELL_RULES)["groups"][0]
    assert groups[4] == _load(HOST_RULES)["groups"][0]

    again = tmp_path / "merged-again.yml"
    assert _merge(out, again).returncode == 0
    assert again.read_text() == out.read_text(), "merge must be idempotent"


def test_merge_rejects_non_rule_file(tmp_path: Path) -> None:
    target = _write(tmp_path / "bad.yml", "global: {}\n")
    result = _merge(target, tmp_path / "out.yml")
    assert result.returncode == 1
    assert "not a Prometheus rule file" in result.stderr
    assert not (tmp_path / "out.yml").exists()
