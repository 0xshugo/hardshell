"""Exposure classification of coolify_recreate_* gaps (internal_only / proxy_routed / public)."""

import json
import subprocess

import pytest

from hardshell.early_warning import (
    blocking_coverage_gaps,
    build_report,
    collect_inventory,
)
from tests.test_early_warning import NOW, nginx_intel

RUNNING = "sha256:" + "1" * 64
STALE = "sha256:" + "2" * 64
SMOKE = "bh33te0uq2mxqlh48wj9bey3-123456789012"

# Coolify default routing labels for an sslip.io host (traefik and caddy families).
SMOKE_LABELS = {
    "coolify.managed": "true",
    "coolify.type": "application",
    "coolify.resourceName": "smoke-nginx",
    "com.docker.compose.image": STALE,
    "traefik.enable": "true",
    "traefik.http.routers.http-0-bh33.rule": "Host(`bh33.203.0.113.10.sslip.io`)",
    "caddy_0": "http://bh33.203.0.113.10.sslip.io",
    "caddy_0.reverse_proxy": "{{upstreams 80}}",
}


def fake_docker(monkeypatch, *, ps_rows, ports, networks, labels):
    """Read-only docker fake: ps, inspect, image inspect. Any other command fails."""
    images = {name: "sha256:" + format(i + 5, "x") * 64 for i, (name, _r) in enumerate(ps_rows)}
    images[SMOKE] = RUNNING
    refs = dict(ps_rows)

    def check_output(cmd, **_kw):
        if cmd[:2] == ["docker", "ps"]:
            return "".join(f"{n}\t{r}\t\n" for n, r in ps_rows)
        if cmd[:3] == ["docker", "image", "inspect"]:
            assert cmd[-1] == STALE
            return json.dumps(["nginx:alpine"]) + "\t{}\t" + json.dumps(["NGINX_VERSION=1.31.3"])
        assert cmd[:2] == ["docker", "inspect"], cmd
        fmt, name = cmd[cmd.index("--format") + 1], cmd[-1]
        if "Config.Image" in fmt:
            return refs[name] + "\n"
        if "Config.Labels" in fmt:
            return json.dumps(labels.get(name, {})) + "\n"
        if "NetworkSettings.Networks" in fmt:
            return json.dumps({n: {} for n in networks.get(name, [])}) + "\n"
        if "NetworkSettings.Ports" in fmt:
            return json.dumps(ports.get(name, {})) + "\n"
        return images[name] + "\n"

    def run(cmd, **_kw):
        assert cmd[:2] == ["docker", "exec"] and cmd[3:] in (
            ["nginx", "-v"],
            ["php", "-n", "-r", "echo PHP_VERSION;"],
        ), cmd
        if cmd[2] == SMOKE and cmd[3] == "nginx":
            return subprocess.CompletedProcess(cmd, 0, "", "nginx version: nginx/1.31.9\n")
        return subprocess.CompletedProcess(cmd, 127, "", "not found")

    monkeypatch.setattr(subprocess, "check_output", check_output)
    monkeypatch.setattr(subprocess, "run", run)


def smoke_report(monkeypatch, *, extra_rows=(), smoke_ports=None, extra_networks=None):
    ps_rows = [(SMOKE, "nginx:1.31.9-alpine"), ("factory-nginx", "nginx:1.31.9"), *extra_rows]
    networks = {SMOKE: ["coolify"], "factory-nginx": ["factory"], **(extra_networks or {})}
    fake_docker(
        monkeypatch,
        ps_rows=ps_rows,
        ports={
            SMOKE: smoke_ports if smoke_ports is not None else {"80/tcp": None},
            "factory-nginx": {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]},
        },
        networks=networks,
        labels={SMOKE: SMOKE_LABELS},
    )
    inv = collect_inventory(budget_seconds=10.0, max_workers=2)
    for asset in inv["assets"]:
        asset["observed_at"] = NOW.isoformat()
    result = build_report(nginx_intel(), {**inv, "gaps": []}, NOW)
    gaps = [g for g in result["coverage_gaps"] if g["reason"].startswith("coolify_recreate")]
    assert len(gaps) == 1
    return result, gaps[0]


def test_smoke_nginx_shape_is_internal_only_low_priority(monkeypatch):
    result, gap = smoke_report(monkeypatch)
    assert gap["reason"] == "coolify_recreate_reverts_nginx"
    assert gap["playbook"] == "operations/playbooks/nginx-upgrade.md#coolify-pin"
    ctx = gap["exposure_context"]
    assert ctx["summary"] == "internal_only"
    assert ctx["host_bindings"] == "none"
    assert ctx["published"] == []
    assert ctx["networks"] == ["coolify"]
    assert ctx["routing_labels"] == ["caddy", "traefik"]
    assert ctx["proxy"] is None
    assert ctx["running_proxies"] == []  # factory-nginx is not a traefik/caddy proxy
    assert gap["priority"] == "low"
    assert gap["blocks_status"] is False
    # Still listed, but neither status nor watch exit / ops-check follow-up is driven by it.
    assert result["status"] == "insufficient_evidence"
    assert blocking_coverage_gaps(result["coverage_gaps"]) == []


def test_routing_labels_with_coolify_proxy_on_same_network_is_proxy_routed(monkeypatch):
    _result, gap = smoke_report(
        monkeypatch,
        extra_rows=[("coolify-proxy", "traefik:v3.1")],
        extra_networks={"coolify-proxy": ["coolify"]},
    )
    assert gap["exposure_context"]["summary"] == "proxy_routed"
    assert gap["exposure_context"]["proxy"] == "coolify-proxy"
    assert gap["priority"] == "normal"
    assert gap["blocks_status"] is True
    assert blocking_coverage_gaps([gap]) == [gap]


@pytest.mark.parametrize(
    ("row", "proxy_networks", "expected"),
    [
        (("caddy-edge", "lucaslorentz/caddy-docker-proxy:2.9"), ["coolify"], "proxy_routed"),
        (("coolify-proxy", "traefik:v3.1"), ["other"], "internal_only"),
    ],
)
def test_proxy_match_requires_kind_and_shared_network(monkeypatch, row, proxy_networks, expected):
    _result, gap = smoke_report(
        monkeypatch, extra_rows=[row], extra_networks={row[0]: proxy_networks}
    )
    assert gap["exposure_context"]["summary"] == expected
    assert gap["blocks_status"] is (expected != "internal_only")


def test_non_loopback_publish_is_public_listener(monkeypatch):
    _result, gap = smoke_report(
        monkeypatch, smoke_ports={"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
    )
    ctx = gap["exposure_context"]
    assert ctx["summary"] == "public_listener"
    assert ctx["host_bindings"] == "public"
    assert gap["blocks_status"] is True


def test_loopback_only_publish_keeps_blocking(monkeypatch):
    _result, gap = smoke_report(
        monkeypatch, smoke_ports={"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
    )
    ctx = gap["exposure_context"]
    assert ctx["summary"] == "local_only"
    assert ctx["host_bindings"] == "loopback_only"
    assert gap["blocks_status"] is True


def test_gap_without_collected_context_keeps_current_behavior():
    asset = {
        "asset_id": "smoke-nginx",
        "product": "nginx",
        "version": "1.31.9",
        "image_digest": RUNNING,
        "exposure": "local",
        "observed_at": NOW.isoformat(),
        "coolify": {
            "managed": True,
            "resource": "smoke-nginx",
            "recreate_image": {"image_id": None, "image_refs": [], "nginx_version": None},
        },
    }
    result = build_report(nginx_intel(), {"assets": [asset], "gaps": []}, NOW)
    (gap,) = result["coverage_gaps"]
    assert gap["reason"] == "coolify_recreate_image_unverified"
    assert gap["exposure_context"]["summary"] == "local_only"
    assert gap["blocks_status"] is True
