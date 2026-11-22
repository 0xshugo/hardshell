"""Coolify recreate revert detection and embedded (non-nginx image) nginx tracking."""

import json
import subprocess

from hardshell.early_warning import build_report, collect_inventory
from tests.test_early_warning import NOW, nginx_intel

RUNNING = "sha256:" + "1" * 64
STALE = "sha256:" + "2" * 64
POSTIZ = "sha256:" + "3" * 64


def coolify_asset(recreate):
    return {
        "asset_id": "smoke-nginx",
        "product": "nginx",
        "version": "1.31.9",
        "image_digest": RUNNING,
        "image_ref": "nginx:1.31.9-alpine",
        "packaging": "official_image",
        "exposure": "local",
        "observed_at": NOW.isoformat(),
        "coolify": {"managed": True, "resource": "smoke-nginx", "recreate_image": recreate},
    }


def report(asset):
    return build_report(nginx_intel(), {"assets": [asset], "gaps": []}, NOW)


def test_coolify_recreate_to_stale_nginx_alpine_is_coverage_gap():
    result = report(
        coolify_asset(
            {"image_id": STALE, "image_refs": ["nginx:alpine"], "nginx_version": "1.31.3"}
        )
    )
    assert not result["cases"]  # running 1.31.9 is patched
    (gap,) = result["coverage_gaps"]
    assert gap["reason"] == "coolify_recreate_reverts_nginx"
    assert gap["recreate_version"] == "1.31.3"
    assert gap["recreate_image_refs"] == ["nginx:alpine"]
    assert gap["fixed"] == "1.31.9"
    assert gap["advisory_ids"] == ["CVE-2026-123007"]
    assert gap["playbook"].endswith("#coolify-pin")


def test_coolify_recreate_matching_running_image_is_clean():
    result = report(
        coolify_asset({"image_id": RUNNING, "image_refs": [], "nginx_version": "1.31.9"})
    )
    assert result["coverage_gaps"] == []


def test_coolify_recreate_unknown_image_is_unverified_gap():
    result = report(coolify_asset({"image_id": None, "image_refs": [], "nginx_version": None}))
    assert [g["reason"] for g in result["coverage_gaps"]] == ["coolify_recreate_image_unverified"]


def test_embedded_nginx_case_carries_distro_and_tunnel_context():
    asset = {
        "asset_id": "postiz",
        "product": "nginx",
        "version": "1.22.1",
        "image_digest": POSTIZ,
        "image_ref": "ghcr.io/gitroomhq/postiz-app:v2.25.3",
        "packaging": "embedded",
        "exposure": "local",
        "exposure_context": {
            "summary": "local_bind_behind_tunnel",
            "published": ["127.0.0.1:8093->5000/tcp"],
            "tunnel": "cloudflared",
        },
        "observed_at": NOW.isoformat(),
    }
    (case,) = report(asset)["cases"]
    assert case["status"] == "potentially_affected"
    assert case["packaging"] == "embedded"
    assert case["exposure_context"]["tunnel"] == "cloudflared"
    assert case["reason"].startswith("embedded_nginx_in_non_nginx_image")
    assert "local_bind_reachable_via_tunnel" in case["reason"]
    assert case["next_steps"][0] == "check_distro_security_tracker"
    assert case["executable"] is False


def test_collect_inventory_reads_coolify_labels_and_embedded_postiz(monkeypatch):
    rows = [
        ("smoke-nginx", "nginx:1.31.9-alpine", "bh33"),
        ("postiz", "ghcr.io/gitroomhq/postiz-app:v2.25.3", "nklf"),
        ("cloudflared-nklf", "cloudflare/cloudflared", "nklf"),
    ]
    image = {"smoke-nginx": RUNNING, "postiz": POSTIZ, "cloudflared-nklf": "sha256:" + "4" * 64}
    ref = {name: r for name, r, _ in rows}
    labels = {
        "smoke-nginx": {
            "coolify.managed": "true",
            "coolify.resourceName": "smoke-nginx",
            "com.docker.compose.image": STALE,
        },
        "postiz": {"coolify.managed": "true", "com.docker.compose.image": POSTIZ},
        "cloudflared-nklf": {},
    }
    ports = {
        "smoke-nginx": {"80/tcp": None},
        "postiz": {"5000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8093"}]},
        "cloudflared-nklf": {},
    }
    networks = {
        "smoke-nginx": {"coolify": {}},
        "postiz": {"nklf": {}},
        "cloudflared-nklf": {"nklf": {}},
    }
    nginx_v = {"smoke-nginx": "nginx/1.31.9", "postiz": "nginx/1.22.1"}
    image_inspects = []

    def fake_check_output(cmd, **_kw):
        if cmd[:2] == ["docker", "ps"]:
            return "".join(f"{n}\t{r}\t{p}\n" for n, r, p in rows)
        if cmd[:3] == ["docker", "image", "inspect"]:
            image_inspects.append(cmd[-1])
            assert cmd[-1] == STALE
            return (
                json.dumps(["nginx:alpine"])
                + "\t{}\t"
                + json.dumps(["PATH=/bin", "NGINX_VERSION=1.31.3", "SECRET=x"])
                + "\n"
            )
        if cmd[:2] == ["docker", "inspect"]:
            fmt, name = cmd[cmd.index("--format") + 1], cmd[-1]
            if "Config.Image" in fmt:
                return ref[name] + "\n"
            if "Config.Labels" in fmt:
                return json.dumps(labels[name]) + "\n"
            if "NetworkSettings.Networks" in fmt:
                return json.dumps(networks[name]) + "\n"
            if "NetworkSettings.Ports" in fmt:
                return json.dumps(ports[name]) + "\n"
            return image[name] + "\n"
        raise AssertionError(cmd)

    def fake_run(cmd, **_kw):
        assert cmd[:2] == ["docker", "exec"]
        name, binary = cmd[2], cmd[3]
        if binary == "nginx" and name in nginx_v:
            return subprocess.CompletedProcess(cmd, 0, "", f"nginx version: {nginx_v[name]}\n")
        return subprocess.CompletedProcess(cmd, 127, "", "not found")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(subprocess, "run", fake_run)
    inv = collect_inventory(budget_seconds=10.0, max_workers=2)
    by_name = {a["asset_id"]: a for a in inv["assets"]}
    assert set(by_name) == {"smoke-nginx", "postiz"}
    assert image_inspects == [STALE]

    smoke = by_name["smoke-nginx"]
    assert smoke["packaging"] == "official_image"
    assert smoke["coolify"]["recreate_image"] == {
        "image_id": STALE,
        "image_refs": ["nginx:alpine"],
        "nginx_version": "1.31.3",
    }
    assert "SECRET" not in json.dumps(smoke)
    assert smoke["exposure_context"]["summary"] == "internal_only"
    assert smoke["exposure_context"]["networks"] == ["coolify"]
    assert smoke["exposure_context"]["host_bindings"] == "none"

    postiz = by_name["postiz"]
    assert postiz["packaging"] == "embedded"
    assert postiz["exposure"] == "local"
    assert postiz["exposure_context"] == {
        "summary": "local_bind_behind_tunnel",
        "published": ["127.0.0.1:8093->5000/tcp"],
        "tunnel": "cloudflared",
        "host_bindings": "loopback_only",
        "networks": ["nklf"],
        "routing_labels": [],
        "proxy": None,
        "running_proxies": [],
    }
    # postiz compose image equals running image: recreate keeps the same nginx.
    assert postiz["coolify"]["recreate_image"]["nginx_version"] == "1.22.1"

    for asset in inv["assets"]:
        asset["observed_at"] = NOW.isoformat()  # align with fixed intel clock
    result = build_report(nginx_intel(), {**inv, "gaps": []}, NOW)
    (gap,) = result["coverage_gaps"]
    assert gap["reason"] == "coolify_recreate_reverts_nginx"
    assert gap["exposure_context"]["summary"] == "internal_only"
    assert gap["blocks_status"] is False
    assert {c["asset_id"] for c in result["cases"]} == {"postiz"}


def test_declared_embedded_nginx_without_exec_answer_is_gap(monkeypatch):
    def fake_check_output(cmd, **_kw):
        if cmd[:2] == ["docker", "ps"]:
            return "coolify\tcoollabsio/coolify:4.7.6\t\n"
        fmt = cmd[cmd.index("--format") + 1]
        if "Config.Image" in fmt:
            return "coollabsio/coolify:4.7.6\n"
        if "Config.Labels" in fmt:
            return json.dumps({"io.coolify.nginx.version": "1.31.9-r1"}) + "\n"
        if "NetworkSettings.Ports" in fmt:
            return "{}\n"
        return RUNNING + "\n"

    def fake_run(cmd, **_kw):
        return subprocess.CompletedProcess(cmd, 126, "", "permission denied")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(subprocess, "run", fake_run)
    inv = collect_inventory(budget_seconds=10.0, max_workers=1)
    assert inv["assets"] == []
    assert inv["gaps"][0] == {
        "asset_id": "coolify",
        "reason": "embedded_nginx_unverified",
        "declared_version": "1.31.9",
        "image_ref": "coollabsio/coolify:4.7.6",
    }
