"""Read-only rapid advisory-to-runtime matching. Model output never authorizes execution."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from hardshell.intel.vendor import VERSION, nginx_version_affected

NGINX_VERSION_LINE = re.compile(r"nginx/(\d+\.\d+\.\d+)", re.I)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
CONTAINER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def _docker_image_id(name: str) -> str:
    return subprocess.check_output(
        ["docker", "inspect", "--format", "{{.Image}}", name], text=True, timeout=10
    ).strip()


def _docker_image_ref(name: str) -> str:
    return subprocess.check_output(
        ["docker", "inspect", "--format", "{{.Config.Image}}", name], text=True, timeout=10
    ).strip()


def _docker_ports(name: str):
    raw = subprocess.check_output(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", name],
        text=True,
        timeout=10,
    ).strip()
    try:
        ports = json.loads(raw) or {}
    except json.JSONDecodeError:
        return None
    return ports if isinstance(ports, dict) else None


def _docker_labels(name: str) -> dict:
    """Container labels only (never Env): used for Coolify / embedded-runtime hints."""
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", "--format", "{{json .Config.Labels}}", name],
            text=True,
            timeout=10,
        ).strip()
        labels = json.loads(raw) or {}
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(labels, dict):
        return {}
    return {str(k): str(v) for k, v in labels.items()}


def _docker_networks(name: str) -> list[str] | None:
    """Names of docker networks the container is attached to (read-only inspect)."""
    try:
        raw = subprocess.check_output(
            ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", name],
            text=True,
            timeout=10,
        ).strip()
        networks = json.loads(raw)
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(networks, dict):
        return None
    return sorted(str(k) for k in networks)


CADDY_LABEL = re.compile(r"caddy(_\d+)?(\.|$)")


def _routing_label_kinds(labels: dict) -> list[str]:
    """Reverse-proxy routing label families present on the container (keys only)."""
    kinds = set()
    for key in labels:
        lowered = key.lower()
        if lowered.startswith("traefik."):
            kinds.add("traefik")
        elif CADDY_LABEL.match(lowered):
            kinds.add("caddy")
    return sorted(kinds)


def _proxy_kind(name: str, image_ref: str) -> str | None:
    """Heuristic: traefik / caddy / coolify-proxy from container name or image."""
    image = (image_ref or "").lower().split("/")[-1]
    lowered = (name or "").lower()
    for kind in ("traefik", "caddy"):
        if kind in image or kind in lowered:
            return kind
    if lowered == "coolify-proxy" or lowered.startswith("coolify-proxy"):
        return "coolify-proxy"
    return None


def _running_proxies(rows) -> list[dict]:
    """Reverse proxies among running containers (``docker ps`` rows + network inspect)."""
    proxies = []
    for name, image_ref, _project in rows:
        kind = _proxy_kind(name, image_ref)
        if kind:
            proxies.append({"name": name, "kind": kind, "networks": _docker_networks(name)})
    return proxies


def _published_bindings(ports) -> list[str]:
    out = []
    for key, bindings in sorted((ports or {}).items()):
        for binding in bindings or []:
            host_ip = (binding or {}).get("HostIp") or "0.0.0.0"
            host_port = (binding or {}).get("HostPort") or ""
            if host_port:
                out.append(f"{host_ip}:{host_port}->{key}")
    return out


def _public_http_exposure(name: str, ports=None) -> str:
    """Classify published HTTP(S) listeners without reading application config."""
    ports = ports if ports is not None else _docker_ports(name)
    if ports is None:
        return "unknown"
    public = False
    for key, bindings in ports.items():
        if not isinstance(key, str) or not key.startswith(("80/", "443/")):
            continue
        if not bindings:
            continue
        for binding in bindings:
            host_ip = (binding or {}).get("HostIp") or ""
            host_port = (binding or {}).get("HostPort") or ""
            if not host_port:
                continue
            # Non-loopback publish counts as public for early-warning urgency.
            if host_ip in ("", "0.0.0.0", "::") or not host_ip.startswith(("127.", "::1")):
                public = True
                break
        if public:
            break
    return "public" if public else "local"


def _looks_like_nginx(image_ref: str) -> bool:
    ref = (image_ref or "").lower()
    return bool(re.search(r"(^|/)nginx([:]|$)", ref) or "nginx" in ref.split("/")[-1])


def _label_nginx_version(labels: dict) -> str | None:
    """Image-declared nginx version (e.g. coolify ``io.coolify.nginx.version=1.31.9-r1``)."""
    for key, value in sorted(labels.items()):
        if key.lower().endswith("nginx.version"):
            match = VERSION.match(value or "")
            if match:
                return match.group(0)
    return None


def _image_nginx_metadata(image_id: str) -> dict:
    """Read-only ``docker image inspect``: tags and declared nginx version, no exec.

    Official ``nginx:*`` images declare ``NGINX_VERSION`` in their Env; only that key
    is retained, never other Env values.
    """
    meta = {"image_id": image_id, "image_refs": [], "nginx_version": None}
    try:
        raw = subprocess.check_output(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{json .RepoTags}}\t{{json .Config.Labels}}\t{{json .Config.Env}}",
                image_id,
            ],
            text=True,
            timeout=10,
        ).strip()
        tags_raw, labels_raw, env_raw = raw.split("\t", 2)
        tags = json.loads(tags_raw) or []
        labels = json.loads(labels_raw) or {}
        env = json.loads(env_raw) or []
    except (subprocess.SubprocessError, OSError, ValueError):
        return meta
    meta["image_refs"] = [t for t in tags if isinstance(t, str)][:5]
    for item in env if isinstance(env, list) else []:
        if isinstance(item, str) and item.startswith("NGINX_VERSION="):
            value = item.split("=", 1)[1]
            if VERSION.fullmatch(value):
                meta["nginx_version"] = value
    if meta["nginx_version"] is None and isinstance(labels, dict):
        meta["nginx_version"] = _label_nginx_version(
            {str(k): str(v) for k, v in labels.items()}
        )
    return meta


def _coolify_context(labels: dict, image: str, version: str) -> dict | None:
    """What a Coolify redeploy would bring back, from container labels only.

    Coolify regenerates the compose file from its own database on every redeploy, so a
    container recreated by hand with a newer tag reverts to the image Coolify resolved
    (``com.docker.compose.image``) unless the tag is pinned in Coolify itself.
    """
    if labels.get("coolify.managed") != "true":
        return None
    ctx = {
        "managed": True,
        "type": labels.get("coolify.type"),
        "resource": labels.get("coolify.resourceName") or labels.get("coolify.name"),
        "project": labels.get("coolify.projectName"),
    }
    compose_image = labels.get("com.docker.compose.image") or ""
    if compose_image == image:
        ctx["recreate_image"] = {"image_id": image, "image_refs": [], "nginx_version": version}
    elif DIGEST.fullmatch(compose_image):
        ctx["recreate_image"] = _image_nginx_metadata(compose_image)
    else:
        ctx["recreate_image"] = {"image_id": None, "image_refs": [], "nginx_version": None}
    return ctx


def _probe_nginx_container(
    name: str,
    *,
    image: str | None = None,
    image_ref: str | None = None,
    labels: dict | None = None,
):
    image = image if image is not None else _docker_image_id(name)
    image_ref = image_ref if image_ref is not None else _docker_image_ref(name)
    labels = labels if labels is not None else {}
    try:
        run = subprocess.run(
            ["docker", "exec", name, "nginx", "-v"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        current = _docker_image_id(name)
        if current != image:
            return None, {"asset_id": name, "reason": "image_changed"}
        match = NGINX_VERSION_LINE.search((run.stderr or "") + "\n" + (run.stdout or ""))
        if run.returncode == 0 and match:
            ports = _docker_ports(name)
            asset = {
                "asset_id": name,
                "product": "nginx",
                "version": match.group(1),
                "image_digest": image,
                "image_ref": image_ref,
                # official_image: nginx:* upstream build; embedded: nginx packaged inside
                # another image (e.g. Debian apt nginx in postiz), distro backports apply.
                "packaging": "official_image" if _looks_like_nginx(image_ref) else "embedded",
                "exposure": _public_http_exposure(name, ports),
                "published": _published_bindings(ports),
                "observed_at": datetime.now(UTC).isoformat(),
            }
            coolify = _coolify_context(labels, image, match.group(1))
            if coolify is not None:
                asset["coolify"] = coolify
                asset["networks"] = _docker_networks(name)
                asset["routing_labels"] = _routing_label_kinds(labels)
            return asset, None
        if _looks_like_nginx(image_ref):
            return None, {"asset_id": name, "reason": "nginx_runtime_unverified"}
        declared = _label_nginx_version(labels)
        if declared:
            # Image metadata says nginx is embedded but `nginx -v` did not answer.
            return None, {
                "asset_id": name,
                "reason": "embedded_nginx_unverified",
                "declared_version": declared,
                "image_ref": image_ref,
            }
        return None, None
    except subprocess.TimeoutExpired:
        return None, {"asset_id": name, "reason": "runtime_probe_timeout"}


def _probe_php_container(
    name: str, *, image: str | None = None, image_ref: str | None = None
):
    image = image if image is not None else _docker_image_id(name)
    try:
        # -n skips application php.ini and auto_prepend_file. No shell, env, labels or network.
        run = subprocess.run(
            ["docker", "exec", name, "php", "-n", "-r", "echo PHP_VERSION;"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = run.stdout.strip()
        current = _docker_image_id(name)
        if current != image:
            return None, {"asset_id": name, "reason": "image_changed"}
        if run.returncode == 0 and VERSION.fullmatch(version):
            resolved_ref = image_ref if image_ref is not None else _docker_image_ref(name)
            return {
                "asset_id": name,
                "product": "php",
                "version": version,
                "image_digest": image,
                "image_ref": resolved_ref,
                "exposure": _public_http_exposure(name),
                "observed_at": datetime.now(UTC).isoformat(),
            }, None
        # Absence from PATH does not prove that no embedded PHP runtime exists.
        return None, {"asset_id": name, "reason": "php_runtime_unverified"}
    except subprocess.TimeoutExpired:
        return None, {"asset_id": name, "reason": "runtime_probe_timeout"}


def _probe_container(name: str):
    image = _docker_image_id(name)
    image_ref = _docker_image_ref(name)
    labels = _docker_labels(name)
    assets = []
    gaps = []
    nginx_asset, nginx_gap = _probe_nginx_container(
        name, image=image, image_ref=image_ref, labels=labels
    )
    if nginx_asset is not None:
        assets.append(nginx_asset)
    elif nginx_gap is not None and nginx_gap.get("reason") == "embedded_nginx_unverified":
        gaps.append(nginx_gap)
    elif nginx_gap is not None and nginx_gap.get("reason") in {
        "image_changed",
        "runtime_probe_timeout",
        "nginx_runtime_unverified",
    }:
        # Known nginx-shaped asset or probe failure: do not also emit php_runtime_unverified.
        return [], [nginx_gap]
    php_asset, php_gap = _probe_php_container(name, image=image, image_ref=image_ref)
    if php_asset is not None:
        assets.append(php_asset)
    elif php_gap is not None and (
        not assets or php_gap.get("reason") != "php_runtime_unverified"
    ):
        gaps.append(php_gap)
    return assets, gaps


def _tunnel_projects(rows) -> set[str]:
    """Compose projects that run a cloudflared container (tunnel ingress, no host port)."""
    return {
        project
        for _name, image_ref, project in rows
        if project and "cloudflared" in (image_ref or "").lower().split("/")[-1]
    }


def _host_bindings(published: list[str]) -> str:
    """none / loopback_only / public from ``HostIp:HostPort->port`` strings."""
    if not published:
        return "none"
    for item in published:
        host_ip = item.split("->", 1)[0].rsplit(":", 1)[0].strip("[]")
        if not host_ip.startswith(("127.", "::1")):
            return "public"
    return "loopback_only"


def _matching_proxy(asset: dict, proxies: list[dict]) -> str | None:
    """Running proxy that could route this container's labels (kind + shared network).

    Unknown network membership on either side is treated as a match (conservative).
    """
    kinds = set(asset.get("routing_labels") or [])
    if not kinds:
        return None
    networks = asset.get("networks")
    for proxy in proxies:
        if proxy["kind"] != "coolify-proxy" and proxy["kind"] not in kinds:
            continue
        if networks is None or proxy.get("networks") is None:
            return proxy["name"]
        if set(networks) & set(proxy["networks"]):
            return proxy["name"]
    return None


def _exposure_context(
    asset: dict,
    tunnels: set[str],
    projects: dict[str, str],
    proxies: list[dict] | None = None,
) -> dict:
    """Human-readable reachability of an nginx asset.

    ``public_listener`` (non-loopback publish) > ``proxy_routed`` (routing labels and a
    matching running proxy) > ``local_bind_behind_tunnel`` > ``internal_only`` (no host
    binding, no proxy, network membership known) > ``local_only`` > ``unknown``.
    """
    project = projects.get(asset.get("asset_id", ""), "")
    tunnel = "cloudflared" if project and project in tunnels else None
    exposure = asset.get("exposure", "unknown")
    published = asset.get("published", [])
    bindings = _host_bindings(published)
    proxy = _matching_proxy(asset, proxies or [])
    networks = asset.get("networks")
    if exposure == "public" or bindings == "public":
        summary = "public_listener"
    elif proxy:
        summary = "proxy_routed"
    elif exposure == "local" and tunnel:
        summary = "local_bind_behind_tunnel"
    elif exposure == "local" and bindings == "none" and networks is not None:
        summary = "internal_only"
    elif exposure == "local":
        summary = "local_only"
    else:
        summary = "unknown"
    context = {
        "summary": summary,
        "published": published,
        "tunnel": tunnel,
    }
    if "networks" in asset or "routing_labels" in asset:
        context.update(
            {
                "host_bindings": bindings,
                "networks": networks,
                "routing_labels": asset.get("routing_labels") or [],
                "proxy": proxy,
                "running_proxies": sorted(p["name"] for p in proxies or []),
            }
        )
    return context


def collect_inventory(budget_seconds: float = 180.0, max_workers: int = 4):
    lines = subprocess.check_output(
        [
            "docker",
            "ps",
            "--format",
            '{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}',
        ],
        text=True,
        timeout=15,
    ).splitlines()
    rows = []
    for line in lines:
        parts = (line.split("\t") + ["", ""])[:3]
        rows.append((parts[0], parts[1], parts[2]))
    names = [row[0] for row in rows]
    tunnels = _tunnel_projects(rows)
    projects = {name: project for name, _ref, project in rows}
    if len(names) > 200:
        raise ValueError("inventory_too_large")
    for name in names:
        if not CONTAINER_NAME.fullmatch(name):
            raise ValueError("invalid_container_name")
    assets, gaps = [], []
    deadline = time.monotonic() + budget_seconds
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = [pool.submit(_probe_container, name) for name in names]
        for idx, fut in enumerate(futures):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for pending in futures[idx:]:
                    pending.cancel()
                gaps.append({"reason": "runtime_collection_budget_exceeded"})
                break
            try:
                found_assets, found_gaps = fut.result(timeout=remaining)
            except TimeoutError:
                for pending in futures[idx:]:
                    pending.cancel()
                gaps.append({"reason": "runtime_collection_budget_exceeded"})
                break
            assets.extend(found_assets)
            gaps.extend(found_gaps)
    nginx_assets = [a for a in assets if a.get("product") == "nginx"]
    proxies = _running_proxies(rows) if any(a.get("coolify") for a in nginx_assets) else []
    for asset in nginx_assets:
        asset["exposure_context"] = _exposure_context(asset, tunnels, projects, proxies)
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "assets": assets,
        "gaps": gaps,
        "scope": (
            "running containers: php on PATH and nginx -v (official and embedded images); "
            "Coolify recreate image via labels; "
            "host and embedded unverified runtimes remain coverage gaps"
        ),
    }


def collect_php(budget_seconds: float = 120.0, max_workers: int = 4):
    """Backward-compatible alias: inventory now includes nginx and php assets."""
    return collect_inventory(budget_seconds=budget_seconds, max_workers=max_workers)


def fresh(value, now, *, maximum_age=timedelta(minutes=45)):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.tzinfo is not None and now - maximum_age <= date <= (now + timedelta(minutes=5))
    except (ValueError, TypeError, AttributeError):
        return False


def _php_cases(asset, advisories, now):
    cases = []
    version = asset.get("version", "")
    exposure = asset.get("exposure", "unknown")
    for advisory in advisories:
        if advisory.get("product") != "php":
            continue
        fixed = [
            v
            for v in advisory["fixed_versions"]
            if VERSION.fullmatch(v) and v.split(".")[:2] == version.split(".")[:2]
        ]
        stamp = advisory.get("observed_at") or advisory.get("_intel_observed_at")
        valid = (
            VERSION.fullmatch(version)
            and DIGEST.fullmatch(asset.get("image_digest") or "")
            and fresh(asset.get("observed_at"), now)
            and fresh(stamp, now, maximum_age=timedelta(hours=2))
        )
        if valid and fixed:
            threshold = min(fixed, key=lambda v: tuple(map(int, v.split("."))))
            if tuple(map(int, version.split("."))) >= tuple(map(int, threshold.split("."))):
                continue
        else:
            threshold = None
        if valid and threshold and exposure == "public":
            status = "actionable"
            reason = "upstream_version_match; public_http_listener; vendor_backport_unverified"
        elif valid and threshold:
            status = "potentially_affected"
            reason = "upstream_version_match; vendor_backport_and_web_exposure_unverified"
        else:
            status = "needs_evidence"
            reason = "upstream_version_match; vendor_backport_and_web_exposure_unverified"
        case_id = hashlib.sha256(
            json.dumps(
                [asset["asset_id"], asset.get("image_digest"), version, advisory["id"]],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        case = {
            "case_id": case_id,
            "advisory_id": advisory["id"],
            "asset_id": asset["asset_id"],
            "product": "php",
            "installed": version,
            "image_digest": asset.get("image_digest"),
            "exposure": exposure,
            "fixed": threshold,
            "status": status,
            "priority": "P1",
            "references": advisory["references"],
            "public_summary": advisory.get("public_summary", ""),
            "reason": reason,
            "next_steps": [
                "verify_vendor_patch",
                "prepare_image_update",
                "request_service_approval",
                "verify_runtime_after_update",
            ],
            "requires_approval": True,
            "executable": False,
        }
        if asset.get("image_ref"):
            case["image_ref"] = asset["image_ref"]
        cases.append(case)
    return cases


def _nginx_cases(asset, advisories, now):
    cases = []
    version = asset.get("version", "")
    exposure = asset.get("exposure", "unknown")
    for advisory in advisories:
        if advisory.get("product") != "nginx":
            continue
        floors = [v for v in advisory.get("fixed_versions", []) if VERSION.fullmatch(v)]
        ranges = advisory.get("vulnerable_ranges") or []
        stamp = advisory.get("observed_at") or advisory.get("_intel_observed_at")
        valid = (
            VERSION.fullmatch(version)
            and DIGEST.fullmatch(asset.get("image_digest") or "")
            and fresh(asset.get("observed_at"), now)
            and fresh(stamp, now, maximum_age=timedelta(hours=2))
            and bool(floors)
            and bool(ranges)
        )
        affected = valid and nginx_version_affected(version, floors, ranges)
        if valid and not affected:
            continue
        severity = (advisory.get("severity") or "medium").lower()
        if affected and exposure == "public" and severity in {"critical", "major", "high"}:
            status = "actionable"
            priority = "P1"
        elif affected:
            status = "potentially_affected"
            priority = "P1" if severity in {"critical", "major", "high"} else "P2"
        else:
            status = "needs_evidence"
            priority = "P1" if severity in {"critical", "major", "high"} else "P2"
        threshold = min(floors, key=lambda v: tuple(map(int, v.split(".")))) if floors else None
        case_id = hashlib.sha256(
            json.dumps(
                [asset["asset_id"], asset.get("image_digest"), version, advisory["id"]],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        embedded = asset.get("packaging") == "embedded"
        reason = "nginx_upstream_version_in_vulnerable_range; distro_backport_unverified"
        next_steps = [
            "verify_vendor_patch",
            "prepare_image_update",
            "request_service_approval",
            "verify_runtime_after_update",
        ]
        if embedded:
            reason = "embedded_nginx_in_non_nginx_image; " + reason
            next_steps = ["check_distro_security_tracker", *next_steps]
        context = asset.get("exposure_context")
        if context and context.get("summary") == "local_bind_behind_tunnel":
            reason += "; local_bind_reachable_via_tunnel"
        case = {
            "case_id": case_id,
            "advisory_id": advisory["id"],
            "asset_id": asset["asset_id"],
            "product": "nginx",
            "installed": version,
            "image_digest": asset.get("image_digest"),
            "image_ref": asset.get("image_ref"),
            "exposure": exposure,
            "severity": severity,
            "fixed": threshold,
            "fixed_versions": floors,
            "status": status,
            "priority": priority,
            "references": advisory.get("references", []),
            "public_summary": advisory.get("public_summary", ""),
            "reason": reason,
            "next_steps": next_steps,
            "requires_approval": True,
            "executable": False,
        }
        for key in ("packaging", "exposure_context"):
            if asset.get(key):
                case[key] = asset[key]
        if asset.get("coolify"):
            case["coolify_managed"] = True
        cases.append(case)
    return cases


def _coolify_recreate_gaps(asset, advisories):
    """Coverage gap when a Coolify redeploy would bring back a vulnerable nginx image.

    Uses the same advisory floors/ranges as the nginx cases (the "minimum safe tag").
    """
    coolify = asset.get("coolify")
    if not coolify or asset.get("product") != "nginx":
        return []
    recreate = coolify.get("recreate_image") or {}
    if recreate.get("image_id") and recreate.get("image_id") == asset.get("image_digest"):
        # Recreate keeps the running image; any exposure is already an nginx case.
        return []
    recreate_version = recreate.get("nginx_version")
    context = asset.get("exposure_context") or _exposure_context(asset, set(), {})
    internal = context.get("summary") == "internal_only"
    base = {
        "asset_id": asset.get("asset_id"),
        "product": "nginx",
        "running_version": asset.get("version"),
        "recreate_image_id": recreate.get("image_id"),
        "recreate_image_refs": recreate.get("image_refs", []),
        "coolify_resource": coolify.get("resource"),
        "playbook": "operations/playbooks/nginx-upgrade.md#coolify-pin",
        "exposure_context": context,
        # internal_only: reachable only from containers on the same docker network.
        # Still listed (with playbook), but must not fail watch/ops-check on its own.
        "priority": "low" if internal else "normal",
        "blocks_status": not internal,
    }
    if not recreate_version or not VERSION.fullmatch(recreate_version):
        return [{**base, "reason": "coolify_recreate_image_unverified"}]
    hits = []
    for advisory in advisories:
        if advisory.get("product") != "nginx":
            continue
        floors = [v for v in advisory.get("fixed_versions", []) if VERSION.fullmatch(v)]
        ranges = advisory.get("vulnerable_ranges") or []
        if floors and ranges and nginx_version_affected(recreate_version, floors, ranges):
            same_branch = [v for v in floors if v.split(".")[:2] == recreate_version.split(".")[:2]]
            hits.append((advisory["id"], max(same_branch or floors, key=_vkey)))
    if not hits:
        return []
    return [
        {
            **base,
            "reason": "coolify_recreate_reverts_nginx",
            "recreate_version": recreate_version,
            "advisory_ids": sorted({h[0] for h in hits}),
            # Minimum safe tag to pin in Coolify (highest floor across matching advisories).
            "fixed": max((h[1] for h in hits), key=_vkey),
        }
    ]


def blocking_coverage_gaps(gaps) -> list[dict]:
    """Coverage gaps that need follow-up (watch exit 2 / ops-check).

    ``php_runtime_unverified`` is expected noise; ``blocks_status: false`` marks
    low-priority gaps (internal_only Coolify recreate) that stay listed only.
    """
    return [
        g
        for g in gaps or []
        if isinstance(g, dict)
        and g.get("reason") != "php_runtime_unverified"
        and g.get("blocks_status") is not False
    ]


def _vkey(version: str):
    return tuple(map(int, version.split(".")))


def build_report(intel, inventory, now=None):
    now = now or datetime.now(UTC)
    cases = []
    gaps = list(intel.get("gaps", []))
    if not fresh(intel.get("observed_at"), now, maximum_age=timedelta(hours=2)):
        gaps.append({"source": "vendor", "reason": "stale_or_missing_observation"})
    advisories = []
    for advisory in intel.get("advisories", []):
        item = dict(advisory)
        item["_intel_observed_at"] = intel.get("observed_at")
        advisories.append(item)
    coverage_gaps = list(inventory.get("gaps", []))
    for asset in inventory["assets"]:
        product = asset.get("product")
        if product == "php":
            cases.extend(_php_cases(asset, advisories, now))
        elif product == "nginx":
            cases.extend(_nginx_cases(asset, advisories, now))
            coverage_gaps.extend(_coolify_recreate_gaps(asset, advisories))
    status = "needs_review" if cases else "insufficient_evidence"
    if any(c.get("status") == "actionable" for c in cases):
        status = "actionable"
    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "status": status,
        "scope": inventory.get("scope", "supplied inventory only"),
        "source_observed_at": intel.get("observed_at"),
        "source_requests": intel.get("source_requests", []),
        "feed_gaps": gaps,
        "coverage_gaps": coverage_gaps,
        "cases": cases,
        "observed_runtimes": [
            {
                k: a.get(k)
                for k in (
                    "asset_id",
                    "product",
                    "version",
                    "image_digest",
                    "image_ref",
                    "packaging",
                    "exposure",
                    "exposure_context",
                    "observed_at",
                )
                if a.get(k) is not None
            }
            for a in inventory["assets"]
        ],
        "execution_enabled": False,
    }
