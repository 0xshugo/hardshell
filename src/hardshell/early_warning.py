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


def _public_http_exposure(name: str) -> str:
    """Classify published HTTP(S) listeners without reading application config."""
    raw = subprocess.check_output(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", name],
        text=True,
        timeout=10,
    ).strip()
    try:
        ports = json.loads(raw) or {}
    except json.JSONDecodeError:
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


def _probe_nginx_container(
    name: str, *, image: str | None = None, image_ref: str | None = None
):
    image = image if image is not None else _docker_image_id(name)
    image_ref = image_ref if image_ref is not None else _docker_image_ref(name)
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
            return {
                "asset_id": name,
                "product": "nginx",
                "version": match.group(1),
                "image_digest": image,
                "image_ref": image_ref,
                "exposure": _public_http_exposure(name),
                "observed_at": datetime.now(UTC).isoformat(),
            }, None
        if _looks_like_nginx(image_ref):
            return None, {"asset_id": name, "reason": "nginx_runtime_unverified"}
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
    assets = []
    gaps = []
    nginx_asset, nginx_gap = _probe_nginx_container(name, image=image, image_ref=image_ref)
    if nginx_asset is not None:
        assets.append(nginx_asset)
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


def collect_inventory(budget_seconds: float = 180.0, max_workers: int = 4):
    names = subprocess.check_output(
        ["docker", "ps", "--format", "{{.Names}}"], text=True, timeout=15
    ).splitlines()
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
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "assets": assets,
        "gaps": gaps,
        "scope": (
            "running containers: php on PATH and nginx -v; "
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
        cases.append(
            {
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
                "reason": (
                    "nginx_upstream_version_in_vulnerable_range; "
                    "distro_backport_unverified"
                ),
                "next_steps": [
                    "verify_vendor_patch",
                    "prepare_image_update",
                    "request_service_approval",
                    "verify_runtime_after_update",
                ],
                "requires_approval": True,
                "executable": False,
            }
        )
    return cases


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
    for asset in inventory["assets"]:
        product = asset.get("product")
        if product == "php":
            cases.extend(_php_cases(asset, advisories, now))
        elif product == "nginx":
            cases.extend(_nginx_cases(asset, advisories, now))
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
        "coverage_gaps": list(inventory.get("gaps", [])),
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
                    "exposure",
                    "observed_at",
                )
                if a.get(k) is not None
            }
            for a in inventory["assets"]
        ],
        "execution_enabled": False,
    }
