"""Read-only rapid advisory-to-runtime matching. Model output never authorizes execution."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from datetime import UTC, datetime, timedelta

from hardshell.intel.vendor import VERSION


def collect_php():
    names = subprocess.check_output(
        ["docker", "ps", "--format", "{{.Names}}"], text=True, timeout=15
    ).splitlines()
    if len(names) > 200:
        raise ValueError("inventory_too_large")
    assets, gaps = [], []
    deadline = time.monotonic() + 60
    for name in names:
        if time.monotonic() > deadline:
            gaps.append({"reason": "runtime_collection_budget_exceeded"})
            break
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
            raise ValueError("invalid_container_name")
        image = subprocess.check_output(
            ["docker", "inspect", "--format", "{{.Image}}", name], text=True, timeout=10
        ).strip()
        try:
            # -n skips application php.ini and auto_prepend_file. No shell, env, labels or network.
            run = subprocess.run(
                ["docker", "exec", name, "php", "-n", "-r", "echo PHP_VERSION;"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version = run.stdout.strip()
            current = subprocess.check_output(
                ["docker", "inspect", "--format", "{{.Image}}", name], text=True, timeout=10
            ).strip()
            if current != image:
                gaps.append({"asset_id": name, "reason": "image_changed"})
            elif run.returncode == 0 and VERSION.fullmatch(version):
                assets.append(
                    {
                        "asset_id": name,
                        "product": "php",
                        "version": version,
                        "image_digest": image,
                        "exposure": "unknown",
                        "observed_at": datetime.now(UTC).isoformat(),
                    }
                )
            else:
                # Absence from PATH does not prove that no embedded PHP runtime exists.
                gaps.append({"asset_id": name, "reason": "php_runtime_unverified"})
        except subprocess.TimeoutExpired:
            gaps.append({"asset_id": name, "reason": "runtime_probe_timeout"})
    return {
        "observed_at": datetime.now(UTC).isoformat(),
        "assets": assets,
        "gaps": gaps,
        "scope": "running containers: php on PATH only; host and embedded runtimes unverified",
    }


def fresh(value, now, *, maximum_age=timedelta(minutes=45)):
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.tzinfo is not None and now - maximum_age <= date <= (now + timedelta(minutes=5))
    except (ValueError, TypeError, AttributeError):
        return False


def build_report(intel, inventory, now=None):
    now = now or datetime.now(UTC)
    cases = []
    gaps = list(intel.get("gaps", []))
    if not fresh(intel.get("observed_at"), now, maximum_age=timedelta(hours=2)):
        gaps.append({"source": "vendor", "reason": "stale_or_missing_observation"})
    for asset in inventory["assets"]:
        if asset.get("product") != "php":
            continue
        version = asset.get("version", "")
        for advisory in intel["advisories"]:
            if advisory.get("product") != "php":
                continue
            fixed = [
                v
                for v in advisory["fixed_versions"]
                if VERSION.fullmatch(v) and v.split(".")[:2] == version.split(".")[:2]
            ]
            valid = (
                VERSION.fullmatch(version)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("image_digest") or "")
                and fresh(asset.get("observed_at"), now)
                and fresh(intel.get("observed_at"), now, maximum_age=timedelta(hours=2))
            )
            if valid and fixed:
                threshold = min(fixed, key=lambda v: tuple(map(int, v.split("."))))
                if tuple(map(int, version.split("."))) >= tuple(map(int, threshold.split("."))):
                    continue
            else:
                threshold = None
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
                    "product": "php",
                    "installed": version,
                    "image_digest": asset.get("image_digest"),
                    "fixed": threshold,
                    "status": "potentially_affected" if valid and threshold else "needs_evidence",
                    "priority": "P1",
                    "references": advisory["references"],
                    "public_summary": advisory.get("public_summary", ""),
                    "reason": "upstream_version_match; vendor_backport_and_web_exposure_unverified",
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
    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "status": "needs_review" if cases else "insufficient_evidence",
        "scope": inventory.get("scope", "supplied inventory only"),
        "source_observed_at": intel.get("observed_at"),
        "source_requests": intel.get("source_requests", []),
        "feed_gaps": gaps,
        "coverage_gaps": list(inventory.get("gaps", [])),
        "cases": cases,
        "observed_runtimes": [
            {k: a.get(k) for k in ("asset_id", "product", "version", "image_digest", "observed_at")}
            for a in inventory["assets"]
        ],
        "execution_enabled": False,
    }
