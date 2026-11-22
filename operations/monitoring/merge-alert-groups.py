#!/usr/bin/env python3
"""Merge HardShell rule groups into the aoi-system Prometheus alert file.

Usage:
    merge-alert-groups.py TARGET OUTPUT RULE_FILE [RULE_FILE ...]

Reads TARGET (a Prometheus rule file with `groups:`), replaces every group whose
name appears in one of the RULE_FILEs (in place, keeping its position) and appends
groups that do not exist yet. All other groups are kept unchanged. The result is
written to OUTPUT; TARGET is never modified. Running it again on its own output
gives the same result (idempotent).

YAML comments and formatting in TARGET are not preserved. apply-monitoring.sh
takes a backup before copying OUTPUT over TARGET.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml


class MergeError(Exception):
    pass


def _load_groups(path: Path) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise MergeError(f"{path}: cannot read rule file: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
        raise MergeError(f"{path}: not a Prometheus rule file (missing top-level 'groups' list)")
    groups = data["groups"]
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            raise MergeError(f"{path}: every group needs a string 'name'")
    return groups


def merge_groups(
    target: list[dict[str, Any]], incoming: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Return (merged groups, replaced names, appended names)."""
    merged = [dict(g) for g in target]
    index = {g["name"]: i for i, g in enumerate(merged)}
    replaced: list[str] = []
    appended: list[str] = []
    seen: set[str] = set()
    for group in incoming:
        name = group["name"]
        if name in seen:
            raise MergeError(f"group {name!r} is defined more than once in the rule files")
        seen.add(name)
        if name in index:
            merged[index[name]] = group
            replaced.append(name)
        else:
            index[name] = len(merged)
            merged.append(group)
            appended.append(name)
    return merged, replaced, appended


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    target_path, output_path = Path(argv[1]), Path(argv[2])
    rule_paths = [Path(p) for p in argv[3:]]
    try:
        target = _load_groups(target_path)
        incoming: list[dict[str, Any]] = []
        for path in rule_paths:
            incoming.extend(_load_groups(path))
        merged, replaced, appended = merge_groups(target, incoming)
    except MergeError as exc:
        print(f"merge-alert-groups: {exc}", file=sys.stderr)
        return 1
    text = yaml.safe_dump(
        {"groups": merged}, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100
    )
    output_path.write_text(text, encoding="utf-8")
    kept = [g["name"] for g in target if g["name"] not in replaced]
    print(f"kept: {', '.join(kept) or '-'}")
    print(f"replaced: {', '.join(replaced) or '-'}")
    print(f"appended: {', '.join(appended) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
