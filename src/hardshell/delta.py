"""Delta detection — compare two scan results to identify new/resolved findings."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from hardshell.models import Finding, ScanResult, Severity


class DeltaResult(BaseModel):
    new_findings: list[Finding] = []
    resolved_findings: list[Finding] = []
    persisting_findings: list[Finding] = []
    prev_timestamp: datetime | None = None

    @property
    def has_new_critical_high(self) -> bool:
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.new_findings
        )

    @property
    def new_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in sorted(self.new_findings, key=lambda x: x.risk_score, reverse=True):
            result.setdefault(f.severity.value, []).append(f)
        return result


def _finding_key(f: Finding) -> str:
    return f"{f.id}::{f.affected}"


def compare_results(prev_path: Path | None, current: ScanResult) -> DeltaResult:
    """Compare current scan against previous report file."""
    if prev_path is None or not prev_path.exists():
        return DeltaResult(new_findings=current.findings)

    try:
        import json
        data = json.loads(prev_path.read_text())
        prev = ScanResult.model_validate(data)
    except Exception:
        return DeltaResult(new_findings=current.findings)

    prev_keys = {_finding_key(f): f for f in prev.findings}
    curr_keys = {_finding_key(f): f for f in current.findings}

    new = [f for k, f in curr_keys.items() if k not in prev_keys]
    resolved = [f for k, f in prev_keys.items() if k not in curr_keys]
    persisting = [f for k, f in curr_keys.items() if k in prev_keys]

    return DeltaResult(
        new_findings=new,
        resolved_findings=resolved,
        persisting_findings=persisting,
        prev_timestamp=prev.timestamp,
    )
