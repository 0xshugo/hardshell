"""JSON report exporter."""

from __future__ import annotations

import json

from hardshell.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Render scan results as JSON string."""
    data = result.model_dump(mode="json")
    # Sort findings by risk score
    data["findings"] = sorted(data["findings"], key=lambda f: f["risk_score"], reverse=True)
    return json.dumps(data, indent=2, ensure_ascii=False)
