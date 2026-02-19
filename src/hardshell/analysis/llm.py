"""Optional LLM analysis via Claude Code CLI."""

from __future__ import annotations

import asyncio
import json
import os
import shutil

from hardshell.models import ScanResult


async def analyze(result: ScanResult) -> str | None:
    """Run LLM analysis on scan findings using `claude -p`."""
    if not shutil.which("claude"):
        return "# LLM analysis unavailable\n`claude` CLI not found in PATH."

    # Build a concise summary for the prompt
    top_findings = result.sorted_findings()[:30]  # Top 30 by risk score
    findings_data = [
        {
            "id": f.id,
            "severity": f.severity.value,
            "risk_score": f.risk_score,
            "title": f.title,
            "affected": f.affected,
            "remediation": f.remediation,
            "in_cisa_kev": f.in_cisa_kev,
            "epss_score": f.epss_score,
        }
        for f in top_findings
    ]

    prompt = (
        f"You are a security engineer. Analyze the following VPS security scan results "
        f"and provide a prioritized remediation plan.\n\n"
        f"Host: {result.hostname}\n"
        f"OS: {result.os_info}\n"
        f"Summary: {result.summary.critical} critical, {result.summary.high} high, "
        f"{result.summary.medium} medium, {result.summary.low} low\n\n"
        f"Top findings (sorted by risk score):\n"
        f"{json.dumps(findings_data, indent=2, ensure_ascii=False)}\n\n"
        f"Provide:\n"
        f"1. Executive summary (2-3 sentences)\n"
        f"2. Immediate actions (critical/high items with specific commands)\n"
        f"3. Short-term improvements (medium items)\n"
        f"4. Long-term recommendations\n"
        f"Be concise and actionable. Output in Markdown."
    )

    # Unset CLAUDECODE to allow nested invocation
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    proc = await asyncio.create_subprocess_exec(
        "claude", "-p", prompt,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        return f"# LLM analysis failed\n```\n{stderr.decode(errors='replace')[:500]}\n```"

    return stdout.decode(errors="replace").strip()
