"""Legacy analysis entry point: unmetered external CLI calls are disabled."""

from __future__ import annotations

from hardshell.models import ScanResult


async def analyze(result: ScanResult) -> str:
    """Keep weekly reports working without bypassing inference budgets."""
    return (
        "# LLM analysis deferred\n"
        "Unmetered Claude CLI analysis is disabled. "
        "Use `hardshell watch --ai` with an explicit persistent inference budget. "
        "Scanner findings remain available independently of AI.\n"
    )
