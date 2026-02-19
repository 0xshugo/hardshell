"""Markdown report generator."""

from __future__ import annotations

from hardshell.models import ScanResult, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: "-",
    Severity.INFO: ".",
}


def render_markdown(result: ScanResult) -> str:
    """Render scan results as Markdown."""
    lines: list[str] = []
    s = result.summary

    lines.append("# Hardshell Security Report")
    lines.append("")
    lines.append(f"- **Host**: {result.hostname}")
    lines.append(f"- **OS**: {result.os_info}")
    lines.append(f"- **Date**: {result.timestamp:%Y-%m-%d %H:%M UTC}")
    lines.append(f"- **Scanners**: {', '.join(result.scanners_used)}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Critical | High | Medium | Low | Info | Total |")
    lines.append("|----------|------|--------|-----|------|-------|")
    lines.append(f"| {s.critical} | {s.high} | {s.medium} | {s.low} | {s.info} | {s.total} |")
    lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    lines.append("| Score | Severity | ID | Title | Affected | Remediation |")
    lines.append("|------:|----------|-----|-------|----------|-------------|")

    for f in result.sorted_findings():
        kev = " **KEV**" if f.in_cisa_kev else ""
        epss = f" (EPSS:{f.epss_score:.0%})" if f.epss_score is not None else ""
        fix = f.remediation or ""
        lines.append(
            f"| {f.risk_score:.0f} | {f.severity.value.upper()}{kev} | "
            f"{f.id} | {f.title[:60]}{epss} | {f.affected[:30]} | `{fix[:40]}` |"
        )

    lines.append("")

    if result.llm_analysis:
        lines.append("## Analysis")
        lines.append("")
        lines.append(result.llm_analysis)
        lines.append("")

    return "\n".join(lines)
