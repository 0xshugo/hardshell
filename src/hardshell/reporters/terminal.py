"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hardshell.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render_terminal(result: ScanResult, console: Console) -> None:
    """Render scan results to terminal using Rich."""
    console.print()

    # Summary panel
    s = result.summary
    summary_text = (
        f"[bold red]Critical: {s.critical}[/]  "
        f"[red]High: {s.high}[/]  "
        f"[yellow]Medium: {s.medium}[/]  "
        f"[cyan]Low: {s.low}[/]  "
        f"[dim]Info: {s.info}[/]  "
        f"| Total: {s.total}"
    )
    console.print(Panel(
        summary_text,
        title=f"[bold]Scan Summary — {result.hostname}[/]",
        subtitle=f"{result.os_info} | {result.timestamp:%Y-%m-%d %H:%M UTC}",
    ))

    # Findings table
    if not result.findings:
        console.print("\n[green]No findings.[/green]")
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Sev", width=8)
    table.add_column("ID", width=20)
    table.add_column("Title", ratio=3)
    table.add_column("Affected", ratio=2)
    table.add_column("Fix", ratio=2)

    for f in result.sorted_findings():
        color = SEVERITY_COLORS.get(f.severity, "")
        kev_badge = " [bold red]KEV[/]" if f.in_cisa_kev else ""
        epss_text = f" (EPSS:{f.epss_score:.0%})" if f.epss_score is not None else ""

        table.add_row(
            f"[{color}]{f.risk_score:.0f}[/]",
            f"[{color}]{f.severity.value.upper()}[/]{kev_badge}",
            f.id,
            f.title[:80] + epss_text,
            f.affected[:40],
            (f.remediation or "")[:50],
        )

    console.print(table)

    # LLM analysis
    if result.llm_analysis:
        console.print(Panel(
            result.llm_analysis,
            title="[bold]LLM Analysis[/]",
            border_style="blue",
        ))
