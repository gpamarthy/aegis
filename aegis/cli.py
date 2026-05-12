import asyncio
import os
import sys

import click
from rich.console import Console
from rich.table import Table

from aegis import __version__
from aegis.core.scan_config import ScanConfig, ScanProfile, TargetConfig
from aegis.core.findings import Severity
from aegis.core.logger import get_logger
from aegis.core.database import AegisDB

logger = get_logger("cli")
console = Console()

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold yellow",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


@click.group()
def main():
    """AEGIS -- LLM Security Scanner."""
    pass


@main.command()
def version():
    """Show version."""
    console.print(f"[bold cyan]AEGIS[/] v{__version__}")


@main.command("list-scanners")
def list_scanners():
    """List available scanner modules."""
    from aegis.scanners.registry import get_all_scanners

    scanners = get_all_scanners()

    table = Table(title="Available Scanners", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Category", style="green")
    table.add_column("Description")

    if not scanners:
        console.print("[yellow]No scanners found.[/] Scanner modules may not be installed yet.")
        return

    for cls in scanners:
        table.add_row(cls.name, cls.category.value, cls.description)

    console.print(table)


@main.command()
@click.option("--target", "-t", required=True, help="Target LLM endpoint URL")
@click.option("--provider", "-p", default="openai", type=click.Choice(["openai", "anthropic", "ollama", "http"]), help="LLM provider")
@click.option("--model", "-m", default="gpt-4o-mini", help="Model name")
@click.option("--api-key", "-k", default="", envvar="AEGIS_API_KEY", help="API key (or set AEGIS_API_KEY)")
@click.option("--profile", default="quick", type=click.Choice(["quick", "standard", "full", "stealth"]), help="Scan profile")
@click.option("--budget", default=5.0, type=float, help="Maximum spend in USD")
@click.option("--output", "-o", default="aegis_report.html", help="Output file path")
@click.option("--format", "output_format", default="html", type=click.Choice(["html", "json"]), help="Report format")
@click.option("--scanners", "scanner_names", default="", help="Comma-separated scanner names (overrides profile)")
@click.option("--concurrency", default=5, type=int, help="Max concurrent scanner tasks")
@click.option("--timeout", default=30.0, type=float, help="Per-request timeout in seconds")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def scan(
    target: str,
    provider: str,
    model: str,
    api_key: str,
    profile: str,
    budget: float,
    output: str,
    output_format: str,
    scanner_names: str,
    concurrency: int,
    timeout: float,
    verbose: bool,
):
    """Run a security scan against an LLM endpoint."""
    if verbose:
        os.environ["AEGIS_LOG_LEVEL"] = "DEBUG"
        # Re-configure to pick up the change
        from aegis.core.logger import configure_logger
        configure_logger()

    console.print(f"[bold cyan]AEGIS[/] v{__version__}")
    console.print()
    
    target_config = TargetConfig(
        endpoint=target,
        provider=provider,
        model=model,
        api_key=api_key,
    )

    selected_scanners = [s.strip() for s in scanner_names.split(",") if s.strip()] if scanner_names else []

    scan_config = ScanConfig(
        target=target_config,
        profile=ScanProfile(profile),
        budget_usd=budget,
        concurrency=concurrency,
        timeout=timeout,
        scanners=selected_scanners,
        output_file=output,
        output_format=output_format,
        verbose=verbose,
    )

    console.print(f"[bold]Target:[/]   {target}")
    console.print(f"[bold]Provider:[/] {provider} / {model}")
    console.print(f"[bold]Profile:[/]  {profile}")
    console.print(f"[bold]Budget:[/]   ${budget:.2f}")
    console.print()

    # Run the async scan
    from aegis.scanners.engine import run_scan

    async def _do_scan():
        db = AegisDB()
        await db.initialize()
        
        result = await run_scan(scan_config)
        
        await db.save_scan_result(result)
        return result

    with console.status("[bold green]Scanning...", spinner="dots"):
        try:
            result = asyncio.run(_do_scan())
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/]")
            sys.exit(1)
        except Exception as exc:
            console.print(f"\n[bold red]Scan failed:[/] {exc}")
            if verbose:
                console.print_exception()
            sys.exit(1)

    # Print summary
    _print_summary(result)

    # Generate report
    try:
        if output_format == "json":
            from aegis.reporters.json_reporter import JSONReporter
            reporter = JSONReporter()
        else:
            from aegis.reporters.html_reporter import HTMLReporter
            reporter = HTMLReporter()

        report_path = reporter.generate(result, output)
        console.print(f"\n[bold green]Report saved to:[/] {report_path}")
    except Exception as exc:
        console.print(f"[bold red]Failed to write report:[/] {exc}")
        if verbose:
            console.print_exception()


def _print_summary(result):
    from aegis.core.findings import ScanResult

    console.print()
    console.rule("[bold cyan]Scan Results")
    console.print()

    # Stats
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column("Key", style="bold")
    stats_table.add_column("Value")
    stats_table.add_row("Target", result.target)
    stats_table.add_row("Profile", result.profile)
    stats_table.add_row("Duration", f"{result.duration_seconds:.1f}s")
    stats_table.add_row("Total tokens", f"{result.total_tokens:,}")
    stats_table.add_row("Total cost", f"${result.total_cost_usd:.4f}")
    stats_table.add_row("Scanners run", ", ".join(result.scanners_run) if result.scanners_run else "none")
    console.print(stats_table)
    console.print()

    # Severity counts
    sev_table = Table(title="Severity Breakdown", show_lines=False)
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")
    for sev in Severity:
        count = sum(1 for f in result.findings if f.severity == sev)
        style = _SEVERITY_STYLES.get(sev, "")
        sev_table.add_row(f"[{style}]{sev.value.upper()}[/]", f"[{style}]{count}[/]")
    sev_table.add_row("[bold]TOTAL[/]", f"[bold]{len(result.findings)}[/]")
    console.print(sev_table)
    console.print()

    # Findings detail
    if result.findings:
        findings_table = Table(title="Findings", show_lines=True)
        findings_table.add_column("ID", style="dim", no_wrap=True)
        findings_table.add_column("Severity")
        findings_table.add_column("Category")
        findings_table.add_column("Title")
        findings_table.add_column("Scanner", style="dim")

        for f in result.findings:
            style = _SEVERITY_STYLES.get(f.severity, "")
            findings_table.add_row(
                f.id,
                f"[{style}]{f.severity.value.upper()}[/]",
                f.category.value,
                f.title,
                f.scanner_name,
            )
        console.print(findings_table)
    else:
        console.print("[green]No vulnerabilities found.[/]")


if __name__ == "__main__":
    main()
