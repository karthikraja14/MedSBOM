# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""MedSBOM CLI — FDA/IEC-62304 compliance tooling for medical device SBOMs."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from medsbom import __version__
from medsbom.core.audit import AuditTrail
from medsbom.core.cve_match import CVEMatcher
from medsbom.core.doc_generator import DocGenerator
from medsbom.core.eol_check import EOLChecker
from medsbom.core.ingest import IngestError, parse_sbom
from medsbom.core.models import ComponentResult, RiskLevel, SBOMScan
from medsbom.core.risk_score import classify_risk, risk_summary, score_component

app = typer.Typer(
    name="medsbom",
    help="MedSBOM — Open-source FDA/IEC-62304 compliance layer for medical device SBOMs.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@app.callback()
def main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False,
) -> None:
    """MedSBOM — compliance tooling for medical device SBOMs."""
    _setup_logging(verbose)


@app.command()
def version() -> None:
    """Show MedSBOM version."""
    console.print(f"MedSBOM v{__version__}")


@app.command()
def ingest(
    sbom_file: Annotated[Path, typer.Argument(help="Path to SBOM file (SPDX or CycloneDX JSON)")],
) -> None:
    """Parse and validate an SBOM file, showing its contents."""
    if not sbom_file.exists():
        err_console.print(f"[red]Error:[/red] File not found: {sbom_file}")
        raise typer.Exit(1)

    try:
        result = parse_sbom(sbom_file)
    except IngestError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from None

    console.print(f"\n[bold green]✓[/bold green] Parsed {result.sbom_format.value.upper()} SBOM")
    console.print(f"  Components: {len(result.components)}")
    console.print(f"  Source tool: {result.source_tool or 'Unknown'}")

    if result.warnings:
        console.print(f"\n[yellow]⚠ {len(result.warnings)} warning(s):[/yellow]")
        for w in result.warnings[:20]:
            console.print(f"  • {w.component_name}: {w.message}")
        if len(result.warnings) > 20:
            console.print(f"  ... and {len(result.warnings) - 20} more")

    table = Table(title="Components", show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("License", style="dim")

    for i, comp in enumerate(result.components[:50], 1):
        table.add_row(str(i), comp.name, comp.version or "—", comp.license or "—")
    if len(result.components) > 50:
        table.add_row("...", f"({len(result.components) - 50} more)", "", "")

    console.print(table)


@app.command()
def check(
    sbom_file: Annotated[Path, typer.Argument(help="Path to SBOM file (SPDX or CycloneDX JSON)")],
    nvd_api_key: Annotated[
        str,
        typer.Option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key for faster lookups"),
    ] = "",
    device_name: Annotated[
        str, typer.Option("--device", "-d", help="Device name")
    ] = "Unknown Device",
    device_version: Annotated[str, typer.Option("--device-version", help="Device version")] = "1.0",
    output_json: Annotated[
        Path | None, typer.Option("--output", "-o", help="Save results as JSON")
    ] = None,
) -> None:
    """Check an SBOM for vulnerabilities and EOL status."""
    if not sbom_file.exists():
        err_console.print(f"[red]Error:[/red] File not found: {sbom_file}")
        raise typer.Exit(1)

    # Parse SBOM
    try:
        ingest_result = parse_sbom(sbom_file)
    except IngestError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from None

    console.print(f"[bold]Checking {len(ingest_result.components)} components...[/bold]\n")

    # CVE matching
    cve_matcher = CVEMatcher(nvd_api_key=nvd_api_key)
    eol_checker = EOLChecker()

    scan_id = str(uuid.uuid4())
    results: list[ComponentResult] = []

    with console.status("[bold blue]Matching vulnerabilities...") as status:
        for i, comp in enumerate(ingest_result.components, 1):
            status.update(
                f"[bold blue]Checking {comp.name} ({i}/{len(ingest_result.components)})..."
            )

            # CVE findings
            findings = cve_matcher.match_component(comp)

            # EOL check
            eol_result = eol_checker.check_component(comp)
            eol_date = eol_result.eol_date

            # Score
            risk_level, _ = score_component(findings, eol_date)

            # Tag findings with risk level
            for f in findings:
                f.risk_level = classify_risk(f.cvss_score + (3.0 if f.kev_flag else 0.0))

            results.append(
                ComponentResult(
                    component=comp,
                    findings=findings,
                    overall_risk=risk_level,
                    eol_date=eol_date,
                    is_eol=eol_result.is_eol,
                )
            )

    # Build scan object
    scan = SBOMScan(
        scan_id=scan_id,
        device_name=device_name,
        device_version=device_version,
        timestamp=datetime.now(UTC),
        sbom_format=ingest_result.sbom_format,
        source_tool=ingest_result.source_tool,
        components=[r.component for r in results],
        results=results,
    )

    # Audit trail
    try:
        audit = AuditTrail()
        audit.log(
            scan_id, "check", details=f"Checked {len(results)} components from {sbom_file.name}"
        )
    except Exception as exc:
        logging.warning("Audit logging failed: %s", exc)

    # Display results
    _display_check_results(scan)

    # Save JSON output
    if output_json:
        output_json.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"\n[green]Results saved to {output_json}[/green]")


@app.command()
def report(
    sbom_file: Annotated[Path, typer.Argument(help="Path to SBOM file or check results JSON")],
    report_format: Annotated[
        str, typer.Option("--format", "-f", help="Report format: fda, soup, vuln, all")
    ] = "all",
    output_dir: Annotated[Path, typer.Option("--output", "-o", help="Output directory")] = Path(
        "./medsbom-reports"
    ),
    device_name: Annotated[
        str, typer.Option("--device", "-d", help="Device name")
    ] = "Unknown Device",
    device_version: Annotated[str, typer.Option("--device-version", help="Device version")] = "1.0",
    nvd_api_key: Annotated[
        str, typer.Option("--nvd-api-key", envvar="NVD_API_KEY", help="NVD API key")
    ] = "",
) -> None:
    """Generate FDA/IEC-62304 compliance documents from an SBOM."""
    if not sbom_file.exists():
        err_console.print(f"[red]Error:[/red] File not found: {sbom_file}")
        raise typer.Exit(1)

    # Try loading as a pre-computed scan result first
    scan = _try_load_scan_result(sbom_file)

    if scan is None:
        # Run a full check first
        console.print("[bold]Running vulnerability check first...[/bold]")
        try:
            ingest_result = parse_sbom(sbom_file)
        except IngestError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from None

        cve_matcher = CVEMatcher(nvd_api_key=nvd_api_key)
        eol_checker = EOLChecker()
        results: list[ComponentResult] = []

        with console.status("[bold blue]Scanning..."):
            for comp in ingest_result.components:
                findings = cve_matcher.match_component(comp)
                eol_result = eol_checker.check_component(comp)
                risk_level, _ = score_component(findings, eol_result.eol_date)
                for f in findings:
                    f.risk_level = classify_risk(f.cvss_score + (3.0 if f.kev_flag else 0.0))
                results.append(
                    ComponentResult(
                        component=comp,
                        findings=findings,
                        overall_risk=risk_level,
                        eol_date=eol_result.eol_date,
                        is_eol=eol_result.is_eol,
                    )
                )

        scan = SBOMScan(
            scan_id=str(uuid.uuid4()),
            device_name=device_name,
            device_version=device_version,
            timestamp=datetime.now(UTC),
            sbom_format=ingest_result.sbom_format,
            source_tool=ingest_result.source_tool,
            components=[r.component for r in results],
            results=results,
        )

    # Generate documents
    doc_gen = DocGenerator()
    generated: list[Path] = []

    if report_format in ("all", "fda"):
        content = doc_gen.generate_fda_summary(scan)
        p = output_dir / "fda_premarket_summary.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        generated.append(p)

    if report_format in ("all", "soup"):
        content = doc_gen.generate_soup_assessment(scan)
        p = output_dir / "soup_risk_assessment.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        generated.append(p)

    if report_format in ("all", "vuln"):
        content = doc_gen.generate_vuln_review_log(scan)
        p = output_dir / "vulnerability_review_log.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        generated.append(p)

    # Audit
    try:
        audit = AuditTrail()
        audit.log(
            scan.scan_id,
            "report",
            details=f"Generated {report_format} report(s) to {output_dir}",
        )
    except Exception:  # noqa: S110
        logging.debug("Audit logging failed", exc_info=True)

    console.print(f"\n[bold green]✓ Generated {len(generated)} document(s):[/bold green]")
    for p in generated:
        console.print(f"  📄 {p}")


@app.command()
def audit(
    scan_id: Annotated[str | None, typer.Argument(help="Filter by scan ID")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max entries to show")] = 20,
) -> None:
    """View the audit trail."""
    trail = AuditTrail()
    entries = trail.get_entries(scan_id=scan_id, limit=limit)

    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    table = Table(title="Audit Trail", show_lines=False)
    table.add_column("Timestamp", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Scan ID", style="dim", max_width=12)
    table.add_column("Actor")
    table.add_column("Details")

    for e in entries:
        table.add_row(
            e.timestamp.strftime("%Y-%m-%d %H:%M"),
            e.action,
            e.scan_id[:12] + "...",
            e.actor,
            e.details[:60],
        )

    console.print(table)
    console.print(f"\n[dim]Total entries: {trail.count(scan_id)}[/dim]")


def _display_check_results(scan: SBOMScan) -> None:
    """Display check results as a rich table."""
    summary = risk_summary(scan.results)

    # Summary
    console.print("\n[bold]Risk Summary[/bold]")
    for level in (
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.NONE,
    ):
        count = summary[level.value]
        color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "none": "green",
        }.get(level.value, "")
        console.print(f"  [{color}]{level.value.upper():>10}: {count}[/{color}]")

    # Detailed table (only components with findings)
    flagged = [r for r in scan.results if r.findings or r.is_eol]
    if flagged:
        console.print(f"\n[bold]Flagged Components ({len(flagged)}):[/bold]")
        table = Table(show_lines=True)
        table.add_column("Component", style="cyan")
        table.add_column("Version")
        table.add_column("Risk", justify="center")
        table.add_column("CVEs", justify="right")
        table.add_column("KEV", justify="center")
        table.add_column("EOL", justify="center")

        for r in sorted(flagged, key=lambda x: x.overall_risk.value, reverse=True):
            risk_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(r.overall_risk.value, "")
            cve_count = len([f for f in r.findings if f.cve_id])
            has_kev = any(f.kev_flag for f in r.findings)
            table.add_row(
                r.component.name,
                r.component.version,
                f"[{risk_style}]{r.overall_risk.value.upper()}[/{risk_style}]",
                str(cve_count),
                "[red bold]YES[/red bold]" if has_kev else "—",
                "[red]PAST EOL[/red]" if r.is_eol else ("⚠" if r.eol_date else "—"),
            )
        console.print(table)

    console.print(f"\n[dim]Scan ID: {scan.scan_id}[/dim]")


def _try_load_scan_result(path: Path) -> SBOMScan | None:
    """Try to load a pre-computed scan result JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if "scan_id" in data and "results" in data:
            return SBOMScan.model_validate(data)
    except (json.JSONDecodeError, KeyError, ValueError):
        pass
    return None


if __name__ == "__main__":
    app()
