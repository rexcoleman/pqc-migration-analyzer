"""CLI entry point for pqc-analyzer.

Usage:
    pqc-analyzer scan --repo ~/my-project
    pqc-analyzer scan --repo ~/my-project --output scan_report.json
    pqc-analyzer report --input scan_report.json
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.detection.regex_scanner import scan_directory
from src.migration.nist_mapping import generate_recommendations


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pqc-analyzer")
def cli():
    """Post-Quantum Cryptography Migration Analyzer — scan codebases for quantum-vulnerable crypto."""
    pass


@cli.command()
@click.option("--repo", required=True, help="Path to codebase to scan")
@click.option("--output", default=None, help="Output JSON report path")
@click.option("--verbose", is_flag=True, help="Show per-file findings")
def scan(repo, output, verbose):
    """Scan a codebase for quantum-vulnerable cryptographic primitives."""
    repo_path = Path(repo).expanduser()
    if not repo_path.exists():
        console.print(f"[red]Error: {repo_path} does not exist[/red]")
        sys.exit(1)

    console.print(f"\n[bold]PQC Migration Analyzer v0.1.0[/bold]")
    console.print(f"Scanning: {repo_path}\n")

    # Run detection
    result = scan_directory(str(repo_path))

    # Generate recommendations
    recommendations = generate_recommendations(result.findings)

    # Summary table
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Files scanned", str(result.files_scanned))
    table.add_row("Files with findings", str(result.files_with_findings))
    table.add_row("Total findings", str(result.total_findings))
    table.add_row("[red]Critical (Shor-vulnerable)[/red]", str(result.critical_count))
    table.add_row("[yellow]High (Grover-weakened)[/yellow]", str(result.high_count))
    table.add_row("Migration recommendations", str(len(recommendations)))
    console.print(table)

    # Primitives breakdown
    if result.by_primitive:
        console.print("\n[bold]Primitives Detected:[/bold]")
        prim_table = Table()
        prim_table.add_column("Primitive")
        prim_table.add_column("Count", justify="right")
        prim_table.add_column("Quantum Risk")
        prim_table.add_column("NIST Replacement")

        from src.core.crypto_primitives import CRYPTO_REGISTRY
        for prim, count in sorted(result.by_primitive.items(), key=lambda x: -x[1]):
            info = CRYPTO_REGISTRY.get(prim)
            risk_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}.get(
                info.quantum_risk.value if info else "?", "white")
            prim_table.add_row(
                prim, str(count),
                f"[{risk_color}]{info.quantum_risk.value if info else '?'}[/{risk_color}]",
                info.nist_replacement or "N/A" if info else "?",
            )
        console.print(prim_table)

    # Recommendations
    if recommendations:
        console.print(f"\n[bold]Top Migration Recommendations ({len(recommendations)} total):[/bold]")
        rec_table = Table()
        rec_table.add_column("Primitive")
        rec_table.add_column("Replace With")
        rec_table.add_column("Difficulty")
        rec_table.add_column("Controllability")
        rec_table.add_column("File:Line")

        for rec in recommendations[:10]:
            diff_color = {"low": "green", "medium": "yellow", "high": "red", "very_high": "bold red"}.get(
                rec.migration_difficulty, "white")
            rec_table.add_row(
                rec.current_primitive,
                rec.recommended_replacement,
                f"[{diff_color}]{rec.migration_difficulty}[/{diff_color}]",
                rec.controllability,
                f"{Path(rec.finding.file_path).name}:{rec.finding.line_number}",
            )
        console.print(rec_table)

    # Verbose: per-file findings
    if verbose and result.findings:
        console.print("\n[bold]All Findings:[/bold]")
        for f in result.findings:
            risk_color = {"critical": "red", "high": "yellow"}.get(f.quantum_risk, "white")
            console.print(
                f"  [{risk_color}]{f.primitive}[/{risk_color}] "
                f"{f.file_path}:{f.line_number} — {f.line_content[:80]}"
            )

    # Output JSON
    if output:
        report = {
            "root": str(repo_path),
            "files_scanned": result.files_scanned,
            "total_findings": result.total_findings,
            "by_primitive": result.by_primitive,
            "by_risk": result.by_risk,
            "findings": [
                {
                    "file": f.file_path, "line": f.line_number,
                    "primitive": f.primitive, "risk": f.quantum_risk,
                    "content": f.line_content,
                }
                for f in result.findings
            ],
            "recommendations": [
                {
                    "primitive": r.current_primitive,
                    "replacement": r.recommended_replacement,
                    "difficulty": r.migration_difficulty,
                    "controllability": r.controllability,
                    "file": r.finding.file_path,
                    "line": r.finding.line_number,
                    "action": r.action,
                }
                for r in recommendations
            ],
        }
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[green]Report written to {output}[/green]")

    # Exit code
    if result.critical_count > 0:
        console.print(f"\n[red bold]⚠ {result.critical_count} CRITICAL findings — Shor-vulnerable primitives detected[/red bold]")
        sys.exit(2)
    elif result.high_count > 0:
        console.print(f"\n[yellow bold]⚠ {result.high_count} HIGH findings — Grover-weakened primitives detected[/yellow bold]")
        sys.exit(1)
    else:
        console.print(f"\n[green bold]✓ No critical quantum vulnerabilities detected[/green bold]")


if __name__ == "__main__":
    cli()
