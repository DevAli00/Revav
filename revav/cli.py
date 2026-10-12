"""Revav CLI — security product reverse engineering framework.

Usage:
    revav scan      Run the full extraction pipeline against a target
    revav analyze   Map extracted mechanisms to ATT&CK techniques
    revav compare   Side-by-side comparison of two products
    revav report    Generate bypass briefs, eval scorecards, vendor audits
    revav export    Export ATT&CK Navigator layers
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from revav import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="revav")
def main() -> None:
    """Revav — security product reverse engineering framework.

    Systematically extract, catalog, and map the detection mechanisms
    of EDRs, AVs, WAFs, and HIDS to MITRE ATT&CK.
    """


@main.command()
@click.option("--target", "-t", required=True, help="Path to target binary/installer or PID of running process")
@click.option("--baseline", "-b", default=None, help="Path to clean baseline for comparison")
@click.option("--output", "-o", default="kb/catalog/", help="Output directory for extraction results")
@click.option("--agents", "-a", default="all", help="Comma-separated extraction agents to run (hook,callback,rule,behavior,telemetry)")
def scan(target: str, baseline: str | None, output: str, agents: str) -> None:
    """Run the full extraction pipeline against a security product.

    Executes all 5 extraction agents (or a subset) against the target
    and writes structured results to the knowledge base.
    """
    from revav.tools.hook_scanner import HookScanConfig, scan_hooks
    from revav.tools.callback_enum import CallbackScanConfig, scan_callbacks
    from revav.tools.rule_parser import RuleParserConfig, parse_rules
    from revav.tools.behavior_map import BehaviorMapConfig, map_behaviors
    from revav.tools.etw_mapper import ETWMapperConfig, map_telemetry

    agent_list = agents.split(",") if agents != "all" else [
        "hook", "callback", "rule", "behavior", "telemetry"
    ]

    console.print(f"[bold cyan]revav[/] scanning target: {target}")
    console.print(f"  Agents: {', '.join(agent_list)}")
    if baseline:
        console.print(f"  Baseline: {baseline}")
    console.print(f"  Output: {output}")
    console.print()

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    target_pid: int | None = None
    target_path: str | None = None
    try:
        target_pid = int(target)
    except ValueError:
        target_path = target

    for agent_name in agent_list:
        console.print(f"  [yellow]●[/] Running {agent_name} extractor...")

        if agent_name == "hook":
            config = HookScanConfig(
                target_pid=target_pid, target_path=target_path, baseline_path=baseline,
            )
            result = scan_hooks(config)
            (output_dir / "hooks.json").write_text(result.model_dump_json(indent=2))
        elif agent_name == "callback":
            config_cb = CallbackScanConfig(target_pid=target_pid, target_path=target_path)
            result_cb = scan_callbacks(config_cb)
            (output_dir / "callbacks.json").write_text(result_cb.model_dump_json(indent=2))
        elif agent_name == "rule":
            config_rp = RuleParserConfig(target_path=target_path or str(target_pid))
            result_rp = parse_rules(config_rp)
            (output_dir / "rules.json").write_text(result_rp.model_dump_json(indent=2))
        elif agent_name == "behavior":
            config_bm = BehaviorMapConfig(target_path=target_path or str(target_pid))
            result_bm = map_behaviors(config_bm)
            (output_dir / "behavioral.json").write_text(result_bm.model_dump_json(indent=2))
        elif agent_name == "telemetry":
            config_etw = ETWMapperConfig(target_path=target_path or str(target_pid))
            result_etw = map_telemetry(config_etw)
            (output_dir / "telemetry.json").write_text(result_etw.model_dump_json(indent=2))

        console.print(f"  [green]✓[/] {agent_name} extraction complete")

    console.print()
    console.print(f"[bold green]Scan complete.[/] Results written to {output}")


@main.command()
@click.option("--catalog", "-c", required=True, help="Path to detection catalog JSON")
@click.option("--output", "-o", default="kb/layers/", help="Output directory for ATT&CK layers")
@click.option("--attack-version", default="15.1", help="ATT&CK framework version")
def analyze(catalog: str, output: str, attack_version: str) -> None:
    """Map extracted detection mechanisms to ATT&CK techniques.

    Takes a detection catalog from the scan stage and produces
    coverage matrices, confidence scores, and blind spot analysis.
    """
    from revav.tools.attack_mapper import build_coverage_matrix

    console.print(f"[bold cyan]revav[/] analyzing catalog: {catalog}")
    console.print(f"  ATT&CK version: {attack_version}")
    console.print(f"  Output: {output}")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    matrix = build_coverage_matrix(
        catalog_path=Path(catalog),
        product_name=Path(catalog).stem,
        attack_version=attack_version,
    )

    output_path = output_dir / f"{Path(catalog).stem}.json"
    output_path.write_text(matrix.model_dump_json(indent=2))

    console.print(f"  Techniques assessed: {matrix.total_techniques_assessed}")
    console.print(f"  Covered: {matrix.covered_count}")
    console.print(f"  Zero coverage: {matrix.zero_coverage_count}")
    console.print(f"[bold green]Analysis complete.[/] Written to {output_path}")


@main.command()
@click.option("--products", "-p", nargs=2, required=True, help="Two product catalog paths to compare")
@click.option("--output", "-o", default=None, help="Output path for comparison report")
def compare(products: tuple[str, str], output: str | None) -> None:
    """Side-by-side comparison of two security products.

    Compares detection coverage, mechanism types, and ATT&CK mappings
    between two analyzed products.
    """
    from revav.tools.diff_engine import compare_products

    console.print(f"[bold cyan]revav[/] comparing: {products[0]} vs {products[1]}")

    result = compare_products(
        matrix_a_path=Path(products[0]),
        matrix_b_path=Path(products[1]),
        name_a=Path(products[0]).stem,
        name_b=Path(products[1]).stem,
    )

    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        console.print(f"  Winner: {result.summary.winner}")
        console.print(f"[bold green]Comparison complete.[/] Written to {output}")
    else:
        console.print(output_json)


@main.command()
@click.option("--profile", "-p", required=True, help="Product profile YAML path")
@click.option(
    "--format", "-f", "report_format",
    type=click.Choice(["bypass-brief", "eval-scorecard", "vendor-audit", "full"]),
    default="full",
    help="Report format to generate",
)
@click.option("--output", "-o", default=None, help="Output path (default: stdout)")
def report(profile: str, report_format: str, output: str | None) -> None:
    """Generate analysis reports.

    Produces bypass briefs for red teams, evaluation scorecards for
    security architects, or vendor claim audits for procurement.
    """
    from revav.tools.report_gen import ReportFormat, generate_report

    console.print(f"[bold cyan]revav[/] generating {report_format} for: {profile}")

    result = generate_report(Path(profile), ReportFormat(report_format))

    if output:
        Path(output).write_text(result.markdown)
        console.print(f"[bold green]Report generated.[/] Written to {output}")
    else:
        console.print(result.markdown)


@main.command(name="export")
@click.option("--layer", "-l", required=True, help="Coverage layer JSON path")
@click.option("--navigator", is_flag=True, help="Export as ATT&CK Navigator layer")
@click.option("--output", "-o", default=None, help="Output file path")
def export_cmd(layer: str, navigator: bool, output: str | None) -> None:
    """Export analysis data in various formats.

    Produces ATT&CK Navigator layers, STIX bundles, or structured
    JSON/YAML for automation pipelines.
    """
    from revav.tools.navigator_export import coverage_to_navigator, export_layer

    console.print(f"[bold cyan]revav[/] exporting layer: {layer}")

    if navigator:
        console.print("  Format: ATT&CK Navigator")
        nav_layer = coverage_to_navigator(Path(layer), layer_name=Path(layer).stem)
        if output:
            export_layer(nav_layer, Path(output))
            console.print(f"[bold green]Export complete.[/] Written to {output}")
        else:
            console.print(nav_layer.model_dump_json(indent=2, by_alias=True))
    else:
        console.print("[yellow]Specify --navigator for ATT&CK Navigator layer export[/]")


if __name__ == "__main__":
    main()
