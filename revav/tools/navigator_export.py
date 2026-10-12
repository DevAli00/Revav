"""Navigator Export — Exports coverage data as MITRE ATT&CK Navigator layers.

Converts coverage matrices and blind spot analysis into the ATT&CK Navigator
JSON format for visualization in the Navigator web application.

Output: ATT&CK Navigator layer JSON files with color-coded technique coverage,
annotations for blind spots, and metadata for filtering.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import click
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models (ATT&CK Navigator layer format)
# ---------------------------------------------------------------------------


class NavigatorGradient(BaseModel):
    """Color gradient definition for the Navigator layer."""

    colors: list[str] = Field(
        default_factory=lambda: ["#ff6666", "#ffaf66", "#ffe766", "#8ec843"],
        description="Colors from low to high score"
    )
    min_value: int = Field(default=0)
    max_value: int = Field(default=100)


class NavigatorMetadata(BaseModel):
    """Metadata entry for a technique in the Navigator layer."""

    name: str
    value: str


class NavigatorLink(BaseModel):
    """External link for a technique in the Navigator layer."""

    label: str
    url: str


class NavigatorTechnique(BaseModel):
    """A single technique entry in the Navigator layer."""

    technique_id: str = Field(..., alias="techniqueID")
    tactic: str = Field(default="")
    score: int = Field(default=0, ge=0, le=100, description="Score 0-100 for color mapping")
    color: str = Field(default="", description="Override color (empty = use gradient)")
    comment: str = Field(default="", description="Annotation text shown in Navigator")
    enabled: bool = Field(default=True)
    metadata: list[NavigatorMetadata] = Field(default_factory=list)
    links: list[NavigatorLink] = Field(default_factory=list)
    show_sub_techniques: bool = Field(default=False, alias="showSubtechniques")

    model_config = {"populate_by_name": True}


class NavigatorLayer(BaseModel):
    """Complete ATT&CK Navigator layer."""

    name: str = Field(..., description="Layer name displayed in Navigator")
    versions: dict[str, str] = Field(
        default_factory=lambda: {"attack": "15", "navigator": "5.1", "layer": "4.5"}
    )
    domain: str = Field(default="enterprise-attack")
    description: str = Field(default="")
    filters: dict = Field(
        default_factory=lambda: {"platforms": ["Windows"]}
    )
    sorting: int = Field(default=3, description="Sort order: 0=A-Z, 3=by score desc")
    layout: dict = Field(
        default_factory=lambda: {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        }
    )
    hide_disabled: bool = Field(default=False, alias="hideDisabled")
    techniques: list[NavigatorTechnique] = Field(default_factory=list)
    gradient: NavigatorGradient = Field(default_factory=NavigatorGradient)
    legend_items: list[dict[str, str]] = Field(
        default_factory=lambda: [
            {"label": "No coverage", "color": "#ff6666"},
            {"label": "Low coverage", "color": "#ffaf66"},
            {"label": "Medium coverage", "color": "#ffe766"},
            {"label": "High coverage", "color": "#8ec843"},
            {"label": "Blind spot (critical)", "color": "#ff0000"},
        ],
        alias="legendItems",
    )
    metadata: list[NavigatorMetadata] = Field(default_factory=list)
    show_tactic_row_background: bool = Field(default=True, alias="showTacticRowBackground")
    tactic_row_background: str = Field(default="#dddddd", alias="tacticRowBackground")
    select_techniques_across_tactics: bool = Field(default=True, alias="selectTechniqueAcrossTactics")
    select_sub_techniques_with_parent: bool = Field(default=False, alias="selectSubtechniquesWithParent")
    select_visible_techniques: bool = Field(default=False, alias="selectVisibleTechniques")

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def coverage_to_navigator(
    matrix_path: Path,
    layer_name: str,
    description: str = "",
) -> NavigatorLayer:
    """Convert a coverage matrix into an ATT&CK Navigator layer."""
    with open(matrix_path) as f:
        matrix = json.load(f)

    techniques: list[NavigatorTechnique] = []

    for tech in matrix.get("techniques", []):
        confidence = tech.get("confidence", 0.0)
        score = int(confidence * 100)
        mechanisms = tech.get("mechanisms", [])

        comment_parts = []
        if mechanisms:
            mech_types = set(m.get("mechanism_type", "") for m in mechanisms)
            comment_parts.append(f"Mechanisms: {', '.join(sorted(mech_types))}")
        gaps = tech.get("coverage_gaps", [])
        if gaps:
            comment_parts.append(f"Gaps: {'; '.join(gaps)}")

        color = ""
        if score == 0:
            color = "#ff6666"  # Red for zero coverage

        nav_tech = NavigatorTechnique(
            techniqueID=tech.get("technique_id", ""),
            score=score,
            color=color,
            comment="\n".join(comment_parts),
            metadata=[
                NavigatorMetadata(name="confidence", value=str(confidence)),
                NavigatorMetadata(name="mechanism_count", value=str(len(mechanisms))),
            ],
        )
        techniques.append(nav_tech)

    layer = NavigatorLayer(
        name=layer_name,
        description=description or f"Coverage layer for {matrix.get('product_name', 'unknown')}",
        techniques=techniques,
        metadata=[
            NavigatorMetadata(
                name="generated_by", value="revav"
            ),
            NavigatorMetadata(
                name="generated_at",
                value=datetime.now(timezone.utc).isoformat(),
            ),
            NavigatorMetadata(
                name="source_matrix",
                value=str(matrix_path),
            ),
        ],
    )

    return layer


def blind_spots_to_navigator(
    score_result_path: Path,
    layer_name: str,
) -> NavigatorLayer:
    """Create a Navigator layer highlighting blind spots in red."""
    with open(score_result_path) as f:
        scored = json.load(f)

    techniques: list[NavigatorTechnique] = []

    for blind_spot in scored.get("blind_spots", []):
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff4444",
            "medium": "#ff8800",
            "low": "#ffcc00",
        }
        color = severity_colors.get(blind_spot.get("severity", "medium"), "#ff8800")

        techniques.append(NavigatorTechnique(
            techniqueID=blind_spot.get("technique_id", ""),
            score=0,
            color=color,
            comment=blind_spot.get("description", ""),
            enabled=True,
        ))

    return NavigatorLayer(
        name=layer_name,
        description="Blind spots and detection gaps",
        techniques=techniques,
    )


def export_layer(layer: NavigatorLayer, output_path: Path) -> None:
    """Write a Navigator layer to a JSON file."""
    output_path.write_text(layer.model_dump_json(indent=2, by_alias=True))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--matrix", "-m", default=None, help="Coverage matrix JSON path")
@click.option("--blind-spots", "-b", default=None, help="Scored coverage JSON for blind spot layer")
@click.option("--name", "-n", default="Revav Coverage", help="Navigator layer name")
@click.option("--output", "-o", required=True, help="Output JSON path for Navigator layer")
def main(matrix: str | None, blind_spots: str | None, name: str, output: str) -> None:
    """Export coverage data as ATT&CK Navigator layers."""
    if matrix:
        layer = coverage_to_navigator(Path(matrix), layer_name=name)
        export_layer(layer, Path(output))
        click.echo(f"Navigator layer written to {output}")
    elif blind_spots:
        layer = blind_spots_to_navigator(Path(blind_spots), layer_name=f"{name} - Blind Spots")
        export_layer(layer, Path(output))
        click.echo(f"Blind spot layer written to {output}")
    else:
        click.echo("Error: provide --matrix or --blind-spots", err=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
