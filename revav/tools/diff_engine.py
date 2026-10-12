"""Diff Engine — Compares detection capabilities between security products or versions.

Takes two coverage matrices and produces a structured diff showing added,
removed, and changed detection mechanisms, coverage improvements and
regressions, and blind spot differences.

Output: comparison report with per-technique diffs, coverage deltas,
and competitive analysis.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import click
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class DiffStatus(str, Enum):
    """Change status for a technique between two products/versions."""

    ADDED = "added"             # Newly covered in product B
    REMOVED = "removed"         # Covered in A but not B
    IMPROVED = "improved"       # Higher confidence in B
    REGRESSED = "regressed"     # Lower confidence in B
    UNCHANGED = "unchanged"     # Same coverage
    MECHANISM_CHANGE = "mechanism_change"  # Same coverage level, different mechanisms


class TechniqueDiff(BaseModel):
    """Diff for a single ATT&CK technique between two products."""

    technique_id: str
    technique_name: str = Field(default="")
    status: DiffStatus
    confidence_a: float = Field(default=0.0, description="Confidence in product A")
    confidence_b: float = Field(default=0.0, description="Confidence in product B")
    confidence_delta: float = Field(default=0.0)
    mechanisms_a: list[str] = Field(default_factory=list, description="Mechanism types in A")
    mechanisms_b: list[str] = Field(default_factory=list, description="Mechanism types in B")
    mechanisms_added: list[str] = Field(default_factory=list)
    mechanisms_removed: list[str] = Field(default_factory=list)
    notes: str = Field(default="")


class ComparisonSummary(BaseModel):
    """High-level summary of a product comparison."""

    techniques_only_in_a: int = Field(default=0)
    techniques_only_in_b: int = Field(default=0)
    techniques_improved: int = Field(default=0)
    techniques_regressed: int = Field(default=0)
    techniques_unchanged: int = Field(default=0)
    overall_score_a: float = Field(default=0.0)
    overall_score_b: float = Field(default=0.0)
    score_delta: float = Field(default=0.0)
    winner: str = Field(default="", description="Product with better overall coverage")


class DiffResult(BaseModel):
    """Complete comparison between two products or versions."""

    diff_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    product_a: str = Field(..., description="First product/version name")
    product_b: str = Field(..., description="Second product/version name")
    summary: ComparisonSummary = Field(default_factory=ComparisonSummary)
    technique_diffs: list[TechniqueDiff] = Field(default_factory=list)
    source_matrix_a: str = Field(default="")
    source_matrix_b: str = Field(default="")
    errors: list[str] = Field(default_factory=list)

    @property
    def significant_changes(self) -> list[TechniqueDiff]:
        return [d for d in self.technique_diffs if d.status != DiffStatus.UNCHANGED]


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def load_matrix(path: Path) -> dict:
    """Load a coverage matrix JSON file."""
    with open(path) as f:
        return json.load(f)


def diff_techniques(
    matrix_a: dict,
    matrix_b: dict,
) -> list[TechniqueDiff]:
    """Compute per-technique diffs between two coverage matrices."""
    techs_a = {t["technique_id"]: t for t in matrix_a.get("techniques", [])}
    techs_b = {t["technique_id"]: t for t in matrix_b.get("techniques", [])}

    all_ids = sorted(set(techs_a.keys()) | set(techs_b.keys()))
    diffs: list[TechniqueDiff] = []

    for tid in all_ids:
        a = techs_a.get(tid)
        b = techs_b.get(tid)

        conf_a = a.get("confidence", 0.0) if a else 0.0
        conf_b = b.get("confidence", 0.0) if b else 0.0
        delta = conf_b - conf_a

        mechs_a = [m.get("mechanism_type", "") for m in (a or {}).get("mechanisms", [])]
        mechs_b = [m.get("mechanism_type", "") for m in (b or {}).get("mechanisms", [])]

        if a and not b:
            status = DiffStatus.REMOVED
        elif b and not a:
            status = DiffStatus.ADDED
        elif delta > 0.05:
            status = DiffStatus.IMPROVED
        elif delta < -0.05:
            status = DiffStatus.REGRESSED
        elif set(mechs_a) != set(mechs_b):
            status = DiffStatus.MECHANISM_CHANGE
        else:
            status = DiffStatus.UNCHANGED

        diffs.append(TechniqueDiff(
            technique_id=tid,
            technique_name=(a or b or {}).get("technique_name", ""),
            status=status,
            confidence_a=conf_a,
            confidence_b=conf_b,
            confidence_delta=round(delta, 3),
            mechanisms_a=mechs_a,
            mechanisms_b=mechs_b,
            mechanisms_added=[m for m in mechs_b if m not in mechs_a],
            mechanisms_removed=[m for m in mechs_a if m not in mechs_b],
        ))

    return diffs


def build_summary(diffs: list[TechniqueDiff], name_a: str, name_b: str) -> ComparisonSummary:
    """Build a high-level comparison summary from technique diffs."""
    summary = ComparisonSummary()

    for d in diffs:
        if d.status == DiffStatus.ADDED:
            summary.techniques_only_in_b += 1
        elif d.status == DiffStatus.REMOVED:
            summary.techniques_only_in_a += 1
        elif d.status == DiffStatus.IMPROVED:
            summary.techniques_improved += 1
        elif d.status == DiffStatus.REGRESSED:
            summary.techniques_regressed += 1
        elif d.status == DiffStatus.UNCHANGED:
            summary.techniques_unchanged += 1

    covered_a = [d for d in diffs if d.confidence_a > 0]
    covered_b = [d for d in diffs if d.confidence_b > 0]

    if covered_a:
        summary.overall_score_a = round(sum(d.confidence_a for d in covered_a) / len(diffs) * 100, 1)
    if covered_b:
        summary.overall_score_b = round(sum(d.confidence_b for d in covered_b) / len(diffs) * 100, 1)

    summary.score_delta = round(summary.overall_score_b - summary.overall_score_a, 1)
    summary.winner = name_b if summary.score_delta > 0 else name_a if summary.score_delta < 0 else "tie"

    return summary


def compare_products(
    matrix_a_path: Path,
    matrix_b_path: Path,
    name_a: str = "Product A",
    name_b: str = "Product B",
) -> DiffResult:
    """Compare two security products' detection coverage."""
    errors: list[str] = []

    try:
        matrix_a = load_matrix(matrix_a_path)
        matrix_b = load_matrix(matrix_b_path)
    except Exception as exc:
        return DiffResult(
            product_a=name_a,
            product_b=name_b,
            errors=[str(exc)],
        )

    diffs = diff_techniques(matrix_a, matrix_b)
    summary = build_summary(diffs, name_a, name_b)

    return DiffResult(
        product_a=name_a,
        product_b=name_b,
        summary=summary,
        technique_diffs=diffs,
        source_matrix_a=str(matrix_a_path),
        source_matrix_b=str(matrix_b_path),
        errors=errors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--matrix-a", "-a", required=True, help="First coverage matrix JSON")
@click.option("--matrix-b", "-b", required=True, help="Second coverage matrix JSON")
@click.option("--name-a", default="Product A", help="First product name")
@click.option("--name-b", default="Product B", help="Second product name")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
def main(matrix_a: str, matrix_b: str, name_a: str, name_b: str, output: str | None) -> None:
    """Compare detection coverage between two security products."""
    result = compare_products(
        matrix_a_path=Path(matrix_a),
        matrix_b_path=Path(matrix_b),
        name_a=name_a,
        name_b=name_b,
    )

    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Comparison written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
