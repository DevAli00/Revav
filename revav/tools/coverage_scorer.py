"""Coverage Scorer — Scores detection confidence and identifies blind spots.

Takes an ATT&CK coverage matrix and applies a scoring model that weights
detection mechanisms by quality (kernel > userland, inline > IAT),
depth (multiple mechanisms > single), and completeness (sub-technique coverage).

Output: scored coverage matrix with blind spot identification, weakness
classification, and remediation priorities.
"""

from __future__ import annotations

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


class WeaknessClass(str, Enum):
    """Classification of detection weaknesses."""

    ZERO_COVERAGE = "zero_coverage"          # No detection mechanism at all
    USERLAND_ONLY = "userland_only"          # Only IAT hooks, bypassable via direct syscall
    SINGLE_MECHANISM = "single_mechanism"    # Only one detection layer
    PARTIAL_SUBTECHNIQUE = "partial_subtechnique"  # Some sub-techniques unmonitored
    TELEMETRY_ONLY = "telemetry_only"        # Logged but no active blocking
    LOW_CONFIDENCE = "low_confidence"        # Detection exists but low confidence


class BlindSpot(BaseModel):
    """An identified gap in detection coverage."""

    technique_id: str = Field(..., description="ATT&CK technique with the gap")
    technique_name: str = Field(default="")
    weakness_class: WeaknessClass
    severity: str = Field(
        default="medium", description="Severity: critical, high, medium, low"
    )
    description: str = Field(..., description="What the gap means operationally")
    bypass_feasibility: str = Field(
        default="medium", description="How easy the gap is to exploit: trivial, easy, medium, hard"
    )
    remediation: str = Field(
        default="", description="Recommended fix for this gap"
    )
    attack_techniques: list[str] = Field(default_factory=list)


class ScoringWeights(BaseModel):
    """Configurable weights for the scoring model."""

    kernel_callback: float = Field(default=1.0, description="Weight for kernel callbacks")
    inline_hook: float = Field(default=0.85, description="Weight for inline hooks")
    iat_hook: float = Field(default=0.4, description="Weight for IAT-only hooks")
    syscall_hook: float = Field(default=0.9, description="Weight for syscall stub hooks")
    behavioral_rule: float = Field(default=0.7, description="Weight for behavioral rules")
    static_rule: float = Field(default=0.6, description="Weight for YARA/Sigma rules")
    telemetry_only: float = Field(default=0.3, description="Weight for telemetry without blocking")
    depth_bonus: float = Field(default=0.1, description="Bonus per additional mechanism")
    max_score: float = Field(default=1.0, description="Maximum achievable score")


class ScoredTechnique(BaseModel):
    """A technique with its computed detection score."""

    technique_id: str
    technique_name: str = Field(default="")
    raw_score: float = Field(..., ge=0.0, le=1.0, description="Weighted detection score")
    mechanism_count: int = Field(default=0)
    has_kernel_coverage: bool = Field(default=False)
    has_blocking: bool = Field(default=False)
    weaknesses: list[WeaknessClass] = Field(default_factory=list)
    grade: str = Field(default="", description="Letter grade: A, B, C, D, F")


class CoverageScoreResult(BaseModel):
    """Complete scored coverage assessment."""

    score_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    product_name: str = Field(...)
    overall_score: float = Field(
        ..., ge=0.0, le=100.0, description="Overall coverage score (0-100)"
    )
    technique_scores: list[ScoredTechnique] = Field(default_factory=list)
    blind_spots: list[BlindSpot] = Field(default_factory=list)
    grade_distribution: dict[str, int] = Field(
        default_factory=dict, description="Count of techniques per grade"
    )
    weights_used: ScoringWeights = Field(default_factory=ScoringWeights)
    source_matrix: str = Field(default="")
    errors: list[str] = Field(default_factory=list)

    @property
    def critical_blind_spots(self) -> list[BlindSpot]:
        return [b for b in self.blind_spots if b.severity in ("critical", "high")]


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def compute_technique_score(
    technique: dict,
    weights: ScoringWeights,
) -> ScoredTechnique:
    """Score a single technique's detection coverage."""
    mechanisms = technique.get("mechanisms", [])
    if not mechanisms:
        return ScoredTechnique(
            technique_id=technique.get("technique_id", ""),
            technique_name=technique.get("technique_name", ""),
            raw_score=0.0,
            mechanism_count=0,
            weaknesses=[WeaknessClass.ZERO_COVERAGE],
            grade="F",
        )

    max_weight = 0.0
    has_kernel = False
    has_blocking = False
    weakness_list: list[WeaknessClass] = []

    for mech in mechanisms:
        mtype = mech.get("mechanism_type", "")
        quality = mech.get("quality", "medium")

        if mtype == "callback":
            max_weight = max(max_weight, weights.kernel_callback)
            has_kernel = True
            has_blocking = True
        elif mtype == "hook":
            if quality == "high":
                max_weight = max(max_weight, weights.inline_hook)
            else:
                max_weight = max(max_weight, weights.iat_hook)
            has_blocking = True
        elif mtype == "behavioral":
            max_weight = max(max_weight, weights.behavioral_rule)
            has_blocking = True
        elif mtype == "rule":
            max_weight = max(max_weight, weights.static_rule)
        elif mtype == "telemetry":
            max_weight = max(max_weight, weights.telemetry_only)

    depth_bonus = weights.depth_bonus * (len(mechanisms) - 1)
    raw_score = min(max_weight + depth_bonus, weights.max_score)

    if not has_kernel and any(m.get("mechanism_type") == "hook" for m in mechanisms):
        weakness_list.append(WeaknessClass.USERLAND_ONLY)
    if len(mechanisms) == 1:
        weakness_list.append(WeaknessClass.SINGLE_MECHANISM)
    if not has_blocking:
        weakness_list.append(WeaknessClass.TELEMETRY_ONLY)

    if raw_score >= 0.9:
        grade = "A"
    elif raw_score >= 0.7:
        grade = "B"
    elif raw_score >= 0.5:
        grade = "C"
    elif raw_score >= 0.3:
        grade = "D"
    else:
        grade = "F"

    return ScoredTechnique(
        technique_id=technique.get("technique_id", ""),
        technique_name=technique.get("technique_name", ""),
        raw_score=raw_score,
        mechanism_count=len(mechanisms),
        has_kernel_coverage=has_kernel,
        has_blocking=has_blocking,
        weaknesses=weakness_list,
        grade=grade,
    )


def identify_blind_spots(
    scored_techniques: list[ScoredTechnique],
) -> list[BlindSpot]:
    """Identify and classify blind spots from scored techniques."""
    blind_spots: list[BlindSpot] = []

    for tech in scored_techniques:
        if WeaknessClass.ZERO_COVERAGE in tech.weaknesses:
            blind_spots.append(BlindSpot(
                technique_id=tech.technique_id,
                technique_name=tech.technique_name,
                weakness_class=WeaknessClass.ZERO_COVERAGE,
                severity="critical",
                description=f"No detection mechanism for {tech.technique_id}",
                bypass_feasibility="trivial",
                remediation=f"Add detection coverage for {tech.technique_id}",
            ))
        elif WeaknessClass.USERLAND_ONLY in tech.weaknesses:
            blind_spots.append(BlindSpot(
                technique_id=tech.technique_id,
                technique_name=tech.technique_name,
                weakness_class=WeaknessClass.USERLAND_ONLY,
                severity="high",
                description=f"Only userland hooks for {tech.technique_id} — bypassable via direct syscall",
                bypass_feasibility="easy",
                remediation=f"Add kernel callback or ETW telemetry for {tech.technique_id}",
            ))
        elif WeaknessClass.TELEMETRY_ONLY in tech.weaknesses:
            blind_spots.append(BlindSpot(
                technique_id=tech.technique_id,
                technique_name=tech.technique_name,
                weakness_class=WeaknessClass.TELEMETRY_ONLY,
                severity="medium",
                description=f"Telemetry only for {tech.technique_id} — logged but not blocked",
                bypass_feasibility="medium",
                remediation=f"Add active blocking mechanism for {tech.technique_id}",
            ))

    return sorted(blind_spots, key=lambda b: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(b.severity, 4))


def score_coverage(
    matrix_path: Path,
    product_name: str,
    weights: ScoringWeights | None = None,
) -> CoverageScoreResult:
    """Score a coverage matrix and identify blind spots."""
    import json

    if weights is None:
        weights = ScoringWeights()

    start = time.monotonic()
    errors: list[str] = []

    try:
        with open(matrix_path) as f:
            matrix = json.load(f)
    except Exception as exc:
        return CoverageScoreResult(
            product_name=product_name,
            overall_score=0.0,
            weights_used=weights,
            errors=[str(exc)],
        )

    techniques = matrix.get("techniques", [])
    scored = [compute_technique_score(t, weights) for t in techniques]
    blind_spots = identify_blind_spots(scored)

    grade_dist: dict[str, int] = {}
    for s in scored:
        grade_dist[s.grade] = grade_dist.get(s.grade, 0) + 1

    overall = (sum(s.raw_score for s in scored) / len(scored) * 100) if scored else 0.0

    return CoverageScoreResult(
        product_name=product_name,
        overall_score=round(overall, 1),
        technique_scores=scored,
        blind_spots=blind_spots,
        grade_distribution=grade_dist,
        weights_used=weights,
        source_matrix=str(matrix_path),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--matrix", "-m", required=True, help="Coverage matrix JSON path")
@click.option("--product", "-p", default="unknown", help="Product name")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
def main(matrix: str, product: str, output: str | None) -> None:
    """Score detection coverage and identify blind spots."""
    result = score_coverage(
        matrix_path=Path(matrix),
        product_name=product,
    )

    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Scored coverage written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
