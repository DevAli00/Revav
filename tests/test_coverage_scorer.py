"""Tests for revav.tools.coverage_scorer."""

from __future__ import annotations

import pytest

from revav.tools.coverage_scorer import (
    BlindSpot,
    ScoredTechnique,
    ScoringWeights,
    WeaknessClass,
    compute_technique_score,
    identify_blind_spots,
)


class TestComputeTechniqueScore:
    def test_zero_coverage_gets_f(self) -> None:
        tech = {"technique_id": "T1055", "technique_name": "Process Injection", "mechanisms": []}
        scored = compute_technique_score(tech, ScoringWeights())
        assert scored.grade == "F"
        assert scored.raw_score == 0.0
        assert WeaknessClass.ZERO_COVERAGE in scored.weaknesses

    def test_kernel_callback_scores_high(self) -> None:
        tech = {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "mechanisms": [
                {"mechanism_type": "callback", "quality": "high"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert scored.grade == "A"
        assert scored.raw_score >= 0.9
        assert scored.has_kernel_coverage is True

    def test_iat_only_flags_userland_weakness(self) -> None:
        tech = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "hook", "quality": "medium"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert WeaknessClass.USERLAND_ONLY in scored.weaknesses

    def test_single_mechanism_weakness(self) -> None:
        tech = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "callback", "quality": "high"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert WeaknessClass.SINGLE_MECHANISM in scored.weaknesses

    def test_multiple_mechanisms_no_single_weakness(self) -> None:
        tech = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "callback", "quality": "high"},
                {"mechanism_type": "hook", "quality": "high"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert WeaknessClass.SINGLE_MECHANISM not in scored.weaknesses

    def test_depth_bonus_increases_score(self) -> None:
        single = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "rule", "quality": "medium"},
            ],
        }
        multi = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "rule", "quality": "medium"},
                {"mechanism_type": "telemetry", "quality": "medium"},
            ],
        }
        weights = ScoringWeights()
        score_single = compute_technique_score(single, weights)
        score_multi = compute_technique_score(multi, weights)
        assert score_multi.raw_score > score_single.raw_score

    def test_telemetry_only_weakness(self) -> None:
        tech = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "telemetry", "quality": "medium"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert WeaknessClass.TELEMETRY_ONLY in scored.weaknesses

    def test_score_capped_at_max(self) -> None:
        tech = {
            "technique_id": "T1055",
            "mechanisms": [
                {"mechanism_type": "callback", "quality": "high"},
                {"mechanism_type": "hook", "quality": "high"},
                {"mechanism_type": "behavioral", "quality": "high"},
                {"mechanism_type": "telemetry", "quality": "high"},
            ],
        }
        scored = compute_technique_score(tech, ScoringWeights())
        assert scored.raw_score <= 1.0


class TestIdentifyBlindSpots:
    def test_zero_coverage_is_critical(self) -> None:
        techniques = [
            ScoredTechnique(
                technique_id="T1055",
                raw_score=0.0,
                weaknesses=[WeaknessClass.ZERO_COVERAGE],
                grade="F",
            )
        ]
        spots = identify_blind_spots(techniques)
        assert len(spots) == 1
        assert spots[0].severity == "critical"

    def test_userland_only_is_high_severity(self) -> None:
        techniques = [
            ScoredTechnique(
                technique_id="T1055",
                raw_score=0.4,
                weaknesses=[WeaknessClass.USERLAND_ONLY],
                grade="D",
            )
        ]
        spots = identify_blind_spots(techniques)
        assert len(spots) == 1
        assert spots[0].severity == "high"

    def test_severity_ordering(self) -> None:
        techniques = [
            ScoredTechnique(technique_id="T1059", raw_score=0.3, weaknesses=[WeaknessClass.TELEMETRY_ONLY], grade="D"),
            ScoredTechnique(technique_id="T1055", raw_score=0.0, weaknesses=[WeaknessClass.ZERO_COVERAGE], grade="F"),
            ScoredTechnique(technique_id="T1003", raw_score=0.4, weaknesses=[WeaknessClass.USERLAND_ONLY], grade="D"),
        ]
        spots = identify_blind_spots(techniques)
        severities = [s.severity for s in spots]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert severities == sorted(severities, key=lambda s: severity_order.get(s, 4))

    def test_no_weaknesses_no_blind_spots(self) -> None:
        techniques = [
            ScoredTechnique(technique_id="T1055", raw_score=0.95, weaknesses=[], grade="A")
        ]
        spots = identify_blind_spots(techniques)
        assert len(spots) == 0
