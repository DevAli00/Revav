"""Tests for revav.tools.diff_engine."""

from __future__ import annotations

import pytest

from revav.tools.diff_engine import (
    DiffStatus,
    TechniqueDiff,
    build_summary,
    diff_techniques,
)


class TestDiffTechniques:
    def test_added_technique(self) -> None:
        matrix_a: dict = {"techniques": []}
        matrix_b: dict = {
            "techniques": [
                {"technique_id": "T1055", "technique_name": "PI", "confidence": 0.8, "mechanisms": []}
            ]
        }
        diffs = diff_techniques(matrix_a, matrix_b)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.ADDED
        assert diffs[0].technique_id == "T1055"

    def test_removed_technique(self) -> None:
        matrix_a: dict = {
            "techniques": [
                {"technique_id": "T1055", "technique_name": "PI", "confidence": 0.8, "mechanisms": []}
            ]
        }
        matrix_b: dict = {"techniques": []}
        diffs = diff_techniques(matrix_a, matrix_b)
        assert len(diffs) == 1
        assert diffs[0].status == DiffStatus.REMOVED

    def test_improved_technique(self) -> None:
        matrix_a: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.5, "mechanisms": [{"mechanism_type": "hook"}]}
            ]
        }
        matrix_b: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.9, "mechanisms": [{"mechanism_type": "hook"}, {"mechanism_type": "callback"}]}
            ]
        }
        diffs = diff_techniques(matrix_a, matrix_b)
        assert diffs[0].status == DiffStatus.IMPROVED
        assert diffs[0].confidence_delta > 0

    def test_regressed_technique(self) -> None:
        matrix_a: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.9, "mechanisms": []}
            ]
        }
        matrix_b: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.3, "mechanisms": []}
            ]
        }
        diffs = diff_techniques(matrix_a, matrix_b)
        assert diffs[0].status == DiffStatus.REGRESSED
        assert diffs[0].confidence_delta < 0

    def test_unchanged_technique(self) -> None:
        matrix_a: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.8, "mechanisms": [{"mechanism_type": "hook"}]}
            ]
        }
        matrix_b: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.8, "mechanisms": [{"mechanism_type": "hook"}]}
            ]
        }
        diffs = diff_techniques(matrix_a, matrix_b)
        assert diffs[0].status == DiffStatus.UNCHANGED

    def test_mechanism_change_same_confidence(self) -> None:
        matrix_a: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.8, "mechanisms": [{"mechanism_type": "hook"}]}
            ]
        }
        matrix_b: dict = {
            "techniques": [
                {"technique_id": "T1055", "confidence": 0.8, "mechanisms": [{"mechanism_type": "callback"}]}
            ]
        }
        diffs = diff_techniques(matrix_a, matrix_b)
        assert diffs[0].status == DiffStatus.MECHANISM_CHANGE


class TestBuildSummary:
    def test_summary_counts(self) -> None:
        diffs = [
            TechniqueDiff(technique_id="T1055", status=DiffStatus.ADDED, confidence_a=0, confidence_b=0.8, confidence_delta=0.8),
            TechniqueDiff(technique_id="T1059", status=DiffStatus.REMOVED, confidence_a=0.7, confidence_b=0, confidence_delta=-0.7),
            TechniqueDiff(technique_id="T1003", status=DiffStatus.UNCHANGED, confidence_a=0.5, confidence_b=0.5, confidence_delta=0),
        ]
        summary = build_summary(diffs, "A", "B")
        assert summary.techniques_only_in_b == 1
        assert summary.techniques_only_in_a == 1
        assert summary.techniques_unchanged == 1

    def test_winner_is_higher_score(self) -> None:
        diffs = [
            TechniqueDiff(technique_id="T1055", status=DiffStatus.IMPROVED, confidence_a=0.3, confidence_b=0.9, confidence_delta=0.6),
        ]
        summary = build_summary(diffs, "ProductA", "ProductB")
        assert summary.winner == "ProductB"
        assert summary.score_delta > 0

    def test_winner_tie(self) -> None:
        diffs = [
            TechniqueDiff(technique_id="T1055", status=DiffStatus.UNCHANGED, confidence_a=0.5, confidence_b=0.5, confidence_delta=0),
        ]
        summary = build_summary(diffs, "A", "B")
        assert summary.winner == "tie"
