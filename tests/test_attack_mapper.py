"""Tests for revav.tools.attack_mapper."""

from __future__ import annotations

import re

import pytest

from revav.tools.attack_mapper import (
    API_TECHNIQUE_MAP,
    CALLBACK_TECHNIQUE_MAP,
    CoverageMatrix,
    DetectionMechanism,
    MechanismType,
    TechniqueCoverage,
    map_callbacks_to_techniques,
    map_hooks_to_techniques,
    merge_coverages,
)


class TestMapHooksToTechniques:
    def test_known_api_produces_coverage(self) -> None:
        hooks = [
            {
                "api_name": "ntdll.dll!NtCreateThreadEx",
                "hook_type": "inline",
                "hooking_module": "edr.dll",
                "confidence": 0.95,
            }
        ]
        coverages = map_hooks_to_techniques(hooks)
        technique_ids = {c.technique_id for c in coverages}
        assert "T1055" in technique_ids

    def test_unknown_api_produces_no_coverage(self) -> None:
        hooks = [
            {
                "api_name": "ntdll.dll!NtSomeUnknownFunction",
                "hook_type": "inline",
                "hooking_module": "edr.dll",
                "confidence": 0.9,
            }
        ]
        coverages = map_hooks_to_techniques(hooks)
        assert len(coverages) == 0

    def test_inline_hook_gets_high_quality(self) -> None:
        hooks = [
            {
                "api_name": "NtCreateThreadEx",
                "hook_type": "inline",
                "hooking_module": "edr.dll",
                "confidence": 0.9,
            }
        ]
        coverages = map_hooks_to_techniques(hooks)
        for cov in coverages:
            for mech in cov.mechanisms:
                assert mech.quality == "high"

    def test_iat_hook_gets_medium_quality(self) -> None:
        hooks = [
            {
                "api_name": "NtCreateThreadEx",
                "hook_type": "iat",
                "hooking_module": "edr.dll",
                "confidence": 0.8,
            }
        ]
        coverages = map_hooks_to_techniques(hooks)
        for cov in coverages:
            for mech in cov.mechanisms:
                assert mech.quality == "medium"

    def test_multiple_hooks_same_technique_increase_confidence(self) -> None:
        hooks = [
            {"api_name": "NtCreateThread", "hook_type": "inline", "hooking_module": "edr.dll", "confidence": 0.9},
            {"api_name": "NtCreateThreadEx", "hook_type": "inline", "hooking_module": "edr.dll", "confidence": 0.9},
        ]
        coverages = map_hooks_to_techniques(hooks)
        t1055 = next((c for c in coverages if c.technique_id == "T1055"), None)
        assert t1055 is not None
        assert t1055.confidence > 0.9


class TestMapCallbacksToTechniques:
    def test_process_callback_maps_correctly(self) -> None:
        callbacks = [
            {
                "callback_type": "process_create",
                "owning_driver": "edr.sys",
                "registration_function": "PsSetCreateProcessNotifyRoutineEx",
                "confidence": 0.95,
            }
        ]
        coverages = map_callbacks_to_techniques(callbacks)
        technique_ids = {c.technique_id for c in coverages}
        assert "T1055" in technique_ids

    def test_callbacks_get_high_confidence(self) -> None:
        callbacks = [
            {
                "registration_function": "PsSetCreateProcessNotifyRoutineEx",
                "owning_driver": "edr.sys",
            }
        ]
        coverages = map_callbacks_to_techniques(callbacks)
        for cov in coverages:
            assert cov.confidence >= 0.9


class TestMergeCoverages:
    def test_merge_combines_mechanisms_for_shared_technique(self) -> None:
        list_a = [
            TechniqueCoverage(
                technique_id="T1055",
                technique_name="Process Injection",
                confidence=0.8,
                mechanisms=[
                    DetectionMechanism(
                        mechanism_id="hook1",
                        mechanism_type=MechanismType.HOOK,
                        mechanism_name="Hook on NtCreateThread",
                    )
                ],
            )
        ]
        list_b = [
            TechniqueCoverage(
                technique_id="T1055",
                technique_name="Process Injection",
                confidence=0.9,
                mechanisms=[
                    DetectionMechanism(
                        mechanism_id="cb1",
                        mechanism_type=MechanismType.CALLBACK,
                        mechanism_name="Process create callback",
                    )
                ],
            )
        ]
        merged = merge_coverages(list_a, list_b)
        t1055 = next(c for c in merged if c.technique_id == "T1055")
        assert len(t1055.mechanisms) == 2
        assert t1055.confidence >= 0.9

    def test_merge_disjoint_keeps_all(self) -> None:
        list_a = [
            TechniqueCoverage(technique_id="T1055", technique_name="PI", confidence=0.8, mechanisms=[])
        ]
        list_b = [
            TechniqueCoverage(technique_id="T1059", technique_name="Exec", confidence=0.7, mechanisms=[])
        ]
        merged = merge_coverages(list_a, list_b)
        ids = {c.technique_id for c in merged}
        assert ids == {"T1055", "T1059"}

    def test_merged_results_are_sorted(self) -> None:
        list_a = [
            TechniqueCoverage(technique_id="T1059", technique_name="", confidence=0.5, mechanisms=[]),
            TechniqueCoverage(technique_id="T1003", technique_name="", confidence=0.5, mechanisms=[]),
        ]
        merged = merge_coverages(list_a)
        assert merged[0].technique_id == "T1003"
        assert merged[1].technique_id == "T1059"


class TestCoverageMatrixProperties:
    def test_covered_count(self) -> None:
        matrix = CoverageMatrix(
            product_name="test",
            techniques=[
                TechniqueCoverage(technique_id="T1055", technique_name="", confidence=0.8, mechanisms=[]),
                TechniqueCoverage(technique_id="T1059", technique_name="", confidence=0.0, mechanisms=[]),
            ],
            total_techniques_assessed=2,
        )
        assert matrix.covered_count == 1

    def test_zero_coverage_count(self) -> None:
        matrix = CoverageMatrix(
            product_name="test",
            techniques=[
                TechniqueCoverage(technique_id="T1055", technique_name="", confidence=0.8, mechanisms=[]),
                TechniqueCoverage(technique_id="T1059", technique_name="", confidence=0.0, mechanisms=[]),
            ],
            total_techniques_assessed=2,
        )
        assert matrix.zero_coverage_count == 1

    def test_coverage_percentage(self) -> None:
        matrix = CoverageMatrix(
            product_name="test",
            techniques=[
                TechniqueCoverage(technique_id="T1055", technique_name="", confidence=0.8, mechanisms=[]),
                TechniqueCoverage(technique_id="T1059", technique_name="", confidence=0.0, mechanisms=[]),
            ],
            total_techniques_assessed=2,
        )
        assert matrix.coverage_percentage == 50.0


class TestAPITechniqueMapFormat:
    def test_all_technique_ids_valid(self) -> None:
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for api, techniques in API_TECHNIQUE_MAP.items():
            for tid in techniques:
                assert pattern.match(tid), f"Invalid technique ID '{tid}' for API '{api}'"

    def test_all_callback_technique_ids_valid(self) -> None:
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for func, techniques in CALLBACK_TECHNIQUE_MAP.items():
            for tid in techniques:
                assert pattern.match(tid), f"Invalid technique ID '{tid}' for callback '{func}'"
