"""ATT&CK Mapper — Correlates extracted detection mechanisms to MITRE ATT&CK techniques.

Takes detection catalogs from the extraction engine and maps each mechanism
to ATT&CK techniques with confidence scores. Produces a coverage matrix
showing which techniques are detected, how, and at what confidence level.

Output: ATT&CK coverage matrix with per-technique detection mechanisms,
confidence scores, and gap identification.
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


class MechanismType(str, Enum):
    """Detection mechanism categories from the extraction engine."""

    HOOK = "hook"
    CALLBACK = "callback"
    RULE = "rule"
    BEHAVIORAL = "behavioral"
    TELEMETRY = "telemetry"


class DetectionMechanism(BaseModel):
    """A single detection mechanism mapped to an ATT&CK technique."""

    mechanism_id: str = Field(..., description="Reference to the extracted mechanism")
    mechanism_type: MechanismType
    mechanism_name: str = Field(..., description="Short description of the mechanism")
    quality: str = Field(
        default="medium",
        description="Mechanism quality: low (easily bypassed), medium, high (robust)"
    )
    source_scan_id: str = Field(default="", description="Scan ID that produced this mechanism")


class TechniqueCoverage(BaseModel):
    """ATT&CK technique coverage assessment."""

    technique_id: str = Field(..., description="ATT&CK technique ID (e.g. 'T1055')")
    technique_name: str = Field(..., description="ATT&CK technique name")
    tactic: str = Field(default="", description="ATT&CK tactic (e.g. 'defense-evasion')")
    sub_technique_id: str | None = Field(
        default=None, description="Sub-technique ID if applicable (e.g. 'T1055.003')"
    )
    mechanisms: list[DetectionMechanism] = Field(
        default_factory=list, description="Detection mechanisms covering this technique"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Overall detection confidence (aggregated from mechanisms)"
    )
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="Identified gaps in coverage for this technique"
    )
    notes: str = Field(default="")

    @property
    def mechanism_count(self) -> int:
        return len(self.mechanisms)

    @property
    def has_kernel_coverage(self) -> bool:
        return any(m.mechanism_type == MechanismType.CALLBACK for m in self.mechanisms)

    @property
    def has_userland_only(self) -> bool:
        return (
            any(m.mechanism_type == MechanismType.HOOK for m in self.mechanisms)
            and not self.has_kernel_coverage
        )


class CoverageMatrix(BaseModel):
    """Complete ATT&CK coverage matrix for a product."""

    matrix_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    product_name: str = Field(..., description="Product being assessed")
    attack_version: str = Field(default="15.1", description="ATT&CK framework version")
    techniques: list[TechniqueCoverage] = Field(default_factory=list)
    total_techniques_assessed: int = Field(default=0)
    source_catalog: str = Field(default="", description="Detection catalog used as input")
    errors: list[str] = Field(default_factory=list)

    @property
    def covered_count(self) -> int:
        return sum(1 for t in self.techniques if t.confidence > 0)

    @property
    def zero_coverage_count(self) -> int:
        return sum(1 for t in self.techniques if t.confidence == 0)

    @property
    def coverage_percentage(self) -> float:
        if not self.total_techniques_assessed:
            return 0.0
        return (self.covered_count / self.total_techniques_assessed) * 100


# ---------------------------------------------------------------------------
# ATT&CK technique database (bundled subset for offline use)
# ---------------------------------------------------------------------------

# Maps common API hooks/callbacks to ATT&CK techniques
API_TECHNIQUE_MAP: dict[str, list[str]] = {
    "NtCreateProcess": ["T1055"],
    "NtCreateProcessEx": ["T1055"],
    "NtCreateUserProcess": ["T1055", "T1106"],
    "NtCreateThread": ["T1055"],
    "NtCreateThreadEx": ["T1055", "T1055.003"],
    "NtResumeThread": ["T1055"],
    "NtAllocateVirtualMemory": ["T1055", "T1055.001"],
    "NtWriteVirtualMemory": ["T1055", "T1055.001"],
    "NtProtectVirtualMemory": ["T1055"],
    "NtMapViewOfSection": ["T1055.012"],
    "NtReadVirtualMemory": ["T1003"],
    "NtQueueApcThread": ["T1055.004"],
    "NtSetContextThread": ["T1055"],
    "NtSuspendThread": ["T1055"],
    "NtCreateFile": ["T1059", "T1105"],
    "NtWriteFile": ["T1105"],
    "NtSetInformationFile": ["T1070"],
    "NtCreateKey": ["T1547.001", "T1112"],
    "NtSetValueKey": ["T1547.001", "T1112"],
    "NtDeleteKey": ["T1112"],
    "CreateProcessW": ["T1059", "T1106"],
    "CreateProcessA": ["T1059", "T1106"],
    "ShellExecuteW": ["T1059"],
    "WinExec": ["T1059"],
    "MiniDumpWriteDump": ["T1003.001"],
    "connect": ["T1071"],
    "WSASend": ["T1071"],
    "HttpSendRequestW": ["T1071.001"],
}

CALLBACK_TECHNIQUE_MAP: dict[str, list[str]] = {
    "PsSetCreateProcessNotifyRoutine": ["T1055", "T1059", "T1106"],
    "PsSetCreateProcessNotifyRoutineEx": ["T1055", "T1059", "T1106"],
    "PsSetCreateThreadNotifyRoutine": ["T1055", "T1055.003"],
    "PsSetLoadImageNotifyRoutine": ["T1055.001", "T1574"],
    "ObRegisterCallbacks": ["T1055", "T1003"],
    "CmRegisterCallbackEx": ["T1547.001", "T1112"],
    "FltRegisterFilter": ["T1059", "T1105", "T1070"],
    "FwpsCalloutRegister": ["T1071", "T1572"],
}


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def load_detection_catalog(catalog_path: Path) -> dict:
    """Load a detection catalog JSON produced by the extraction engine."""
    if not catalog_path.exists():
        raise FileNotFoundError(f"Catalog not found: {catalog_path}")
    with open(catalog_path) as f:
        return json.load(f)


def map_hooks_to_techniques(hooks: list[dict]) -> list[TechniqueCoverage]:
    """Map extracted hooks to ATT&CK techniques using the API map."""
    technique_mechs: dict[str, list[DetectionMechanism]] = {}

    for hook in hooks:
        api_name = hook.get("api_name", "")
        bare_name = api_name.split("!")[-1] if "!" in api_name else api_name

        techniques = API_TECHNIQUE_MAP.get(bare_name, [])
        for tid in techniques:
            if tid not in technique_mechs:
                technique_mechs[tid] = []
            technique_mechs[tid].append(DetectionMechanism(
                mechanism_id=hook.get("api_name", "unknown"),
                mechanism_type=MechanismType.HOOK,
                mechanism_name=f"Hook on {api_name}",
                quality="high" if hook.get("hook_type") == "inline" else "medium",
            ))

    coverages: list[TechniqueCoverage] = []
    for tid, mechs in technique_mechs.items():
        best_quality = max(
            (0.9 if m.quality == "high" else 0.6 if m.quality == "medium" else 0.3)
            for m in mechs
        )
        coverages.append(TechniqueCoverage(
            technique_id=tid,
            technique_name="",  # TODO: resolve from ATT&CK STIX data
            mechanisms=mechs,
            confidence=min(best_quality + 0.05 * (len(mechs) - 1), 1.0),
        ))

    return coverages


def map_callbacks_to_techniques(callbacks: list[dict]) -> list[TechniqueCoverage]:
    """Map extracted kernel callbacks to ATT&CK techniques."""
    technique_mechs: dict[str, list[DetectionMechanism]] = {}

    for cb in callbacks:
        reg_func = cb.get("registration_function", "")
        techniques = CALLBACK_TECHNIQUE_MAP.get(reg_func, [])
        for tid in techniques:
            if tid not in technique_mechs:
                technique_mechs[tid] = []
            technique_mechs[tid].append(DetectionMechanism(
                mechanism_id=cb.get("owning_driver", "unknown"),
                mechanism_type=MechanismType.CALLBACK,
                mechanism_name=f"Callback via {reg_func}",
                quality="high",
            ))

    coverages: list[TechniqueCoverage] = []
    for tid, mechs in technique_mechs.items():
        coverages.append(TechniqueCoverage(
            technique_id=tid,
            technique_name="",
            mechanisms=mechs,
            confidence=min(0.9 + 0.05 * (len(mechs) - 1), 1.0),
        ))

    return coverages


def merge_coverages(
    *coverage_lists: list[TechniqueCoverage],
) -> list[TechniqueCoverage]:
    """Merge multiple coverage lists, combining mechanisms for shared techniques."""
    merged: dict[str, TechniqueCoverage] = {}

    for coverages in coverage_lists:
        for cov in coverages:
            if cov.technique_id in merged:
                existing = merged[cov.technique_id]
                existing.mechanisms.extend(cov.mechanisms)
                existing.confidence = min(
                    max(existing.confidence, cov.confidence) + 0.05,
                    1.0,
                )
            else:
                merged[cov.technique_id] = cov.model_copy(deep=True)

    return sorted(merged.values(), key=lambda c: c.technique_id)


def build_coverage_matrix(
    catalog_path: Path,
    product_name: str,
    attack_version: str = "15.1",
) -> CoverageMatrix:
    """Build a complete ATT&CK coverage matrix from a detection catalog."""
    start = time.monotonic()
    errors: list[str] = []

    try:
        catalog = load_detection_catalog(catalog_path)
    except Exception as exc:
        return CoverageMatrix(
            product_name=product_name,
            attack_version=attack_version,
            errors=[str(exc)],
        )

    hook_coverages = map_hooks_to_techniques(catalog.get("hooks", []))
    callback_coverages = map_callbacks_to_techniques(catalog.get("callbacks", []))

    all_coverages = merge_coverages(hook_coverages, callback_coverages)

    return CoverageMatrix(
        product_name=product_name,
        attack_version=attack_version,
        techniques=all_coverages,
        total_techniques_assessed=len(all_coverages),
        source_catalog=str(catalog_path),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--catalog", "-c", required=True, help="Detection catalog JSON path")
@click.option("--product", "-p", default="unknown", help="Product name for the matrix")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
@click.option("--attack-version", default="15.1", help="ATT&CK framework version")
def main(catalog: str, product: str, output: str | None, attack_version: str) -> None:
    """Map detection mechanisms to MITRE ATT&CK techniques."""
    matrix = build_coverage_matrix(
        catalog_path=Path(catalog),
        product_name=product,
        attack_version=attack_version,
    )

    output_json = matrix.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Coverage matrix written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
