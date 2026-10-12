"""Hook Scanner — Scans for userland API hooks in security products.

Detects inline JMP patches, Import Address Table (IAT) hooks,
Export Address Table (EAT) hooks, and syscall stub modifications
by comparing runtime memory against clean baselines.

Output: list of hooked APIs with hook type, original bytes,
patched bytes, and the module responsible for the hook.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class HookType(str, Enum):
    """Classification of userland hook mechanisms."""

    INLINE = "inline"           # JMP/CALL patch at function entry
    IAT = "iat"                 # Import Address Table replacement
    EAT = "eat"                 # Export Address Table replacement
    SYSCALL = "syscall"         # Syscall stub modification (e.g. ntdll stubs)
    TRAMPOLINE = "trampoline"   # Multi-stage trampoline hook
    HOTPATCH = "hotpatch"       # Microsoft hot-patch (MOV EDI, EDI) style
    VTABLE = "vtable"           # COM/C++ vtable pointer swap


class HookInfo(BaseModel):
    """A single detected API hook."""

    api_name: str = Field(
        ..., description="Fully qualified API name, e.g. 'kernel32.dll!CreateProcessW'"
    )
    hook_type: HookType = Field(
        ..., description="Mechanism used for hooking"
    )
    original_bytes: str = Field(
        ..., description="Hex-encoded original bytes at the hook site"
    )
    patched_bytes: str = Field(
        ..., description="Hex-encoded patched bytes found at the hook site"
    )
    hooking_module: str = Field(
        ..., description="Module that installed the hook, e.g. 'CrowdStrike\\CSAgent.dll'"
    )
    hook_address: int = Field(
        ..., description="Virtual address where the hook was placed"
    )
    target_address: int = Field(
        ..., description="Address the hook redirects execution to"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence that this is a genuine hook (0.0-1.0)"
    )
    displaced_instructions: list[str] = Field(
        default_factory=list,
        description="Disassembled instructions that were overwritten"
    )
    notes: str = Field(
        default="", description="Analyst notes or additional context"
    )


class BaselineEntry(BaseModel):
    """Clean baseline reference for a single API function."""

    api_name: str = Field(..., description="API name matching HookInfo.api_name")
    module_path: str = Field(
        ..., description="Path to the clean module on disk"
    )
    expected_bytes: str = Field(
        ..., description="Hex-encoded expected prologue bytes"
    )
    expected_hash: str = Field(
        default="", description="SHA-256 hash of the clean module"
    )
    os_version: str = Field(
        default="", description="OS build the baseline was captured from"
    )


class HookScanConfig(BaseModel):
    """Configuration for a hook scanning session."""

    target_pid: int | None = Field(
        default=None, description="PID of running process to scan"
    )
    target_path: str | None = Field(
        default=None, description="Path to target binary on disk"
    )
    baseline_path: str | None = Field(
        default=None, description="Path to baseline directory or JSON"
    )
    scan_modules: list[str] = Field(
        default_factory=lambda: ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll"],
        description="Modules to scan for hooks"
    )
    hook_types: list[HookType] = Field(
        default_factory=lambda: list(HookType),
        description="Hook types to scan for"
    )
    min_confidence: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Minimum confidence threshold for reporting"
    )


class HookScanResult(BaseModel):
    """Complete result of a hook scanning session."""

    scan_id: str = Field(..., description="Unique scan identifier")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = Field(
        ..., description="Target that was scanned (PID or path)"
    )
    baseline_used: str | None = Field(
        default=None, description="Baseline file used for comparison"
    )
    hooks: list[HookInfo] = Field(default_factory=list)
    modules_scanned: list[str] = Field(default_factory=list)
    total_apis_checked: int = Field(default=0)
    scan_duration_ms: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)

    @property
    def hook_count_by_type(self) -> dict[str, int]:
        """Count hooks grouped by type."""
        counts: dict[str, int] = {}
        for hook in self.hooks:
            counts[hook.hook_type.value] = counts.get(hook.hook_type.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def load_baseline(baseline_path: Path) -> list[BaselineEntry]:
    """Load clean API baselines from a JSON file.

    Args:
        baseline_path: Path to baseline JSON file.

    Returns:
        List of baseline entries for comparison.
    """
    # TODO: implement baseline loading from JSON/directory
    # Baselines are OS-version-specific snapshots of clean API prologues
    if not baseline_path.exists():
        return []

    with open(baseline_path) as f:
        data = json.load(f)

    return [BaselineEntry(**entry) for entry in data.get("entries", [])]


def scan_inline_hooks(
    target: str,
    baselines: list[BaselineEntry],
    modules: list[str],
) -> list[HookInfo]:
    """Scan for inline JMP/CALL patches at function entry points.

    Compares the first N bytes of each exported function against the
    baseline. Looks for JMP rel32, JMP [rip+disp], PUSH+RET, and
    MOV RAX+JMP RAX patterns.

    Args:
        target: PID (as string) or path to target binary.
        baselines: Clean baseline entries for comparison.
        modules: List of module names to scan.

    Returns:
        List of detected inline hooks.
    """
    hooks: list[HookInfo] = []
    # TODO: implement inline hook detection
    # 1. Attach to target process or load binary
    # 2. For each module, enumerate exported functions
    # 3. Read first 16 bytes of each function
    # 4. Compare against baseline
    # 5. If mismatch, classify the patch pattern (JMP rel32, etc.)
    # 6. Resolve the hook target address
    # 7. Identify which module owns the target address
    return hooks


def scan_iat_hooks(
    target: str,
    baselines: list[BaselineEntry],
    modules: list[str],
) -> list[HookInfo]:
    """Scan for Import Address Table hooks.

    Checks whether IAT entries point to the expected module or have
    been redirected to a hooking DLL.

    Args:
        target: PID (as string) or path to target binary.
        baselines: Clean baseline entries for comparison.
        modules: List of module names to scan.

    Returns:
        List of detected IAT hooks.
    """
    hooks: list[HookInfo] = []
    # TODO: implement IAT hook detection
    # 1. Parse PE headers for each loaded module
    # 2. Walk the Import Directory Table
    # 3. For each imported function, check if the resolved address
    #    falls within the expected module's address range
    # 4. If redirected, identify the hooking module
    return hooks


def scan_eat_hooks(
    target: str,
    baselines: list[BaselineEntry],
    modules: list[str],
) -> list[HookInfo]:
    """Scan for Export Address Table hooks.

    Checks for forwarded exports and modified EAT entries that redirect
    function resolution to a different module.

    Args:
        target: PID (as string) or path to target binary.
        baselines: Clean baseline entries for comparison.
        modules: List of module names to scan.

    Returns:
        List of detected EAT hooks.
    """
    hooks: list[HookInfo] = []
    # TODO: implement EAT hook detection
    # 1. Parse PE headers for each target module
    # 2. Walk the Export Directory Table
    # 3. Check for forwarded RVA strings pointing outside the module
    # 4. Compare export addresses against baseline
    return hooks


def scan_syscall_hooks(
    target: str,
    baselines: list[BaselineEntry],
) -> list[HookInfo]:
    """Scan for syscall stub modifications in ntdll.dll.

    Checks the syscall stubs (mov eax, SSN; syscall) for patches that
    redirect through a user-mode hook before the actual syscall.

    Args:
        target: PID (as string) or path to target binary.
        baselines: Clean baseline entries for comparison.

    Returns:
        List of detected syscall hooks.
    """
    hooks: list[HookInfo] = []
    # TODO: implement syscall stub hook detection
    # 1. Locate ntdll.dll in the target
    # 2. Enumerate Zw/Nt syscall stubs
    # 3. Verify the standard stub pattern:
    #    mov r10, rcx / mov eax, <SSN> / syscall / ret
    # 4. Flag any deviations (extra JMP, modified SSN, etc.)
    return hooks


def scan_hooks(config: HookScanConfig) -> HookScanResult:
    """Run a complete hook scan with the given configuration.

    Orchestrates all enabled hook type scanners and aggregates
    results into a single HookScanResult.

    Args:
        config: Scan configuration specifying target, baseline, and options.

    Returns:
        Aggregated scan results.
    """
    import uuid
    import time

    start = time.monotonic()
    target = str(config.target_pid or config.target_path or "unknown")
    all_hooks: list[HookInfo] = []
    errors: list[str] = []

    # Load baselines
    baselines: list[BaselineEntry] = []
    if config.baseline_path:
        try:
            baselines = load_baseline(Path(config.baseline_path))
        except Exception as exc:
            errors.append(f"Failed to load baseline: {exc}")

    # Run each scanner
    scanners: dict[HookType, Any] = {
        HookType.INLINE: lambda: scan_inline_hooks(target, baselines, config.scan_modules),
        HookType.IAT: lambda: scan_iat_hooks(target, baselines, config.scan_modules),
        HookType.EAT: lambda: scan_eat_hooks(target, baselines, config.scan_modules),
        HookType.SYSCALL: lambda: scan_syscall_hooks(target, baselines),
    }

    for hook_type in config.hook_types:
        scanner = scanners.get(hook_type)
        if scanner is None:
            continue
        try:
            hooks = scanner()
            all_hooks.extend(hooks)
        except Exception as exc:
            errors.append(f"{hook_type.value} scan failed: {exc}")

    # Filter by confidence
    filtered = [h for h in all_hooks if h.confidence >= config.min_confidence]
    elapsed = int((time.monotonic() - start) * 1000)

    return HookScanResult(
        scan_id=str(uuid.uuid4()),
        target=target,
        baseline_used=config.baseline_path,
        hooks=filtered,
        modules_scanned=config.scan_modules,
        total_apis_checked=0,  # TODO: track actual count
        scan_duration_ms=elapsed,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--input", "-i", "input_path", required=True, help="Target binary path or PID")
@click.option("--baseline", "-b", default=None, help="Path to clean baseline JSON")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
@click.option(
    "--hook-types", "-t", default="all",
    help="Comma-separated hook types to scan: inline,iat,eat,syscall,trampoline,hotpatch,vtable"
)
@click.option("--min-confidence", default=0.5, type=float, help="Minimum confidence threshold")
@click.option("--modules", "-m", default=None, help="Comma-separated module names to scan")
def main(
    input_path: str,
    baseline: str | None,
    output: str | None,
    hook_types: str,
    min_confidence: float,
    modules: str | None,
) -> None:
    """Scan a target for userland API hooks."""
    types = list(HookType) if hook_types == "all" else [HookType(t) for t in hook_types.split(",")]
    module_list = modules.split(",") if modules else ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]

    # Determine if input is PID or path
    target_pid: int | None = None
    target_path: str | None = None
    try:
        target_pid = int(input_path)
    except ValueError:
        target_path = input_path

    config = HookScanConfig(
        target_pid=target_pid,
        target_path=target_path,
        baseline_path=baseline,
        scan_modules=module_list,
        hook_types=types,
        min_confidence=min_confidence,
    )

    result = scan_hooks(config)
    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Results written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
