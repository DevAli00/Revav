"""Callback Enumerator — Enumerates kernel callbacks registered by security products.

Identifies process/thread/image-load notify routines, object callbacks,
registry callbacks, minifilter registrations, and WFP callout drivers.

Output: list of registered callbacks with owning driver, callback type,
registration address, and ATT&CK technique coverage.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import click
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CallbackType(str, Enum):
    """Classification of kernel callback mechanisms."""

    PROCESS_CREATE = "process_create"       # PsSetCreateProcessNotifyRoutine(Ex)
    THREAD_CREATE = "thread_create"         # PsSetCreateThreadNotifyRoutine(Ex)
    IMAGE_LOAD = "image_load"              # PsSetLoadImageNotifyRoutine
    OBJECT_ACCESS = "object_access"         # ObRegisterCallbacks
    REGISTRY = "registry"                   # CmRegisterCallbackEx
    MINIFILTER = "minifilter"              # FltRegisterFilter
    WFP_CALLOUT = "wfp_callout"            # FwpsCalloutRegister
    SHUTDOWN = "shutdown"                   # IoRegisterShutdownNotification
    POWER = "power"                         # PoRegisterPowerSettingCallback
    ETW_THREAT_INTEL = "etw_threat_intel"   # EtwThreatIntelligence provider


class MinifilterAltitude(BaseModel):
    """Minifilter registration with altitude positioning."""

    altitude: str = Field(..., description="Minifilter altitude string (e.g. '385200')")
    instance_name: str = Field(default="", description="Filter instance name")
    volume: str = Field(default="", description="Volume the instance is attached to")
    frame: int = Field(default=0, description="Filter manager frame ID")


class CallbackInfo(BaseModel):
    """A single detected kernel callback registration."""

    callback_type: CallbackType
    owning_driver: str = Field(
        ..., description="Driver module that registered the callback"
    )
    callback_address: int = Field(
        ..., description="Virtual address of the callback function"
    )
    registration_function: str = Field(
        ..., description="Kernel API used for registration (e.g. 'PsSetCreateProcessNotifyRoutineEx')"
    )
    pre_operation: bool = Field(
        default=False, description="Whether this is a pre-operation callback"
    )
    post_operation: bool = Field(
        default=False, description="Whether this is a post-operation callback"
    )
    minifilter_details: MinifilterAltitude | None = Field(
        default=None, description="Minifilter-specific registration details"
    )
    operations_monitored: list[str] = Field(
        default_factory=list, description="IRP major functions or operations monitored"
    )
    attack_techniques: list[str] = Field(
        default_factory=list, description="ATT&CK techniques this callback helps detect"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in the callback identification"
    )
    notes: str = Field(default="")


class CallbackScanConfig(BaseModel):
    """Configuration for kernel callback enumeration."""

    target_pid: int | None = Field(default=None, description="PID for driver-level inspection")
    target_path: str | None = Field(default=None, description="Path to driver image on disk")
    callback_types: list[CallbackType] = Field(
        default_factory=lambda: list(CallbackType),
        description="Callback types to enumerate"
    )
    enumerate_minifilters: bool = Field(default=True, description="Run fltmc-style enumeration")


class CallbackScanResult(BaseModel):
    """Complete result of a kernel callback enumeration."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = Field(..., description="Target that was scanned")
    callbacks: list[CallbackInfo] = Field(default_factory=list)
    drivers_enumerated: list[str] = Field(default_factory=list)
    scan_duration_ms: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)

    @property
    def callback_count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for cb in self.callbacks:
            counts[cb.callback_type.value] = counts.get(cb.callback_type.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def enumerate_process_callbacks(target: str) -> list[CallbackInfo]:
    """Enumerate PsSetCreateProcessNotifyRoutine(Ex) callbacks."""
    # TODO: implement via kernel debugging or driver interaction
    # 1. Read PspCreateProcessNotifyRoutine array from kernel
    # 2. Resolve each callback address to its owning driver
    # 3. Determine if Ex variant (with filtering) is used
    return []


def enumerate_thread_callbacks(target: str) -> list[CallbackInfo]:
    """Enumerate PsSetCreateThreadNotifyRoutine(Ex) callbacks."""
    # TODO: implement
    return []


def enumerate_image_callbacks(target: str) -> list[CallbackInfo]:
    """Enumerate PsSetLoadImageNotifyRoutine callbacks."""
    # TODO: implement
    return []


def enumerate_object_callbacks(target: str) -> list[CallbackInfo]:
    """Enumerate ObRegisterCallbacks registrations."""
    # TODO: implement
    # 1. Walk ObCallbackListHead
    # 2. For each entry, extract ObjectType, PreOperation, PostOperation
    # 3. Resolve callback addresses to owning drivers
    return []


def enumerate_registry_callbacks(target: str) -> list[CallbackInfo]:
    """Enumerate CmRegisterCallbackEx registrations."""
    # TODO: implement
    return []


def enumerate_minifilters(target: str) -> list[CallbackInfo]:
    """Enumerate registered minifilter drivers and their altitudes."""
    # TODO: implement via FltEnumerateFilters or fltmc parsing
    # 1. List all registered minifilter instances
    # 2. Extract altitude, frame, volume bindings
    # 3. Enumerate IRP_MJ_* pre/post callbacks for each
    return []


def enumerate_wfp_callouts(target: str) -> list[CallbackInfo]:
    """Enumerate WFP callout driver registrations."""
    # TODO: implement
    # 1. Query WFP callout table
    # 2. Map each callout to its owning driver
    # 3. Identify inspection layers (INBOUND, OUTBOUND, STREAM, etc.)
    return []


def scan_callbacks(config: CallbackScanConfig) -> CallbackScanResult:
    """Run a complete kernel callback enumeration."""
    start = time.monotonic()
    target = str(config.target_pid or config.target_path or "unknown")
    all_callbacks: list[CallbackInfo] = []
    errors: list[str] = []

    scanners: dict[CallbackType, Any] = {
        CallbackType.PROCESS_CREATE: lambda: enumerate_process_callbacks(target),
        CallbackType.THREAD_CREATE: lambda: enumerate_thread_callbacks(target),
        CallbackType.IMAGE_LOAD: lambda: enumerate_image_callbacks(target),
        CallbackType.OBJECT_ACCESS: lambda: enumerate_object_callbacks(target),
        CallbackType.REGISTRY: lambda: enumerate_registry_callbacks(target),
        CallbackType.MINIFILTER: lambda: enumerate_minifilters(target),
        CallbackType.WFP_CALLOUT: lambda: enumerate_wfp_callouts(target),
    }

    for cb_type in config.callback_types:
        scanner = scanners.get(cb_type)
        if scanner is None:
            continue
        try:
            all_callbacks.extend(scanner())
        except Exception as exc:
            errors.append(f"{cb_type.value} enumeration failed: {exc}")

    elapsed = int((time.monotonic() - start) * 1000)

    return CallbackScanResult(
        target=target,
        callbacks=all_callbacks,
        scan_duration_ms=elapsed,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--input", "-i", "input_path", required=True, help="Target PID or driver path")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
@click.option("--types", "-t", default="all", help="Comma-separated callback types to enumerate")
def main(input_path: str, output: str | None, types: str) -> None:
    """Enumerate kernel callbacks registered by security products."""
    cb_types = list(CallbackType) if types == "all" else [CallbackType(t) for t in types.split(",")]

    target_pid: int | None = None
    target_path: str | None = None
    try:
        target_pid = int(input_path)
    except ValueError:
        target_path = input_path

    config = CallbackScanConfig(
        target_pid=target_pid,
        target_path=target_path,
        callback_types=cb_types,
    )

    result = scan_callbacks(config)
    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Results written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
