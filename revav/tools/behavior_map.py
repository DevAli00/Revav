"""Behavior Mapper — Profiles behavioral detection patterns in security products.

Identifies monitored process trees, suspicious parent-child relationships,
file system paths under surveillance, registry keys watched, and memory
scanning trigger conditions.

Output: behavioral detection model with monitored patterns, correlation
rules, and ATT&CK technique coverage.
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


class BehaviorCategory(str, Enum):
    """Classification of behavioral detection patterns."""

    PROCESS_TREE = "process_tree"         # Parent-child process chain monitoring
    FILE_ACTIVITY = "file_activity"       # File creation/modification/deletion patterns
    REGISTRY_ACTIVITY = "registry_activity"  # Registry key/value monitoring
    NETWORK_ACTIVITY = "network_activity"  # Network connection patterns
    MEMORY_SCAN = "memory_scan"           # In-memory pattern scanning triggers
    API_SEQUENCE = "api_sequence"         # Ordered API call sequence detection
    TIMING = "timing"                     # Time-based behavioral analysis windows


class ProcessTreeRule(BaseModel):
    """A monitored parent-child process chain."""

    parent_image: str = Field(..., description="Parent process image name pattern")
    child_image: str = Field(..., description="Child process image name pattern")
    grandchild_image: str = Field(default="", description="Optional grandchild pattern")
    command_line_pattern: str = Field(default="", description="Regex for suspicious command lines")
    is_blocked: bool = Field(default=False, description="Whether this chain is blocked vs. alerted")


class FileMonitorRule(BaseModel):
    """A file system path or pattern under active monitoring."""

    path_pattern: str = Field(..., description="File path glob or regex pattern")
    operations: list[str] = Field(
        default_factory=list,
        description="Monitored operations: create, write, delete, rename, set_info"
    )
    extensions: list[str] = Field(default_factory=list, description="File extensions monitored")


class RegistryMonitorRule(BaseModel):
    """A registry key/value under active monitoring."""

    key_path: str = Field(..., description="Registry key path pattern")
    value_names: list[str] = Field(default_factory=list, description="Specific value names watched")
    operations: list[str] = Field(
        default_factory=list,
        description="Monitored operations: create_key, set_value, delete_key, delete_value"
    )


class BehaviorPattern(BaseModel):
    """A single identified behavioral detection pattern."""

    pattern_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: BehaviorCategory
    name: str = Field(..., description="Pattern name or description")
    process_tree: ProcessTreeRule | None = Field(default=None)
    file_monitor: FileMonitorRule | None = Field(default=None)
    registry_monitor: RegistryMonitorRule | None = Field(default=None)
    detection_action: str = Field(
        default="alert", description="Action taken: alert, block, quarantine, log"
    )
    attack_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str = Field(default="", description="Where this pattern was extracted from")
    notes: str = Field(default="")


class BehaviorMapConfig(BaseModel):
    """Configuration for behavioral profiling."""

    target_path: str = Field(..., description="Path to product installation or config directory")
    categories: list[BehaviorCategory] = Field(
        default_factory=lambda: list(BehaviorCategory)
    )
    include_default_rules: bool = Field(
        default=True, description="Include vendor default behavioral rules"
    )


class BehaviorMapResult(BaseModel):
    """Complete result of behavioral profiling."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = Field(...)
    patterns: list[BehaviorPattern] = Field(default_factory=list)
    config_files_parsed: list[str] = Field(default_factory=list)
    scan_duration_ms: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)

    @property
    def pattern_count_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self.patterns:
            counts[p.category.value] = counts.get(p.category.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def extract_process_trees(target: str) -> list[BehaviorPattern]:
    """Extract monitored process tree rules from product configs."""
    # TODO: implement
    # 1. Parse behavioral engine config files
    # 2. Extract parent-child chain rules
    # 3. Identify blocked vs. alerted chains
    # 4. Map common chains to ATT&CK (e.g. word.exe -> powershell.exe = T1059.001)
    return []


def extract_file_monitors(target: str) -> list[BehaviorPattern]:
    """Extract file system monitoring rules."""
    # TODO: implement
    # 1. Parse minifilter configuration for monitored paths
    # 2. Extract file extension lists from scanning config
    # 3. Identify exclusion paths (bypass opportunities)
    return []


def extract_registry_monitors(target: str) -> list[BehaviorPattern]:
    """Extract registry monitoring rules."""
    # TODO: implement
    # 1. Parse registry callback configuration
    # 2. Extract watched key paths (Run keys, services, COM objects)
    # 3. Map to ATT&CK persistence techniques
    return []


def extract_memory_triggers(target: str) -> list[BehaviorPattern]:
    """Extract memory scanning trigger conditions."""
    # TODO: implement
    # 1. Identify memory scan scheduling (on-access, periodic, on-event)
    # 2. Extract memory region criteria (RWX, unbacked, etc.)
    # 3. Map to injection detection techniques
    return []


def map_behaviors(config: BehaviorMapConfig) -> BehaviorMapResult:
    """Run all behavioral pattern extractors."""
    start = time.monotonic()
    all_patterns: list[BehaviorPattern] = []
    errors: list[str] = []

    extractors = {
        BehaviorCategory.PROCESS_TREE: lambda: extract_process_trees(config.target_path),
        BehaviorCategory.FILE_ACTIVITY: lambda: extract_file_monitors(config.target_path),
        BehaviorCategory.REGISTRY_ACTIVITY: lambda: extract_registry_monitors(config.target_path),
        BehaviorCategory.MEMORY_SCAN: lambda: extract_memory_triggers(config.target_path),
    }

    for category in config.categories:
        extractor = extractors.get(category)
        if extractor is None:
            continue
        try:
            all_patterns.extend(extractor())
        except Exception as exc:
            errors.append(f"{category.value} extraction failed: {exc}")

    elapsed = int((time.monotonic() - start) * 1000)

    return BehaviorMapResult(
        target=config.target_path,
        patterns=all_patterns,
        scan_duration_ms=elapsed,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--input", "-i", "input_path", required=True, help="Product install or config directory")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
@click.option("--categories", "-c", default="all", help="Comma-separated behavior categories")
def main(input_path: str, output: str | None, categories: str) -> None:
    """Profile behavioral detection patterns in a security product."""
    cats = (
        list(BehaviorCategory) if categories == "all"
        else [BehaviorCategory(c) for c in categories.split(",")]
    )

    config = BehaviorMapConfig(target_path=input_path, categories=cats)
    result = map_behaviors(config)
    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Results written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
