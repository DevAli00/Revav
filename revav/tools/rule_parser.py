"""Rule Parser — Extracts detection rules embedded in security products.

Parses YARA rules from scanning engines, Sigma rules from correlation
engines, and Snort/Suricata rules from network inspection components.

Output: extracted rules with type, content, targeted techniques, and
confidence in the extraction.
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


class RuleType(str, Enum):
    """Classification of detection rule formats."""

    YARA = "yara"
    SIGMA = "sigma"
    SNORT = "snort"
    SURICATA = "suricata"
    CUSTOM = "custom"          # Vendor-proprietary format
    REGEX = "regex"            # Raw regex patterns in scanning engine
    BYTE_PATTERN = "byte_pattern"  # Byte-level signatures


class RuleInfo(BaseModel):
    """A single extracted detection rule."""

    rule_id: str = Field(..., description="Unique rule identifier (original or generated)")
    rule_type: RuleType
    rule_name: str = Field(..., description="Human-readable rule name")
    raw_content: str = Field(..., description="Raw rule text as extracted")
    source_file: str = Field(..., description="Binary/file the rule was extracted from")
    source_offset: int = Field(default=0, description="Byte offset in source file")
    attack_techniques: list[str] = Field(
        default_factory=list, description="ATT&CK techniques this rule targets"
    )
    severity: str = Field(default="medium", description="Rule severity: low, medium, high, critical")
    description: str = Field(default="", description="Rule description if embedded in metadata")
    tags: list[str] = Field(default_factory=list, description="Tags or labels from rule metadata")
    confidence: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in the extraction accuracy"
    )
    notes: str = Field(default="")


class RuleParserConfig(BaseModel):
    """Configuration for rule extraction."""

    target_path: str = Field(..., description="Path to binary/installer to parse")
    rule_types: list[RuleType] = Field(
        default_factory=lambda: list(RuleType),
        description="Rule formats to look for"
    )
    extract_strings: bool = Field(
        default=True, description="Extract embedded string patterns alongside rules"
    )
    max_rule_size: int = Field(
        default=65536, description="Maximum rule size in bytes to extract"
    )


class RuleParserResult(BaseModel):
    """Complete result of a rule extraction session."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = Field(..., description="Target that was parsed")
    rules: list[RuleInfo] = Field(default_factory=list)
    files_scanned: list[str] = Field(default_factory=list)
    scan_duration_ms: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)

    @property
    def rule_count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for rule in self.rules:
            counts[rule.rule_type.value] = counts.get(rule.rule_type.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def extract_yara_rules(target_path: str) -> list[RuleInfo]:
    """Extract YARA rules from a binary's embedded resources or data sections."""
    # TODO: implement
    # 1. Scan PE sections for YARA rule signatures ("rule ", "condition:", "strings:")
    # 2. Parse resource sections for .yar/.yara files
    # 3. Extract and validate each rule
    # 4. Parse rule metadata for ATT&CK tags
    return []


def extract_sigma_rules(target_path: str) -> list[RuleInfo]:
    """Extract Sigma rules from config files or embedded YAML."""
    # TODO: implement
    # 1. Search for YAML files with Sigma structure (title, logsource, detection)
    # 2. Parse embedded configs for Sigma-formatted rules
    # 3. Extract logsource and detection sections
    return []


def extract_snort_rules(target_path: str) -> list[RuleInfo]:
    """Extract Snort/Suricata rules from network inspection components."""
    # TODO: implement
    # 1. Locate .rules files in installation directories
    # 2. Parse alert/drop/pass rules with SID, msg, content
    # 3. Map content matches to network-based ATT&CK techniques
    return []


def extract_byte_patterns(target_path: str) -> list[RuleInfo]:
    """Extract raw byte-level signature patterns from scanning engines."""
    # TODO: implement
    # 1. Identify signature database files (proprietary formats)
    # 2. Extract pattern entries with their metadata
    # 3. Attempt to decompile patterns into readable form
    return []


def parse_rules(config: RuleParserConfig) -> RuleParserResult:
    """Run all configured rule extractors against the target."""
    start = time.monotonic()
    all_rules: list[RuleInfo] = []
    errors: list[str] = []

    extractors = {
        RuleType.YARA: lambda: extract_yara_rules(config.target_path),
        RuleType.SIGMA: lambda: extract_sigma_rules(config.target_path),
        RuleType.SNORT: lambda: extract_snort_rules(config.target_path),
        RuleType.SURICATA: lambda: extract_snort_rules(config.target_path),
        RuleType.BYTE_PATTERN: lambda: extract_byte_patterns(config.target_path),
    }

    for rule_type in config.rule_types:
        extractor = extractors.get(rule_type)
        if extractor is None:
            continue
        try:
            all_rules.extend(extractor())
        except Exception as exc:
            errors.append(f"{rule_type.value} extraction failed: {exc}")

    elapsed = int((time.monotonic() - start) * 1000)

    return RuleParserResult(
        target=config.target_path,
        rules=all_rules,
        scan_duration_ms=elapsed,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.option("--input", "-i", "input_path", required=True, help="Target binary or directory path")
@click.option("--output", "-o", default=None, help="Output JSON path (default: stdout)")
@click.option("--types", "-t", default="all", help="Comma-separated rule types to extract")
def main(input_path: str, output: str | None, types: str) -> None:
    """Extract detection rules from security product binaries."""
    rule_types = list(RuleType) if types == "all" else [RuleType(t) for t in types.split(",")]

    config = RuleParserConfig(
        target_path=input_path,
        rule_types=rule_types,
    )

    result = parse_rules(config)
    output_json = result.model_dump_json(indent=2)

    if output:
        Path(output).write_text(output_json)
        click.echo(f"Results written to {output}")
    else:
        click.echo(output_json)


if __name__ == "__main__":
    main()
