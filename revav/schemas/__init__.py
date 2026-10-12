"""Revav data schemas and validation utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_DIR = Path(__file__).parent


def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON Schema by name (without .schema.json suffix)."""
    schema_path = SCHEMA_DIR / f"{name}.schema.json"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found: {schema_path}")
    with open(schema_path) as f:
        return json.load(f)  # type: ignore[no-any-return]


def validate(data: dict[str, Any], schema_name: str) -> None:
    """Validate data against a named schema. Raises jsonschema.ValidationError on failure."""
    schema = load_schema(schema_name)
    jsonschema.validate(instance=data, schema=schema)
