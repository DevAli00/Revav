"""Tests for revav.schemas validation."""

from __future__ import annotations

import pytest
import jsonschema

from revav.schemas import load_schema, validate


class TestLoadSchema:
    def test_load_product_profile(self) -> None:
        schema = load_schema("product_profile")
        assert schema["title"] == "Product Profile"
        assert "properties" in schema

    def test_load_detection_catalog(self) -> None:
        schema = load_schema("detection_catalog")
        assert schema["title"] == "Detection Catalog"

    def test_load_coverage_matrix(self) -> None:
        schema = load_schema("coverage_matrix")
        assert schema["title"] == "Coverage Matrix"

    def test_load_navigator_layer(self) -> None:
        schema = load_schema("navigator_layer")
        assert schema["title"] == "ATT&CK Navigator Layer"

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_schema("nonexistent_schema")


class TestValidate:
    def test_valid_minimal_product_profile(self) -> None:
        data = {
            "product_name": "TestProduct",
            "product_type": "edr",
            "vendor": "TestVendor",
            "version": "1.0.0",
        }
        validate(data, "product_profile")

    def test_invalid_product_profile_missing_required(self) -> None:
        data = {"product_name": "TestProduct"}
        with pytest.raises(jsonschema.ValidationError):
            validate(data, "product_profile")

    def test_invalid_product_type_enum(self) -> None:
        data = {
            "product_name": "TestProduct",
            "product_type": "invalid_type",
            "vendor": "TestVendor",
            "version": "1.0.0",
        }
        with pytest.raises(jsonschema.ValidationError):
            validate(data, "product_profile")

    def test_valid_coverage_matrix(self) -> None:
        data = {
            "product_name": "TestProduct",
            "attack_version": "15.1",
            "techniques": [
                {
                    "technique_id": "T1055",
                    "confidence": 0.8,
                }
            ],
        }
        validate(data, "coverage_matrix")

    def test_invalid_technique_id_pattern(self) -> None:
        data = {
            "product_name": "TestProduct",
            "attack_version": "15.1",
            "techniques": [
                {
                    "technique_id": "INVALID",
                    "confidence": 0.8,
                }
            ],
        }
        with pytest.raises(jsonschema.ValidationError):
            validate(data, "coverage_matrix")

    def test_valid_technique_subtechnique_id(self) -> None:
        data = {
            "product_name": "TestProduct",
            "attack_version": "15.1",
            "techniques": [
                {
                    "technique_id": "T1055.003",
                    "confidence": 0.9,
                }
            ],
        }
        validate(data, "coverage_matrix")

    def test_valid_navigator_layer(self) -> None:
        data = {
            "name": "Test Layer",
            "domain": "enterprise-attack",
            "techniques": [
                {"techniqueID": "T1055", "score": 80}
            ],
        }
        validate(data, "navigator_layer")
