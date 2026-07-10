# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.ingest — SBOM parsing and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from medsbom.core.ingest import IngestError, detect_format, parse_sbom
from medsbom.core.models import SBOMFormat

# ============================================================
# Positive cases
# ============================================================


class TestDetectFormat:
    """Format auto-detection tests."""

    def test_detect_cyclonedx(self, sample_cyclonedx_dict: dict) -> None:
        assert detect_format(sample_cyclonedx_dict) == SBOMFormat.CYCLONEDX

    def test_detect_spdx(self, sample_spdx_dict: dict) -> None:
        assert detect_format(sample_spdx_dict) == SBOMFormat.SPDX

    def test_detect_cyclonedx_heuristic(self) -> None:
        """Detect CycloneDX without explicit bomFormat, using heuristic."""
        data = {"specVersion": "1.5", "components": []}
        assert detect_format(data) == SBOMFormat.CYCLONEDX

    def test_detect_spdx_heuristic(self) -> None:
        """Detect SPDX without explicit spdxVersion, using heuristic."""
        data = {"documentNamespace": "https://example.com/test", "packages": []}
        assert detect_format(data) == SBOMFormat.SPDX


class TestParseCycloneDX:
    """CycloneDX parsing tests."""

    def test_parse_from_file(self, sample_cyclonedx_path: Path) -> None:
        result = parse_sbom(sample_cyclonedx_path)
        assert result.sbom_format == SBOMFormat.CYCLONEDX
        assert len(result.components) == 8
        assert result.source_tool == "syft"

    def test_parse_from_dict(self, sample_cyclonedx_dict: dict) -> None:
        result = parse_sbom(sample_cyclonedx_dict)
        assert result.sbom_format == SBOMFormat.CYCLONEDX
        assert len(result.components) == 8

    def test_parse_from_json_string(self, sample_cyclonedx_dict: dict) -> None:
        json_str = json.dumps(sample_cyclonedx_dict)
        # Create a temp file path that doesn't exist so it falls through to string parsing
        result = parse_sbom(json_str)
        assert result.sbom_format == SBOMFormat.CYCLONEDX

    def test_component_fields(self, sample_cyclonedx_dict: dict) -> None:
        result = parse_sbom(sample_cyclonedx_dict)
        openssl = next(c for c in result.components if c.name == "openssl")
        assert openssl.version == "1.1.1w"
        assert openssl.purl == "pkg:generic/openssl@1.1.1w"
        assert openssl.license == "Apache-2.0"
        assert openssl.supplier == "OpenSSL Project"
        assert openssl.component_type == "library"

    def test_minimal_cyclonedx(self, minimal_cyclonedx: dict) -> None:
        result = parse_sbom(minimal_cyclonedx)
        assert len(result.components) == 1
        assert result.components[0].name == "test-lib"

    def test_component_identifier_with_purl(self, minimal_cyclonedx: dict) -> None:
        result = parse_sbom(minimal_cyclonedx)
        comp = result.components[0]
        assert comp.identifier == "pkg:generic/test-lib@1.0.0"

    def test_component_identifier_without_purl(self) -> None:
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "no-purl", "version": "1.0"}],
        }
        result = parse_sbom(data)
        assert result.components[0].identifier == "no-purl@1.0"


class TestParseSPDX:
    """SPDX parsing tests."""

    def test_parse_from_file(self, sample_spdx_path: Path) -> None:
        result = parse_sbom(sample_spdx_path)
        assert result.sbom_format == SBOMFormat.SPDX
        assert len(result.components) == 5
        assert result.source_tool == "trivy-0.52.0"

    def test_parse_from_dict(self, sample_spdx_dict: dict) -> None:
        result = parse_sbom(sample_spdx_dict)
        assert result.sbom_format == SBOMFormat.SPDX

    def test_spdx_purl_extraction(self, sample_spdx_dict: dict) -> None:
        result = parse_sbom(sample_spdx_dict)
        openssl = next(c for c in result.components if c.name == "openssl")
        assert openssl.purl == "pkg:generic/openssl@3.0.13"

    def test_spdx_noassertion_license(self, sample_spdx_dict: dict) -> None:
        """NOASSERTION should be normalized to empty string."""
        result = parse_sbom(sample_spdx_dict)
        ubuntu = next(c for c in result.components if c.name == "ubuntu")
        assert ubuntu.license == ""

    def test_minimal_spdx(self, minimal_spdx: dict) -> None:
        result = parse_sbom(minimal_spdx)
        assert len(result.components) == 1
        assert result.components[0].name == "test-pkg"


# ============================================================
# Negative cases
# ============================================================


class TestIngestErrors:
    """Error handling tests."""

    def test_invalid_json_string(self) -> None:
        with pytest.raises(IngestError, match="Invalid JSON"):
            parse_sbom("{not valid json!!!")

    def test_non_object_json(self) -> None:
        with pytest.raises(IngestError, match="root must be an object"):
            parse_sbom("[1, 2, 3]")

    def test_unknown_format(self) -> None:
        with pytest.raises(IngestError, match="Cannot detect SBOM format"):
            parse_sbom({"random": "data"})

    def test_file_not_found(self) -> None:
        with pytest.raises(IngestError, match="File not found"):
            parse_sbom(Path("/nonexistent/file.json"))

    def test_components_not_list(self) -> None:
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": "not a list"}
        with pytest.raises(IngestError, match="must be a list"):
            parse_sbom(data)

    def test_spdx_packages_not_list(self) -> None:
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "packages": "oops",
        }
        with pytest.raises(IngestError, match="must be a list"):
            parse_sbom(data)


# ============================================================
# Edge cases
# ============================================================


class TestIngestEdgeCases:
    """Edge case tests."""

    def test_empty_components_list(self) -> None:
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        result = parse_sbom(data)
        assert len(result.components) == 0
        assert len(result.warnings) == 0

    def test_component_missing_name(self) -> None:
        """Component without name should be skipped with warning."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "version": "1.0"}],
        }
        result = parse_sbom(data)
        assert len(result.components) == 0
        assert len(result.warnings) == 1
        assert "name" in result.warnings[0].field

    def test_component_missing_version(self) -> None:
        """Component without version should produce warning but still be included."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "no-version"}],
        }
        result = parse_sbom(data)
        assert len(result.components) == 1
        assert result.components[0].version == ""
        assert any(w.field == "version" for w in result.warnings)

    def test_component_missing_purl(self) -> None:
        """Component without purl should produce warning but still be included."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "no-purl", "version": "1.0"}],
        }
        result = parse_sbom(data)
        assert len(result.components) == 1
        assert any(w.field == "purl" for w in result.warnings)

    def test_non_dict_component_skipped(self) -> None:
        """Non-dict items in components list are skipped."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": ["not-a-dict", {"type": "library", "name": "good", "version": "1.0"}],
        }
        result = parse_sbom(data)
        assert len(result.components) == 1
        assert result.components[0].name == "good"

    def test_special_characters_in_name(self) -> None:
        """Component names with special characters should be handled."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": "lib-with-special/chars@v2", "version": "2.0"}
            ],
        }
        result = parse_sbom(data)
        assert result.components[0].name == "lib-with-special/chars@v2"

    def test_very_large_sbom(self) -> None:
        """Parse SBOM with many components without crashing."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"type": "library", "name": f"lib-{i}", "version": f"{i}.0.0"} for i in range(1000)
            ],
        }
        result = parse_sbom(data)
        assert len(result.components) == 1000

    def test_source_tool_string_format(self) -> None:
        """Handle tools list with string items (older CycloneDX)."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {"tools": ["syft"]},
            "components": [],
        }
        result = parse_sbom(data)
        assert result.source_tool == "syft"

    def test_spdx_package_missing_external_refs(self) -> None:
        """SPDX package with no externalRefs should still parse."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "packages": [{"SPDXID": "SPDXRef-1", "name": "no-refs", "versionInfo": "1.0"}],
        }
        result = parse_sbom(data)
        assert len(result.components) == 1
        assert result.components[0].purl == ""

    def test_identifier_without_version_or_purl(self) -> None:
        """Component with no purl and no version returns just the name."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "bare-lib"}],
        }
        result = parse_sbom(data)
        assert result.components[0].identifier == "bare-lib"
