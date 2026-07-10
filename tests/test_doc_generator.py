# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.doc_generator — Document generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from medsbom.core.doc_generator import DocGenerator, DocGeneratorError
from medsbom.core.models import (
    Component,
    ComponentResult,
    Finding,
    RiskLevel,
    SBOMFormat,
    SBOMScan,
)


@pytest.fixture
def doc_gen() -> DocGenerator:
    return DocGenerator()


@pytest.fixture
def populated_scan() -> SBOMScan:
    """A scan with multiple components and findings for doc generation tests."""
    comp_ssl = Component(
        name="openssl", version="1.1.1w", purl="pkg:generic/openssl@1.1.1w", license="Apache-2.0"
    )
    comp_zlib = Component(
        name="zlib", version="1.2.13", purl="pkg:generic/zlib@1.2.13", license="Zlib"
    )
    comp_python = Component(
        name="python", version="3.10.14", purl="pkg:generic/python@3.10.14", license="PSF-2.0"
    )

    return SBOMScan(
        scan_id="doc-test-scan-001",
        device_name="Insulin Pump Controller",
        device_version="2.3.1",
        timestamp=datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC),
        sbom_format=SBOMFormat.CYCLONEDX,
        source_tool="syft",
        components=[comp_ssl, comp_zlib, comp_python],
        results=[
            ComponentResult(
                component=comp_ssl,
                findings=[
                    Finding(
                        cve_id="CVE-2024-0001",
                        cvss_score=9.8,
                        severity="CRITICAL",
                        kev_flag=True,
                        description="RCE in OpenSSL",
                        source="NVD",
                    ),
                    Finding(
                        cve_id="CVE-2024-0002",
                        cvss_score=5.5,
                        severity="MEDIUM",
                        description="Info disclosure",
                        source="NVD",
                    ),
                ],
                overall_risk=RiskLevel.CRITICAL,
            ),
            ComponentResult(
                component=comp_zlib,
                findings=[],
                overall_risk=RiskLevel.NONE,
            ),
            ComponentResult(
                component=comp_python,
                findings=[
                    Finding(
                        cve_id="CVE-2024-0003",
                        cvss_score=4.0,
                        severity="MEDIUM",
                        description="DoS in urllib",
                        source="NVD",
                    ),
                ],
                overall_risk=RiskLevel.MEDIUM,
                is_eol=True,
                eol_date=datetime(2026, 10, 4).date(),
            ),
        ],
    )


# ============================================================
# Positive cases
# ============================================================


class TestDocGeneratorPositive:
    """Positive path tests for document generation."""

    def test_fda_summary_generated(self, doc_gen: DocGenerator, populated_scan: SBOMScan) -> None:
        content = doc_gen.generate_fda_summary(populated_scan)
        assert "FDA Premarket Cybersecurity Summary" in content
        assert "Insulin Pump Controller" in content
        assert populated_scan.device_version in content

    def test_fda_summary_contains_disclaimer(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_fda_summary(populated_scan)
        assert "DISCLAIMER" in content
        assert "DRAFT" in content

    def test_fda_summary_contains_risk_table(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_fda_summary(populated_scan)
        assert "openssl" in content
        assert "CRITICAL" in content

    def test_fda_summary_kev_section(self, doc_gen: DocGenerator, populated_scan: SBOMScan) -> None:
        content = doc_gen.generate_fda_summary(populated_scan)
        assert "CVE-2024-0001" in content
        assert "KEV" in content

    def test_fda_summary_eol_section(self, doc_gen: DocGenerator, populated_scan: SBOMScan) -> None:
        content = doc_gen.generate_fda_summary(populated_scan)
        assert "End-of-Life" in content
        assert "python" in content

    def test_soup_assessment_generated(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_soup_assessment(populated_scan)
        assert "IEC 62304 SOUP Risk Assessment" in content
        assert "openssl" in content
        assert "zlib" in content

    def test_soup_assessment_contains_disclaimer(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_soup_assessment(populated_scan)
        assert "DISCLAIMER" in content

    def test_vuln_review_log_generated(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_vuln_review_log(populated_scan)
        assert "Vulnerability Review Log" in content
        assert "doc-test-scan-001" in content

    def test_vuln_review_log_contains_findings(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_vuln_review_log(populated_scan)
        assert "CVE-2024-0001" in content
        assert "CVE-2024-0002" in content

    def test_vuln_review_log_attestation(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan
    ) -> None:
        content = doc_gen.generate_vuln_review_log(populated_scan)
        assert "Review Attestation" in content
        assert "Reviewed by" in content

    def test_full_bundle(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "reports"
        generated = doc_gen.generate_full_bundle(populated_scan, output_dir)
        assert len(generated) == 3
        assert all(p.exists() for p in generated)
        assert (output_dir / "fda_premarket_summary.md").exists()
        assert (output_dir / "soup_risk_assessment.md").exists()
        assert (output_dir / "vulnerability_review_log.md").exists()


# ============================================================
# Negative cases
# ============================================================


class TestDocGeneratorNegative:
    """Error handling tests."""

    def test_invalid_templates_dir(self) -> None:
        with pytest.raises(DocGeneratorError, match="Templates directory not found"):
            DocGenerator(templates_dir=Path("/nonexistent/templates"))


# ============================================================
# Edge cases
# ============================================================


class TestDocGeneratorEdgeCases:
    """Edge case tests."""

    def test_empty_scan(self, doc_gen: DocGenerator, empty_scan: SBOMScan) -> None:
        """Empty scan should still generate valid documents."""
        content = doc_gen.generate_fda_summary(empty_scan)
        assert "FDA Premarket Cybersecurity Summary" in content
        assert "0" in content  # 0 components

    def test_scan_no_findings(self, doc_gen: DocGenerator) -> None:
        """Scan with components but no findings."""
        scan = SBOMScan(
            scan_id="test-no-findings",
            device_name="Clean Device",
            device_version="1.0",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
            sbom_format=SBOMFormat.CYCLONEDX,
            components=[Component(name="safe-lib", version="1.0")],
            results=[
                ComponentResult(
                    component=Component(name="safe-lib", version="1.0"),
                    findings=[],
                    overall_risk=RiskLevel.NONE,
                )
            ],
        )
        content = doc_gen.generate_fda_summary(scan)
        assert "NONE" in content

    def test_special_characters_in_component(self, doc_gen: DocGenerator) -> None:
        """Component names with special chars should render safely."""
        scan = SBOMScan(
            scan_id="test-special",
            device_name="Test <Device> & More",
            device_version="1.0",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
            sbom_format=SBOMFormat.CYCLONEDX,
            components=[Component(name="lib-with-<angle>&brackets", version="1.0")],
            results=[
                ComponentResult(
                    component=Component(name="lib-with-<angle>&brackets", version="1.0"),
                    findings=[],
                    overall_risk=RiskLevel.NONE,
                )
            ],
        )
        content = doc_gen.generate_fda_summary(scan)
        assert "lib-with-<angle>&brackets" in content

    def test_output_dir_created_automatically(
        self, doc_gen: DocGenerator, populated_scan: SBOMScan, tmp_path: Path
    ) -> None:
        """Output directory should be created if it doesn't exist."""
        output_dir = tmp_path / "deep" / "nested" / "dir"
        assert not output_dir.exists()
        generated = doc_gen.generate_full_bundle(populated_scan, output_dir)
        assert output_dir.exists()
        assert len(generated) == 3
