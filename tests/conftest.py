# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Shared test fixtures for MedSBOM test suite."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from medsbom.core.models import (
    Component,
    ComponentResult,
    Finding,
    RiskLevel,
    SBOMFormat,
    SBOMScan,
)

SAMPLE_DATA_DIR = Path(__file__).parent / "sample_data"


@pytest.fixture
def sample_cyclonedx_path() -> Path:
    return SAMPLE_DATA_DIR / "sample_cyclonedx.json"


@pytest.fixture
def sample_spdx_path() -> Path:
    return SAMPLE_DATA_DIR / "sample_spdx.json"


@pytest.fixture
def sample_cyclonedx_dict() -> dict:
    return json.loads((SAMPLE_DATA_DIR / "sample_cyclonedx.json").read_text())


@pytest.fixture
def sample_spdx_dict() -> dict:
    return json.loads((SAMPLE_DATA_DIR / "sample_spdx.json").read_text())


@pytest.fixture
def minimal_cyclonedx() -> dict:
    """Minimal valid CycloneDX SBOM."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "test-lib",
                "version": "1.0.0",
                "purl": "pkg:generic/test-lib@1.0.0",
            }
        ],
    }


@pytest.fixture
def minimal_spdx() -> dict:
    """Minimal valid SPDX SBOM."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test",
        "documentNamespace": "https://example.com/test",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": "test-pkg",
                "versionInfo": "2.0.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:generic/test-pkg@2.0.0"}
                ],
            }
        ],
    }


@pytest.fixture
def sample_component() -> Component:
    return Component(
        name="openssl",
        version="1.1.1w",
        purl="pkg:generic/openssl@1.1.1w",
        license="Apache-2.0",
    )


@pytest.fixture
def sample_finding_critical() -> Finding:
    return Finding(
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        severity="CRITICAL",
        description="Remote code execution in test component",
        kev_flag=True,
        source="NVD",
    )


@pytest.fixture
def sample_finding_medium() -> Finding:
    return Finding(
        cve_id="CVE-2024-0002",
        cvss_score=5.5,
        severity="MEDIUM",
        description="Information disclosure vulnerability",
        kev_flag=False,
        source="NVD",
    )


@pytest.fixture
def sample_finding_low() -> Finding:
    return Finding(
        cve_id="CVE-2024-0003",
        cvss_score=2.1,
        severity="LOW",
        description="Minor denial of service",
        kev_flag=False,
        source="NVD",
    )


@pytest.fixture
def sample_scan(sample_component: Component, sample_finding_critical: Finding) -> SBOMScan:
    return SBOMScan(
        scan_id="test-scan-001",
        device_name="Test Medical Device",
        device_version="1.0.0",
        timestamp=datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC),
        sbom_format=SBOMFormat.CYCLONEDX,
        source_tool="syft",
        components=[sample_component],
        results=[
            ComponentResult(
                component=sample_component,
                findings=[sample_finding_critical],
                overall_risk=RiskLevel.CRITICAL,
            )
        ],
    )


@pytest.fixture
def empty_scan() -> SBOMScan:
    return SBOMScan(
        scan_id="test-scan-empty",
        device_name="Empty Device",
        device_version="0.0.1",
        timestamp=datetime(2026, 7, 10, 12, 0, 0, tzinfo=UTC),
        sbom_format=SBOMFormat.CYCLONEDX,
    )


@pytest.fixture
def tmp_audit_db(tmp_path: Path) -> Path:
    """Temporary audit database path."""
    return tmp_path / "test_audit.db"


# --- Mock NVD / KEV response data ---


@pytest.fixture
def mock_nvd_response() -> dict:
    """A realistic NVD API 2.0 response."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": (
                                "A test vulnerability in openssl 1.1.1w"
                                " allowing remote code execution."
                            ),
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                }
            }
        ],
    }


@pytest.fixture
def mock_nvd_empty_response() -> dict:
    return {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}


@pytest.fixture
def mock_kev_response() -> dict:
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.07.10",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-99999",
                "vendorProject": "OpenSSL",
                "product": "OpenSSL",
                "dateAdded": "2024-01-15",
                "shortDescription": "OpenSSL RCE",
                "requiredAction": "Apply updates per vendor instructions.",
            },
            {
                "cveID": "CVE-2023-44487",
                "vendorProject": "IETF",
                "product": "HTTP/2",
                "dateAdded": "2023-10-10",
                "shortDescription": "HTTP/2 Rapid Reset",
                "requiredAction": "Apply updates.",
            },
        ],
    }


@pytest.fixture
def mock_eol_response_python() -> list[dict]:
    """endoflife.date response for Python."""
    return [
        {
            "cycle": "3.12",
            "releaseDate": "2023-10-02",
            "eol": "2028-10-02",
            "latest": "3.12.4",
            "lts": False,
            "support": "2025-04-02",
        },
        {
            "cycle": "3.10",
            "releaseDate": "2021-10-04",
            "eol": "2026-10-04",
            "latest": "3.10.14",
            "lts": False,
            "support": "2023-04-04",
        },
        {
            "cycle": "3.8",
            "releaseDate": "2019-10-14",
            "eol": "2024-10-14",
            "latest": "3.8.20",
            "lts": False,
            "support": "2021-05-03",
        },
    ]


@pytest.fixture
def mock_eol_cycle_response() -> dict:
    """endoflife.date response for a single cycle."""
    return {
        "cycle": "3.10",
        "releaseDate": "2021-10-04",
        "eol": "2026-10-04",
        "latest": "3.10.14",
        "lts": False,
        "support": "2023-04-04",
    }
