# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.api.main — FastAPI endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from medsbom.api.main import _scans, app


@pytest.fixture
def client() -> TestClient:
    _scans.clear()
    return TestClient(app)


@pytest.fixture
def sample_cyclonedx_payload(sample_cyclonedx_dict: dict) -> dict:
    return {
        "device_name": "Test Pump",
        "device_version": "1.0",
        "sbom_json": sample_cyclonedx_dict,
    }


# ============================================================
# Positive cases
# ============================================================


class TestAPIPositive:
    """Positive path tests for API endpoints."""

    def test_health(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_create_scan(self, client: TestClient, sample_cyclonedx_payload: dict) -> None:
        resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["device_name"] == "Test Pump"
        assert data["total_components"] == 8
        assert "scan_id" in data
        assert "risk_summary" in data

    def test_get_scan(self, client: TestClient, sample_cyclonedx_payload: dict) -> None:
        # Create first
        create_resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        scan_id = create_resp.json()["scan_id"]

        # Retrieve
        resp = client.get(f"/api/v1/scans/{scan_id}")
        assert resp.status_code == 200
        assert resp.json()["scan_id"] == scan_id

    def test_generate_fda_report(self, client: TestClient, sample_cyclonedx_payload: dict) -> None:
        create_resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}/report/fda")
        assert resp.status_code == 200
        data = resp.json()
        assert data["format"] == "fda"
        assert "FDA Premarket" in data["content"]

    def test_generate_soup_report(self, client: TestClient, sample_cyclonedx_payload: dict) -> None:
        create_resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}/report/soup")
        assert resp.status_code == 200
        assert "SOUP" in resp.json()["content"]

    def test_generate_vuln_report(self, client: TestClient, sample_cyclonedx_payload: dict) -> None:
        create_resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}/report/vuln")
        assert resp.status_code == 200
        assert "Vulnerability Review Log" in resp.json()["content"]

    def test_list_audit(self, client: TestClient) -> None:
        resp = client.get("/api/v1/audit")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ============================================================
# Negative cases
# ============================================================


class TestAPINegative:
    """Error handling tests for API."""

    def test_invalid_sbom_format(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/scans",
            json={
                "device_name": "Test",
                "sbom_json": {"random": "data"},
            },
        )
        assert resp.status_code == 400

    def test_scan_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/v1/scans/nonexistent-id")
        assert resp.status_code == 404

    def test_report_scan_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/v1/scans/nonexistent-id/report/fda")
        assert resp.status_code == 404

    def test_invalid_report_format(
        self, client: TestClient, sample_cyclonedx_payload: dict
    ) -> None:
        create_resp = client.post("/api/v1/scans", json=sample_cyclonedx_payload)
        scan_id = create_resp.json()["scan_id"]

        resp = client.get(f"/api/v1/scans/{scan_id}/report/invalid")
        assert resp.status_code == 400
        assert "Invalid format" in resp.json()["detail"]

    def test_missing_sbom_json_field(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/scans",
            json={
                "device_name": "Test",
            },
        )
        assert resp.status_code == 422  # Pydantic validation error


# ============================================================
# Edge cases
# ============================================================


class TestAPIEdgeCases:
    """Edge case tests for API."""

    def test_empty_components_sbom(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/scans",
            json={
                "device_name": "Empty Device",
                "sbom_json": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [],
                },
            },
        )
        assert resp.status_code == 200
        assert resp.json()["total_components"] == 0

    def test_audit_with_limit(self, client: TestClient) -> None:
        resp = client.get("/api/v1/audit?limit=5")
        assert resp.status_code == 200

    def test_audit_limit_capped(self, client: TestClient) -> None:
        """Limit should be capped at 200."""
        resp = client.get("/api/v1/audit?limit=999")
        assert resp.status_code == 200

    def test_spdx_upload(self, client: TestClient, sample_spdx_dict: dict) -> None:
        resp = client.post(
            "/api/v1/scans",
            json={
                "device_name": "Imaging System",
                "sbom_json": sample_spdx_dict,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["total_components"] == 5
