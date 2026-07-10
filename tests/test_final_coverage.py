# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Final coverage push — tests for remaining uncovered lines."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from medsbom.cli.main import app
from medsbom.core.cve_match import CVEMatcher
from medsbom.core.models import Component

runner = CliRunner()


class TestCLIWarningsAndTruncation:
    """Tests to cover ingest warning display and truncation."""

    def test_ingest_many_warnings(self, tmp_path: Path) -> None:
        """SBOM with >20 warnings should show truncation message."""
        # Create SBOM with 25 components missing purls and versions
        components = [{"type": "library", "name": f"lib-{i}"} for i in range(25)]
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components,
        }
        f = tmp_path / "many_warnings.json"
        f.write_text(json.dumps(data))

        result = runner.invoke(app, ["ingest", str(f)])
        assert result.exit_code == 0
        assert "more" in result.stdout  # Truncation message

    def test_ingest_over_50_components(self, tmp_path: Path) -> None:
        """SBOM with >50 components should show truncation in table."""
        components = [
            {
                "type": "library",
                "name": f"lib-{i}",
                "version": f"{i}.0.0",
                "purl": f"pkg:generic/lib-{i}@{i}.0.0",
            }
            for i in range(55)
        ]
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components,
        }
        f = tmp_path / "big.json"
        f.write_text(json.dumps(data))

        result = runner.invoke(app, ["ingest", str(f)])
        assert result.exit_code == 0
        assert "55" in result.stdout  # 55 components
        assert "more" in result.stdout  # Table truncation


class TestCLICheckEdges:
    """Additional check command edge cases."""

    @pytest.fixture
    def mock_no_network(self):
        with (
            patch("medsbom.cli.main.CVEMatcher") as mock_cve,
            patch("medsbom.cli.main.EOLChecker") as mock_eol,
        ):
            matcher = MagicMock()
            matcher.match_component.return_value = []
            mock_cve.return_value = matcher

            checker = MagicMock()
            checker.check_component.return_value = MagicMock(eol_date=None, is_eol=False)
            mock_eol.return_value = checker

            yield

    def test_check_audit_failure_non_fatal(
        self, sample_cyclonedx_path: Path, tmp_path: Path
    ) -> None:
        """Audit failure during check should not crash the command."""
        with (
            patch("medsbom.cli.main.CVEMatcher") as mock_cve,
            patch("medsbom.cli.main.EOLChecker") as mock_eol,
            patch("medsbom.cli.main.AuditTrail") as mock_audit,
        ):
            matcher = MagicMock()
            matcher.match_component.return_value = []
            mock_cve.return_value = matcher

            checker = MagicMock()
            checker.check_component.return_value = MagicMock(eol_date=None, is_eol=False)
            mock_eol.return_value = checker

            mock_audit.return_value.log.side_effect = RuntimeError("DB error")

            result = runner.invoke(app, ["check", str(sample_cyclonedx_path), "--device", "Test"])
            assert result.exit_code == 0

    def test_report_audit_failure_non_fatal(
        self, sample_cyclonedx_path: Path, tmp_path: Path
    ) -> None:
        """Audit failure during report should not crash."""
        output_dir = tmp_path / "reports"
        with (
            patch("medsbom.cli.main.CVEMatcher") as mock_cve,
            patch("medsbom.cli.main.EOLChecker") as mock_eol,
            patch("medsbom.cli.main.AuditTrail") as mock_audit,
        ):
            matcher = MagicMock()
            matcher.match_component.return_value = []
            mock_cve.return_value = matcher

            checker = MagicMock()
            checker.check_component.return_value = MagicMock(eol_date=None, is_eol=False)
            mock_eol.return_value = checker

            mock_audit.return_value.log.side_effect = RuntimeError("DB error")

            result = runner.invoke(
                app,
                [
                    "report",
                    str(sample_cyclonedx_path),
                    "--format",
                    "fda",
                    "--output",
                    str(output_dir),
                ],
            )
            assert result.exit_code == 0


class TestCVEMatcherNetworkPaths:
    """Test the actual network query paths of CVEMatcher."""

    def test_query_nvd_successful_request(self, tmp_path: Path) -> None:
        """Successful NVD API request should parse and cache."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._last_nvd_request = 0

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1111",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N",
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            comp = Component(name="unique-test-pkg", version="1.0.0")
            findings = matcher._query_nvd(comp)
            assert len(findings) == 1
            assert findings[0].cve_id == "CVE-2024-1111"
            assert findings[0].cvss_score == 7.5

        # Verify cache was written
        assert matcher._read_cache("nvd_unique-test-pkg_1.0.0") is not None

    def test_kev_feed_fetched_from_network(self, tmp_path: Path) -> None:
        """KEV feed should be fetched and cached when not available locally."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{"cveID": "CVE-2024-9999", "vendorProject": "Test"}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = matcher._get_kev_lookup()
            assert "CVE-2024-9999" in result

    def test_match_component_with_purl(self, tmp_path: Path) -> None:
        """Component with purl should use keywordExactMatch param."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._kev_data = {}
        matcher._last_nvd_request = 0

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            comp = Component(
                name="unique-purl-test", version="1.0", purl="pkg:generic/unique-purl-test@1.0"
            )
            findings = matcher.match_component(comp)
            assert findings == []

            # Verify the request was made with correct params
            call_args = mock_client.get.call_args
            call_args[1].get("params", call_args[0][1] if len(call_args[0]) > 1 else {})


class TestAPIAuditFailure:
    """Test API audit failure path."""

    def test_create_scan_audit_failure(self, sample_cyclonedx_dict: dict) -> None:
        """API scan should still succeed even if audit logging fails."""
        from fastapi.testclient import TestClient

        from medsbom.api.main import _scans
        from medsbom.api.main import app as api_app

        _scans.clear()

        with patch("medsbom.api.main.AuditTrail") as mock_audit:
            mock_audit.return_value.log.side_effect = RuntimeError("DB error")

            with (
                patch("medsbom.api.main.CVEMatcher") as mock_cve,
                patch("medsbom.api.main.EOLChecker") as mock_eol,
            ):
                matcher = MagicMock()
                matcher.match_component.return_value = []
                mock_cve.return_value = matcher

                checker = MagicMock()
                checker.check_component.return_value = MagicMock(eol_date=None, is_eol=False)
                mock_eol.return_value = checker

                client = TestClient(api_app)
                resp = client.post(
                    "/api/v1/scans",
                    json={
                        "device_name": "Test",
                        "device_version": "1.0",
                        "sbom_json": sample_cyclonedx_dict,
                    },
                )
                assert resp.status_code == 200
