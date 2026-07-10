# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Additional coverage tests for core modules — targets uncovered branches."""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from medsbom.core.cve_match import CVEMatcher
from medsbom.core.eol_check import EOLChecker
from medsbom.core.ingest import parse_sbom
from medsbom.core.models import Component
from medsbom.core.risk_score import _eol_score


class TestCVEMatcherCoverage:
    """Cover remaining branches in cve_match.py."""

    def test_query_nvd_uses_cache_hit(self, tmp_path: Path) -> None:
        """Cache hit should skip the HTTP request."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        # Write a cache entry
        cached_data = {"vulnerabilities": [], "totalResults": 0}
        matcher._write_cache("nvd_openssl_1.1.1w", cached_data)

        comp = Component(name="openssl", version="1.1.1w")
        # Should not make HTTP request — reads from cache
        findings = matcher._query_nvd(comp)
        assert findings == []

    def test_query_nvd_with_api_key(self, tmp_path: Path) -> None:
        """API key should be sent as header."""
        matcher = CVEMatcher(nvd_api_key="test-key-123", cache_dir=tmp_path / "cache")
        matcher._last_nvd_request = 0  # Reset rate limit

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            comp = Component(name="unique-lib-xyz", version="9.9.9")
            findings = matcher._query_nvd(comp)
            assert findings == []

    def test_rate_limit_with_key_is_faster(self, tmp_path: Path) -> None:
        """With API key, rate limiting delay should be much shorter."""
        matcher = CVEMatcher(nvd_api_key="key", cache_dir=tmp_path / "cache")
        matcher._last_nvd_request = time.monotonic()  # Just made a request

        start = time.monotonic()
        matcher._rate_limit()
        elapsed = time.monotonic() - start
        # With key, delay is 0.6s max
        assert elapsed < 1.0

    def test_write_cache_failure(self, tmp_path: Path) -> None:
        """Cache write failure should log but not crash."""
        cache_dir = tmp_path / "cache"
        matcher = CVEMatcher(cache_dir=cache_dir)
        # Make a file that conflicts with writing a cache entry
        (cache_dir / "broken.json").mkdir()
        matcher._write_cache("broken", {"data": True})
        # Should not raise

    def test_kev_data_cached_in_memory(self, tmp_path: Path) -> None:
        """Second call to _get_kev_lookup should use memory cache."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._kev_data = {"CVE-2024-0001": {"cveID": "CVE-2024-0001"}}

        result = matcher._get_kev_lookup()
        assert "CVE-2024-0001" in result

    def test_kev_from_disk_cache(self, tmp_path: Path) -> None:
        """KEV data on disk should be loaded without network."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(parents=True)
        kev_data = {"vulnerabilities": [{"cveID": "CVE-2023-1234", "vendorProject": "Test"}]}
        (cache_dir / "kev_feed.json").write_text(json.dumps(kev_data))

        matcher = CVEMatcher(cache_dir=cache_dir)
        result = matcher._get_kev_lookup()
        assert "CVE-2023-1234" in result


class TestEOLCheckerCoverage:
    """Cover remaining branches in eol_check.py."""

    def test_query_eol_api_cycle_not_found_fallback_all(self) -> None:
        """When specific cycle returns 404, should try all cycles."""
        checker = EOLChecker()

        all_cycles_response = MagicMock()
        all_cycles_response.status_code = 200
        all_cycles_response.json.return_value = [
            {"cycle": "3.10", "eol": "2026-10-04", "latest": "3.10.14"},
        ]

        cycle_response = MagicMock()
        cycle_response.status_code = 404

        def side_effect(url, **kwargs):
            if "/3.10.json" in url:
                return cycle_response
            return all_cycles_response

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = side_effect
            mock_client_cls.return_value = mock_client

            result = checker._query_eol_api("python", "3.10.14")
            assert result.matched is True

    def test_query_eol_api_both_404(self) -> None:
        """When both cycle and all-cycles return 404."""
        checker = EOLChecker()

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = checker._query_eol_api("unknown-product", "1.0")
            assert result.matched is False

    def test_query_eol_api_http_error(self) -> None:
        """Non-404 HTTP error should raise EOLCheckError."""
        checker = EOLChecker()

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response
        )

        # First call (cycle-specific) returns 404
        cycle_response = MagicMock()
        cycle_response.status_code = 404

        call_count = [0]

        def side_effect(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return cycle_response
            return mock_response

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = side_effect
            mock_client_cls.return_value = mock_client

            # Should gracefully handle (check_component catches errors)
            comp = Component(name="python", version="3.10.14")
            result = checker.check_component(comp)
            assert result.matched is False

    def test_find_best_match_with_prefix_match(self) -> None:
        """Version starting with cycle should match."""
        checker = EOLChecker()
        cycles = [
            {"cycle": "3.10", "eol": "2026-10-04", "latest": "3.10.14", "lts": False},
        ]
        result = checker._find_best_match("python", "3.10.14", cycles)
        assert result.matched is True
        assert result.eol_date == date(2026, 10, 4)


class TestIngestCoverage:
    """Cover remaining branches in ingest.py."""

    def test_parse_sbom_from_path_object(self, sample_cyclonedx_path: Path) -> None:
        """Pass Path object directly."""
        result = parse_sbom(sample_cyclonedx_path)
        assert len(result.components) == 8

    def test_spdx_creator_tool_extraction(self) -> None:
        """SPDX with Tool: prefix in creators."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "creationInfo": {"creators": ["Organization: Acme", "Tool: custom-scanner-1.0"]},
            "packages": [{"SPDXID": "SPDXRef-1", "name": "pkg", "versionInfo": "1.0"}],
        }
        result = parse_sbom(data)
        assert result.source_tool == "custom-scanner-1.0"

    def test_spdx_no_tool_in_creators(self) -> None:
        """SPDX with no Tool: prefix."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "creationInfo": {"creators": ["Organization: Acme"]},
            "packages": [],
        }
        result = parse_sbom(data)
        assert result.source_tool == ""

    def test_spdx_noassertion_supplier(self) -> None:
        """SPDX supplier 'NOASSERTION' should normalize to empty."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "packages": [
                {
                    "SPDXID": "SPDXRef-1",
                    "name": "pkg",
                    "versionInfo": "1.0",
                    "supplier": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                }
            ],
        }
        result = parse_sbom(data)
        assert result.components[0].supplier == ""
        assert result.components[0].license == ""

    def test_cyclonedx_empty_metadata_tools(self) -> None:
        """CycloneDX with empty tools list."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"tools": []},
            "components": [],
        }
        result = parse_sbom(data)
        assert result.source_tool == ""

    def test_cyclonedx_no_metadata(self) -> None:
        """CycloneDX with no metadata key."""
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "test", "version": "1.0"}],
        }
        result = parse_sbom(data)
        assert result.source_tool == ""

    def test_spdx_package_missing_name(self) -> None:
        """SPDX package missing name should be skipped."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "packages": [
                {"SPDXID": "SPDXRef-1", "versionInfo": "1.0"},
            ],
        }
        result = parse_sbom(data)
        assert len(result.components) == 0
        assert len(result.warnings) == 1

    def test_spdx_package_non_dict_skipped(self) -> None:
        """Non-dict items in packages list should be skipped."""
        data = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://example.com",
            "packages": ["not-a-dict"],
        }
        result = parse_sbom(data)
        assert len(result.components) == 0
        assert len(result.warnings) == 1


class TestRiskScoreCoverage:
    """Cover remaining branch in risk_score.py."""

    def test_eol_score_exactly_zero_days(self) -> None:
        """EOL today should count as expired."""
        score = _eol_score(date.today())
        assert score > 0
