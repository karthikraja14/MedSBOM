# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.cve_match — CVE and KEV vulnerability matching."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from medsbom.core.cve_match import CVEMatcher, CVEMatchError, _severity_from_score
from medsbom.core.models import Component

# ============================================================
# Positive cases
# ============================================================


class TestCVEMatcherPositive:
    """Positive path tests for CVE matching."""

    def test_parse_nvd_response_single_cve(self, mock_nvd_response: dict, tmp_path: Path) -> None:
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(mock_nvd_response)
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-99999"
        assert findings[0].cvss_score == 9.8
        assert findings[0].severity == "CRITICAL"
        assert "remote code execution" in findings[0].description.lower()

    def test_parse_nvd_response_empty(self, mock_nvd_empty_response: dict, tmp_path: Path) -> None:
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(mock_nvd_empty_response)
        assert len(findings) == 0

    def test_kev_lookup_build(self, mock_kev_response: dict) -> None:
        lookup = CVEMatcher._build_kev_lookup(mock_kev_response)
        assert "CVE-2024-99999" in lookup
        assert "CVE-2023-44487" in lookup
        assert lookup["CVE-2024-99999"]["vendorProject"] == "OpenSSL"

    def test_kev_flag_applied(
        self, mock_nvd_response: dict, mock_kev_response: dict, tmp_path: Path
    ) -> None:
        """KEV flag should be set when CVE is in KEV catalog."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        # Pre-load KEV data
        matcher._kev_data = CVEMatcher._build_kev_lookup(mock_kev_response)

        # Mock NVD call to return cached data
        with patch.object(matcher, "_query_nvd") as mock_nvd:
            mock_nvd.return_value = matcher._parse_nvd_response(mock_nvd_response)

            comp = Component(name="openssl", version="1.1.1w", purl="pkg:generic/openssl@1.1.1w")
            findings = matcher.match_component(comp)

            assert len(findings) == 1
            assert findings[0].kev_flag is True
            assert findings[0].kev_date_added == "2024-01-15"

    def test_match_components_batch(self, mock_nvd_empty_response: dict, tmp_path: Path) -> None:
        """Test batch matching of multiple components."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._kev_data = {}

        with patch.object(matcher, "_query_nvd") as mock_nvd:
            mock_nvd.return_value = []

            components = [
                Component(name="lib-a", version="1.0"),
                Component(name="lib-b", version="2.0"),
            ]
            results = matcher.match_components(components)

            assert len(results) == 2
            assert all(len(v) == 0 for v in results.values())

    def test_multiple_cves_per_component(self, tmp_path: Path) -> None:
        """Multiple CVEs should all be returned for one component."""
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "First vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "",
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [{"lang": "en", "value": "Second vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 4.3,
                                        "vectorString": "",
                                        "baseSeverity": "MEDIUM",
                                    }
                                }
                            ]
                        },
                    }
                },
            ]
        }
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(response)
        assert len(findings) == 2
        assert {f.cve_id for f in findings} == {"CVE-2024-0001", "CVE-2024-0002"}


# ============================================================
# Negative cases
# ============================================================


class TestCVEMatcherNegative:
    """Error handling tests."""

    def test_nvd_api_rate_limit(self, tmp_path: Path) -> None:
        """403 from NVD should raise descriptive error."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        mock_response = MagicMock()
        mock_response.status_code = 403

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "Forbidden", request=MagicMock(), response=mock_response
            )
            mock_client_cls.return_value = mock_client

            comp = Component(name="test", version="1.0")
            with pytest.raises(CVEMatchError, match="rate limit"):
                matcher._query_nvd(comp)

    def test_nvd_api_server_error(self, tmp_path: Path) -> None:
        """500 from NVD should raise CVEMatchError."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_response
            )
            mock_client_cls.return_value = mock_client

            comp = Component(name="test", version="1.0")
            with pytest.raises(CVEMatchError, match="NVD API error: 500"):
                matcher._query_nvd(comp)

    def test_nvd_api_network_error(self, tmp_path: Path) -> None:
        """Network failure should raise CVEMatchError."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            comp = Component(name="test", version="1.0")
            with pytest.raises(CVEMatchError, match="request failed"):
                matcher._query_nvd(comp)

    def test_kev_feed_failure_graceful(self, tmp_path: Path) -> None:
        """KEV feed failure should return empty dict, not crash."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            kev = matcher._get_kev_lookup()
            assert kev == {}

    def test_match_component_error_in_batch(self, tmp_path: Path) -> None:
        """One component failing shouldn't crash the whole batch."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._kev_data = {}

        call_count = 0

        def mock_query(comp: Component):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise CVEMatchError("Simulated failure")
            return []

        with patch.object(matcher, "_query_nvd", side_effect=mock_query):
            components = [
                Component(name="failing", version="1.0"),
                Component(name="working", version="2.0"),
            ]
            results = matcher.match_components(components)
            assert len(results) == 2
            # Failed component gets empty list
            assert results["failing@1.0"] == []


# ============================================================
# Edge cases
# ============================================================


class TestCVEMatcherEdgeCases:
    """Edge case tests."""

    def test_severity_from_score_critical(self) -> None:
        assert _severity_from_score(10.0) == "CRITICAL"
        assert _severity_from_score(9.0) == "CRITICAL"

    def test_severity_from_score_high(self) -> None:
        assert _severity_from_score(8.9) == "HIGH"
        assert _severity_from_score(7.0) == "HIGH"

    def test_severity_from_score_medium(self) -> None:
        assert _severity_from_score(6.9) == "MEDIUM"
        assert _severity_from_score(4.0) == "MEDIUM"

    def test_severity_from_score_low(self) -> None:
        assert _severity_from_score(3.9) == "LOW"
        assert _severity_from_score(0.1) == "LOW"

    def test_severity_from_score_none(self) -> None:
        assert _severity_from_score(0.0) == "NONE"

    def test_cache_write_and_read(self, tmp_path: Path) -> None:
        """Cache should persist and be read on next call."""
        cache_dir = tmp_path / "cache"
        matcher = CVEMatcher(cache_dir=cache_dir)

        test_data = {"vulnerabilities": [], "totalResults": 0}
        matcher._write_cache("test_key", test_data)

        cached = matcher._read_cache("test_key")
        assert cached is not None
        assert cached["totalResults"] == 0

    def test_cache_miss_returns_none(self, tmp_path: Path) -> None:
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        assert matcher._read_cache("nonexistent") is None

    def test_parse_nvd_missing_cve_id(self, tmp_path: Path) -> None:
        """CVE entry without ID should be skipped."""
        response = {
            "vulnerabilities": [
                {"cve": {"descriptions": [{"lang": "en", "value": "no id"}], "metrics": {}}}
            ]
        }
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(response)
        assert len(findings) == 0

    def test_description_truncation(self, tmp_path: Path) -> None:
        """Long descriptions should be truncated to 500 chars."""
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "A" * 1000}],
                        "metrics": {},
                    }
                }
            ]
        }
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(response)
        assert len(findings[0].description) == 500

    def test_component_no_version(self, tmp_path: Path) -> None:
        """Component with no version should still be queryable."""
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        matcher._kev_data = {}

        with patch.object(matcher, "_query_nvd", return_value=[]):
            comp = Component(name="test-lib", version="")
            findings = matcher.match_component(comp)
            assert findings == []

    def test_kev_empty_vulnerabilities(self) -> None:
        """KEV feed with no vulnerabilities should return empty lookup."""
        lookup = CVEMatcher._build_kev_lookup({"vulnerabilities": []})
        assert lookup == {}

    def test_cvss_v2_fallback(self, tmp_path: Path) -> None:
        """Should fall back to CVSS v2 if v3 not available."""
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-0001",
                        "descriptions": [{"lang": "en", "value": "Old vuln"}],
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "cvssData": {
                                        "baseScore": 6.5,
                                        "vectorString": "AV:N/AC:L/Au:S/C:P/I:P/A:P",
                                    },
                                    "baseSeverity": "MEDIUM",
                                }
                            ]
                        },
                    }
                }
            ]
        }
        matcher = CVEMatcher(cache_dir=tmp_path / "cache")
        findings = matcher._parse_nvd_response(response)
        assert findings[0].cvss_score == 6.5
