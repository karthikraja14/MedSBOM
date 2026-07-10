# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.eol_check — End-of-life status checking."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

import httpx

from medsbom.core.eol_check import (
    PRODUCT_SLUG_MAP,
    EOLChecker,
    EOLResult,
    _extract_cycle,
    _parse_date_field,
)
from medsbom.core.models import Component

# ============================================================
# Positive cases
# ============================================================


class TestEOLCheckerPositive:
    """Positive path tests for EOL checking."""

    def test_resolve_known_slug(self) -> None:
        checker = EOLChecker()
        assert checker._resolve_slug("python") == "python"
        assert checker._resolve_slug("Python") == "python"
        assert checker._resolve_slug("nodejs") == "nodejs"
        assert checker._resolve_slug("PostgreSQL") == "postgresql"

    def test_resolve_slug_with_namespace(self) -> None:
        """Should handle namespaced names like 'org.postgresql:postgresql'."""
        checker = EOLChecker()
        assert checker._resolve_slug("org.postgresql:postgresql") == "postgresql"

    def test_check_component_with_mock(self, mock_eol_cycle_response: dict) -> None:
        """Should return correct EOL data for a known product."""
        checker = EOLChecker()

        with patch.object(checker, "_query_eol_api") as mock_query:
            mock_query.return_value = EOLResult(
                product="python",
                version="3.10.14",
                eol_date=date(2026, 10, 4),
                is_eol=False,
                latest_version="3.10.14",
                lts=False,
                matched=True,
            )

            comp = Component(name="python", version="3.10.14")
            result = checker.check_component(comp)

            assert result.matched is True
            assert result.eol_date == date(2026, 10, 4)
            assert result.is_eol is False

    def test_parse_cycle_response(self, mock_eol_cycle_response: dict) -> None:
        checker = EOLChecker()
        result = checker._parse_cycle_response("python", "3.10.14", mock_eol_cycle_response)
        assert result.matched is True
        assert result.eol_date == date(2026, 10, 4)
        assert result.latest_version == "3.10.14"

    def test_check_components_batch(self) -> None:
        checker = EOLChecker()

        with patch.object(checker, "check_component") as mock_check:
            mock_check.return_value = EOLResult(product="test", version="1.0", matched=False)

            components = [
                Component(name="lib-a", version="1.0"),
                Component(name="lib-b", version="2.0"),
            ]
            results = checker.check_components(components)
            assert len(results) == 2

    def test_product_still_supported(self, mock_eol_cycle_response: dict) -> None:
        """Product with future EOL date should not be marked as EOL."""
        # Modify to have future EOL
        mock_eol_cycle_response["eol"] = "2030-01-01"
        checker = EOLChecker()
        result = checker._parse_cycle_response("python", "3.10.14", mock_eol_cycle_response)
        assert result.is_eol is False


# ============================================================
# Negative cases
# ============================================================


class TestEOLCheckerNegative:
    """Error handling tests."""

    def test_unknown_product(self) -> None:
        """Unknown product should return unmatched result."""
        checker = EOLChecker()
        comp = Component(name="totally-unknown-product-xyz", version="1.0")
        result = checker.check_component(comp)
        assert result.matched is False

    def test_api_unavailable(self) -> None:
        """API failure should return unmatched result, not crash."""
        checker = EOLChecker()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            comp = Component(name="python", version="3.10.14")
            result = checker.check_component(comp)
            assert result.matched is False

    def test_api_404_product(self) -> None:
        """404 for a product should return unmatched result."""
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


# ============================================================
# Edge cases
# ============================================================


class TestEOLCheckerEdgeCases:
    """Edge case tests."""

    def test_extract_cycle_major_minor(self) -> None:
        assert _extract_cycle("3.10.14") == "3.10"
        assert _extract_cycle("18.20.3") == "18.20"

    def test_extract_cycle_major_only(self) -> None:
        assert _extract_cycle("3") == "3"

    def test_extract_cycle_complex_version(self) -> None:
        assert _extract_cycle("1.2.3.4.5") == "1.2"

    def test_extract_cycle_non_numeric(self) -> None:
        assert _extract_cycle("latest") == "latest"

    def test_parse_date_field_valid(self) -> None:
        assert _parse_date_field("2026-10-04") == date(2026, 10, 4)

    def test_parse_date_field_boolean(self) -> None:
        assert _parse_date_field(True) is None
        assert _parse_date_field(False) is None

    def test_parse_date_field_invalid(self) -> None:
        assert _parse_date_field("not-a-date") is None

    def test_parse_date_field_none(self) -> None:
        assert _parse_date_field(None) is None

    def test_eol_date_in_past(self) -> None:
        """Component with past EOL date should be marked as EOL."""
        checker = EOLChecker()
        data = {
            "cycle": "3.8",
            "eol": "2024-10-14",
            "latest": "3.8.20",
            "lts": False,
            "support": "2021-05-03",
            "releaseDate": "2019-10-14",
        }
        result = checker._parse_cycle_response("python", "3.8.20", data)
        assert result.is_eol is True
        assert result.eol_date == date(2024, 10, 14)

    def test_eol_boolean_true(self) -> None:
        """eol=True (no date) should mark as EOL."""
        checker = EOLChecker()
        data = {"cycle": "1.0", "eol": True, "latest": "1.0.99"}
        result = checker._parse_cycle_response("test", "1.0.0", data)
        assert result.is_eol is True
        assert result.eol_date is None

    def test_product_slug_map_coverage(self) -> None:
        """Verify key products are mapped."""
        expected = ["python", "nodejs", "openssl", "django", "postgresql", "ubuntu", "debian"]
        for product in expected:
            assert product in PRODUCT_SLUG_MAP.values(), f"{product} not in slug map"

    def test_find_best_match_empty_cycles(self) -> None:
        """Empty cycle list should return unmatched."""
        checker = EOLChecker()
        result = checker._find_best_match("test", "1.0", [])
        assert result.matched is False

    def test_find_best_match_no_match(self) -> None:
        """No matching cycle should return unmatched."""
        checker = EOLChecker()
        cycles = [
            {"cycle": "2.0", "eol": "2030-01-01", "latest": "2.0.1"},
            {"cycle": "3.0", "eol": "2031-01-01", "latest": "3.0.1"},
        ]
        result = checker._find_best_match("test", "1.0", cycles)
        assert result.matched is False
