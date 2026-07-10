# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Extended tests for CLI check/report commands and full code coverage."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from medsbom.cli.main import _display_check_results, _try_load_scan_result, app
from medsbom.core.models import (
    Component,
    ComponentResult,
    Finding,
    RiskLevel,
    SBOMFormat,
    SBOMScan,
)

runner = CliRunner()


@pytest.fixture
def mock_no_network():
    """Mock all network calls to return empty results."""
    with (
        patch("medsbom.cli.main.CVEMatcher") as mock_cve,
        patch("medsbom.cli.main.EOLChecker") as mock_eol,
    ):
        matcher_instance = MagicMock()
        matcher_instance.match_component.return_value = []
        mock_cve.return_value = matcher_instance

        checker_instance = MagicMock()
        checker_instance.check_component.return_value = MagicMock(eol_date=None, is_eol=False)
        mock_eol.return_value = checker_instance

        yield mock_cve, mock_eol


@pytest.fixture
def mock_network_with_findings():
    """Mock network calls to return findings."""
    with (
        patch("medsbom.cli.main.CVEMatcher") as mock_cve,
        patch("medsbom.cli.main.EOLChecker") as mock_eol,
    ):
        matcher_instance = MagicMock()
        matcher_instance.match_component.return_value = [
            Finding(
                cve_id="CVE-2024-0001",
                cvss_score=9.8,
                severity="CRITICAL",
                kev_flag=True,
                description="Test vulnerability",
                source="NVD",
            )
        ]
        mock_cve.return_value = matcher_instance

        checker_instance = MagicMock()
        checker_instance.check_component.return_value = MagicMock(
            eol_date=date(2024, 1, 1), is_eol=True
        )
        mock_eol.return_value = checker_instance

        yield mock_cve, mock_eol


class TestCLICheckCommand:
    """Tests for the 'check' command."""

    def test_check_basic(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "check",
                str(sample_cyclonedx_path),
                "--device",
                "Test Device",
                "--device-version",
                "1.0",
            ],
        )
        assert result.exit_code == 0
        assert "Risk Summary" in result.stdout

    def test_check_with_output_json(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        output = tmp_path / "results.json"
        result = runner.invoke(
            app,
            [
                "check",
                str(sample_cyclonedx_path),
                "--output",
                str(output),
            ],
        )
        assert result.exit_code == 0
        assert output.exists()
        data = json.loads(output.read_text())
        assert "scan_id" in data
        assert "results" in data

    def test_check_with_findings(
        self, sample_cyclonedx_path: Path, mock_network_with_findings
    ) -> None:
        result = runner.invoke(
            app,
            ["check", str(sample_cyclonedx_path), "--device", "Pump"],
        )
        assert result.exit_code == 0
        assert "CRITICAL" in result.stdout or "HIGH" in result.stdout

    def test_check_file_not_found(self) -> None:
        result = runner.invoke(app, ["check", "/no/such/file.json"])
        assert result.exit_code == 1

    def test_check_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{{invalid}}")
        result = runner.invoke(app, ["check", str(bad)])
        assert result.exit_code == 1


class TestCLIReportCommand:
    """Tests for the 'report' command."""

    def test_report_all_formats(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "reports"
        result = runner.invoke(
            app,
            [
                "report",
                str(sample_cyclonedx_path),
                "--format",
                "all",
                "--output",
                str(output_dir),
                "--device",
                "Test Pump",
            ],
        )
        assert result.exit_code == 0
        assert "Generated 3 document" in result.stdout
        assert (output_dir / "fda_premarket_summary.md").exists()
        assert (output_dir / "soup_risk_assessment.md").exists()
        assert (output_dir / "vulnerability_review_log.md").exists()

    def test_report_fda_only(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "reports"
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
        assert "Generated 1 document" in result.stdout

    def test_report_soup_only(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "reports"
        result = runner.invoke(
            app,
            [
                "report",
                str(sample_cyclonedx_path),
                "--format",
                "soup",
                "--output",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0
        assert (output_dir / "soup_risk_assessment.md").exists()

    def test_report_vuln_only(
        self, sample_cyclonedx_path: Path, mock_no_network, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "reports"
        result = runner.invoke(
            app,
            [
                "report",
                str(sample_cyclonedx_path),
                "--format",
                "vuln",
                "--output",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0
        assert (output_dir / "vulnerability_review_log.md").exists()

    def test_report_from_precomputed_results(self, tmp_path: Path, mock_no_network) -> None:
        """Should load pre-computed scan results JSON and generate reports."""
        scan = SBOMScan(
            scan_id="precomputed-001",
            device_name="Pre Device",
            device_version="2.0",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
            sbom_format=SBOMFormat.CYCLONEDX,
            components=[Component(name="lib-x", version="1.0")],
            results=[
                ComponentResult(
                    component=Component(name="lib-x", version="1.0"),
                    findings=[],
                    overall_risk=RiskLevel.NONE,
                )
            ],
        )
        result_file = tmp_path / "scan_result.json"
        result_file.write_text(scan.model_dump_json(indent=2))

        output_dir = tmp_path / "reports"
        result = runner.invoke(
            app,
            [
                "report",
                str(result_file),
                "--format",
                "fda",
                "--output",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0

    def test_report_file_not_found(self) -> None:
        result = runner.invoke(app, ["report", "/no/such/file.json"])
        assert result.exit_code == 1

    def test_report_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("invalid!")
        result = runner.invoke(app, ["report", str(bad), "--format", "fda"])
        assert result.exit_code == 1


class TestCLIAuditCommand:
    """Tests for the 'audit' command."""

    def test_audit_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("medsbom.core.audit.DEFAULT_DB_PATH", tmp_path / "a.db")
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0

    def test_audit_with_entries(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db_path = tmp_path / "audit.db"
        monkeypatch.setattr("medsbom.core.audit.DEFAULT_DB_PATH", db_path)

        # Seed some audit entries
        from medsbom.core.audit import AuditTrail

        trail = AuditTrail(db_path=db_path)
        trail.log("scan-001", "check", details="Test")
        trail.log("scan-001", "report", details="Generated")

        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0
        assert "check" in result.stdout
        assert "report" in result.stdout

    def test_audit_filter_by_scan_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db_path = tmp_path / "audit.db"
        monkeypatch.setattr("medsbom.core.audit.DEFAULT_DB_PATH", db_path)

        from medsbom.core.audit import AuditTrail

        trail = AuditTrail(db_path=db_path)
        trail.log("scan-001", "check")
        trail.log("scan-002", "check")

        result = runner.invoke(app, ["audit", "scan-001"])
        assert result.exit_code == 0


class TestCLIHelpers:
    """Tests for CLI helper functions."""

    def test_try_load_scan_result_valid(self, tmp_path: Path) -> None:
        scan = SBOMScan(
            scan_id="test-001",
            device_name="Dev",
            device_version="1.0",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            sbom_format=SBOMFormat.CYCLONEDX,
            results=[],
        )
        f = tmp_path / "scan.json"
        f.write_text(scan.model_dump_json())
        loaded = _try_load_scan_result(f)
        assert loaded is not None
        assert loaded.scan_id == "test-001"

    def test_try_load_scan_result_invalid_json(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json")
        assert _try_load_scan_result(f) is None

    def test_try_load_scan_result_not_scan(self, tmp_path: Path) -> None:
        f = tmp_path / "other.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        assert _try_load_scan_result(f) is None

    def test_display_check_results(self, capsys) -> None:
        """_display_check_results should render without crashing."""
        scan = SBOMScan(
            scan_id="display-test",
            device_name="Dev",
            device_version="1.0",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            sbom_format=SBOMFormat.CYCLONEDX,
            results=[
                ComponentResult(
                    component=Component(name="openssl", version="1.1.1"),
                    findings=[
                        Finding(
                            cve_id="CVE-2024-0001",
                            cvss_score=9.8,
                            severity="CRITICAL",
                            kev_flag=True,
                        )
                    ],
                    overall_risk=RiskLevel.CRITICAL,
                    is_eol=True,
                    eol_date=date(2024, 1, 1),
                ),
                ComponentResult(
                    component=Component(name="safe-lib", version="2.0"),
                    findings=[],
                    overall_risk=RiskLevel.NONE,
                ),
            ],
        )
        # Should not raise
        _display_check_results(scan)
