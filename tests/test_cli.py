# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.cli.main — CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from medsbom.cli.main import app

runner = CliRunner()


# ============================================================
# Positive cases
# ============================================================


class TestCLIPositive:
    """Positive path tests for CLI commands."""

    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "MedSBOM" in result.stdout

    def test_ingest_cyclonedx(self, sample_cyclonedx_path: Path) -> None:
        result = runner.invoke(app, ["ingest", str(sample_cyclonedx_path)])
        assert result.exit_code == 0
        assert "Parsed" in result.stdout
        assert "CYCLONEDX" in result.stdout
        assert "8" in result.stdout  # 8 components

    def test_ingest_spdx(self, sample_spdx_path: Path) -> None:
        result = runner.invoke(app, ["ingest", str(sample_spdx_path)])
        assert result.exit_code == 0
        assert "SPDX" in result.stdout
        assert "5" in result.stdout  # 5 components

    def test_help_text(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "FDA" in result.stdout or "compliance" in result.stdout.lower()

    def test_ingest_shows_components(self, sample_cyclonedx_path: Path) -> None:
        result = runner.invoke(app, ["ingest", str(sample_cyclonedx_path)])
        assert "openssl" in result.stdout
        assert "zlib" in result.stdout


# ============================================================
# Negative cases
# ============================================================


class TestCLINegative:
    """Error handling tests for CLI commands."""

    def test_ingest_file_not_found(self) -> None:
        result = runner.invoke(app, ["ingest", "/nonexistent/file.json"])
        assert result.exit_code == 1
        assert (
            "not found" in result.stdout.lower()
            or "error" in result.stdout.lower()
            or result.exit_code != 0
        )

    def test_ingest_invalid_json(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all!!!")
        result = runner.invoke(app, ["ingest", str(bad_file)])
        assert result.exit_code == 1

    def test_check_file_not_found(self) -> None:
        result = runner.invoke(app, ["check", "/nonexistent/file.json"])
        assert result.exit_code == 1

    def test_report_file_not_found(self) -> None:
        result = runner.invoke(app, ["report", "/nonexistent/file.json"])
        assert result.exit_code == 1

    def test_no_args(self) -> None:
        """Running medsbom with no args should show help."""
        result = runner.invoke(app, [])
        # typer's no_args_is_help returns exit code 0 or 2 depending on version
        assert result.exit_code in (0, 2)
        assert (
            "Usage" in result.stdout
            or "MedSBOM" in result.stdout
            or "medsbom" in result.stdout.lower()
        )


# ============================================================
# Edge cases
# ============================================================


class TestCLIEdgeCases:
    """Edge case tests for CLI."""

    def test_ingest_empty_sbom(self, tmp_path: Path) -> None:
        """SBOM with no components should parse but show 0."""
        empty = tmp_path / "empty.json"
        empty.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [],
                }
            )
        )
        result = runner.invoke(app, ["ingest", str(empty)])
        assert result.exit_code == 0
        assert "0" in result.stdout

    def test_verbose_flag(self, sample_cyclonedx_path: Path) -> None:
        result = runner.invoke(app, ["-v", "ingest", str(sample_cyclonedx_path)])
        assert result.exit_code == 0

    def test_audit_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Audit command on empty DB should work gracefully."""
        monkeypatch.setattr("medsbom.core.audit.DEFAULT_DB_PATH", tmp_path / "audit.db")
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0
