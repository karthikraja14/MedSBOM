# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Document generator — Jinja2 templates to FDA/IEC-62304 formatted output."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from medsbom.core.models import REGULATORY_DISCLAIMER, ComponentResult, RiskLevel, SBOMScan

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class DocGeneratorError(Exception):
    """Raised when document generation fails."""


class DocGenerator:
    """Generate regulatory documents from scan results."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        tpl_dir = templates_dir or TEMPLATES_DIR
        if not tpl_dir.exists():
            raise DocGeneratorError(f"Templates directory not found: {tpl_dir}")
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=select_autoescape(default_for_string=False, default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.globals["disclaimer"] = REGULATORY_DISCLAIMER
        self._env.globals["now"] = lambda: datetime.now(UTC)

    def generate_fda_summary(self, scan: SBOMScan, **extra: Any) -> str:
        """Generate FDA Premarket Cybersecurity Summary (Markdown)."""
        template = self._env.get_template("fda_premarket_summary.md.j2")
        return template.render(scan=scan, risk_summary=_risk_summary(scan.results), **extra)

    def generate_soup_assessment(self, scan: SBOMScan, **extra: Any) -> str:
        """Generate IEC 62304 SOUP Risk Assessment table (Markdown)."""
        template = self._env.get_template("soup_risk_assessment.md.j2")
        return template.render(scan=scan, **extra)

    def generate_vuln_review_log(self, scan: SBOMScan, **extra: Any) -> str:
        """Generate Vulnerability Review Log (Markdown)."""
        template = self._env.get_template("vulnerability_review_log.md.j2")
        return template.render(scan=scan, **extra)

    def generate_full_bundle(self, scan: SBOMScan, output_dir: Path, **extra: Any) -> list[Path]:
        """Generate all documents and write to output directory.

        Returns list of generated file paths.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        docs = [
            ("fda_premarket_summary.md", self.generate_fda_summary),
            ("soup_risk_assessment.md", self.generate_soup_assessment),
            ("vulnerability_review_log.md", self.generate_vuln_review_log),
        ]

        for filename, generator in docs:
            content = generator(scan, **extra)
            path = output_dir / filename
            path.write_text(content, encoding="utf-8")
            generated.append(path)
            logger.info("Generated: %s", path)

        return generated


def _risk_summary(results: list[ComponentResult]) -> dict[str, int]:
    """Count components at each risk level."""
    counts: dict[str, int] = {level.value: 0 for level in RiskLevel}
    for r in results:
        counts[r.overall_risk.value] += 1
    return counts
