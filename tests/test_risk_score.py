# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for medsbom.core.risk_score — Risk scoring engine."""

from __future__ import annotations

from datetime import date, timedelta

from medsbom.core.models import ComponentResult, Finding, RiskLevel
from medsbom.core.risk_score import (
    classify_risk,
    risk_summary,
    score_component,
    score_finding,
    score_scan_results,
)

# ============================================================
# Positive cases
# ============================================================


class TestScoreFinding:
    """Tests for individual finding scoring."""

    def test_critical_cvss(self) -> None:
        """CVSS 9.8 finding should score high."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=9.8, severity="CRITICAL")
        score = score_finding(finding)
        assert score >= 4.0  # CVSS weight alone: 9.8 * 0.5 = 4.9

    def test_kev_elevates_score(self) -> None:
        """KEV flag should increase the score."""
        finding_no_kev = Finding(cve_id="CVE-2024-0001", cvss_score=7.0)
        finding_with_kev = Finding(cve_id="CVE-2024-0001", cvss_score=7.0, kev_flag=True)

        score_no_kev = score_finding(finding_no_kev)
        score_with_kev = score_finding(finding_with_kev)

        assert score_with_kev > score_no_kev

    def test_eol_elevates_score(self) -> None:
        """Past EOL date should increase the score."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=5.0)
        past_eol = date.today() - timedelta(days=30)

        score_no_eol = score_finding(finding)
        score_with_eol = score_finding(finding, eol_date=past_eol)

        assert score_with_eol > score_no_eol

    def test_max_score_capped_at_10(self) -> None:
        """Score should never exceed 10.0."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=10.0, kev_flag=True)
        past_eol = date.today() - timedelta(days=365)

        score = score_finding(finding, eol_date=past_eol)
        assert score <= 10.0


class TestClassifyRisk:
    """Tests for risk level classification."""

    def test_critical_threshold(self) -> None:
        assert classify_risk(8.5) == RiskLevel.CRITICAL
        assert classify_risk(10.0) == RiskLevel.CRITICAL

    def test_high_threshold(self) -> None:
        assert classify_risk(6.0) == RiskLevel.HIGH
        assert classify_risk(8.4) == RiskLevel.HIGH

    def test_medium_threshold(self) -> None:
        assert classify_risk(3.5) == RiskLevel.MEDIUM
        assert classify_risk(5.9) == RiskLevel.MEDIUM

    def test_low_threshold(self) -> None:
        assert classify_risk(0.1) == RiskLevel.LOW
        assert classify_risk(3.4) == RiskLevel.LOW

    def test_none_threshold(self) -> None:
        assert classify_risk(0.0) == RiskLevel.NONE
        assert classify_risk(0.09) == RiskLevel.NONE


class TestScoreComponent:
    """Tests for component-level scoring."""

    def test_component_with_critical_finding(self, sample_finding_critical: Finding) -> None:
        risk_level, score = score_component([sample_finding_critical])
        # CVSS 9.8 * 0.5 = 4.9, plus KEV bonus 3.0 * 0.3 = 0.9 → 5.8 → HIGH
        assert risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
        assert score > 0.0

    def test_component_with_medium_finding(self, sample_finding_medium: Finding) -> None:
        risk_level, score = score_component([sample_finding_medium])
        assert risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW)

    def test_component_with_multiple_findings(
        self,
        sample_finding_critical: Finding,
        sample_finding_low: Finding,
    ) -> None:
        """Should use maximum score across findings."""
        risk_level, score = score_component([sample_finding_critical, sample_finding_low])
        single_level, single_score = score_component([sample_finding_critical])
        assert score == single_score  # Max should be the critical one

    def test_component_eol_only(self) -> None:
        """Component with only EOL risk (no CVEs) should still get a risk level."""
        past_eol = date.today() - timedelta(days=30)
        risk_level, score = score_component([], eol_date=past_eol)
        assert score > 0.0
        assert risk_level != RiskLevel.NONE


# ============================================================
# Negative cases
# ============================================================


class TestScoreComponentNegative:
    """Negative tests for scoring."""

    def test_no_findings_no_eol(self) -> None:
        """No findings and no EOL should return NONE."""
        risk_level, score = score_component([])
        assert risk_level == RiskLevel.NONE
        assert score == 0.0

    def test_empty_results_scan(self) -> None:
        """Empty scan results should return NONE."""
        assert score_scan_results([]) == RiskLevel.NONE


# ============================================================
# Edge cases
# ============================================================


class TestScoreEdgeCases:
    """Edge case tests."""

    def test_cvss_zero(self) -> None:
        """CVSS 0.0 with no flags should score zero."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=0.0)
        score = score_finding(finding)
        assert score == 0.0

    def test_cvss_exactly_10(self) -> None:
        """CVSS 10.0 should still be within bounds."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=10.0)
        score = score_finding(finding)
        assert 0.0 <= score <= 10.0

    def test_eol_far_future(self) -> None:
        """EOL date far in the future should add no risk."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=5.0)
        future_eol = date.today() + timedelta(days=1000)

        score_no_eol = score_finding(finding)
        score_future_eol = score_finding(finding, eol_date=future_eol)

        assert score_no_eol == score_future_eol

    def test_eol_within_6_months(self) -> None:
        """EOL within 6 months should add some risk."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=5.0)
        soon_eol = date.today() + timedelta(days=90)  # 3 months

        score_no_eol = score_finding(finding)
        score_soon_eol = score_finding(finding, eol_date=soon_eol)

        assert score_soon_eol > score_no_eol

    def test_eol_within_12_months(self) -> None:
        """EOL within 12 months should add some risk."""
        finding = Finding(cve_id="CVE-2024-0001", cvss_score=5.0)
        approaching_eol = date.today() + timedelta(days=300)  # ~10 months

        score_no_eol = score_finding(finding)
        score_approaching = score_finding(finding, eol_date=approaching_eol)

        assert score_approaching > score_no_eol

    def test_risk_summary_counts(self) -> None:
        """Risk summary should correctly count each level."""
        from medsbom.core.models import Component

        dummy = Component(name="test", version="1.0")
        results = [
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.CRITICAL),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.CRITICAL),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.LOW),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.NONE),
        ]
        summary = risk_summary(results)
        assert summary["critical"] == 2
        assert summary["low"] == 1
        assert summary["none"] == 1
        assert summary["high"] == 0
        assert summary["medium"] == 0

    def test_scan_results_returns_highest(self) -> None:
        """Overall scan risk should be the highest among all components."""
        from medsbom.core.models import Component

        dummy = Component(name="test", version="1.0")

        results = [
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.LOW),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.HIGH),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.MEDIUM),
        ]
        assert score_scan_results(results) == RiskLevel.HIGH

    def test_all_none_scan(self) -> None:
        """Scan with all NONE components should return NONE."""
        from medsbom.core.models import Component

        dummy = Component(name="test", version="1.0")

        results = [
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.NONE),
            ComponentResult(component=dummy, findings=[], overall_risk=RiskLevel.NONE),
        ]
        assert score_scan_results(results) == RiskLevel.NONE
