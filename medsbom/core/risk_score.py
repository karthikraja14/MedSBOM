# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""Risk scoring engine — combines CVSS, KEV, and EOL data into a composite risk level."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

from medsbom.core.models import ComponentResult, Finding, RiskLevel

# --- Weighting factors (documented for auditability) ---
# These can be overridden via config in the future.

CVSS_WEIGHT = 0.5  # Base vulnerability severity
KEV_WEIGHT = 0.3  # Actively exploited bonus
EOL_WEIGHT = 0.2  # End-of-life proximity

KEV_BONUS = 3.0  # Points added if on CISA KEV list
EOL_EXPIRED_BONUS = 2.5  # Points added if already past EOL
EOL_SOON_BONUS = 1.5  # Points added if EOL within 6 months
EOL_APPROACHING_BONUS = 0.5  # Points added if EOL within 12 months

# Risk level thresholds (on a 0-10 scale)
CRITICAL_THRESHOLD = 8.5
HIGH_THRESHOLD = 6.0
MEDIUM_THRESHOLD = 3.5
LOW_THRESHOLD = 0.1


def score_finding(finding: Finding, eol_date: date | None = None) -> float:
    """Score a single finding on a 0–10 scale.

    Args:
        finding: The vulnerability finding.
        eol_date: Optional EOL date for the component.

    Returns:
        Composite risk score (0.0–10.0).
    """
    # CVSS component (0-10 already)
    cvss_component = finding.cvss_score * CVSS_WEIGHT

    # KEV component
    kev_component = (KEV_BONUS if finding.kev_flag else 0.0) * KEV_WEIGHT

    # EOL component
    eol_component = _eol_score(eol_date) * EOL_WEIGHT

    raw = cvss_component + kev_component + eol_component
    return min(raw, 10.0)


def classify_risk(score: float) -> RiskLevel:
    """Map a numeric score to a risk level."""
    if score >= CRITICAL_THRESHOLD:
        return RiskLevel.CRITICAL
    if score >= HIGH_THRESHOLD:
        return RiskLevel.HIGH
    if score >= MEDIUM_THRESHOLD:
        return RiskLevel.MEDIUM
    if score >= LOW_THRESHOLD:
        return RiskLevel.LOW
    return RiskLevel.NONE


def score_component(
    findings: Sequence[Finding],
    eol_date: date | None = None,
) -> tuple[RiskLevel, float]:
    """Compute the overall risk level for a component.

    Takes the maximum score across all findings. If there are no findings,
    still checks EOL status.

    Returns:
        Tuple of (risk_level, max_score).
    """
    if not findings and eol_date is None:
        return RiskLevel.NONE, 0.0

    scores = [score_finding(f, eol_date) for f in findings]

    # Even with no CVE findings, EOL status alone can create risk
    if not scores:
        eol_only_score = _eol_score(eol_date)
        return classify_risk(eol_only_score), eol_only_score

    max_score = max(scores)
    return classify_risk(max_score), max_score


def score_scan_results(results: list[ComponentResult]) -> RiskLevel:
    """Compute the overall risk level for an entire scan.

    Returns the highest risk across all components.
    """
    if not results:
        return RiskLevel.NONE

    levels = [r.overall_risk for r in results]
    risk_order = [
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.NONE,
    ]
    for level in risk_order:
        if level in levels:
            return level
    return RiskLevel.NONE


def risk_summary(results: list[ComponentResult]) -> dict[str, int]:
    """Count components at each risk level."""
    counts: dict[str, int] = {level.value: 0 for level in RiskLevel}
    for r in results:
        counts[r.overall_risk.value] += 1
    return counts


def _eol_score(eol_date: date | None) -> float:
    """Compute EOL risk score (0-10 scale) based on proximity to today."""
    if eol_date is None:
        return 0.0

    days_until = (eol_date - date.today()).days

    if days_until <= 0:
        return EOL_EXPIRED_BONUS / EOL_WEIGHT  # Already past EOL
    if days_until <= 180:
        return EOL_SOON_BONUS / EOL_WEIGHT  # Within 6 months
    if days_until <= 365:
        return EOL_APPROACHING_BONUS / EOL_WEIGHT  # Within 12 months
    return 0.0
