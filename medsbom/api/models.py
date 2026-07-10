# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""API request/response schemas."""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, Field

from medsbom.core.models import RiskLevel


class UploadSBOMRequest(BaseModel):
    """Request body for SBOM upload."""

    device_name: str = "Unknown Device"
    device_version: str = "1.0"
    sbom_json: dict = Field(..., description="Raw SBOM JSON (CycloneDX or SPDX)")


class ComponentResponse(BaseModel):
    name: str
    version: str
    purl: str = ""
    license: str = ""
    risk_level: RiskLevel = RiskLevel.NONE
    cve_count: int = 0
    has_kev: bool = False
    is_eol: bool = False
    eol_date: date | None = None


class ScanSummaryResponse(BaseModel):
    scan_id: str
    device_name: str
    device_version: str
    timestamp: datetime
    sbom_format: str
    total_components: int
    risk_summary: dict[str, int]
    components: list[ComponentResponse]


class ReportResponse(BaseModel):
    scan_id: str
    format: str
    content: str
    generated_at: datetime


class AuditEntryResponse(BaseModel):
    entry_id: str
    scan_id: str
    action: str
    timestamp: datetime
    actor: str
    details: str


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
