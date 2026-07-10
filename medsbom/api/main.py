# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""FastAPI application for MedSBOM web API and dashboard."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException

from medsbom import __version__
from medsbom.api.models import (
    AuditEntryResponse,
    ComponentResponse,
    HealthResponse,
    ReportResponse,
    ScanSummaryResponse,
    UploadSBOMRequest,
)
from medsbom.core.audit import AuditTrail
from medsbom.core.cve_match import CVEMatcher
from medsbom.core.doc_generator import DocGenerator
from medsbom.core.eol_check import EOLChecker
from medsbom.core.ingest import IngestError, parse_sbom
from medsbom.core.models import ComponentResult, SBOMScan
from medsbom.core.risk_score import classify_risk, risk_summary, score_component

app = FastAPI(
    title="MedSBOM API",
    description="Open-source FDA/IEC-62304 compliance layer for medical device SBOMs",
    version=__version__,
    license_info={"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
)

# In-memory store for MVP (replace with DB for production)
_scans: dict[str, SBOMScan] = {}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="ok", version=__version__)


@app.post("/api/v1/scans", response_model=ScanSummaryResponse)
def create_scan(req: UploadSBOMRequest) -> ScanSummaryResponse:
    """Upload an SBOM and run vulnerability + EOL checks."""
    # Guard against excessively large uploads (DoS prevention)
    sbom_str = json.dumps(req.sbom_json)
    if len(sbom_str) > 50_000_000:  # 50MB limit
        raise HTTPException(status_code=413, detail="SBOM payload too large (max 50MB)")

    try:
        ingest_result = parse_sbom(req.sbom_json)
    except IngestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    cve_matcher = CVEMatcher()
    eol_checker = EOLChecker()

    scan_id = str(uuid.uuid4())
    results: list[ComponentResult] = []

    for comp in ingest_result.components:
        findings = cve_matcher.match_component(comp)
        eol_result = eol_checker.check_component(comp)
        risk_level, _ = score_component(findings, eol_result.eol_date)

        for f in findings:
            f.risk_level = classify_risk(f.cvss_score + (3.0 if f.kev_flag else 0.0))

        results.append(
            ComponentResult(
                component=comp,
                findings=findings,
                overall_risk=risk_level,
                eol_date=eol_result.eol_date,
                is_eol=eol_result.is_eol,
            )
        )

    scan = SBOMScan(
        scan_id=scan_id,
        device_name=req.device_name,
        device_version=req.device_version,
        timestamp=datetime.now(UTC),
        sbom_format=ingest_result.sbom_format,
        source_tool=ingest_result.source_tool,
        components=[r.component for r in results],
        results=results,
        raw_sbom=req.sbom_json,
    )

    _scans[scan_id] = scan

    # Audit
    try:
        audit = AuditTrail()
        audit.log(scan_id, "api_scan", actor="api", details=f"{len(results)} components")
    except Exception:  # noqa: S110
        logging.getLogger(__name__).debug("Audit logging failed", exc_info=True)

    return _scan_to_response(scan)


@app.get("/api/v1/scans/{scan_id}", response_model=ScanSummaryResponse)
def get_scan(scan_id: str) -> ScanSummaryResponse:
    """Retrieve a scan result by ID."""
    scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _scan_to_response(scan)


@app.get("/api/v1/scans/{scan_id}/report/{report_format}", response_model=ReportResponse)
def generate_report(scan_id: str, report_format: str) -> ReportResponse:
    """Generate a compliance report for a scan."""
    scan = _scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    doc_gen = DocGenerator()

    generators = {
        "fda": doc_gen.generate_fda_summary,
        "soup": doc_gen.generate_soup_assessment,
        "vuln": doc_gen.generate_vuln_review_log,
    }

    if report_format not in generators:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{report_format}'. Choose from: {', '.join(generators)}",
        )

    content = generators[report_format](scan)

    return ReportResponse(
        scan_id=scan_id,
        format=report_format,
        content=content,
        generated_at=datetime.now(UTC),
    )


@app.get("/api/v1/audit", response_model=list[AuditEntryResponse])
def list_audit(scan_id: str | None = None, limit: int = 50) -> list[AuditEntryResponse]:
    """List audit trail entries."""
    audit = AuditTrail()
    entries = audit.get_entries(scan_id=scan_id, limit=min(limit, 200))
    return [
        AuditEntryResponse(
            entry_id=e.entry_id,
            scan_id=e.scan_id,
            action=e.action,
            timestamp=e.timestamp,
            actor=e.actor,
            details=e.details,
        )
        for e in entries
    ]


def _scan_to_response(scan: SBOMScan) -> ScanSummaryResponse:
    """Convert internal scan model to API response."""
    summary = risk_summary(scan.results)
    return ScanSummaryResponse(
        scan_id=scan.scan_id,
        device_name=scan.device_name,
        device_version=scan.device_version,
        timestamp=scan.timestamp,
        sbom_format=scan.sbom_format.value,
        total_components=len(scan.components),
        risk_summary=summary,
        components=[
            ComponentResponse(
                name=r.component.name,
                version=r.component.version,
                purl=r.component.purl,
                license=r.component.license,
                risk_level=r.overall_risk,
                cve_count=len([f for f in r.findings if f.cve_id]),
                has_kev=any(f.kev_flag for f in r.findings),
                is_eol=r.is_eol,
                eol_date=r.eol_date,
            )
            for r in scan.results
        ],
    )
