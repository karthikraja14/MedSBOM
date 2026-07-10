# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""SBOM ingestion — parse CycloneDX and SPDX JSON into normalized Component models."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from medsbom.core.models import Component, SBOMFormat

logger = logging.getLogger(__name__)


class IngestError(Exception):
    """Raised when SBOM ingestion fails."""


class ValidationWarning:
    """A non-fatal validation issue found during ingestion."""

    def __init__(self, component_name: str, field: str, message: str) -> None:
        self.component_name = component_name
        self.field = field
        self.message = message

    def __repr__(self) -> str:
        return f"ValidationWarning({self.component_name}: {self.field} — {self.message})"


class IngestResult:
    """Result of SBOM ingestion."""

    def __init__(
        self,
        sbom_format: SBOMFormat,
        components: list[Component],
        warnings: list[ValidationWarning],
        raw: dict[str, Any],
        source_tool: str = "",
    ) -> None:
        self.sbom_format = sbom_format
        self.components = components
        self.warnings = warnings
        self.raw = raw
        self.source_tool = source_tool


def detect_format(data: dict[str, Any]) -> SBOMFormat:
    """Auto-detect whether a parsed JSON dict is CycloneDX or SPDX.

    Raises IngestError if the format cannot be determined.
    """
    if "bomFormat" in data and str(data["bomFormat"]).lower() == "cyclonedx":
        return SBOMFormat.CYCLONEDX
    if "spdxVersion" in data:
        return SBOMFormat.SPDX
    # Heuristic fallbacks
    if "components" in data and "specVersion" in data:
        return SBOMFormat.CYCLONEDX
    if "packages" in data and "documentNamespace" in data:
        return SBOMFormat.SPDX
    raise IngestError(
        "Cannot detect SBOM format. Expected CycloneDX ('bomFormat') or SPDX ('spdxVersion') keys."
    )


def parse_sbom(source: str | Path | dict[str, Any]) -> IngestResult:
    """Parse an SBOM from a file path, JSON string, or pre-parsed dict.

    Returns an IngestResult with normalized components and any validation warnings.
    """
    data = _load_json(source)
    sbom_format = detect_format(data)

    if sbom_format == SBOMFormat.CYCLONEDX:
        return _parse_cyclonedx(data)
    return _parse_spdx(data)


def _load_json(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load JSON from file path, string, or pass through a dict."""
    if isinstance(source, dict):
        return source

    path = Path(source) if not isinstance(source, Path) else source
    if path.exists():
        text = path.read_text(encoding="utf-8")
    elif isinstance(source, str):
        # Might be a JSON string directly
        text = source
    else:
        raise IngestError(f"File not found: {source}")

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IngestError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise IngestError("SBOM JSON root must be an object, got " + type(data).__name__)

    return data


def _parse_cyclonedx(data: dict[str, Any]) -> IngestResult:
    """Parse CycloneDX 1.4+ JSON SBOM."""
    components: list[Component] = []
    warnings: list[ValidationWarning] = []

    source_tool = ""
    metadata = data.get("metadata", {})
    tools = metadata.get("tools", [])
    if isinstance(tools, list) and tools:
        first_tool = tools[0]
        if isinstance(first_tool, dict):
            source_tool = first_tool.get("name", "")
        elif isinstance(first_tool, str):
            source_tool = first_tool

    raw_components = data.get("components", [])
    if not isinstance(raw_components, list):
        raise IngestError("CycloneDX 'components' field must be a list.")

    for idx, comp in enumerate(raw_components):
        if not isinstance(comp, dict):
            warnings.append(
                ValidationWarning(
                    f"component[{idx}]", "type", "Component is not an object, skipped"
                )
            )
            continue

        name = comp.get("name", "")
        if not name:
            warnings.append(
                ValidationWarning(f"component[{idx}]", "name", "Missing component name, skipped")
            )
            continue

        version = comp.get("version", "")
        if not version:
            warnings.append(ValidationWarning(name, "version", "Missing version"))

        purl = comp.get("purl", "")
        if not purl:
            warnings.append(ValidationWarning(name, "purl", "Missing Package URL (purl)"))

        comp_license = ""
        licenses = comp.get("licenses", [])
        if isinstance(licenses, list) and licenses:
            first_lic = licenses[0]
            if isinstance(first_lic, dict):
                lic_obj = first_lic.get("license", first_lic)
                comp_license = lic_obj.get("id", lic_obj.get("name", ""))

        supplier = ""
        supplier_obj = comp.get("supplier", {})
        if isinstance(supplier_obj, dict):
            supplier = supplier_obj.get("name", "")

        comp_type = comp.get("type", "library")

        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                license=comp_license,
                supplier=supplier,
                component_type=comp_type,
            )
        )

    logger.info("Parsed CycloneDX SBOM: %d components, %d warnings", len(components), len(warnings))

    return IngestResult(
        sbom_format=SBOMFormat.CYCLONEDX,
        components=components,
        warnings=warnings,
        raw=data,
        source_tool=source_tool,
    )


def _parse_spdx(data: dict[str, Any]) -> IngestResult:
    """Parse SPDX 2.3 JSON SBOM."""
    components: list[Component] = []
    warnings: list[ValidationWarning] = []

    source_tool = ""
    creation_info = data.get("creationInfo", {})
    creators = creation_info.get("creators", [])
    for c in creators:
        if isinstance(c, str) and c.startswith("Tool:"):
            source_tool = c.removeprefix("Tool:").strip()
            break

    packages = data.get("packages", [])
    if not isinstance(packages, list):
        raise IngestError("SPDX 'packages' field must be a list.")

    for idx, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            warnings.append(
                ValidationWarning(f"package[{idx}]", "type", "Package is not an object, skipped")
            )
            continue

        name = pkg.get("name", "")
        if not name:
            warnings.append(
                ValidationWarning(f"package[{idx}]", "name", "Missing package name, skipped")
            )
            continue

        version = pkg.get("versionInfo", "")
        if not version:
            warnings.append(ValidationWarning(name, "versionInfo", "Missing version"))

        # SPDX uses externalRefs for purls
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break

        if not purl:
            warnings.append(ValidationWarning(name, "purl", "Missing Package URL (purl)"))

        comp_license = pkg.get("licenseConcluded", pkg.get("licenseDeclared", ""))
        if comp_license == "NOASSERTION":
            comp_license = ""

        supplier = pkg.get("supplier", "")
        if supplier == "NOASSERTION":
            supplier = ""

        components.append(
            Component(
                name=name,
                version=version,
                purl=purl,
                license=comp_license,
                supplier=supplier,
                component_type="library",
            )
        )

    logger.info("Parsed SPDX SBOM: %d components, %d warnings", len(components), len(warnings))

    return IngestResult(
        sbom_format=SBOMFormat.SPDX,
        components=components,
        warnings=warnings,
        raw=data,
        source_tool=source_tool,
    )
