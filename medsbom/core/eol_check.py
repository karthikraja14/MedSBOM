# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""End-of-life and end-of-support checking via endoflife.date API."""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any

import httpx

from medsbom.core.models import Component

logger = logging.getLogger(__name__)

EOL_API_BASE = "https://endoflife.date/api"

# Map common component names to endoflife.date product slugs
PRODUCT_SLUG_MAP: dict[str, str] = {
    "python": "python",
    "cpython": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "go": "go",
    "golang": "go",
    "java": "java",
    "openjdk": "java",
    "ruby": "ruby",
    "php": "php",
    "dotnet": "dotnet",
    ".net": "dotnet",
    "linux": "linux",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "alpine": "alpine",
    "centos": "centos",
    "rhel": "rhel",
    "redis": "redis",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "nginx": "nginx",
    "openssl": "openssl",
    "django": "django",
    "rails": "rails",
    "react": "react",
    "angular": "angular",
    "vue": "vue",
    "spring-boot": "spring-boot",
    "spring-framework": "spring-framework",
    "tomcat": "tomcat",
    "elasticsearch": "elasticsearch",
    "kubernetes": "kubernetes",
    "docker-engine": "docker-engine",
}


class EOLCheckError(Exception):
    """Raised when EOL checking fails."""


class EOLResult:
    """Result of an EOL check for a single component."""

    def __init__(
        self,
        product: str,
        version: str,
        eol_date: date | None = None,
        eos_date: date | None = None,
        is_eol: bool = False,
        latest_version: str = "",
        release_date: date | None = None,
        lts: bool = False,
        matched: bool = False,
    ) -> None:
        self.product = product
        self.version = version
        self.eol_date = eol_date
        self.eos_date = eos_date
        self.is_eol = is_eol
        self.latest_version = latest_version
        self.release_date = release_date
        self.lts = lts
        self.matched = matched


class EOLChecker:
    """Check end-of-life status for software components."""

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = timeout

    def check_component(self, component: Component) -> EOLResult:
        """Check EOL status for a single component."""
        slug = self._resolve_slug(component.name)
        if not slug:
            return EOLResult(
                product=component.name,
                version=component.version,
                matched=False,
            )

        try:
            return self._query_eol_api(slug, component.version)
        except EOLCheckError:
            return EOLResult(
                product=component.name,
                version=component.version,
                matched=False,
            )

    def check_components(self, components: list[Component]) -> dict[str, EOLResult]:
        """Check EOL status for a list of components."""
        results: dict[str, EOLResult] = {}
        for comp in components:
            results[comp.identifier] = self.check_component(comp)
        return results

    def _resolve_slug(self, name: str) -> str:
        """Map a component name to an endoflife.date product slug."""
        normalized = name.lower().strip()
        # Direct lookup
        if normalized in PRODUCT_SLUG_MAP:
            return PRODUCT_SLUG_MAP[normalized]
        # Strip common prefixes (e.g., "org.postgresql:postgresql" -> "postgresql")
        if ":" in normalized:
            _, _, after = normalized.rpartition(":")
            if after in PRODUCT_SLUG_MAP:
                return PRODUCT_SLUG_MAP[after]
        # No match — product may not be tracked by endoflife.date
        return ""

    def _query_eol_api(self, slug: str, version: str) -> EOLResult:
        """Query endoflife.date for a specific product version."""
        # Extract major.minor for version cycle matching
        cycle = _extract_cycle(version)

        try:
            with httpx.Client(timeout=self._timeout) as client:
                if cycle:
                    resp = client.get(
                        f"{EOL_API_BASE}/{slug}/{cycle}.json",
                        headers={"Accept": "application/json"},
                    )
                    if resp.status_code == 200:
                        return self._parse_cycle_response(slug, version, resp.json())

                # Fall back to all cycles and find the best match
                resp = client.get(
                    f"{EOL_API_BASE}/{slug}.json",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    return self._find_best_match(slug, version, resp.json())

                if resp.status_code == 404:
                    return EOLResult(product=slug, version=version, matched=False)

                resp.raise_for_status()
                return EOLResult(product=slug, version=version, matched=False)

        except httpx.HTTPStatusError as exc:
            raise EOLCheckError(f"EOL API error: {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise EOLCheckError(f"EOL API request failed: {exc}") from exc

    def _parse_cycle_response(self, slug: str, version: str, data: dict[str, Any]) -> EOLResult:
        """Parse a single cycle response from endoflife.date."""
        eol_date = _parse_date_field(data.get("eol"))
        eos_date = _parse_date_field(data.get("support"))
        release_date = _parse_date_field(data.get("releaseDate"))
        latest = data.get("latest", "")
        lts = bool(data.get("lts", False))

        is_eol = False
        if eol_date is not None:
            is_eol = eol_date <= date.today()
        elif data.get("eol") is True:
            is_eol = True

        return EOLResult(
            product=slug,
            version=version,
            eol_date=eol_date,
            eos_date=eos_date,
            is_eol=is_eol,
            latest_version=str(latest),
            release_date=release_date,
            lts=lts,
            matched=True,
        )

    def _find_best_match(self, slug: str, version: str, cycles: list[dict[str, Any]]) -> EOLResult:
        """Find the best matching cycle from a list of all cycles."""
        if not isinstance(cycles, list) or not cycles:
            return EOLResult(product=slug, version=version, matched=False)

        target = _extract_cycle(version)
        for cycle_data in cycles:
            cycle_id = str(cycle_data.get("cycle", ""))
            if cycle_id == target or version.startswith(cycle_id):
                return self._parse_cycle_response(slug, version, cycle_data)

        # No exact match — return the first cycle as reference
        return EOLResult(product=slug, version=version, matched=False)


def _extract_cycle(version: str) -> str:
    """Extract the major.minor cycle from a version string."""
    parts = version.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    if len(parts) == 1 and parts[0].isdigit():
        return parts[0]
    return version


def _parse_date_field(value: Any) -> date | None:
    """Parse a date from endoflife.date API (can be a string date, True, or False)."""
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None
    return None
