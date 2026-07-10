# Copyright 2024 MedSBOM Contributors
# SPDX-License-Identifier: Apache-2.0

"""CVE and KEV vulnerability matching for SBOM components."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from medsbom.core.models import Component, Finding

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Local cache directory
CACHE_DIR = Path.home() / ".medsbom" / "cache"

# Rate limit: NVD allows 5 requests per 30 seconds without API key
NVD_RATE_LIMIT_DELAY = 6.5  # seconds between requests (safe margin)


class CVEMatchError(Exception):
    """Raised when CVE matching fails."""


class CVEMatcher:
    """Match components against NVD CVEs and CISA KEV feed."""

    def __init__(
        self,
        nvd_api_key: str = "",
        cache_dir: Path | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._nvd_api_key = nvd_api_key
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._kev_data: dict[str, dict[str, Any]] | None = None
        self._last_nvd_request: float = 0.0

    def match_component(self, component: Component) -> list[Finding]:
        """Find all CVE findings for a single component."""
        findings: list[Finding] = []

        # Query NVD
        nvd_findings = self._query_nvd(component)
        findings.extend(nvd_findings)

        # Check KEV for any matched CVEs
        kev_lookup = self._get_kev_lookup()
        for finding in findings:
            if finding.cve_id in kev_lookup:
                finding.kev_flag = True
                finding.kev_date_added = kev_lookup[finding.cve_id].get("dateAdded", "")

        return findings

    def match_components(self, components: list[Component]) -> dict[str, list[Finding]]:
        """Match a list of components, keyed by component identifier."""
        results: dict[str, list[Finding]] = {}
        for component in components:
            try:
                results[component.identifier] = self.match_component(component)
            except CVEMatchError as exc:
                logger.warning("CVE match failed for %s: %s", component.identifier, exc)
                results[component.identifier] = []
        return results

    def _query_nvd(self, component: Component) -> list[Finding]:
        """Query the NVD API for CVEs affecting a component."""
        cache_key = f"nvd_{component.name}_{component.version}".replace("/", "_")
        cached = self._read_cache(cache_key)
        if cached is not None:
            return self._parse_nvd_response(cached)

        # Rate limit
        self._rate_limit()

        params: dict[str, str] = {}
        if component.purl:
            # Use CPE match via keyword search (NVD 2.0 API)
            params["keywordSearch"] = f"{component.name} {component.version}"
            params["keywordExactMatch"] = ""
        else:
            params["keywordSearch"] = f"{component.name} {component.version}"

        params["resultsPerPage"] = "50"

        headers: dict[str, str] = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(NVD_API_BASE, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            self._write_cache(cache_key, data)
            return self._parse_nvd_response(data)

        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                raise CVEMatchError("NVD API rate limit exceeded. Use --nvd-api-key.") from exc
            raise CVEMatchError(f"NVD API error: {exc.response.status_code}") from exc
        except httpx.RequestError as exc:
            raise CVEMatchError(f"NVD API request failed: {exc}") from exc

    def _parse_nvd_response(self, data: dict[str, Any]) -> list[Finding]:
        """Parse NVD API 2.0 response into Findings."""
        findings: list[Finding] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln_wrapper in vulnerabilities:
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS score (prefer v3.1, fall back to v3.0, then v2)
            cvss_score = 0.0
            cvss_vector = ""
            severity = ""

            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    severity = cvss_data.get("baseSeverity", metric_list[0].get("baseSeverity", ""))
                    break

            # Extract description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            findings.append(
                Finding(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    severity=severity.upper() if severity else _severity_from_score(cvss_score),
                    description=description[:500],  # Truncate long descriptions
                    source="NVD",
                )
            )

        return findings

    def _get_kev_lookup(self) -> dict[str, dict[str, Any]]:
        """Load CISA KEV feed, caching locally."""
        if self._kev_data is not None:
            return self._kev_data

        cached = self._read_cache("kev_feed")
        if cached is not None:
            self._kev_data = self._build_kev_lookup(cached)
            return self._kev_data

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(KEV_FEED_URL)
                resp.raise_for_status()
                data = resp.json()

            self._write_cache("kev_feed", data)
            self._kev_data = self._build_kev_lookup(data)
            return self._kev_data

        except (httpx.HTTPError, httpx.RequestError) as exc:
            logger.warning("Failed to fetch KEV feed: %s", exc)
            self._kev_data = {}
            return self._kev_data

    @staticmethod
    def _build_kev_lookup(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Build a dict keyed by CVE ID from the KEV feed."""
        lookup: dict[str, dict[str, Any]] = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                lookup[cve_id] = vuln
        return lookup

    def _rate_limit(self) -> None:
        """Enforce NVD API rate limits."""
        delay = NVD_RATE_LIMIT_DELAY if not self._nvd_api_key else 0.6
        elapsed = time.monotonic() - self._last_nvd_request
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_nvd_request = time.monotonic()

    def _read_cache(self, key: str) -> dict[str, Any] | None:
        """Read from local JSON cache."""
        cache_file = self._cache_dir / f"{key}.json"
        if not cache_file.exists():
            return None

        # Cache entries older than 24 hours are stale
        age_hours = (time.time() - cache_file.stat().st_mtime) / 3600
        if age_hours > 24:
            return None

        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(self, key: str, data: dict[str, Any]) -> None:
        """Write to local JSON cache."""
        cache_file = self._cache_dir / f"{key}.json"
        try:
            cache_file.write_text(json.dumps(data), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write cache: %s", exc)


def _severity_from_score(score: float) -> str:
    """Derive severity label from CVSS score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
