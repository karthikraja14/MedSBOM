<div align="center">

# 🏥 MedSBOM

**Open-source FDA/IEC-62304 compliance layer for medical device SBOMs**

[![CI](https://github.com/medsbom/medsbom/actions/workflows/ci.yml/badge.svg)](https://github.com/medsbom/medsbom/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/medsbom)](https://pypi.org/project/medsbom/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

*Turn raw SBOM scans into FDA-submission-ready documentation in seconds, not weeks.*

[Quick Start](#quick-start) • [Examples](examples/) • [API Docs](#api) • [Contributing](CONTRIBUTING.md) • [Sponsor](#sponsor)

</div>

---

## The Problem

Medical device manufacturers must (FDA 2023 guidance, PATCH Act, 2026 QMSR):
- Maintain Software Bills of Materials for every device
- Continuously monitor SOUP components for vulnerabilities
- Document a Secure Product Development Framework
- Produce audit-ready evidence of regular vulnerability review (IEC 62304 §7.1.3)

**Today:** Teams spend 40–80 hours per device manually translating Syft/Grype/Trivy output into regulatory documents. Paid platforms charge $50K–$200K/year.

**With MedSBOM:** One command. Audit-ready docs in seconds. Free forever.

## What MedSBOM Does

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────────────┐
│  SBOM Input │ ──▶ │  MedSBOM     │ ──▶ │  FDA Premarket Summary    │
│ (SPDX/CDX)  │     │  Engine      │     │  SOUP Risk Assessment     │
└─────────────┘     │              │     │  Vulnerability Review Log │
                    │  • CVE match │     │  Audit Trail              │
┌─────────────┐     │  • KEV check │     └───────────────────────────┘
│ NVD + KEV   │ ──▶ │  • EOL check │
│ feeds       │     │  • Risk score│
└─────────────┘     └──────────────┘
```

## Quick Start

### Install

```bash
pip install medsbom
```

### Generate your SBOM (if you don't have one)

```bash
# Using Syft
syft dir:./my-firmware -o cyclonedx-json > my-device.sbom.json

# Using Trivy
trivy fs --format cyclonedx --output my-device.sbom.json ./my-project/
```

### Run MedSBOM

```bash
# Check for vulnerabilities and EOL status
medsbom check my-device.sbom.json --device "Insulin Pump" --device-version "2.3.1"

# Generate FDA compliance documents
medsbom report my-device.sbom.json --format all --output ./compliance-docs/
```

**That's it.** You now have:
- `fda_premarket_summary.md` — Maps to FDA 2023 Cybersecurity Guidance structure
- `soup_risk_assessment.md` — IEC 62304 §7.1.3 SOUP register with risk levels
- `vulnerability_review_log.md` — Timestamped audit evidence

## Features

| Feature | Description |
|---|---|
| **SBOM Ingestion** | CycloneDX and SPDX JSON (from Syft, Trivy, or any scanner) |
| **CVE Matching** | Cross-reference against NVD with local caching |
| **CISA KEV** | Flag actively exploited vulnerabilities |
| **EOL Detection** | Check end-of-life status via endoflife.date |
| **Risk Scoring** | Composite score: CVSS + KEV + EOL proximity |
| **FDA Docs** | Premarket Cybersecurity Summary template |
| **IEC 62304** | SOUP Risk Assessment table |
| **Audit Trail** | Immutable, append-only log for regulatory evidence |
| **REST API** | FastAPI server for integration and dashboards |
| **Docker** | Single container, no external dependencies |

## CLI Commands

```bash
medsbom ingest <sbom-file>          # Parse and validate an SBOM
medsbom check <sbom-file>           # Vulnerability + EOL check
medsbom report <sbom-file>          # Generate compliance documents
medsbom audit                       # View audit trail
medsbom version                     # Show version
```

## API

Start the API server:

```bash
uvicorn medsbom.api.main:app --host 0.0.0.0 --port 8000
```

Endpoints:
- `GET /health` — Health check
- `POST /api/v1/scans` — Upload SBOM and run analysis
- `GET /api/v1/scans/{id}` — Get scan results
- `GET /api/v1/scans/{id}/report/{format}` — Generate report (fda/soup/vuln)
- `GET /api/v1/audit` — Audit trail

Interactive docs at: `http://localhost:8000/docs`

## Docker

```bash
# CLI mode
docker run --rm -v $(pwd):/data medsbom check /data/my-sbom.json

# API mode
docker compose -f docker/docker-compose.yml up
```

## Configuration

| Environment Variable | Description | Default |
|---|---|---|
| `NVD_API_KEY` | NVD API key (recommended — 10x faster) | None |
| `MEDSBOM_CACHE_DIR` | Local cache directory | `~/.medsbom/cache` |
| `MEDSBOM_AUDIT_DB` | Audit database path | `~/.medsbom/audit.db` |

Get a free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

## Important Disclaimer

> **⚠️ REGULATORY NOTICE:** MedSBOM generates DRAFT compliance documentation to assist with FDA/IEC-62304 workflows. This tool does NOT constitute legal or regulatory advice. All generated output must be reviewed and approved by a qualified regulatory professional before submission to any regulatory body. MedSBOM contributors accept no liability for regulatory decisions made based on this output.

## Project Structure

```
medsbom/
├── cli/               # Typer CLI
├── core/
│   ├── ingest.py      # SBOM parsing (CycloneDX + SPDX)
│   ├── cve_match.py   # NVD + KEV vulnerability matching
│   ├── eol_check.py   # End-of-life checking
│   ├── risk_score.py  # Composite risk scoring
│   ├── doc_generator.py  # Jinja2 → Markdown/PDF
│   ├── audit.py       # Append-only audit trail
│   └── models.py      # Pydantic data models
├── api/               # FastAPI REST API
├── templates/         # Jinja2 regulatory doc templates
├── tests/             # Comprehensive test suite
├── examples/          # Sample SBOMs and usage guides
└── docker/            # Container deployment
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Especially welcome:
- Regulatory template improvements (FDA, IEC 62304, ISO 14971, EU MDR)
- Additional SBOM format support
- Integration with more scanners
- Translations of templates

## Sponsor

MedSBOM is free and open source. If it saves your team time and money, consider supporting development:

- **[GitHub Sponsors](https://github.com/sponsors/medsbom)** — Monthly or one-time support
- **[Open Collective](https://opencollective.com/medsbom)** — Transparent community funding
- **[Buy Me a Coffee](https://www.buymeacoffee.com/medsbom)** — Quick one-time tips

For enterprise support contracts or custom template development, open an issue or email the maintainers.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Chosen specifically for medical device companies: permissive, includes patent grant, no copyleft concerns for proprietary firmware integration.

---

<div align="center">

**Built for the medical device community. Free forever.**

*If MedSBOM helps your team, [star the repo](https://github.com/medsbom/medsbom) and tell your colleagues.*

</div>
