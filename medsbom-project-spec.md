# MedSBOM — Open Source FDA/IEC-62304 Compliance Layer for Medical Device SBOMs

## 1. Problem Statement

Medical device manufacturers are required by the FDA (2023 cybersecurity guidance, PATCH Act, and the 2026 QMSR transition) to:
- Maintain a Software Bill of Materials (SBOM) for every device
- Continuously monitor third-party/open-source components (SOUP) for known vulnerabilities
- Document a Secure Product Development Framework (SPDF)
- Produce audit-ready evidence of "regular vulnerability review" (IEC 62304 §7.1.3)
- Track end-of-support/EOL status of OS and library dependencies across a device fleet

Generic tools (Syft, Grype, Trivy, Dependency-Track, JFrog Xray) generate SBOMs and flag CVEs, but none of them speak the regulatory language device makers must submit. Today, teams manually translate raw scan output into FDA-shaped documentation — a slow, expensive, error-prone process that paid platforms (Ketryx, Blue Goat, Innolitics tooling) charge enterprise prices to solve.

**There is no free, open-source project that closes this specific gap.**

## 2. Goal

Build a thin, focused, open-source compliance layer that sits on top of existing SBOM/CVE scanners and outputs:
1. FDA-submission-ready documentation artifacts
2. IEC 62304 SOUP risk assessments
3. Continuous vulnerability monitoring with audit trail
4. Device/fleet-level EOL and risk dashboards

## 3. Explicit Non-Goals (v1)

- Not a replacement for Syft/Grype/Trivy — we consume their output, we don't rebuild scanning
- Not a full QMS (quality management system) — no design controls, no CAPA workflows
- Not a regulatory consultancy — we generate draft documentation, not legal/regulatory sign-off
- No hardware/firmware analysis in v1 — software SBOMs only

## 4. Target Users

- Small/mid medical device software teams (no budget for Ketryx/Black Duck)
- Open-source medical device projects (e.g. insulin pump firmware, imaging software)
- Independent regulatory consultants who need to demo compliance quickly
- Security researchers auditing device fleets

## 5. High-Level Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────────┐
│  SBOM Input │ --> │  MedSBOM Core │ --> │  Outputs           │
│ (SPDX/CDX)  │     │  Engine       │     │  - FDA doc bundle  │
└─────────────┘     │               │     │  - SOUP risk sheet │
                     │  - CVE match  │     │  - Audit log       │
┌─────────────┐     │  - EOL check  │     │  - Fleet dashboard │
│ CVE feeds   │ --> │  - Risk score │     └───────────────────┘
│ (NVD, KEV)  │     └──────────────┘
└─────────────┘             │
                             v
                     ┌──────────────┐
                     │ Storage (DB) │
                     │ Postgres     │
                     └──────────────┘
```

## 6. Tech Stack (suggested — Copilot should scaffold this)

- **Language:** Python 3.12 (fits existing SBOM ecosystem: Syft/Grype wrappers, CycloneDX libs)
- **CLI:** `typer` (developer-friendly, matches Karthik's CLI tooling background)
- **Backend API:** FastAPI
- **DB:** PostgreSQL (SBOM history, scan results, audit trail)
- **Frontend dashboard:** Single-file React + Tailwind (or a lightweight HTMX + FastAPI templates for v1 to ship faster)
- **SBOM parsing:** `cyclonedx-python-lib`, SPDX tools
- **CVE data:** NVD API + CISA KEV feed (free, no key needed for KEV; NVD API key recommended)
- **EOL data:** endoflife.date public API (free, community-maintained EOL data for OS/software)
- **Docs generation:** Jinja2 templates → Markdown/PDF (via WeasyPrint or Pandoc)
- **Packaging:** pip package + Docker image + GitHub Action (so CI can run it automatically)
- **License:** Apache 2.0 (permissive, patent grant — reassuring for medtech companies wary of GPL)

## 7. MVP Feature Scope (v1 — shippable in weeks, not months)

### 7.1 CLI (`medsbom`)
```bash
medsbom scan ./my-device-firmware        # runs Syft under the hood, generates SBOM
medsbom check my-sbom.json                # cross-references CVEs + EOL status
medsbom report my-sbom.json --format fda  # generates FDA-shaped doc bundle (md/pdf)
medsbom watch my-sbom.json --schedule daily  # continuous monitoring mode
```

### 7.2 Core Engine Modules
1. **Ingest** — accept SPDX or CycloneDX JSON (from Syft, Trivy, or manual upload)
2. **Match** — cross-reference each component against:
   - NVD CVE database
   - CISA Known Exploited Vulnerabilities (KEV) list
   - endoflife.date for OS/runtime EOL dates
3. **Score** — simple risk scoring: CVSS severity + KEV flag + EOL proximity → Low/Medium/High/Critical
4. **Document Generator** — Jinja2 templates that output:
   - SOUP Risk Assessment table (IEC 62304 §7.1.3 format)
   - Vulnerability Review Log (date-stamped, for audit trail)
   - Premarket Cybersecurity Summary (maps to FDA's 2023 guidance structure)
5. **Audit Trail** — every scan run is timestamped and stored immutably (append-only table) so teams can prove "regular review" over time
6. **Dashboard** — fleet-level view: devices × components × risk level × EOL countdown

### 7.3 Nice-to-have (v1.1+)
- GitHub Action / GitLab CI template: fail a build if a Critical/KEV-listed vuln is introduced
- Slack/email digest of new vulnerabilities affecting tracked SBOMs
- Import existing SBOMs from JFrog Xray / Dependency-Track (so it complements, not competes)

## 8. Data Model (simplified)

```
Device (id, name, model_version)
  └── SBOMScan (id, device_id, timestamp, sbom_json, source_tool)
        └── Component (id, scan_id, name, version, purl, license)
              └── Finding (id, component_id, cve_id, cvss_score, kev_flag, eol_date, risk_level)
AuditLog (id, scan_id, action, timestamp, actor)
```

## 9. Repo Structure (for Copilot to scaffold)

```
medsbom/
├── cli/                  # typer CLI entrypoints
├── core/
│   ├── ingest.py
│   ├── cve_match.py
│   ├── eol_check.py
│   ├── risk_score.py
│   └── doc_generator.py
├── api/                  # FastAPI app
│   ├── main.py
│   ├── routers/
│   └── models.py
├── dashboard/             # frontend
├── templates/             # Jinja2 doc templates (FDA bundle, SOUP sheet)
├── tests/
├── docker/
├── .github/workflows/     # CI + release automation
├── docs/
├── README.md
├── LICENSE (Apache-2.0)
└── pyproject.toml
```

## 10. Milestones

| Milestone | Scope | Target |
|---|---|---|
| M0 | Repo scaffold, CLI skeleton, SBOM ingest | Week 1 |
| M1 | CVE + KEV matching, risk scoring | Week 2 |
| M2 | FDA doc bundle generator (Markdown output) | Week 3 |
| M3 | Audit trail + SQLite/Postgres storage | Week 4 |
| M4 | Simple web dashboard | Week 5–6 |
| M5 | Docker image + GitHub Action + public launch | Week 7 |

## 11. Prompt for Copilot / Claude Code (paste this in as the kickoff instruction)

> Scaffold a Python 3.12 project called `medsbom` matching the repo structure and data model above. Start with the CLI (`typer`) and the `core/ingest.py` + `core/cve_match.py` modules. Use `cyclonedx-python-lib` to parse SBOMs, call the NVD REST API and CISA KEV JSON feed for vulnerability matching, and endoflife.date's public API for EOL data. Write unit tests with pytest for each core module before wiring up the FastAPI layer. Use Apache-2.0 license headers.

---

## 12. How you'll know if people are using it

Open source projects can't rely on guessing — here's how maintainers actually track this, roughly in order of effort vs. signal:

1. **GitHub signals (zero setup)** — stars, forks, clone traffic (Insights → Traffic, visible to you as maintainer for 14 days rolling), issues/PRs opened by non-you accounts. Weak signal but free and instant.
2. **PyPI/Docker download counts** — `pypistats.org` for PyPI downloads, Docker Hub pull counts. Shows adoption without needing any telemetry code.
3. **Opt-in anonymous telemetry (recommended)** — on first run, CLI asks "Send anonymous usage stats to help development? (Y/n)". If yes, ping a simple endpoint (self-hosted, e.g. a tiny FastAPI + Postgres on Fly.io/Railway) with: command run, project version, anonymized hash of machine ID, nothing about the actual SBOM contents. This is the industry-standard pattern (Homebrew, Next.js, Docker CLI all do this). **Never send SBOM contents or company-identifying data** — that would itself be a compliance/trust problem for a security tool.
5. **A public "who's using this" doc** — invite users to open a PR adding their org/logo to a `ADOPTERS.md` file (common in CNCF projects). Voluntary but great social proof.
6. **GitHub Sponsors / Open Collective dashboards** — these tools show you follower/backer counts as a side effect of the payment infra below.

## 13. How people can send you money

Standard, low-friction options for an open-source maintainer:

- **GitHub Sponsors** — built into GitHub, zero fees on Anthropic/Microsoft-sponsored platform (GitHub covers processing fees for individuals), supports one-time and monthly. Easiest to set up: add a `FUNDING.yml` in `.github/` pointing to your GitHub Sponsors profile — GitHub then shows a "Sponsor" button directly on the repo.
- **Open Collective** — better if you expect multiple contributors and want transparent public ledger of funds in/out (common for community-governed OSS). Takes a small platform fee (~10%).
- **Buy Me a Coffee / Ko-fi** — lowest friction for one-off small tips, simple links, low fees.
- **Tidelift / thanks.dev** — pay-for-maintenance marketplaces where companies using your OSS in production pay a subscription; more relevant once you have real enterprise adopters (medtech companies specifically might prefer this since it looks like a normal vendor invoice for their procurement process).

For a project like this, the realistic path is: **GitHub Sponsors from day one** (just a `FUNDING.yml` file, takes 5 minutes) → if a medtech company wants to sponsor a feature or get a support contract, point them to Open Collective or set up a simple paid "priority support" tier alongside the free OSS core (dual-license-style model, common for compliance tooling).

```yaml
# .github/FUNDING.yml
github: [your-username]
open_collective: medsbom
custom: ["https://www.buymeacoffee.com/your-username"]
```
