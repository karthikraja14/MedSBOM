# MedSBOM Examples

This directory contains examples and guides to help you get started with MedSBOM.

## Quick Start Examples

### 1. Parse an SBOM

```bash
# Parse and inspect a CycloneDX SBOM
medsbom ingest ./sample_cyclonedx.json

# Parse an SPDX SBOM
medsbom ingest ./sample_spdx.json
```

### 2. Check for Vulnerabilities

```bash
# Run a full vulnerability + EOL check
medsbom check ./sample_cyclonedx.json --device "Insulin Pump" --device-version "2.3.1"

# With NVD API key for faster lookups (recommended)
export NVD_API_KEY="your-key-here"
medsbom check ./sample_cyclonedx.json --device "Insulin Pump"

# Save results as JSON for later use
medsbom check ./sample_cyclonedx.json --output results.json
```

### 3. Generate FDA Compliance Documents

```bash
# Generate all compliance documents
medsbom report ./sample_cyclonedx.json --format all --device "Insulin Pump" --device-version "2.3.1"

# Generate only the FDA premarket summary
medsbom report ./sample_cyclonedx.json --format fda --output ./reports/

# Generate only the SOUP risk assessment (IEC 62304)
medsbom report ./sample_cyclonedx.json --format soup

# Generate only the vulnerability review log
medsbom report ./sample_cyclonedx.json --format vuln
```

### 4. View Audit Trail

```bash
# View recent audit entries
medsbom audit

# View entries for a specific scan
medsbom audit <scan-id>
```

## Generating SBOMs

MedSBOM consumes SBOMs — it doesn't generate them. Use these free tools to create SBOMs:

### With Syft (recommended for firmware/containers)
```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate CycloneDX SBOM from a directory
syft dir:./my-firmware -o cyclonedx-json > my-device-sbom.json

# Generate from a Docker image
syft your-registry/device-image:latest -o cyclonedx-json > my-device-sbom.json
```

### With Trivy (great for container images)
```bash
# Install Trivy
# See: https://aquasecurity.github.io/trivy/latest/getting-started/installation/

# Generate SPDX SBOM
trivy image --format spdx-json --output my-device-sbom.json your-image:latest

# Generate CycloneDX SBOM
trivy fs --format cyclonedx --output my-device-sbom.json ./my-project/
```

## API Usage

### Start the API server

```bash
# Using Python
uvicorn medsbom.api.main:app --host 0.0.0.0 --port 8000

# Using Docker
docker compose -f docker/docker-compose.yml up
```

### API Examples (curl)

```bash
# Health check
curl http://localhost:8000/health

# Upload SBOM and run scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "Insulin Pump",
    "device_version": "2.3.1",
    "sbom_json": '"$(cat sample_cyclonedx.json)"'
  }'

# Get scan results (use the scan_id from the response above)
curl http://localhost:8000/api/v1/scans/{scan_id}

# Generate FDA report
curl http://localhost:8000/api/v1/scans/{scan_id}/report/fda

# Generate SOUP assessment
curl http://localhost:8000/api/v1/scans/{scan_id}/report/soup

# View audit trail
curl http://localhost:8000/api/v1/audit
```

### API Docs
When the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/sbom-check.yml
name: SBOM Compliance Check

on:
  push:
    branches: [main]
  pull_request:

jobs:
  medsbom-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Syft
        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Generate SBOM
        run: syft dir:. -o cyclonedx-json > sbom.json

      - name: Install MedSBOM
        run: pip install medsbom

      - name: Check vulnerabilities
        run: medsbom check sbom.json --device "${{ github.repository }}" --output results.json

      - name: Generate compliance report
        run: medsbom report sbom.json --format all --output ./compliance-reports/

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: ./compliance-reports/
```

## Typical Workflow for Medical Device Teams

```
1. Developer commits code
   │
2. CI generates SBOM (Syft/Trivy)
   │
3. CI runs: medsbom check sbom.json
   │  → Flags new CVEs, KEV entries, EOL components
   │
4. CI runs: medsbom report sbom.json --format all
   │  → Generates FDA summary, SOUP assessment, vuln log
   │
5. Regulatory team reviews generated docs
   │  → Signs off on risk acceptances
   │  → Files in QMS document control
   │
6. Docs submitted with 510(k)/PMA/De Novo
```
