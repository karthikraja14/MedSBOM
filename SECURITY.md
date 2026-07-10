# Security Policy

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability in MedSBOM, please report it responsibly:

1. **Email:** Send a detailed report to the maintainers (set up a security email or use GitHub's private vulnerability reporting)
2. **GitHub:** Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository

### What to include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What NOT to include:
- Actual SBOM data from production medical devices
- Patient health information (PHI)
- Proprietary device configurations

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity; critical issues targeted within 14 days

## Scope

This policy covers:
- The `medsbom` Python package
- The Docker images
- The GitHub Actions workflows
- The generated document templates

## Important Note

MedSBOM is a compliance documentation tool, not a security scanning engine. We consume output from established scanners (Syft, Grype, Trivy). Vulnerabilities in those upstream tools should be reported to their respective projects.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |
