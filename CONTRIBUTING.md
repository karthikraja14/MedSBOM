# Contributing to MedSBOM

Thank you for your interest in contributing to MedSBOM! This project helps medical device teams achieve FDA/IEC-62304 compliance with free, open-source tooling.

## Getting Started

### Prerequisites
- Python 3.12+
- Git

### Setup

```bash
git clone https://github.com/medsbom/medsbom.git
cd medsbom
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest tests/ -v --cov=medsbom
```

### Linting

```bash
ruff check medsbom/ tests/
mypy medsbom/ --ignore-missing-imports
```

## How to Contribute

### Reporting Bugs
Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). **Never include actual SBOM contents** from production devices — use the sample data in `tests/sample_data/` to reproduce issues.

### Suggesting Features
Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Regulatory context is especially helpful — tell us which standard section your request relates to.

### Submitting Code

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality (aim for positive, negative, and edge cases)
3. Ensure all tests pass: `pytest tests/ -v`
4. Ensure linting passes: `ruff check medsbom/ tests/`
5. Add Apache-2.0 license header to new files
6. Submit a pull request with a clear description

### Regulatory Template Contributions

Contributions to the Jinja2 templates in `medsbom/templates/` are especially welcome! If you have domain expertise in:
- FDA premarket cybersecurity guidance
- IEC 62304 software lifecycle processes
- ISO 14971 risk management
- EU MDR / IVDR requirements

Please help us improve the accuracy and completeness of generated documents.

**Important:** Template contributions should reference specific guidance sections (e.g., "FDA 2023 Premarket Guidance §V.B") so the community can verify accuracy.

## Code Standards

- **Type hints** on all public functions
- **Docstrings** for modules and public classes/functions
- **Tests** for every new feature (positive, negative, edge cases)
- **No secrets** in code — API keys via environment variables only
- **Apache-2.0 header** on every source file

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
