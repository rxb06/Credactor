[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/Credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/Credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENSE)

# Credactor

> Detect and redact hardcoded credentials before they hit version control.

Credactor scans source code for hardcoded secrets: API keys, tokens, passwords, private keys, connection strings, and redacts or replaces them with environment variable references. It runs as a CLI tool, a pre-commit hook, or in CI pipelines with SARIF output for GitHub Code Scanning.

<img width="1280" height="640" alt="credactor" src="https://github.com/user-attachments/assets/f1f94a9c-feea-4b8b-9ea4-81f25f07c4df" />

## Install

```bash
pip install credactor
```

## Quick Start

```bash
# Scan (dry run first — always review before redacting)
credactor --dry-run .

# Interactive redaction
credactor .

# Batch redaction
credactor --fix-all .

# CI mode (read-only, exit 1 on findings)
credactor --ci .
```

## Why Credactor?

Most secret scanners stop at detection. Credactor goes further: it redacts in place, generates language-aware env var replacements (`os.environ` in Python, `process.env` in JS, `System.getenv` in Java), and assigns severity levels so you can triage critical findings first.

## Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/setup.md) | Installation, configuration, CI/CD integration |
| [User Guide](docs/user-guide.md) | CLI reference, replacement modes, backup safety |
| [Examples](docs/examples.md) | Common workflows with output |
| [Integration](docs/integration.md) | Pre-commit hooks, CI pipelines |
| [Security](docs/security.md) | Threat model, hardening measures, known limitations |
| [Changelog](CHANGELOG.md) | Version history |
| [Contributing](CONTRIBUTING.md) | Development setup, code style, PR process |
| [Disclaimer](docs/DISCLAIMER.md) | Limitations, safe usage, warranty |

## Licence

Apache 2.0. See [LICENSE](LICENSE).
