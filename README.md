[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/Credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/Credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/licence-Apache%202.0-blue)](LICENSE)

# Credactor

> **TL;DR:** Detect and redact hardcoded credentials before they hit version control. Regex + entropy + context-aware analysis, SARIF output, pre-commit hooks, parallel scanning, automated redaction.

Credactor scans source code for hardcoded secrets — API keys, tokens, passwords, private keys, connection strings — and replaces them with language-aware environment variable references before they reach version control. It runs as a CLI tool, a pre-commit hook, or in CI pipelines. SARIF output plugs straight into GitHub Code Scanning.

<img width="1280" height="640" alt="credactor" src="https://github.com/user-attachments/assets/f1f94a9c-feea-4b8b-9ea4-81f25f07c4df" />

---

## Why Credactor?

Most secret scanners stop at detection. Credactor redacts in place and replaces credentials with the right env var syntax for each language — `os.environ` in Python, `process.env` in JS, `System.getenv` in Java, and so on. It assigns severity levels so you can triage critical findings first instead of wading through noise.

## Install

```bash
pip install credactor
```

From source:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e .
```

After either method, `credactor` works from any directory.

## Quick Start

> Always run `--dry-run` first and review findings before redacting. False positives are possible — use `# credactor:ignore` or `.credactorignore` to suppress them.

```bash
# Scan current directory (dry run)
credactor --dry-run .

# Scan and interactively redact
credactor .

# Redact everything without prompting
credactor --fix-all .

# CI mode — exit 1 on findings
credactor --ci .
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rxb06/Credactor
    rev: v2.3.3
    hooks:
      - id: credactor
```

Or run as a module:

```bash
python -m credactor .
```

## Detection

| Category | Examples | Severity |
|---|---|---|
| Cloud provider keys | AWS (`AKIA...`), GCP (`AIza...`), Stripe (`sk_live_...`), Slack (`xoxb-...`) | Critical |
| Platform tokens | GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`), npm (`npm_`), PyPI (`pypi-`) | Critical |
| Private keys | PEM blocks (`-----BEGIN RSA PRIVATE KEY-----`) | Critical |
| JWT tokens | `eyJ...` three-segment tokens | High |
| Connection strings | `postgresql://user:pass@host`, `mongodb+srv://...`, `redis://...` | High |
| Variable assignments | `password = "..."`, `api_key = "..."`, `db_password = "..."` | High/Medium |
| XML attributes | `<add key="Password" value="..." />` | High |
| High-entropy strings | Hex (32-64 chars), Base64 (60+ chars) | Medium/Low |

## Features

- Entropy-based detection with per-pattern thresholds to cut false positives
- Interactive or batch redaction — review one-by-one, or `--fix-all`
- Language-aware replacements (`os.environ`, `process.env`, `System.getenv`, etc.)
- Git history scanning via `--scan-history`
- `.bak` backups before any file modification
- Inline `# credactor:ignore` suppression and `.credactorignore` allowlists
- Per-repo config via `.credactor.toml`
- Parallel scanning (8 workers) for large repos
- SARIF 2.1.0 output with column-level annotations for GitHub Code Scanning
- `--fail-on-error` to catch files that couldn't be scanned

## Scanned File Types

`.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.env.*` `.cfg` `.ini` `.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl` `.conf` `.properties` `.xml`

JSON files are excluded by default (high false-positive rate from API responses). Use `--scan-json` to include them.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings, or all resolved |
| `1` | Unresolved findings |
| `2` | Error, or files skipped with `--fail-on-error` |

## Docs

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
