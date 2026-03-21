[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/Credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/Credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

# Credactor

Credactor scans source code for hardcoded secrets — API keys, tokens, passwords, private keys, connection strings — and redacts or replaces them with environment variable references before they reach version control. It runs as a CLI tool, a pre-commit hook, or in CI pipelines. SARIF output integrates directly with GitHub Code Scanning.


<img width="1536" height="1024" alt="credactor" src="https://github.com/user-attachments/assets/f1f94a9c-feea-4b8b-9ea4-81f25f07c4df" />

---

## Why Credactor?

Most secret scanners stop at detection. Credactor goes further: it redacts in place, generates language-aware env var replacements (`os.environ` in Python, `process.env` in JS, `System.getenv` in Java), and assigns severity levels so you can triage critical findings first instead of wading through noise.

## Install

```bash
pip install credactor
```

## Quick Start

> **Recommended:** Always run `--dry-run` first and review findings before redacting. False positives are possible — use `# credactor:ignore` or `.credactorignore` to suppress them.

```bash
# Scan current directory (dry run first)
credactor --dry-run .

# Scan and interactively redact
credactor .

# Redact everything without prompting
credactor --fix-all .

# CI mode — exit 1 on findings
credactor --ci .
```

### Pre-commit Hook (Beta)

> Hook-based scanning is in beta. Run `credactor --dry-run .` manually before relying on hooks alone.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rxb06/Credactor
    rev: v2.1.1
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
- Git history scanning via `--scan-history`
- `.bak` backups before any file modification
- Inline `# credactor:ignore` suppression and `.credactorignore` allowlists
- Per-repo config via `.credactor.toml`
- Parallel scanning for large repos

## Scanned File Types

`.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.env.*` `.cfg` `.ini` `.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl` `.conf` `.properties` `.xml`

JSON files are excluded by default due to high false-positive rates from API response data. Use `--scan-json` to include them.

## Auto-Skipped

Directories: `.git`, `__pycache__`, `node_modules`, `.venv`, `venv`, `.tox`, `dist`, `build`

Files: `package-lock.json`, `yarn.lock`, `poetry.lock`, `pnpm-lock.yaml`

Values: placeholders (`your_api_key`, `changeme`), env var references (`$VAR`, `${VAR}`), function calls, file paths, URLs without credentials, dynamic lookups (`os.getenv()`, Vault/SOPS refs)

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings, or all resolved |
| `1` | Unresolved findings |
| `2` | Error |

## Docs

- [Setup Guide](docs/setup.md) — install, config, CI
- [User Guide](docs/user-guide.md) — CLI reference, feature walkthrough
- [Examples](docs/examples.md) — common workflows
- [Integration](docs/integration.md) — pre-commit hooks, CI setup
- [Disclaimer](docs/DISCLAIMER.md) — limitations, safe usage, warranty

> AI Use Transparency: AI was used for code review, bug fixes, security auditing, and documentation structuring. All output was reviewed and validated manually.

## License

Apache 2.0. See [LICENSE](LICENSE).
