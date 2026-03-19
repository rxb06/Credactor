# CredRedactor

Credential scanner and redactor for source code. Finds hardcoded API keys, tokens, passwords, connection strings, and private keys across 20+ file types, then helps you remove them.

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
- Severity levels (critical / high / medium / low) for triage
- Interactive or batch redaction — review one-by-one, or `--fix-all`
- Language-aware replacement — `--replace-with env` generates `os.environ["KEY"]` in Python, `process.env.KEY` in JS, `System.getenv("KEY")` in Java, etc.
- Pre-commit hook support via `--staged`
- Git history scanning via `--scan-history`
- Text, JSON, and SARIF output (SARIF integrates with GitHub Code Scanning)
- `.bak` backups before any file modification
- Inline `# credredactor:ignore` suppression and `.credredactorignore` allowlists
- Per-repo config via `.credredactor.toml`
- Parallel scanning for large repos

## Quick Start

```bash
# Scan current directory
python -m credredactor

# Dry run (no modifications)
python -m credredactor --dry-run

# Redact everything without prompting
python -m credredactor --fix-all

# CI mode — exit 1 on findings
python -m credredactor --ci
```

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

## License

Apache 2.0. See [LICENSE](LICENSE).
