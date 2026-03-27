# Contributing

Thanks for your interest in Credactor. Bug reports, feature requests, and pull requests are welcome via [GitHub Issues](https://github.com/rxb06/Credactor/issues).

## Development Setup

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
ruff check credactor/ tests/
```

## Build and Audit

```bash
pip install build
python -m build
python scripts/audit_wheel.py
```

The wheel audit (`scripts/audit_wheel.py`) verifies that the built wheel contains only files tracked in the git repo. This is a supply chain protection — see [SECURITY.md](SECURITY.md) for details.

## Code Style

- Formatted with [Ruff](https://docs.astral.sh/ruff/)
- Type hints on all public functions
- No external runtime dependencies — stdlib only

## CI Pipeline

Every PR runs:
- **test** — pytest across Python 3.10–3.13
- **self-scan** — Credactor scans its own codebase (SARIF uploaded to Code Scanning)
- **build-audit** — builds the wheel and verifies contents match the repo

All CI dependencies are hash-pinned via `requirements-ci.txt` (`--require-hashes`). GitHub Actions are pinned to commit SHAs.

## Pull Request Process

1. Branch from `main` (`feat/`, `fix/`, `security/`, `docs/`)
2. Ensure all CI checks pass
3. One logical change per PR
4. Security fixes use `security/` prefix and reference SEC-XX identifiers

## Development Process

AI tools were used during development for code review, bug detection, security auditing, and documentation structuring. All output was reviewed and validated manually. The architecture, design decisions, and feature selection are the maintainer's own.
