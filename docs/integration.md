# Integration Guide

Credactor works best as a pre-commit hook that catches secrets before they reach git history. A CI pipeline can serve as a secondary safety net.

## Pre-commit Framework

If you use [pre-commit](https://pre-commit.com), add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/rxb06/Credactor
    rev: v2.0.0  # pin to a release tag
    hooks:
      - id: credactor
```

Then install the hook:

```bash
pre-commit install
```

Every `git commit` will now scan staged files automatically. The commit is blocked if credentials are found.

## Standalone Git Hook

No framework needed. Copy the provided script into your repo:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or create your own `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if ! command -v credactor &>/dev/null; then
    echo "credactor not found. Install with: pip install credactor" >&2
    exit 1
fi

credactor --staged
```

Requires `credactor` to be installed in your environment (`pip install credactor`).

## CI Pipeline (Safety Net)

Copy [`examples/ci-credactor.yml`](../examples/ci-credactor.yml) to `.github/workflows/credactor.yml` in your repository.

This runs a full scan on every push and pull request to `main`. If Credactor finds credentials, the workflow fails and blocks the merge.

### SARIF Upload

To surface findings as GitHub Code Scanning alerts, extend the workflow:

```yaml
      - name: Scan for credentials
        run: credactor . --format sarif -o results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

This requires Code Scanning to be enabled in your repository settings under Security > Code scanning.

## Configuration

Credactor looks for `.credactor.toml` in the project root. Common options:

```toml
min_entropy = 3.5
custom_replacement = "REDACTED"
no_backup = false
```

To suppress false positives on a specific line, add an inline comment:

```python
API_KEY = "not-a-real-key"  # credactor:ignore
```

To exclude entire files, add patterns to `.credactorignore`:

```
tests/*.py
fixtures/
*.test.js
```

See the [User Guide](user-guide.md) for the full list of CLI flags and config options.
