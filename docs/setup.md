# Setup

## Requirements

- Python 3.10+
- No required dependencies. Optional: `charset-normalizer` or `chardet` for non-UTF-8 files.

## Install

### From PyPI

```bash
pip install credactor
```

### From source (local install)

To install from source so `credactor` works globally from any directory:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e .
```

If `pip` is managed by `uv` and you're outside a virtualenv, use `pip3` or add `--system`:

```bash
pip3 install -e .
# or
pip install --system -e .
```

After this, `credactor` is available from any directory in your terminal:

```bash
credactor --dry-run /path/to/project
```

To uninstall:

```bash
pip uninstall credactor
```

### Run without installing

If you just want to run it from the cloned repo without a global install:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
python -m credactor --help
# or
python credential_redactor.py --help
```

### Optional deps

Better encoding detection for legacy codebases:

```bash
pip install charset-normalizer
# or
pip install chardet
```

TOML config on Python < 3.11:

```bash
pip install tomli
```

## Config File

`.credactor.toml` in your project root (or any parent directory). The tool walks upward from the scan target to find it.

```toml
# .credactor.toml

entropy_threshold = 3.5    # Shannon entropy floor
min_value_length = 8       # Ignore shorter values

# Extra dirs to skip (merged with defaults)
skip_dirs = [".terraform", "vendor"]
skip_files = ["generated_config.py"]

# Extra extensions to scan
extra_extensions = [".env.encrypted"]

# Values to never flag
extra_safe_values = ["test_fixture_token_abc123"]

replacement = "REDACTED_BY_CREDACTOR"
```

Override path:

```bash
python -m credactor --config /path/to/.credactor.toml .
```

## Suppression

### Inline

```python
api_key = "test_key_for_unit_tests"  # credactor:ignore
```

```javascript
const key = "test_key";  // credactor:ignore
```

### Allowlist

`.credactorignore` in your project root:

```
# Glob patterns
tests/fixtures/*.py
**/test_data/**

# Specific line
config/defaults.py:42

# Specific value
test_fixture_value_abc123
```

## Pre-commit Hook

With the `pre-commit` framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: credactor
        name: credactor
        entry: python -m credactor --staged --ci
        language: python
        pass_filenames: false
        always_run: true
```

Or manually in `.git/hooks/pre-commit`:

```bash
#!/bin/sh
python -m credactor --staged --ci
```

`--ci` exits 1 on findings, blocking the commit. Exit 0 means clean.

## CI/CD

### GitHub Actions

```yaml
- name: Credential scan
  run: python -m credactor --ci --fail-on-error --format sarif . > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

`--fail-on-error` ensures the pipeline also fails if any files could not be scanned (e.g. permission errors), rather than silently skipping them.

### GitLab CI

```yaml
credential-scan:
  script:
    - python -m credactor --ci --fail-on-error --format json . > credential-report.json
  artifacts:
    reports:
      codequality: credential-report.json
  allow_failure: false
```

### Generic

```bash
python -m credactor --ci .

# Strict mode: also fail if files were skipped due to errors
python -m credactor --ci --fail-on-error .
```

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Project Structure

```
credactor/
    __init__.py          # version
    __main__.py          # python -m entry point
    cli.py               # arg parsing, main flow
    config.py            # .credactor.toml loading
    gitignore.py         # .gitignore matching
    patterns.py          # regexes, constants
    redactor.py          # file modification, backups
    report.py            # text/JSON/SARIF output
    scanner.py           # detection logic
    suppressions.py      # inline ignore, allowlist
    utils.py             # entropy, encoding detection
    walker.py            # directory traversal, parallelism
scripts/
    audit_wheel.py       # supply chain: verify wheel matches repo
tests/
    conftest.py
    test_cli.py
    test_config.py
    test_gitignore.py
    test_patterns.py
    test_redactor.py
    test_report.py
    test_safe_values.py
    test_scanner.py
    test_suppressions.py
    test_walker.py
requirements-ci.in       # CI dependency source (human-readable)
requirements-ci.txt      # CI dependency lockfile (hash-pinned)
```
