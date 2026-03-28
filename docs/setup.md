# Setup

## Requirements

- Python 3.10+
- No required dependencies. Optional: `charset-normalizer` or `chardet` for non-UTF-8 files.

## Installation

### From PyPI

```bash
pip install credactor
```

### From Source

To install from source so `credactor` works globally from any directory:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e .
```

If `pip` is managed by `uv` and you are outside a virtualenv, use `pip3` or add `--system`:

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

### Run Without Installing

If you just want to run it from the cloned repo without a global install:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
python -m credactor --help
```

### Optional Dependencies

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

## Configuration

### Config File

`.credactor.toml` in your project root (or any parent directory). The tool walks upward from the scan target to find it.

```toml
# .credactor.toml

entropy_threshold = 3.5    # Shannon entropy floor
min_value_length = 8       # Ignore shorter values

# Extra directories to skip (merged with defaults)
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
credactor --config /path/to/.credactor.toml .
```

### Suppression

#### Inline

```python
api_key = "test_key_for_unit_tests"  # credactor:ignore
```

```javascript
const key = "test_key";  // credactor:ignore
```

#### Allowlist

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

## Pre-commit Hooks and CI/CD

See the [Integration Guide](integration.md) for pre-commit hook setup (framework and standalone) and CI pipeline configuration (GitHub Actions, GitLab CI).

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Project Structure

```
credactor/
    __init__.py          # version
    __main__.py          # python -m entry point
    cli.py               # argument parsing, main flow
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
    test_security.py
    test_suppressions.py
    test_walker.py
requirements-ci.in       # CI dependency source (human-readable)
requirements-ci.txt      # CI dependency lockfile (hash-pinned)
```
