# User Guide

## Usage

```bash
# Scan current directory
python -m credactor

# Scan a specific path
python -m credactor /path/to/project
python -m credactor src/config.py
```

In interactive mode each finding is shown and you choose whether to redact it:

```
  [1/3]  src/config.py  --  line 12
  Type     : variable:api_key
  Severity : high
  Value    : sk_l[REDACTED]

  Replace? [y/N]:
```

## CLI Flags

### Mode

| Flag | What it does |
|---|---|
| `--ci` | Report only, no prompts, exits 1 on findings |
| `--dry-run` | Show findings without modifying anything |
| `--fix-all` | Redact all findings, no prompts |
| `--staged` | Scan only git-staged files |
| `--scan-history` | Scan git commit history |

### Output

| Flag | What it does |
|---|---|
| `--format text` | Human-readable with colors (default) |
| `--format json` | Machine-readable JSON |
| `--format sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `--no-color` | Strip ANSI codes |

### Replacement

| Flag | What it does |
|---|---|
| `--replace-with sentinel` | Use `REDACTED_BY_CREDACTOR` (default) |
| `--replace-with env` | Language-appropriate env var lookup |
| `--replace-with custom` | Use your own string |
| `--replacement STRING` | The custom string |
| `--no-backup` | Skip `.bak` file creation |

### Config

| Flag | What it does |
|---|---|
| `--config PATH` | Explicit config file path |
| `--scan-json` | Include `.json` files |

## Replacement Modes

### Sentinel (default)

```python
# Before
api_key = "sk_live_abc123def456"
# After
api_key = "REDACTED_BY_CREDACTOR"
```

Fails loudly at runtime instead of silently passing a wrong value.

### Environment Variable

`--replace-with env` picks the right syntax per language:

```python
# Python
api_key = os.environ["API_KEY"]
```

```javascript
// JavaScript
const apiKey = process.env.API_KEY;
```

```go
// Go
apiKey := os.Getenv("API_KEY")
```

```java
// Java / Kotlin
String apiKey = System.getenv("API_KEY");
```

```ruby
# Ruby
api_key = ENV['API_KEY']
```

```php
// PHP
$api_key = getenv('API_KEY');
```

```bash
# Shell / .env / YAML / TOML
API_KEY=${API_KEY}
```

### Custom

```bash
python -m credactor --replace-with custom --replacement "TODO_REPLACE_ME"
```

## Severity

| Level | Color | What triggers it |
|---|---|---|
| Critical | Red | Deterministic match — provider prefix, PEM key. Near-zero false positives. |
| High | Red | Strong match — JWT, connection string, high-entropy password variable. |
| Medium | Yellow | Heuristic — hex string, Stripe test key, generic credential variable. |
| Low | Cyan | Weak heuristic — long Base64. Higher false positive rate. |

## Suppression

### Inline

Append `credactor:ignore` in any comment style:

```python
test_key = "abc123"  # credactor:ignore
```

```xml
<!-- credactor:ignore -->
<add key="Password" value="test_only" />
```

### Allowlist

`.credactorignore` supports three entry types:

```
# Glob patterns — suppress entire files
tests/fixtures/**
**/testdata/*.py

# File:line — suppress a specific line
src/config.py:42

# Value literals — suppress a value anywhere
test_fixture_token_value
```

## Backup and Safety

Modified files get a `.bak` copy first. Skip with `--no-backup`.

Other protections:
- File permissions preserved after modification
- Encoding auto-detected and preserved
- UTF-8 BOM handled
- Replacements applied bottom-to-top so line numbers stay correct
- Credential values masked in all report output — secrets never leak to logs

## Output Formats

### Text

```
======================================================================
  CREDENTIAL SCAN REPORT  --  3 finding(s) in 1 file(s)
======================================================================

  FILE: src/config.py
  ────────────────────────────────────────────────────────────
  Line   12  [CRITICAL]  [pattern:AWS access key]
           api_key = "AKIA[REDACTED]"
  Line   15  [HIGH]  [variable:password]
           db_password = "xK9#[REDACTED]"
```

### JSON

```json
{
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "type": "pattern:AWS access key",
      "severity": "critical",
      "value": "AKIA[REDACTED]",
      "commit": null
    }
  ],
  "count": 1
}
```

### SARIF

SARIF 2.1.0 output for GitHub Code Scanning, VS Code SARIF Viewer, or any compatible tool.

## Not Flagged

These are treated as safe automatically:

- Placeholder values: `your_api_key`, `changeme`, `placeholder`, `TODO`
- Env var references: `$VAR`, `${VAR}`, `os.getenv("KEY")`
- Dynamic lookups: `config.get()`, `Variable.get()`, `keyring.get_password()`, Vault, SOPS
- File paths: `/home/user/.ssh/key`, `./config/secret.yaml`
- URLs without credentials: `https://api.example.com/v1/endpoint`
- Function definitions: `def get_password(self, password="default"):`
- Low-entropy values (below 3.5 bits/char by default)
- Short values (under 8 characters)
- Already-redacted values: `REDACTED_BY_CREDACTOR`
