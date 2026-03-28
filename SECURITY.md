# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.3.x   | :white_check_mark: |
| < 2.3   | :x:                |

Only the latest minor release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately using one of these methods:

1. **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository.
2. **Email:** Send details to the repository maintainer (see the commit history or profile for contact info).

### What to include

- A clear description of the vulnerability and its impact.
- Steps to reproduce, including any proof-of-concept files or commands.
- The affected version(s) and any configuration required to trigger the issue.
- If applicable, a suggested fix or mitigation.

### Response timeline

| Stage                          | Target    |
|--------------------------------|-----------|
| Acknowledgement of report      | 48 hours  |
| Initial triage and severity    | 5 days    |
| Patch release (critical/high)  | 14 days   |
| Patch release (medium/low)     | 30 days   |

We will keep you informed of progress and coordinate disclosure timing with you.

## Security Model

Credactor is a **developer-side static analysis tool** that scans source files for hardcoded credentials. Understanding its trust boundaries is important:

### What Credactor protects against

- Accidentally committing hardcoded API keys, tokens, passwords, and private keys.
- Credentials in assignment statements, XML attributes, connection strings, PEM blocks, and multi-line strings.
- Re-flagging already-redacted values (the sentinel `REDACTED_BY_CREDACTOR` is in the safe-values list).

### What Credactor does NOT protect against

- **Obfuscated credentials:** Base64-encoded secrets, encrypted blobs (other than SOPS), or credentials split across multiple files.
- **Runtime secrets:** Credentials injected via environment variables, secret managers, or APIs at runtime are intentionally ignored (these are the *correct* pattern).
- **Binary files:** Only text-based source files are scanned; binary formats (`.exe`, `.zip`, `.png`, etc.) are skipped.
- **Determined adversaries:** An attacker with write access to your codebase could craft evasion patterns. Credactor is a safety net, not a security boundary.

### Trust boundaries

| Component                   | Trust Level | Notes                                                                   |
|-----------------------------|-------------|-------------------------------------------------------------------------|
| Source files being scanned  | Untrusted   | May contain adversarial content; regex patterns are hardened against ReDoS |
| `.credactor.toml` config | Semi-trusted | Can adjust thresholds and safe-values; traversal limited to 5 parent dirs; warns if loaded from outside project root |
| `.credactorignore`       | Semi-trusted | Can suppress findings for specific files, lines, or values              |
| CLI arguments               | Trusted     | Provided by the developer running the tool                              |
| Git history (`--scan-history`) | Untrusted | Parses `git log -p` output; input is sanitized                         |

### Hardening measures (v2.0.0)

- **No shell injection:** All subprocess calls use list arguments, never `shell=True`.
- **File size guard:** Files over 50 MB are skipped to prevent OOM.
- **PEM block recovery:** Unclosed PEM blocks auto-reset after 100 lines to prevent scan suppression.
- **Config traversal limit:** Config file search stops after 5 parent directories.
- **Credential masking:** All output formats (text, JSON, SARIF) mask credential values; `full_value` never appears in user-facing output.
- **Safe-value precision:** Function call detection uses regex matching (`identifier(...)`) instead of naive substring checks.
- **Symlink safety:** `os.walk` does not follow symlinks by default.
- **Encoding safety:** Uses `errors='surrogateescape'` for lossless round-trip on non-UTF-8 files.

### Hardening measures (v2.2.1)

- **SEC-01 — Secure backup handling:** `--secure-backup-dir` stores `.bak` files outside the repo; `--secure-delete` overwrites backups with random data before unlinking.
- **SEC-02 — Untrusted config warning:** Config files loaded from outside the git project root trigger a `[WARN]` on stderr.
- **SEC-03 — Config parse failure surfacing:** `_basic_toml_parse()` and `_parse_toml()` now warn on stderr instead of silently returning empty config.
- **SEC-04 — Subprocess path sanitization:** All `subprocess.run(cwd=...)` calls resolve paths via `Path.resolve()` before execution.
- **SEC-05 — File descriptor exhaustion protection:** `EMFILE` errors in the thread pool trigger automatic sequential fallback with re-scan of failed files.
- **SEC-06 — ReDoS line-length guard:** Lines longer than 4096 characters are truncated before regex pattern matching to bound worst-case execution time.
- **SEC-07 — Temp file leakage prevention:** `.credactor.tmp` files are cleaned up via a `finally` block even on crashes, and added to `.gitignore` to prevent accidental commits of plaintext credential residue.
- **SEC-08 — Forward-only scanning with expanded protected directories:** Hardcoded blocklist covers 30+ system directories across Linux, macOS, and Windows. Symlink escape guard prunes subdirectories whose resolved path leaves the scan root, enforcing strictly forward (downward) traversal.
- **SEC-09 — Symlink race in backup creation:** `_create_backup()` checks `os.path.islink()` before writing `.bak` files, preventing an attacker from placing a symlink to overwrite arbitrary files.
- **SEC-10 — Replacement string injection validation:** `--replacement` values are checked against a pattern of dangerous characters (`$`, backticks, `__import__`, `eval(`, `exec(`, `system(`, `subprocess`). Rejects strings that could enable code injection when the modified file is executed.
- **SEC-11 — Data loss safeguard for `--fix-all --no-backup`:** Displays a prominent DANGER banner warning that original values will be permanently lost, and suggests `--dry-run` first.
- **SEC-12 — Config injection bounds validation:** `entropy_threshold` is clamped to 0.0–6.0 and `min_value_length` to 1–200. Out-of-range values from `.credactor.toml` are rejected with a warning and reset to defaults, preventing silent scan disablement.
- **SEC-13 — Wildcard `.credactorignore` warning:** Overly broad patterns (`*`, `**`, `**/*`, `*.*`) trigger a `[WARN]` on stderr alerting the user that all files are being suppressed.
- **SEC-14 — `--replace-with env` semantic change warning:** Warns on stderr that env replacement changes string literals to function calls, and that environment variables must be set before running the modified code.
- **SEC-15 — TOCTOU file locking:** `batch_replace_in_file()` acquires an advisory `fcntl.flock()` lock (Unix) before reading, held through atomic replacement, mitigating race conditions with concurrent file edits.
- **SEC-16 — Terminal escape sequence sanitization:** All filenames, types, and values displayed in interactive mode are stripped of ANSI escape sequences and control characters to prevent terminal injection attacks via crafted filenames.
- **SEC-17 — NFS/network mount warning:** Warns on stderr if the scan target appears to be on a mounted or network volume (`/mnt/`, `/media/`, `/Volumes/`, `/net/`), where `os.replace()` atomicity is not guaranteed.
- **SEC-18 — Root user warning:** Warns on stderr if running as root (UID 0), as backup files may have restrictive ownership preventing recovery by normal users.
- **SEC-19 — Multiline ReDoS cap:** Triple-quoted string blocks are truncated to 8192 characters before regex scanning, preventing catastrophic backtracking on multi-megabyte string literals.
- **SEC-20 — Symlink in `--secure-backup-dir` validation:** Refuses to follow symlinks for the backup directory, preventing credential exfiltration to attacker-controlled locations.
- **SEC-21 — CI log prefix exposure:** Credential masking shows only the first 4 characters (`AKIA[REDACTED]`). In CI logs retained long-term, even short prefixes combined with file path and line number may narrow down the credential. Use `--format json` or `--format sarif` in CI and restrict log access.
- **SEC-22 — Setuid/setgid bit preservation:** File permission restoration now uses `st_mode & 0o7777` instead of `stat.S_IMODE()`, preserving setuid, setgid, and sticky bits after replacement.
- **SEC-23 — File symlink boundary enforcement (v2.2.2):** File symlinks that resolve outside the scan root are now skipped during directory walking. Prevents a malicious repo from using symlinks to exfiltrate secrets from external host files via scan output. Directory symlinks were already filtered; this extends the same protection to file symlinks.
- **SEC-24 — SARIF output sanitization (v2.2.2):** Finding type and masked secret preview in SARIF `message.text` fields are now HTML-escaped via `html.escape()`. Prevents injection in downstream SARIF consumers that render annotations without sanitizing.
- **SEC-25 — Git history path traversal guard (v2.2.2):** File paths extracted from `git log -p` output (`+++ b/...`) that contain `..` traversal sequences are rejected. Prevents crafted git history from injecting external file paths into scan reports.
- **SEC-26 — CI read-only enforcement (v2.3.0):** `--ci` now implies read-only mode. `--ci --fix-all` is rejected as mutually exclusive. Without `--fix-all`, `--ci` forces `--dry-run`. File modifications are impossible in CI mode.
- **SEC-27 — Suppression audit trail (v2.3.0):** `--verbose` flag emits `[SKIP]` notices to stderr for every suppressed finding, including the suppression reason (inline ignore, allowlist, safe value heuristic, hash context). Enables audit trail in CI logs.
- **SEC-28 — Plaintext backup warning (v2.3.0):** When redaction creates a `.bak` file without `--secure-delete` or `--secure-backup-dir`, a one-time warning is printed to stderr reminding the user that plaintext credentials remain on disk.
- **SEC-29 — Config trust boundary enforcement in CI (v2.3.0):** In CI mode, `.credactor.toml` files found outside the project root (git root) are refused instead of loaded with a warning. Prevents planted configs from weakening scanning in untrusted PR scenarios.
- **SEC-30 — Env var name sanitization (v2.3.1):** `_derive_env_var_name()` strips all non-identifier characters (`[^A-Za-z0-9_]`) from XML attribute keys before generating env replacement strings. JS/TS output uses bracket notation (`process.env["VAR"]`) instead of dot notation. Defence-in-depth validation checks the sanitized var name, not the full replacement string (which intentionally contains shell metacharacters for shell/YAML/config files). Prevents code injection via crafted XML attribute keys in `--replace-with env` mode.
- **SEC-31 — Staged config tampering warning (v2.3.1):** `--staged` mode now warns on stderr when `.credactor.toml` or `.credactorignore` files are staged alongside code changes. Alerts reviewers to potential detection-bypass attempts in the same PR.
- **SEC-13b — Extended broad pattern warning (v2.3.1):** `.credactorignore` now warns on extension-targeting wildcard patterns (e.g. `**/*.py`, `*.js`) that cover scannable file types, in addition to the existing SEC-13 warnings on `*`, `**`, `**/*`, `*.*`.
- **SEC-09 — Atomic backup creation (v2.3.1):** Backup files are now created via `tempfile.mkstemp()` + `shutil.copy2()` + `os.replace()` instead of `os.path.islink()` + `shutil.copy2()`. Eliminates the TOCTOU race window where an attacker could swap the backup path with a symlink between the check and the write.
- **SEC-32 — Staged mode path traversal guard (v2.3.1):** File paths from `git diff --cached` output that contain `..` traversal sequences are rejected, consistent with SEC-25 for git history paths. Additionally validates that resolved paths stay within the scan root.
- **SEC-15 — Windows file handle fix (v2.3.1):** On Windows (where `fcntl` is unavailable), the lock file handle is now closed before `os.replace()` to prevent "Access Denied" errors. On Unix, the handle remains open for advisory locking as before.

### Supply chain hardening (v2.2.1)

- **Wheel integrity audit:** `scripts/audit_wheel.py` verifies that the built wheel contains only files tracked in the git repo and expected metadata. Catches `.pth` injection, binary `.so` injection, `sitecustomize.py`, and any unknown payload — without enumerating attack vectors. Runs in both CI (on every PR) and the publish workflow (before PyPI upload).
- **SHA-pinned GitHub Actions:** All `uses:` references in CI workflows pin to commit SHAs, not mutable tags. Prevents supply chain attacks via force-pushed action tags. Exception: `pypa/gh-action-pypi-publish` uses `release/v1` because Docker-based actions don't resolve SHA pins.
- **Hash-pinned CI dependencies:** `requirements-ci.txt` is generated by `pip-compile --generate-hashes` and installed with `pip install --require-hashes`. Any tampered or substituted dependency is rejected at install time.
- **OIDC trusted publishing:** PyPI uploads use short-lived OIDC tokens tied to this specific repo and workflow. No long-lived API token to compromise.
- **Sigstore attestations:** Published wheels include cryptographic provenance attestations, allowing users to verify the package was built from this GitHub repo.
- **Environment protection:** The `pypi` GitHub environment requires manual approval before the publish workflow can run.

## Disclosure Policy

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix is released, we will:

1. Publish a GitHub Security Advisory with full details.
2. Credit the reporter (unless they prefer anonymity).
3. Tag the fix commit and release a patched version.

## Scope

The following are **in scope** for security reports:

- Detection bypasses (crafted input that evades scanning).
- Credential leakage in tool output (unmasked secrets in reports, logs, or error messages).
- File system safety issues (path traversal, symlink attacks, TOCTOU races).
- Denial of service (ReDoS, OOM, infinite loops).
- Config injection (malicious `.credactor.toml` or `.credactorignore` causing unsafe behavior).

The following are **out of scope**:

- Known limitations listed in the "What Credactor does NOT protect against" section above.
- Vulnerabilities in dependencies (report these to the upstream project).
- Social engineering or phishing attacks.
