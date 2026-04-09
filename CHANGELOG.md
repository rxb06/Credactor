# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **SEC-35:** SARIF output injection — HTML-escape finding type in all SARIF rule fields to prevent XSS via attacker-controlled XML attribute names.
- **SEC-36:** Terminal escape injection — sanitise file paths, finding types, and raw source lines in text report output.
- **SEC-37:** Bare `$` prefix detection bypass — validate POSIX env var name syntax after `$` to prevent credential suppression.
- **SEC-38:** Config type confusion DoS — guard `float()`/`int()` conversions against malformed `.credactor.toml` values.
- **SEC-39:** Config trust boundary (non-git) — fall back to scan root when no `.git` exists, preventing silent config loading from parent directories.

### Added

- TTP-based vulnerability chain analysis (`mydocs/vulnerability-chains.md`).
- 21 new security tests covering SEC-35 through SEC-39.

## [2.3.2] - 2026-03-28

### Fixed

- **SEC-33:** Path containment prefix collision — `_is_within_root()` now appends `os.sep` after `normpath()` to prevent `/tmp/repo` matching `/tmp/repo_evil`.
- **SEC-34:** Template safe-value bypass — unclosed `${AKIA...` was falsely marked safe because the `$`-prefix check was too broad. Now requires matching closing delimiters.
- **SEC-20:** Secure backup dir symlink — now returns an error and skips redaction instead of silently falling back to an in-repo backup.

### Added

- Security test suite (`tests/test_security.py`) covering path containment, symlink boundaries, CI enforcement, and template safe-value logic.

## [2.3.1] - 2026-03-27

### Fixed

- **SEC-30:** Code injection via crafted XML attribute keys in `--replace-with env` mode. Env var names now stripped to `[A-Za-z0-9_]`. JS/TS uses bracket notation.
- **SEC-09:** Atomic backup creation via `mkstemp()` + `os.replace()` eliminates TOCTOU race.
- **SEC-25/SEC-32:** Path traversal guards now reject `..` as a path component, not a substring.
- **SEC-15:** Windows file handle released before `os.replace()` to prevent "Access Denied" errors.

### Added

- **SEC-31:** Warning when `.credactor.toml` or `.credactorignore` are staged alongside code changes.
- **SEC-13b:** Warning on extension-targeting wildcard patterns in `.credactorignore`.
- Windows compatibility: drive root protection, permission test skip, `fcntl` handle fix.
- 7 new security tests for env var sanitisation and language-specific replacements.

## [2.3.0] - 2026-03-27

### Added

- **SEC-26:** `--ci` now enforces read-only mode — blocks `--fix-all` and forces `--dry-run`.
- **SEC-27:** `--verbose` / `-v` flag with suppression audit trail (`[SKIP]` notices on stderr).
- **SEC-28:** One-time plaintext backup warning when `--secure-delete` is not used.
- **SEC-29:** `.credactor.toml` from outside project root is blocked in CI mode.
- `--version` flag.
- Clean `KeyboardInterrupt` handling (exit 130, no traceback).
- Home directory scan protection (prevents hang on `~`).

## [2.2.2] - 2026-03-27

### Fixed

- **SEC-23:** File symlinks resolving outside scan root are now skipped.
- **SEC-24:** SARIF output HTML-escaped to prevent injection in downstream consumers.
- **SEC-25:** Git history paths with `..` traversal sequences are rejected.

## [2.2.1] - 2026-03-27

### Added

- Supply chain hardening: wheel integrity audit, SHA-pinned GitHub Actions, hash-pinned CI dependencies, OIDC trusted publishing, Sigstore attestations.
- 22 security hardening measures (SEC-01 through SEC-22).

### Fixed

- Ruff lint compliance across all source files.

## [2.2.0] - 2026-03-26

### Added

- Initial public release.
- Multi-phase detection engine: regex signatures, entropy analysis, context-aware variable inspection.
- 14 credential patterns (AWS, GCP, Stripe, GitHub, GitLab, Slack, npm, PyPI, PEM, JWT, connection strings, hex, base64).
- Interactive and batch redaction modes.
- Language-aware env var replacement (Python, JS/TS, Go, Java, Ruby, PHP, shell).
- SARIF 2.1.0 output for GitHub Code Scanning.
- `.credactor.toml` configuration and `.credactorignore` suppressions.
- Parallel file scanning via `ThreadPoolExecutor`.
- Git staged file and history scanning.
- Pre-commit hook support (beta).

[2.3.2]: https://github.com/rxb06/Credactor/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/rxb06/Credactor/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/rxb06/Credactor/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/rxb06/Credactor/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/rxb06/Credactor/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/rxb06/Credactor/releases/tag/v2.2.0
