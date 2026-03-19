# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

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

CredRedactor is a **developer-side static analysis tool** that scans source files for hardcoded credentials. Understanding its trust boundaries is important:

### What CredRedactor protects against

- Accidentally committing hardcoded API keys, tokens, passwords, and private keys.
- Credentials in assignment statements, XML attributes, connection strings, PEM blocks, and multi-line strings.
- Re-flagging already-redacted values (the sentinel `REDACTED_BY_CREDREDACTOR` is in the safe-values list).

### What CredRedactor does NOT protect against

- **Obfuscated credentials:** Base64-encoded secrets, encrypted blobs (other than SOPS), or credentials split across multiple files.
- **Runtime secrets:** Credentials injected via environment variables, secret managers, or APIs at runtime are intentionally ignored (these are the *correct* pattern).
- **Binary files:** Only text-based source files are scanned; binary formats (`.exe`, `.zip`, `.png`, etc.) are skipped.
- **Determined adversaries:** An attacker with write access to your codebase could craft evasion patterns. CredRedactor is a safety net, not a security boundary.

### Trust boundaries

| Component                   | Trust Level | Notes                                                                   |
|-----------------------------|-------------|-------------------------------------------------------------------------|
| Source files being scanned  | Untrusted   | May contain adversarial content; regex patterns are hardened against ReDoS |
| `.credredactor.toml` config | Semi-trusted | Can adjust thresholds and safe-values; traversal limited to 5 parent dirs |
| `.credredactorignore`       | Semi-trusted | Can suppress findings for specific files, lines, or values              |
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
- Config injection (malicious `.credredactor.toml` or `.credredactorignore` causing unsafe behavior).

The following are **out of scope**:

- Known limitations listed in the "What CredRedactor does NOT protect against" section above.
- Vulnerabilities in dependencies (report these to the upstream project).
- Social engineering or phishing attacks.
