# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.3.x   | :white_check_mark: |
| < 2.3   | :x:                |

Only the latest minor release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using one of these methods:

1. **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository.
2. **Email:** Send details to the repository maintainer (see the commit history or profile for contact information).

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

## Scope

The following are **in scope** for security reports:

- Detection bypasses (crafted input that evades scanning).
- Credential leakage in tool output (unmasked secrets in reports, logs, or error messages).
- File system safety issues (path traversal, symlink attacks, TOCTOU races).
- Denial of service (ReDoS, OOM, infinite loops).
- Configuration injection (malicious `.credactor.toml` or `.credactorignore` causing unsafe behaviour).

The following are **out of scope**:

- Known limitations listed in the [security model](docs/security.md#known-limitations).
- Vulnerabilities in dependencies (report these to the upstream project).
- Social engineering or phishing attacks.

## Disclosure Policy

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix is released, we will:

1. Publish a GitHub Security Advisory with full details.
2. Credit the reporter (unless they prefer anonymity).
3. Tag the fix commit and release a patched version.

## Security Model and Hardening

For the full security model, trust boundaries, hardening measures, and known limitations, see [docs/security.md](docs/security.md).
