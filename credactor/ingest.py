"""
External scanner ingestion: Gitleaks JSON and TruffleHog NDJSON.
SEC-40: All parsing uses stdlib json only (zero runtime deps policy).
"""
from __future__ import annotations

import functools
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Optional

from .config import Config
from .utils import detect_encoding
from .walker import _is_within_root

# Maximum number of findings to ingest to prevent memory exhaustion (SEC-40b)
_MAX_FINDINGS = 10_000
# Maximum Gitleaks report file size — guards against OOM before json.load()
# deserialises the full array.  100 MB >> any real report (10 k findings ≈ 5 MB).
_MAX_REPORT_BYTES = 100_000_000

# ---------------------------------------------------------------------------
# Severity mapping tables
# ---------------------------------------------------------------------------

_GITLEAKS_SEVERITY: dict[str, str] = {
    'aws-access-token': 'critical',
    'aws-secret-access-key': 'critical',
    'gcp-api-key': 'critical',
    'gcp-service-account': 'critical',
    'github-pat': 'critical',
    'github-fine-grained-pat': 'critical',
    'github-oauth': 'critical',
    'github-app-token': 'critical',
    'gitlab-pat': 'critical',
    'gitlab-pipeline-trigger-token': 'critical',
    'slack-bot-token': 'critical',
    'slack-user-token': 'critical',
    'slack-webhook-url': 'high',
    'stripe-access-token': 'critical',
    'twilio-api-key': 'critical',
    'sendgrid-api-token': 'critical',
    'npm-access-token': 'critical',
    'pypi-upload-token': 'critical',
    'private-key': 'critical',
    'generic-api-key': 'medium',
    'jwt': 'high',
    'password-in-url': 'high',
}


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _gitleaks_severity(rule_id: str, tags: list | None = None) -> str:
    """Map a Gitleaks RuleID (and optional Tags) to a Credactor severity string.

    Tags override: if any tag matches a severity level (case-insensitive),
    that takes precedence over the table lookup.
    """
    _severity_levels = {'critical', 'high', 'medium', 'low'}
    if tags:
        for tag in tags:
            if isinstance(tag, str) and tag.lower() in _severity_levels:
                return tag.lower()
    return _GITLEAKS_SEVERITY.get(rule_id, 'medium')


# ---------------------------------------------------------------------------
# Raw line synthesis
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=64)
def _read_file_lines(filepath: str) -> tuple[str, ...]:
    """Read all lines of a file and return as an immutable tuple (LRU-cached).

    Cached to avoid re-reading the same file for multiple findings.
    """
    enc = detect_encoding(filepath)
    try:
        with open(filepath, encoding=enc, errors='replace') as fh:
            return tuple(fh.readlines())
    except (OSError, PermissionError):
        return ()


def _synthesise_raw(filepath: str, lineno: int) -> str:
    """Read the source line at *lineno* (1-indexed) from *filepath*.

    Returns the line stripped of trailing whitespace, or ``""`` on any error.
    """
    try:
        lines = _read_file_lines(filepath)
        if lines and 1 <= lineno <= len(lines):
            return lines[lineno - 1].rstrip()
    except Exception:  # noqa: BLE001
        pass
    return ''


# ---------------------------------------------------------------------------
# Gitleaks parser
# ---------------------------------------------------------------------------

def ingest_gitleaks(
    filepath: str,
    target: str,
    *,
    config: Optional[Config] = None,
) -> list[dict]:
    """Parse a Gitleaks JSON report and return a list of Credactor finding dicts.

    SEC-40a: validates top-level is a list.
    SEC-40b: caps at 10,000 findings.
    SEC-40c: validates resolved paths are within the target directory.
    """
    verbose = config.verbose if config else False
    target_path = Path(target).resolve()
    if target_path.is_file():
        # Defensive guard: callers should pass the repo root directory, not a
        # file. Using the file's parent prevents broken path joins like
        # <file>/src/config.py, but a warning is emitted so the caller knows.
        if verbose:
            print(
                f'[WARN] ingest_gitleaks: target {str(target_path)!r} is a file; '
                f'using its parent directory for path resolution.',
                file=sys.stderr,
            )
        target_path = target_path.parent
    target_resolved = str(target_path)

    # SEC-40b: reject oversized files before json.load() reads the whole
    # array into memory — the 10,000-finding cap can only fire after full
    # deserialisation, so a gigantic file would OOM first.
    try:
        report_size = os.path.getsize(filepath)
    except OSError as exc:
        raise ValueError(
            f'Cannot open Gitleaks file {filepath!r}: {exc}'
        ) from exc
    if report_size > _MAX_REPORT_BYTES:
        raise ValueError(
            f'Gitleaks file {filepath!r} is {report_size:,} bytes; refusing to '
            f'parse files over {_MAX_REPORT_BYTES:,} bytes (SEC-40b memory guard).'
        )

    # Load JSON
    try:
        with open(filepath, encoding='utf-8', errors='replace') as fh:
            data = json.load(fh)
    except (OSError, PermissionError) as exc:
        raise ValueError(
            f'Cannot open Gitleaks file {filepath!r}: {exc}'
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f'Gitleaks file is not valid JSON ({filepath!r}): {exc}'
        ) from exc

    # SEC-40a: top-level must be a list
    if not isinstance(data, list):
        raise ValueError(
            f'Gitleaks report must be a JSON array at top level '
            f'(got {type(data).__name__}). File: {filepath!r}'
        )

    # SEC-40b: cap at 10,000
    if len(data) > _MAX_FINDINGS:
        print(
            f'[WARN] Gitleaks report contains {len(data)} findings; '
            f'truncating to {_MAX_FINDINGS}.',
            file=sys.stderr,
        )
        data = data[:_MAX_FINDINGS]

    findings: list[dict] = []

    for obj in data:
        if not isinstance(obj, dict):
            if verbose:
                print('[WARN] Skipping non-object entry in Gitleaks report.',
                      file=sys.stderr)
            continue

        # --- Secret ---
        secret = obj.get('Secret', '')
        if not isinstance(secret, str) or not secret:
            if verbose:
                print('[WARN] Skipping Gitleaks finding with empty Secret.',
                      file=sys.stderr)
            continue

        # --- File path ---
        # Use SymlinkFile if non-empty, otherwise File
        raw_file = obj.get('SymlinkFile') or obj.get('File', '')
        if not isinstance(raw_file, str) or not raw_file:
            if verbose:
                print('[WARN] Skipping Gitleaks finding with non-string or empty File.',
                      file=sys.stderr)
            continue

        # Resolve path relative to target; resolve symlinks so SEC-40c
        # containment check cannot be bypassed via a symlink pointing outside.
        resolved = str(Path(os.path.normpath(os.path.join(target_resolved, raw_file))).resolve())

        # SEC-40c: path traversal check (also catches symlinks outside root)
        if not _is_within_root(resolved, target_resolved):
            print(
                f'[WARN] Skipping Gitleaks finding: path {raw_file!r} resolves '
                f'outside target directory (possible path traversal).',
                file=sys.stderr,
            )
            continue

        if verbose and not os.path.isfile(resolved):
            print(f'[WARN] Gitleaks finding references missing file: {resolved!r}',
                  file=sys.stderr)

        # --- Line number ---
        line = obj.get('StartLine', 1)
        if not isinstance(line, int) or line < 1:
            line = 1

        # --- raw context line ---
        match_ctx = obj.get('Match', '')
        if isinstance(match_ctx, str) and match_ctx:
            raw = match_ctx
        else:
            raw = _synthesise_raw(resolved, line)

        # --- Type ---
        rule_id = obj.get('RuleID', 'unknown')
        ftype = f'external:gitleaks:{rule_id}'

        # --- Severity ---
        tags = obj.get('Tags') or []
        severity = _gitleaks_severity(rule_id, tags if isinstance(tags, list) else [])

        # --- Finding dict ---
        finding: dict = {
            'file': resolved,
            'line': line,
            'type': ftype,
            'severity': severity,
            'full_value': secret,
            'value_preview': secret[:60],
            'raw': raw,
        }

        # --- Commit (omit key when empty) ---
        commit = obj.get('Commit', '')
        if commit:
            finding['commit'] = commit[:12]

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# TruffleHog severity mapping table
# ---------------------------------------------------------------------------

_TRUFFLEHOG_SEVERITY: dict[str, str] = {
    'AWS': 'high',
    'GCP': 'high',
    'Azure': 'high',
    'GitHub': 'high',
    'GitHubApp': 'high',
    'GitLab': 'high',
    'Slack': 'high',
    'SlackWebhook': 'medium',
    'Stripe': 'high',
    'Twilio': 'high',
    'SendGrid': 'high',
    'Mailgun': 'high',
    'NPMToken': 'high',
    'PyPI': 'high',
    'PrivateKey': 'critical',
    'JWT': 'high',
    'MongoDB': 'high',
    'PostgreSQL': 'high',
    'MySQL': 'high',
}


def _trufflehog_severity(detector_name: str, verified: bool) -> str:
    """Map a TruffleHog DetectorName + Verified flag to a Credactor severity.

    Verified=True always escalates to critical regardless of DetectorName.
    """
    if verified:
        return 'critical'
    return _TRUFFLEHOG_SEVERITY.get(detector_name, 'medium')


# ---------------------------------------------------------------------------
# TruffleHog parser
# ---------------------------------------------------------------------------

def ingest_trufflehog(
    filepath: str,
    target: str,
    *,
    config: Optional[Config] = None,
) -> list[dict]:
    """Parse a TruffleHog NDJSON output file and return Credactor finding dicts.

    SEC-40a: each line is validated as a JSON object.
    SEC-40b: caps at 10,000 findings.
    SEC-40c: validates resolved paths are within the target directory.
    """
    verbose = config.verbose if config else False
    target_path = Path(target).resolve()
    if target_path.is_file():
        if verbose:
            print(
                f'[WARN] ingest_trufflehog: target {str(target_path)!r} is a file; '
                f'using its parent directory for path resolution.',
                file=sys.stderr,
            )
        target_path = target_path.parent
    target_resolved = str(target_path)

    try:
        fh = open(filepath, encoding='utf-8', errors='replace')
    except (OSError, PermissionError) as exc:
        raise ValueError(
            f'Cannot open TruffleHog file {filepath!r}: {exc}'
        ) from exc

    findings: list[dict] = []
    count = 0

    with fh:
        for lineno_file, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                if verbose:
                    print(
                        f'[WARN] TruffleHog file line {lineno_file}: '
                        f'skipping invalid JSON: {exc}',
                        file=sys.stderr,
                    )
                continue

            if not isinstance(obj, dict):
                if verbose:
                    print(
                        f'[WARN] TruffleHog file line {lineno_file}: '
                        f'skipping non-object JSON value.',
                        file=sys.stderr,
                    )
                continue

            # SEC-40b: cap at 10,000
            if count >= _MAX_FINDINGS:
                print(
                    f'[WARN] TruffleHog report exceeds {_MAX_FINDINGS} findings; '
                    f'truncating.',
                    file=sys.stderr,
                )
                break

            # --- Raw secret ---
            raw_secret = obj.get('Raw', '')
            if not isinstance(raw_secret, str) or not raw_secret:
                if verbose:
                    print(
                        f'[WARN] TruffleHog line {lineno_file}: '
                        f'skipping finding with empty Raw.',
                        file=sys.stderr,
                    )
                continue
            # TruffleHog URL-encodes special characters in URI-based credentials
            # (e.g. '@' → '%40' in MongoDB/PostgreSQL connection strings).
            # Decode so full_value matches the literal text in the source file.
            raw_secret = urllib.parse.unquote(raw_secret)

            # --- Source metadata ---
            source_meta = obj.get('SourceMetadata', {})
            data = source_meta.get('Data', {}) if isinstance(source_meta, dict) else {}

            file_path_raw: str = ''
            line_num: int = 1
            commit: str = ''
            source_found = False

            if isinstance(data, dict):
                # Filesystem source (preferred)
                fs = data.get('Filesystem')
                if isinstance(fs, dict):
                    file_path_raw = fs.get('file', '') or ''
                    line_num = fs.get('line', 1) or 1
                    source_found = True
                else:
                    # Git source
                    git = data.get('Git')
                    if isinstance(git, dict):
                        file_path_raw = git.get('file', '') or ''
                        line_num = git.get('line', 1) or 1
                        raw_commit = git.get('commit', '') or ''
                        if raw_commit:
                            commit = raw_commit[:12]
                        source_found = True

            if not source_found:
                if verbose:
                    supported = {'Filesystem', 'Git'}
                    unsupported = set(data.keys()) - supported if isinstance(data, dict) else set()
                    print(
                        f'[WARN] TruffleHog line {lineno_file}: '
                        f'unsupported source type '
                        f'{list(unsupported) if unsupported else "(unknown)"}; skipping.',
                        file=sys.stderr,
                    )
                continue

            if not isinstance(file_path_raw, str) or not file_path_raw:
                if verbose:
                    print(
                        f'[WARN] TruffleHog line {lineno_file}: '
                        f'skipping finding with non-string or empty file path.',
                        file=sys.stderr,
                    )
                continue

            # Resolve path relative to target
            resolved = str(
                Path(os.path.normpath(os.path.join(target_resolved, file_path_raw))).resolve()
            )

            # SEC-40c: path traversal check
            if not _is_within_root(resolved, target_resolved):
                print(
                    f'[WARN] Skipping TruffleHog finding: path {file_path_raw!r} resolves '
                    f'outside target directory (possible path traversal).',
                    file=sys.stderr,
                )
                continue

            if verbose and not os.path.isfile(resolved):
                print(
                    f'[WARN] TruffleHog finding references missing file: {resolved!r}',
                    file=sys.stderr,
                )

            # Validate line number
            if not isinstance(line_num, int) or line_num < 1:
                line_num = 1

            # --- Synthesise raw context line ---
            raw_ctx = _synthesise_raw(resolved, line_num)
            if not raw_ctx:
                raw_ctx = raw_secret  # fallback per plan section 3.2.1

            # --- Type ---
            detector_name = obj.get('DetectorName', 'unknown')
            if not isinstance(detector_name, str):
                detector_name = 'unknown'
            ftype = f'external:trufflehog:{detector_name}'

            # --- Severity ---
            verified = bool(obj.get('Verified', False))
            severity = _trufflehog_severity(detector_name, verified)

            # --- Finding dict ---
            finding: dict = {
                'file': resolved,
                'line': line_num,
                'type': ftype,
                'severity': severity,
                'full_value': raw_secret,
                'value_preview': raw_secret[:60],
                'raw': raw_ctx,
            }

            if commit:
                finding['commit'] = commit

            findings.append(finding)
            count += 1

    return findings
