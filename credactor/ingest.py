"""
External scanner ingestion: Gitleaks JSON and TruffleHog NDJSON.
SEC-40: All parsing uses stdlib json only (zero runtime deps policy).
"""
from __future__ import annotations

import functools
import json
import os
import sys
from pathlib import Path
from typing import Optional

from .config import Config
from .utils import detect_encoding
from .walker import _is_within_root

# Maximum number of findings to ingest to prevent memory exhaustion (SEC-40b)
_MAX_FINDINGS = 10_000

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
    target_resolved = str(Path(target).resolve())

    # Load JSON
    try:
        with open(filepath, encoding='utf-8', errors='replace') as fh:
            data = json.load(fh)
    except (OSError, PermissionError) as exc:
        print(f'[ERROR] Cannot open Gitleaks file {filepath!r}: {exc}',
              file=sys.stderr)
        return []
    except json.JSONDecodeError as exc:
        print(f'[ERROR] Gitleaks file is not valid JSON ({filepath!r}): {exc}',
              file=sys.stderr)
        return []

    # SEC-40a: top-level must be a list
    if not isinstance(data, list):
        print(
            f'[ERROR] Gitleaks report must be a JSON array at top level '
            f'(got {type(data).__name__}). File: {filepath!r}',
            file=sys.stderr,
        )
        return []

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
        if not secret:
            if verbose:
                print('[WARN] Skipping Gitleaks finding with empty Secret.',
                      file=sys.stderr)
            continue

        # --- File path ---
        # Use SymlinkFile if non-empty, otherwise File
        raw_file = obj.get('SymlinkFile') or obj.get('File', '')
        if not raw_file:
            if verbose:
                print('[WARN] Skipping Gitleaks finding with empty File.',
                      file=sys.stderr)
            continue

        # Resolve path relative to target
        resolved = os.path.normpath(os.path.join(target_resolved, raw_file))

        # SEC-40c: path traversal check
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
        if match_ctx:
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
