"""
Core scanning logic: line-level and file-level credential detection.

Addresses: #3 (inline suppression in scan), #10 (multi-line awareness),
           #12 (severity), #13 (fixed ASSIGNMENT_RE), #15 (.env.* files),
           #18 (PEM key blocks)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

from .config import Config
from .patterns import (
    _PEM_KEY_RE,
    ASSIGNMENT_RE,
    CRED_VAR_PATTERNS,
    DYNAMIC_LOOKUP_RE,
    SAFE_VALUES,
    SCAN_EXTENSIONS,
    VALUE_PATTERNS,
    xml_attr_finditer,
)
from .suppressions import AllowList, has_inline_suppression
from .utils import detect_encoding, entropy

# Global defaults (can be overridden by Config)
ENTROPY_THRESHOLD = 3.5
MIN_VALUE_LENGTH = 8

# Max lines to skip inside a PEM block before force-resetting (CVE-02 fix)
_MAX_PEM_BLOCK_LINES = 100

# Max file size to scan (bytes) — skip silently above this (HIGH-05 fix)
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Function call heuristic: identifier(...) pattern
_FUNC_CALL_RE = re.compile(
    r'^[a-zA-Z_][\w.]*\(.*\)$', re.DOTALL,
)


def _is_safe_value(val: str, extra_safe: set[str] | None = None) -> bool:
    """Return True if the value is clearly NOT a real hardcoded credential."""
    raw = val.strip()
    cleaned = raw.lower().strip('"\'')

    safe = SAFE_VALUES | extra_safe if extra_safe else SAFE_VALUES
    if cleaned in safe:
        return True

    # Environment variable reference ($VAR, ${VAR}, ${{VAR}})
    if cleaned.startswith('$'):
        return True

    # Template variable reference (${VAR} or {%...%} Jinja) — must have
    # the full template syntax, not bare curly braces (CVE-03 fix)
    if cleaned.startswith('${') or cleaned.startswith('{%'):
        return True

    # Function call: full value looks like identifier(...) (CVE-01 fix)
    # e.g. get_secret(), Variable.get("key"), os.getenv("X")
    if _FUNC_CALL_RE.match(raw):
        return True

    # File paths: ./, ~/, Windows drive letter
    # NOTE: bare / prefix is NOT safe (could hide creds); require ./ or ~/
    if (cleaned.startswith('./')
            or cleaned.startswith('~/')
            or (len(cleaned) >= 3 and cleaned[1:3] in (':\\', ':/'))):
        return True

    # URLs without embedded credentials
    if '://' in cleaned and '@' not in cleaned:
        if cleaned.startswith(('http', 'ftp')):
            return True

    # Path-like strings: require high slash density (>20%) AND at least
    # 3 slashes to reduce false negatives (HIGH-02 fix)
    slash_count = raw.count('/')
    if slash_count >= 3 and (slash_count / max(len(raw), 1)) > 0.20:
        return True

    return False


def _severity_for_variable(var_name: str) -> str:
    """Assign severity based on the variable name pattern."""
    low = var_name.lower()
    if any(kw in low for kw in ('password', 'passwd', 'passphrase', 'private_key', 'secret_key')):
        return 'high'
    if any(kw in low for kw in ('token', 'api_key', 'apikey', 'access_key')):
        return 'high'
    if any(kw in low for kw in ('client_id', 'tenant_id', 'app_id')):
        return 'low'
    return 'medium'


def scan_line(
    lineno: int,
    line: str,
    filepath: str,
    *,
    config: Optional[Config] = None,
    allowlist: Optional[AllowList] = None,
) -> list[dict]:
    """Analyse a single line and return a list of credential findings."""
    findings: list[dict] = []
    stripped = line.strip()

    if not stripped:
        return findings

    # #3 — inline suppression
    if has_inline_suppression(line):
        return findings

    ent_threshold = config.entropy_threshold if config else ENTROPY_THRESHOLD
    min_len = config.min_value_length if config else MIN_VALUE_LENGTH
    extra_safe = config.extra_safe_values if config else None

    is_comment = stripped.startswith('#') or stripped.startswith('//')

    # --- 1. High-value VALUE_PATTERNS scan ---
    if not is_comment:
        for pattern, label, min_ent, severity in VALUE_PATTERNS:
            for match in pattern.finditer(line):
                val = match.group(0)

                # high-entropy string: additional path/slash guard
                if label == 'high-entropy string':
                    if val.count('/') > 2:
                        continue
                    start = match.start()
                    if start == 0 or line[start - 1] not in ('"', "'"):
                        continue

                if _is_safe_value(val, extra_safe):
                    continue
                if len(val) < min_len and label != 'private key header':
                    continue
                if min_ent > 0 and entropy(val) < min_ent:
                    continue

                # Allowlist check
                if allowlist and allowlist.is_suppressed(filepath, lineno, val):
                    continue

                findings.append({
                    'file':          filepath,
                    'line':          lineno,
                    'type':          f'pattern:{label}',
                    'severity':      severity,
                    'full_value':    val,
                    'value_preview': val[:60] + ('...' if len(val) > 60 else ''),
                    'raw':           line.rstrip(),
                })
            if findings:
                return findings

    # --- 2. XML attribute check (#21) ---
    if not is_comment:
        for xml_key, xml_val in xml_attr_finditer(line):
            if not CRED_VAR_PATTERNS.search(xml_key):
                continue
            if _is_safe_value(xml_val, extra_safe):
                continue
            if len(xml_val.strip()) < min_len:
                continue
            if entropy(xml_val.strip()) < ent_threshold:
                continue
            if allowlist and allowlist.is_suppressed(filepath, lineno, xml_val):
                continue
            findings.append({
                'file':          filepath,
                'line':          lineno,
                'type':          f'xml-attr:{xml_key}',
                'severity':      _severity_for_variable(xml_key),
                'full_value':    xml_val,
                'value_preview': xml_val[:60] + ('...' if len(xml_val) > 60 else ''),
                'raw':           line.rstrip(),
            })
        if findings:
            return findings

    # --- 3. Assignment check ---
    if is_comment and '=' not in line and ':' not in line:
        return findings
    if is_comment and any(kw in stripped for kw in ('def ', 'async def ', 'class ')):
        return findings

    code_start = stripped.lstrip()
    if code_start.startswith(('def ', 'async def ', 'class ')):
        return findings

    if DYNAMIC_LOOKUP_RE.search(line):
        return findings

    for match in ASSIGNMENT_RE.finditer(line):
        var = match.group('var')
        # #13 fix: use the correct capture group (quoted vs unquoted)
        val = match.group('val_q') or match.group('val_u') or ''

        if not CRED_VAR_PATTERNS.search(var):
            continue
        if _is_safe_value(val, extra_safe):
            continue
        val_stripped = val.strip()
        if len(val_stripped) < min_len:
            continue
        if entropy(val_stripped) < ent_threshold:
            continue
        if allowlist and allowlist.is_suppressed(filepath, lineno, val_stripped):
            continue

        findings.append({
            'file':          filepath,
            'line':          lineno,
            'type':          f'variable:{var}',
            'severity':      _severity_for_variable(var),
            'full_value':    val_stripped,
            'value_preview': val_stripped[:60] + ('...' if len(val_stripped) > 60 else ''),
            'raw':           line.rstrip(),
        })

    return findings


def scan_file(
    filepath: str,
    *,
    config: Optional[Config] = None,
    allowlist: Optional[AllowList] = None,
) -> list[dict]:
    """Scan a single file for credential findings.

    Addresses #16 (encoding detection), #18 (PEM multi-line).
    """
    findings: list[dict] = []

    # HIGH-05 — file size guard to prevent OOM on huge files
    try:
        file_size = Path(filepath).stat().st_size
        if file_size > _MAX_FILE_SIZE:
            print(f'[WARN] Skipping {filepath}: file too large '
                  f'({file_size / 1024 / 1024:.1f} MB > '
                  f'{_MAX_FILE_SIZE / 1024 / 1024:.0f} MB limit)',
                  file=sys.stderr)
            return findings
    except OSError:
        pass  # proceed; open() will fail with a better message

    # #16 — detect encoding
    encoding = detect_encoding(filepath)

    try:
        with open(filepath, encoding=encoding, errors='surrogateescape') as fh:
            lines = fh.readlines()
    except (OSError, PermissionError) as exc:
        print(f'[WARN] Cannot read {filepath}: {exc}', file=sys.stderr)
        return findings

    # Strip BOM from first line if present
    if lines and lines[0].startswith('\ufeff'):
        lines[0] = lines[0][1:]

    # #18 — PEM private key block detection (multi-line)
    # CVE-02 fix: track lines inside PEM block; force-reset after
    # _MAX_PEM_BLOCK_LINES to prevent unclosed blocks from suppressing
    # the rest of the file.
    in_pem_block = False
    pem_block_lines = 0
    for lineno, line in enumerate(lines, start=1):
        if _PEM_KEY_RE.search(line):
            in_pem_block = True
            pem_block_lines = 0
            # Check suppression — still skip body lines even if header suppressed
            if has_inline_suppression(line):
                continue
            if allowlist and allowlist.is_suppressed(filepath, lineno, line.strip()):
                continue
            findings.append({
                'file':          filepath,
                'line':          lineno,
                'type':          'pattern:private key block',
                'severity':      'critical',
                'full_value':    line.strip(),
                'value_preview': line.strip()[:60],
                'raw':           line.rstrip(),
            })
        elif in_pem_block and '-----END' in line and 'PRIVATE KEY' in line:
            in_pem_block = False
            pem_block_lines = 0
        elif in_pem_block:
            pem_block_lines += 1
            if pem_block_lines > _MAX_PEM_BLOCK_LINES:
                # CVE-02: unclosed PEM block — stop suppressing lines
                in_pem_block = False
                pem_block_lines = 0
                print(f'[WARN] {filepath}:{lineno}: unclosed PEM block '
                      f'(>{_MAX_PEM_BLOCK_LINES} lines) — resuming scan',
                      file=sys.stderr)
                findings.extend(scan_line(lineno, line, filepath,
                                          config=config, allowlist=allowlist))
            else:
                continue  # skip lines inside PEM block
        else:
            findings.extend(scan_line(lineno, line, filepath,
                                      config=config, allowlist=allowlist))

    # #10 — basic multi-line detection: triple-quoted strings in Python
    _scan_multiline_strings(filepath, lines, findings, config, allowlist)

    return findings


def _scan_multiline_strings(
    filepath: str,
    lines: list[str],
    existing_findings: list[dict],
    config: Optional[Config],
    allowlist: Optional[AllowList],
) -> None:
    """Detect credentials inside triple-quoted strings and JS template literals.

    This is a best-effort heuristic: it concatenates the contents of multi-line
    string blocks and runs the value-pattern scan on the combined text.
    """
    already_flagged = {f['line'] for f in existing_findings}
    min_len = config.min_value_length if config else MIN_VALUE_LENGTH
    extra_safe = config.extra_safe_values if config else None

    # Find triple-quote blocks (Python) and template literal blocks (JS/TS)
    delimiters = [('"""', '"""'), ("'''", "'''"), ('`', '`')]

    full_text = ''.join(lines)
    for open_delim, close_delim in delimiters:
        start = 0
        while True:
            idx = full_text.find(open_delim, start)
            if idx < 0:
                break
            end_idx = full_text.find(close_delim, idx + len(open_delim))
            if end_idx < 0:
                break
            block = full_text[idx + len(open_delim):end_idx]
            # Determine line number of the opening delimiter
            block_lineno = full_text[:idx].count('\n') + 1
            if block_lineno in already_flagged:
                start = end_idx + len(close_delim)
                continue

            # Run value patterns on the block
            for pattern, label, min_ent, severity in VALUE_PATTERNS:
                for match in pattern.finditer(block):
                    val = match.group(0)
                    if _is_safe_value(val, extra_safe):
                        continue
                    if len(val) < min_len and label != 'private key header':
                        continue
                    if min_ent > 0 and entropy(val) < min_ent:
                        continue
                    if allowlist and allowlist.is_suppressed(filepath, block_lineno, val):
                        continue
                    existing_findings.append({
                        'file':          filepath,
                        'line':          block_lineno,
                        'type':          f'multiline:{label}',
                        'severity':      severity,
                        'full_value':    val,
                        'value_preview': val[:60] + ('...' if len(val) > 60 else ''),
                        'raw':           block.replace('\n', '\\n')[:120],
                    })
                    break  # one finding per block is enough

            start = end_idx + len(close_delim)


def should_scan_file(
    filename: str,
    extra_extensions: set[str] | None = None,
) -> bool:
    """Return True if the filename's extension (or name) is in the scan list.

    #15: Handles .env.* variants (e.g. .env.local, .env.production).
    MED-04: Tightened .env prefix matching to avoid false hits.
    """
    p = Path(filename)
    suffix = p.suffix.lower() or p.name.lower()

    extensions = SCAN_EXTENSIONS | extra_extensions if extra_extensions else SCAN_EXTENSIONS
    if suffix in extensions:
        return True

    # #15 — .env.* variants: .env.local, .env.staging, .env.production
    # MED-04: require .env or .env.<suffix> pattern, not arbitrary .env* prefix
    name_lower = p.name.lower()
    if name_lower == '.env' or name_lower == 'env':
        return True
    if name_lower.startswith('.env.') or name_lower.startswith('.env-'):
        return True

    return False
