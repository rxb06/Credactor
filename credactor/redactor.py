"""
File modification: backup, batch replacement, env-var mode.

Addresses: #1 (backup), #5 (env var replacement), #14 (batch per-file),
           #16 (encoding-aware), #30 (loud sentinel)
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

from .config import Config
from .utils import detect_encoding


# ---------------------------------------------------------------------------
# Replacement value generation (#5, #30)
# ---------------------------------------------------------------------------
def _make_replacement(
    finding: dict,
    config: Config,
    filepath: str,
) -> str:
    """Produce the replacement string for a credential finding.

    Modes (config.replace_mode):
      - 'sentinel':  REDACTED_BY_CREDACTOR  (or config.custom_replacement)
      - 'env':       os.environ["VAR_NAME"]  (Python-style env var reference)
      - 'custom':    config.custom_replacement
    """
    mode = config.replace_mode

    if mode == 'env':
        # Derive env var name from the variable name in the finding
        var_name = _derive_env_var_name(finding)
        ext = Path(filepath).suffix.lower()
        return _env_ref_for_language(var_name, ext)

    if mode == 'custom':
        return config.custom_replacement

    # Default sentinel
    return config.custom_replacement


def _derive_env_var_name(finding: dict) -> str:
    """Extract a reasonable env var name from the finding type."""
    ftype = finding.get('type', '')
    # variable:api_key -> API_KEY
    if ftype.startswith('variable:'):
        name = ftype.split(':', 1)[1]
        # Remove dotted prefixes (e.g. self.api_key -> api_key)
        if '.' in name:
            name = name.rsplit('.', 1)[1]
        return name.upper().replace('-', '_')
    # pattern:AWS access key -> AWS_ACCESS_KEY
    if ftype.startswith('pattern:') or ftype.startswith('xml-attr:'):
        label = ftype.split(':', 1)[1]
        return label.upper().replace(' ', '_').replace('-', '_')
    return 'CREDENTIAL'


def _env_ref_for_language(var_name: str, ext: str) -> str:
    """Generate a language-appropriate env var reference."""
    if ext in ('.py',):
        return f'os.environ["{var_name}"]'
    if ext in ('.js', '.ts', '.jsx', '.tsx'):
        return f'process.env.{var_name}'
    if ext in ('.rb',):
        return f"ENV['{var_name}']"
    if ext in ('.go',):
        return f'os.Getenv("{var_name}")'
    if ext in ('.java', '.kt'):
        return f'System.getenv("{var_name}")'
    if ext in ('.php',):
        return f"getenv('{var_name}')"
    if ext in ('.sh', '.bash', '.env') or ext.startswith('.env'):
        return f'${{{var_name}}}'
    if ext in ('.yaml', '.yml', '.toml', '.cfg', '.ini', '.conf'):
        return f'${{{var_name}}}'
    # Fallback
    return f'${{{var_name}}}'


# ---------------------------------------------------------------------------
# Backup (#1)
# ---------------------------------------------------------------------------
def _create_backup(filepath: str) -> str | None:
    """Create a .bak copy of the file. Returns backup path or None on failure."""
    bak = filepath + '.bak'
    try:
        shutil.copy2(filepath, bak)
        return bak
    except (OSError, PermissionError) as exc:
        print(f'  [WARN] Could not create backup {bak}: {exc}', file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Batch replacement per file (#14)
# ---------------------------------------------------------------------------
def batch_replace_in_file(
    filepath: str,
    file_findings: list[dict],
    config: Config,
) -> tuple[int, int]:
    """Replace all findings in a single file in one read-modify-write pass.

    Applies replacements bottom-to-top to preserve line numbers.
    Returns (replaced_count, failed_count).

    Addresses #1 (backup), #14 (batch), #16 (encoding-aware).
    """
    if not file_findings:
        return 0, 0

    # #16 — detect encoding
    encoding = detect_encoding(filepath)

    # Preserve file permissions
    try:
        orig_stat = os.stat(filepath)
        orig_mode = stat.S_IMODE(orig_stat.st_mode)
    except OSError:
        orig_mode = None

    try:
        with open(filepath, encoding=encoding, errors='surrogateescape') as fh:
            lines = fh.readlines()
    except (OSError, PermissionError) as exc:
        print(f'  [ERROR] Cannot read {filepath}: {exc}', file=sys.stderr)
        return 0, len(file_findings)

    # #1 — backup before modifying
    if not config.no_backup:
        bak = _create_backup(filepath)
        if bak is None:
            print(f'  [ERROR] Backup failed for {filepath} — skipping replacements.',
                  file=sys.stderr)
            return 0, len(file_findings)

    replaced = 0
    failed = 0

    # Sort by line number descending so earlier replacements don't shift later ones
    sorted_findings = sorted(file_findings, key=lambda f: f['line'], reverse=True)

    for finding in sorted_findings:
        lineno = finding['line']
        full_value = finding['full_value']
        idx = lineno - 1

        if idx >= len(lines):
            print(f'  [WARN] Line {lineno} out of range in {filepath} — skipping.')
            failed += 1
            continue

        original = lines[idx]
        if full_value not in original:
            print(f'  [WARN] Value no longer found on line {lineno} (already replaced?).')
            failed += 1
            continue

        replacement = _make_replacement(finding, config, filepath)
        lines[idx] = original.replace(full_value, replacement, 1)
        replaced += 1

    # Write back
    try:
        with open(filepath, 'w', encoding=encoding, errors='surrogateescape') as fh:
            fh.writelines(lines)
    except (OSError, PermissionError) as exc:
        print(f'  [ERROR] Cannot write {filepath}: {exc}', file=sys.stderr)
        return 0, len(file_findings)

    # Restore original file permissions
    if orig_mode is not None:
        try:
            os.chmod(filepath, orig_mode)
        except OSError:
            pass

    return replaced, failed


def replace_single(
    filepath: str,
    finding: dict,
    config: Config,
) -> bool:
    """Replace a single finding. Used in interactive mode.

    Returns True on success.
    """
    replaced, failed = batch_replace_in_file(filepath, [finding], config)
    return replaced > 0


# ---------------------------------------------------------------------------
# Interactive review
# ---------------------------------------------------------------------------
def interactive_review(
    findings: list[dict],
    root: str,
    config: Config,
) -> int:
    """Walk through every finding and ask the user whether to replace it.

    Returns the number of unresolved findings (for exit-code use).
    """
    root_path = Path(root).resolve()
    total = len(findings)
    replaced = 0
    skipped = 0

    replacement_desc = config.custom_replacement
    if config.replace_mode == 'env':
        replacement_desc = 'env var reference'

    from .utils import mask_secret

    print(f'{"=" * 70}')
    print(f'  INTERACTIVE REDACTION  --  {total} credential(s) found')
    print(f"  Answer y to replace each value with '{replacement_desc}', n (or Enter) to skip.")
    print(f'{"=" * 70}\n')

    for i, finding in enumerate(findings, 1):
        try:
            rel = Path(finding['file']).relative_to(root_path)
        except ValueError:
            rel = Path(finding['file'])

        masked = mask_secret(finding['full_value'])

        print(f'  [{i}/{total}]  {rel}  --  line {finding["line"]}')
        print(f'  Type     : {finding["type"]}')
        print(f'  Severity : {finding.get("severity", "medium")}')
        print(f'  Value    : {masked}')
        print()

        while True:
            try:
                answer = input("  Replace? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print('\n\n  Interrupted -- no further changes made.')
                _print_summary(replaced, skipped, total)
                return total - replaced

            if answer in ('y', 'yes'):
                ok = replace_single(finding['file'], finding, config)
                if ok:
                    print('  -> Replaced.\n')
                    replaced += 1
                else:
                    print('  -> Replacement failed -- skipping.\n')
                    skipped += 1
                break
            elif answer in ('n', 'no', ''):
                print('  -- Skipped.\n')
                skipped += 1
                break
            else:
                print("  Please enter 'y' or 'n'.")

    _print_summary(replaced, skipped, total)
    return total - replaced


def fix_all(
    findings: list[dict],
    root: str,
    config: Config,
) -> int:
    """Replace all findings without prompting (#33).

    Returns the number of unresolved findings.
    """
    # Group by file for batch replacement
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f['file'], []).append(f)

    total_replaced = 0
    total_failed = 0

    for filepath, file_findings in by_file.items():
        r, f = batch_replace_in_file(filepath, file_findings, config)
        total_replaced += r
        total_failed += f

    _print_summary(total_replaced, total_failed, len(findings))
    return total_failed


def _print_summary(replaced: int, skipped: int, total: int) -> None:
    print(f'{"=" * 70}')
    print(f'  Summary:  {replaced} replaced  |  {skipped} skipped  |  {total} total')
    if replaced:
        print('  Reminder: rotate / revoke any credentials that were just redacted.')
        print('  WARNING:  .bak backup files contain original credentials.')
        print('            Delete them securely after verifying replacements.')
    print(f'{"=" * 70}\n')
