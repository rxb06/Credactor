"""
File modification: backup, batch replacement, env-var mode.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from .config import Config
from .utils import detect_encoding, sanitize_for_terminal

# SEC-10: Pattern for dangerous characters in replacement strings that could
# enable code injection when the replaced file is executed.
_UNSAFE_REPLACEMENT_RE = re.compile(
    r'[`$\\;|&]|__import__|eval\s*\(|exec\s*\(|system\s*\(|subprocess'
)

# SEC-28: Track whether plaintext backup warning has been shown this run
_backup_warned = False


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
        # SEC-30: Defence-in-depth — validate the sanitised var name (not the
        # full replacement, which intentionally contains shell metacharacters
        # like ${} for shell/YAML/config files).
        if _UNSAFE_REPLACEMENT_RE.search(var_name):
            return 'REDACTED_BY_CREDACTOR'
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
        raw = name.upper().replace('-', '_')
    # pattern:AWS access key -> AWS_ACCESS_KEY
    elif ftype.startswith('pattern:') or ftype.startswith('xml-attr:'):
        label = ftype.split(':', 1)[1]
        raw = label.upper().replace(' ', '_').replace('-', '_')
    # external:gitleaks:aws-access-token -> AWS_ACCESS_TOKEN
    elif ftype.startswith('external:'):
        label = ftype.rsplit(':', 1)[1]
        raw = label.upper().replace(' ', '_').replace('-', '_')
    else:
        return 'CREDENTIAL'

    # SEC-30: Strip non-identifier characters to prevent code injection via
    # crafted xml-attr keys (e.g. "password]);evil()//").  Environment variable
    # names must be alphanumeric + underscore only.
    sanitized = re.sub(r'[^A-Za-z0-9_]', '', raw)
    return sanitized if sanitized else 'CREDENTIAL'


def _env_ref_for_language(var_name: str, ext: str) -> str:
    """Generate a language-appropriate env var reference."""
    if ext in ('.py',):
        return f'os.environ["{var_name}"]'
    if ext in ('.js', '.ts', '.jsx', '.tsx'):
        return f'process.env["{var_name}"]'
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
def _create_backup(filepath: str, config: Config) -> str | None:
    """Create a .bak copy of the file. Returns backup path or None on failure.

    SEC-01: When ``config.secure_backup_dir`` is set, the backup is placed
    in that directory instead of beside the original file.
    """
    bak = filepath + '.bak'

    # SEC-09: Atomic backup via mkstemp (O_CREAT|O_EXCL prevents symlink race).
    # Previous approach used islink() + copy2() with a TOCTOU gap between
    # the check and the write.
    dir_name = os.path.dirname(filepath) or '.'
    tmp_bak: str | None = None
    try:
        fd, tmp_bak = tempfile.mkstemp(dir=dir_name, suffix='.credactor.bak')
        os.close(fd)
        shutil.copy2(filepath, tmp_bak)
        os.replace(tmp_bak, bak)
        tmp_bak = None  # rename succeeded
    except (OSError, PermissionError) as exc:
        print(f'  [WARN] Could not create backup {bak}: {exc}', file=sys.stderr)
        if tmp_bak is not None:
            try:
                os.unlink(tmp_bak)
            except OSError:
                pass
        return None

    # SEC-28: Warn once about plaintext backups when not using secure options
    global _backup_warned
    if not _backup_warned and not config.secure_delete and not config.secure_backup_dir:
        print('  [WARN] Plaintext backup created beside original file.',
              file=sys.stderr)
        print('    Use --secure-delete to auto-wipe, --secure-backup-dir to store '
              'outside repo, or --no-backup to skip.', file=sys.stderr)
        _backup_warned = True

    # SEC-01: Move backup to secure directory if configured
    if config.secure_backup_dir:
        dest_dir = Path(config.secure_backup_dir).resolve()
        # SEC-20: Refuse if secure-backup-dir is a symlink to untrusted location.
        # Return None to signal failure — caller will skip redaction for this file.
        if os.path.islink(config.secure_backup_dir):
            print(f'  [ERROR] --secure-backup-dir is a symlink (possible attack): '
                  f'{config.secure_backup_dir}', file=sys.stderr)
            print('  Refusing to proceed — backup security cannot be guaranteed.',
                  file=sys.stderr)
            # Clean up the in-repo backup we already created
            try:
                os.unlink(bak)
            except OSError:
                pass
            return None
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = str(dest_dir / Path(bak).name)
            shutil.move(bak, dest)
            return dest
        except (OSError, PermissionError) as exc:
            print(f'  [WARN] Could not move backup to {dest_dir}: {exc}',
                  file=sys.stderr)
            # Fall through — backup still exists at original location
    return bak


def _secure_delete(filepath: str) -> None:
    """SEC-01: Overwrite file with random bytes before unlinking."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'wb') as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
        os.unlink(filepath)
    except (OSError, PermissionError) as exc:
        print(f'  [WARN] Secure delete failed for {filepath}: {exc}',
              file=sys.stderr)


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

    # Preserve file permissions (SEC-22: include setuid/setgid/sticky bits)
    try:
        orig_stat = os.stat(filepath)
        orig_mode = orig_stat.st_mode & 0o7777  # full mode including setuid/setgid
    except OSError:
        orig_mode = None

    # SEC-15: Acquire advisory file lock to mitigate TOCTOU races between
    # read and replace. Uses fcntl on Unix; silently skipped on Windows.
    # On Windows fcntl is unavailable, so the handle must be closed
    # immediately — keeping it open would block os.replace() later.
    lock_fh = None
    try:
        lock_fh = open(filepath, 'r')  # noqa: SIM115
        try:
            import fcntl
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            # Windows: fcntl unavailable — close handle to avoid blocking
            # os.replace() which cannot overwrite an open file on Windows.
            lock_fh.close()
            lock_fh = None
        except OSError:
            pass  # Lock contention — proceed without lock
    except OSError:
        pass

    try:
        with open(filepath, encoding=encoding, errors='surrogateescape') as fh:
            lines = fh.readlines()
    except (OSError, PermissionError) as exc:
        print(f'  [ERROR] Cannot read {filepath}: {exc}', file=sys.stderr)
        if lock_fh:
            lock_fh.close()
        return 0, len(file_findings)

    # #1 — backup before modifying (immediately after read per SEC-15)
    bak: str | None = None
    if not config.no_backup:
        bak = _create_backup(filepath, config)
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

    # Atomic write: write to temp file, then rename over original.
    # Prevents corruption if process crashes mid-write.
    # SEC-07: finally block ensures temp file cleanup even on unexpected crashes,
    # preventing plaintext credential residue on disk.
    dir_name = os.path.dirname(filepath) or '.'
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.credactor.tmp')
        with os.fdopen(fd, 'w', encoding=encoding, errors='surrogateescape') as fh:
            fh.writelines(lines)
        os.replace(tmp_path, filepath)
        tmp_path = None  # rename succeeded — nothing to clean up
    except (OSError, PermissionError) as exc:
        print(f'  [ERROR] Cannot write {filepath}: {exc}', file=sys.stderr)
        return 0, len(file_findings)
    finally:
        # SEC-07: Always remove temp file if it still exists (crash safety)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # Restore original file permissions
    if orig_mode is not None:
        try:
            os.chmod(filepath, orig_mode)
        except OSError:
            pass

    # SEC-01: Secure-delete backup after successful replacement
    if bak and config.secure_delete and replaced > 0:
        _secure_delete(bak)

    # SEC-15: Release advisory file lock
    if lock_fh:
        lock_fh.close()

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

        # SEC-16: Sanitize display strings to prevent terminal injection
        safe_rel = sanitize_for_terminal(str(rel))
        safe_type = sanitize_for_terminal(finding['type'])
        safe_masked = sanitize_for_terminal(masked)

        print(f'  [{i}/{total}]  {safe_rel}  --  line {finding["line"]}')
        print(f'  Type     : {safe_type}')
        print(f'  Severity : {finding.get("severity", "medium")}')
        print(f'  Value    : {safe_masked}')
        print()

        while True:
            try:
                answer = input("  Replace? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print(f'\n\n  Interrupted — {replaced} file(s) already '
                      f'modified. No further changes will be made.')
                if replaced and not config.no_backup:
                    print('  .bak backups exist for modified files.')
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
        print('  SECURITY: .bak backup files contain original credentials in PLAINTEXT.')
        print('            Use --secure-backup-dir to store backups outside the repo,')
        print('            or --secure-delete to overwrite backups after verification.')
        print('            At minimum, delete .bak files before committing.')
    print(f'{"=" * 70}\n')
