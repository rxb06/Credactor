"""
Directory walking, git-staged scanning, git-history scanning, and parallelism.

Addresses: #6 (--staged), #11 (--scan-history), #26 (single os.walk),
           #27 (thread-pool parallelism)
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional

from .config import Config
from .gitignore import load_gitignore_patterns, matches_gitignore
from .patterns import SKIP_DIRS, SKIP_FILES
from .scanner import scan_file, should_scan_file
from .suppressions import AllowList


def _progress_callback_factory(total: int, no_color: bool) -> Callable[[int], None]:
    """Return a callback that prints a progress line to stderr."""
    def _progress(done: int) -> None:
        if sys.stderr.isatty() and not no_color:
            sys.stderr.write(f'\r  Scanning... {done}/{total} files')
            sys.stderr.flush()
            if done == total:
                sys.stderr.write('\r' + ' ' * 40 + '\r')
                sys.stderr.flush()
    return _progress


def walk_and_scan(
    root: str,
    config: Config,
    allowlist: Optional[AllowList] = None,
) -> tuple[list[dict], list[str], list[str]]:
    """Single-pass directory walk (#26).

    Returns (findings, gitignore_skipped, json_files_available).
    """
    root_path = Path(root).resolve()
    gi_patterns = load_gitignore_patterns(root)

    scannable: list[str] = []
    json_files: list[str] = []
    gitignore_skipped: list[str] = []

    extra_skip_dirs = SKIP_DIRS | config.skip_dirs
    extra_skip_files = SKIP_FILES | config.skip_files

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in extra_skip_dirs]
        for filename in filenames:
            if filename in extra_skip_files:
                continue
            full_path = os.path.join(dirpath, filename)

            # Gitignore check
            if gi_patterns and matches_gitignore(full_path, gi_patterns):
                gitignore_skipped.append(full_path)
                continue

            # Allowlist file-level suppression
            if allowlist and allowlist.is_file_suppressed(full_path):
                continue

            p = Path(filename)
            suffix = p.suffix.lower()

            if suffix == '.json':
                json_files.append(full_path)
                continue

            if should_scan_file(filename, config.extra_extensions):
                scannable.append(full_path)

    # #27 — parallel file scanning
    findings = _parallel_scan(scannable, config, allowlist)

    return findings, gitignore_skipped, json_files


def _parallel_scan(
    files: list[str],
    config: Config,
    allowlist: Optional[AllowList],
) -> list[dict]:
    """Scan files using a thread pool (#27)."""
    all_findings: list[dict] = []

    if not files:
        return all_findings

    progress = _progress_callback_factory(len(files), config.no_color)
    done_count = 0

    # Use threads (I/O-bound); limit to 8 workers to avoid fd exhaustion
    max_workers = min(8, len(files))
    if max_workers <= 1 or len(files) <= 4:
        # Sequential for small batches
        for i, fp in enumerate(files, 1):
            all_findings.extend(scan_file(fp, config=config, allowlist=allowlist))
            progress(i)
        return all_findings

    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(scan_file, fp, config=config, allowlist=allowlist): fp
            for fp in files
        }
        for future in as_completed(future_to_file):
            with lock:
                done_count += 1
                progress(done_count)
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    fp = future_to_file[future]
                    print(f'[WARN] Error scanning {fp}: {exc}',
                          file=sys.stderr)

    return all_findings


# ---------------------------------------------------------------------------
# #6 — Git staged-only scanning
# ---------------------------------------------------------------------------
def scan_staged_files(
    root: str,
    config: Config,
    allowlist: Optional[AllowList] = None,
) -> list[dict]:
    """Scan only files staged in the git index (``git diff --cached``)."""
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
            capture_output=True, text=True, cwd=root, timeout=30,
        )
        if result.returncode != 0:
            print(f'[ERROR] git diff failed: {result.stderr.strip()}', file=sys.stderr)
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f'[ERROR] Cannot run git: {exc}', file=sys.stderr)
        return []

    root_path = Path(root).resolve()
    staged = []
    for line in result.stdout.strip().splitlines():
        full_path = str(root_path / line)
        if os.path.isfile(full_path) and should_scan_file(line, config.extra_extensions):
            staged.append(full_path)

    if not staged:
        return []

    return _parallel_scan(staged, config, allowlist)


# ---------------------------------------------------------------------------
# #11 — Git history scanning
# ---------------------------------------------------------------------------
def scan_git_history(
    root: str,
    config: Config,
    allowlist: Optional[AllowList] = None,
    max_commits: int = 100,
) -> list[dict]:
    """Scan ``git log -p`` output for credentials in committed history."""
    try:
        result = subprocess.run(
            ['git', 'log', f'-{max_commits}', '-p', '--diff-filter=ACMR',
             '--no-color', '--format=commit %H'],
            capture_output=True, text=True, cwd=root, timeout=120,
        )
        if result.returncode != 0:
            print(f'[ERROR] git log failed: {result.stderr.strip()}', file=sys.stderr)
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f'[ERROR] Cannot run git: {exc}', file=sys.stderr)
        return []

    findings: list[dict] = []
    current_commit = ''
    current_file = ''
    diff_lineno = 0

    from .scanner import scan_line

    for line in result.stdout.splitlines():
        if line.startswith('commit '):
            current_commit = line.split(' ', 1)[1][:12]
            continue
        if line.startswith('+++ b/'):
            current_file = line[6:]
            diff_lineno = 0
            continue
        if line.startswith('@@'):
            # Parse hunk header: @@ -old,count +new,count @@
            # MED-01 fix: use regex instead of naive split on '+'
            hunk_match = re.search(r'\+(\d+)', line)
            if hunk_match:
                diff_lineno = int(hunk_match.group(1)) - 1
            else:
                diff_lineno = 0
            continue
        if line.startswith('+') and not line.startswith('+++'):
            diff_lineno += 1
            added_line = line[1:]  # strip the leading '+'
            line_findings = scan_line(diff_lineno, added_line,
                                      f'{current_file} (commit {current_commit})',
                                      config=config, allowlist=allowlist)
            for f in line_findings:
                f['commit'] = current_commit
            findings.extend(line_findings)
        elif not line.startswith('-'):
            diff_lineno += 1

    return findings


# ---------------------------------------------------------------------------
# JSON file selection (interactive, kept from original)
# ---------------------------------------------------------------------------
def select_json_files(
    json_files: list[str],
    root: str,
) -> list[str]:
    """Let the user pick which .json files to scan from a numbered list."""
    root_path = Path(root).resolve()

    if not json_files:
        print('  [INFO] No .json files available to scan.\n')
        return []

    print(f'\n  Found {len(json_files)} .json file(s):\n')
    for i, path in enumerate(json_files, 1):
        try:
            rel = Path(path).relative_to(root_path)
        except ValueError:
            rel = Path(path)
        print(f'    [{i:>3}]  {rel}')

    print()
    print('  Enter file numbers to scan (e.g. 1,3,5  or  2-4  or  all):')

    while True:
        try:
            answer = input('  Selection: ').strip().lower()
        except (KeyboardInterrupt, EOFError):
            print('\n  Skipping .json scan.')
            return []

        if not answer:
            print('  Skipping .json scan.\n')
            return []

        if answer == 'all':
            return json_files

        selected: list[str] = []
        valid = True
        for token in answer.replace(' ', '').split(','):
            if '-' in token:
                parts = token.split('-', 1)
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    lo, hi = int(parts[0]), int(parts[1])
                    if 1 <= lo <= hi <= len(json_files):
                        selected.extend(json_files[lo - 1:hi])
                    else:
                        print(f'  [ERROR] Range {token} out of bounds (1-{len(json_files)}).')
                        valid = False
                        break
                else:
                    print(f'  [ERROR] Invalid range: {token}')
                    valid = False
                    break
            elif token.isdigit():
                idx = int(token)
                if 1 <= idx <= len(json_files):
                    selected.append(json_files[idx - 1])
                else:
                    print(f'  [ERROR] Number {token} out of bounds (1-{len(json_files)}).')
                    valid = False
                    break
            else:
                print(f'  [ERROR] Unrecognised token: {token!r}')
                valid = False
                break

        if valid:
            seen: set[str] = set()
            unique = [p for p in selected if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]
            print(f'  Selected {len(unique)} file(s) for .json scan.\n')
            return unique
