"""
Suppression mechanisms: inline comments and .credactorignore file.

Addresses: #3 (inline suppression), #4 (allowlist file)
"""

import fnmatch
import os
import sys
from pathlib import Path

from .patterns import SUPPRESS_RE


def has_inline_suppression(line: str) -> bool:
    """Return True if the line contains a ``credactor:ignore`` comment."""
    return bool(SUPPRESS_RE.search(line))


class AllowList:
    """Loads and matches entries from a ``.credactorignore`` file.

    Supported entry formats::

        # comment
        path/to/file.py          # ignore entire file (glob)
        path/to/file.py:42       # ignore specific file + line number
        **/test_*.py             # glob pattern
        secret_value_literal     # ignore a specific value anywhere
    """

    def __init__(self, root: str) -> None:
        self._file_globs: list[str] = []
        self._file_line: dict[str, set[int]] = {}
        self._value_literals: set[str] = set()
        self._root = Path(root).resolve()
        self._load()

    def _load(self) -> None:
        ignore_path = self._root / '.credactorignore'
        if not ignore_path.is_file():
            return
        try:
            with open(ignore_path, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # file:line entry
                    if ':' in line:
                        parts = line.rsplit(':', 1)
                        if parts[1].isdigit():
                            path_str = parts[0]
                            lineno = int(parts[1])
                            self._file_line.setdefault(path_str, set()).add(lineno)
                            continue
                    # glob-like or plain path
                    if any(c in line for c in ('*', '?', '/', os.sep, '.')):
                        # SEC-13: Warn on overly broad patterns that suppress everything
                        if line in ('*', '**', '**/*', '*.*'):
                            print(f'[WARN] .credactorignore contains overly broad '
                                  f'pattern "{line}" — this suppresses ALL files.',
                                  file=sys.stderr)
                        self._file_globs.append(line)
                    else:
                        # treat as a value literal to suppress
                        self._value_literals.add(line)
        except (OSError, PermissionError):
            pass

    def is_file_suppressed(self, filepath: str) -> bool:
        """Return True if the entire file is suppressed by a glob pattern."""
        try:
            rel = Path(filepath).resolve().relative_to(self._root).as_posix()
        except ValueError:
            rel = filepath
        return any(fnmatch.fnmatch(rel, g) for g in self._file_globs)

    def is_line_suppressed(self, filepath: str, lineno: int) -> bool:
        """Return True if a specific file:line is suppressed."""
        try:
            rel = Path(filepath).resolve().relative_to(self._root).as_posix()
        except ValueError:
            rel = filepath
        lines = self._file_line.get(rel, set())
        return lineno in lines

    def is_value_suppressed(self, value: str) -> bool:
        """Return True if the value literal is in the allowlist."""
        return value in self._value_literals

    def is_suppressed(self, filepath: str, lineno: int, value: str) -> bool:
        """Combined check for any suppression."""
        return (self.is_file_suppressed(filepath)
                or self.is_line_suppressed(filepath, lineno)
                or self.is_value_suppressed(value))
