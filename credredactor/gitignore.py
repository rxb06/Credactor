"""
.gitignore pattern loading and matching.

Extracted from the original credential_redactor.py with no logic changes.
"""

import fnmatch
import os
from pathlib import Path

from .patterns import SKIP_DIRS


def load_gitignore_patterns(root: str) -> list[tuple[str, str]]:
    """Walk *root* and collect ``(pattern, base_dir)`` from every ``.gitignore``."""
    patterns: list[tuple[str, str]] = []
    root_path = Path(root).resolve()

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if '.gitignore' in filenames:
            gi_path = os.path.join(dirpath, '.gitignore')
            try:
                with open(gi_path, encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#') or stripped.startswith('!'):
                            continue
                        patterns.append((stripped, dirpath))
            except (OSError, PermissionError):
                pass

    return patterns


def matches_gitignore(filepath: str, patterns: list[tuple[str, str]]) -> bool:
    """Return True if *filepath* is covered by any collected ``.gitignore`` pattern."""
    file_path = Path(filepath).resolve()

    for pattern, base_dir in patterns:
        base_path = Path(base_dir).resolve()

        try:
            rel = file_path.relative_to(base_path)
        except ValueError:
            continue

        rel_str = rel.as_posix()
        rel_parts = rel.parts

        # Pattern ending with '/' targets directories
        if pattern.endswith('/'):
            dir_pattern = pattern.rstrip('/')
            if any(fnmatch.fnmatch(part, dir_pattern) for part in rel_parts[:-1]):
                return True
            continue

        # Pattern with '/' is anchored to the .gitignore directory
        if '/' in pattern.lstrip('/'):
            clean = pattern.lstrip('/')
            if clean.startswith('**/'):
                sub = clean[3:]
                if fnmatch.fnmatch(rel_str, sub) or fnmatch.fnmatch(rel.name, sub):
                    return True
            elif fnmatch.fnmatch(rel_str, clean):
                return True
        else:
            if fnmatch.fnmatch(rel.name, pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in rel_parts[:-1]):
                return True

    return False
