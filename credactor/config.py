"""
Configuration loading from ``.credactor.toml`` files.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """Runtime configuration — populated from CLI flags and/or config file."""

    # Thresholds
    entropy_threshold: float = 3.5
    min_value_length: int = 8

    # Directories / files
    skip_dirs: set[str] = field(default_factory=lambda: set())
    skip_files: set[str] = field(default_factory=lambda: set())
    extra_extensions: set[str] = field(default_factory=lambda: set())
    extra_safe_values: set[str] = field(default_factory=lambda: set())

    # Behaviour flags (populated by CLI)
    ci_mode: bool = False
    dry_run: bool = False
    fix_all: bool = False
    staged_only: bool = False
    scan_history: bool = False
    scan_json: bool = False
    no_backup: bool = False
    secure_backup_dir: str | None = None
    secure_delete: bool = False
    no_color: bool = False
    fail_on_error: bool = False
    verbose: bool = False
    replace_mode: str = 'sentinel'  # 'sentinel' | 'env' | 'custom'
    custom_replacement: str = 'REDACTED_BY_CREDACTOR'
    output_format: str = 'text'  # 'text' | 'json' | 'sarif'
    target: str = '.'
    config_path: Optional[str] = None


def _find_project_root(start: Path) -> Path | None:
    """SEC-02: Walk up from *start* looking for a ``.git`` directory.

    Returns the directory containing ``.git``, or ``None`` if not found.
    """
    p = start.resolve()
    for _ in range(20):  # reasonable upper bound
        if (p / '.git').exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    return None


def load_config_file(
    root: str,
    explicit_path: Optional[str] = None,
    ci_mode: bool = False,
) -> dict:
    """Load a .credactor.toml config file and return the raw dict.

    Searches for .credactor.toml in root, then parent dirs up to /.
    If explicit_path is given, only that path is tried.
    """
    if explicit_path:
        candidates = [Path(explicit_path)]
    else:
        # HIGH-06: Limit traversal depth to prevent picking up config files
        # from shared parent directories (e.g. /tmp/.credactor.toml).
        # Walk up at most 5 levels — enough for monorepo nesting.
        max_depth = 5
        candidates = []
        p = Path(root).resolve()
        for _ in range(max_depth):
            candidates.append(p / '.credactor.toml')
            if p.parent == p:
                break
            p = p.parent

    # SEC-02: Determine project root for trust boundary check
    project_root = _find_project_root(Path(root).resolve())

    for candidate in candidates:
        if candidate.is_file():
            # SEC-02 / SEC-29: Config trust boundary check
            if project_root and not str(candidate.resolve()).startswith(
                str(project_root) + os.sep
            ):
                if ci_mode:
                    # SEC-29: Hard block in CI — never trust external config
                    print(
                        f'[ERROR] Refusing to load config from outside project '
                        f'root in CI mode: {candidate}',
                        file=sys.stderr,
                    )
                    return {}
                print(
                    f'[WARN] Config loaded from outside project root: '
                    f'{candidate} (project root: {project_root})',
                    file=sys.stderr,
                )
            return _parse_toml(candidate)

    return {}


def _parse_toml(path: Path) -> dict:
    """Parse a TOML file. Uses tomllib (3.11+) or tomli as fallback."""
    try:
        if sys.version_info >= (3, 11):
            import tomllib
            with open(path, 'rb') as fh:
                return tomllib.load(fh)
        else:
            try:
                import tomli
                with open(path, 'rb') as fh:
                    return tomli.load(fh)
            except ImportError:
                # Fall back to very basic key=value parsing for simple configs
                return _basic_toml_parse(path)
    except (OSError, PermissionError) as exc:
        # SEC-03: Surface config read failures instead of silently ignoring
        print(f'[WARN] Could not read config {path}: {exc}', file=sys.stderr)
        return {}


def _basic_toml_parse(path: Path) -> dict:
    """Minimal TOML-like parser for key = value pairs (no nested tables)."""
    result: dict = {}
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or stripped.startswith('['):
                    continue
                if '=' not in stripped:
                    continue
                key, _, val = stripped.partition('=')
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                # Try to parse as list
                if val.startswith('[') and val.endswith(']'):
                    items = val[1:-1].split(',')
                    result[key] = [i.strip().strip('"').strip("'") for i in items if i.strip()]
                elif val.lower() in ('true', 'false'):
                    result[key] = val.lower() == 'true'
                elif val.isdigit():
                    result[key] = int(val)
                else:
                    try:
                        result[key] = float(val)
                    except ValueError:
                        result[key] = val
    except (OSError, PermissionError) as exc:
        # SEC-03: Surface config read failures instead of silently ignoring
        print(f'[WARN] Could not read config {path}: {exc}', file=sys.stderr)
    return result


def apply_config_file(config: Config, file_data: dict) -> None:
    """Merge values from a parsed config file into the Config object."""
    if 'entropy_threshold' in file_data:
        val = float(file_data['entropy_threshold'])
        # SEC-12: Bound entropy threshold to valid Shannon entropy range
        if not 0.0 <= val <= 6.0:
            print(f'[WARN] entropy_threshold={val} out of valid range (0.0-6.0), '
                  f'using default 3.5', file=sys.stderr)
            val = 3.5
        config.entropy_threshold = val
    if 'min_value_length' in file_data:
        val_i = int(file_data['min_value_length'])
        # SEC-12: Bound min_value_length to reasonable range
        if not 1 <= val_i <= 200:
            print(f'[WARN] min_value_length={val_i} out of valid range (1-200), '
                  f'using default 8', file=sys.stderr)
            val_i = 8
        config.min_value_length = val_i
    if 'skip_dirs' in file_data:
        config.skip_dirs.update(file_data['skip_dirs'])
    if 'skip_files' in file_data:
        config.skip_files.update(file_data['skip_files'])
    if 'extra_extensions' in file_data:
        config.extra_extensions.update(file_data['extra_extensions'])
    if 'extra_safe_values' in file_data:
        config.extra_safe_values.update(v.lower() for v in file_data['extra_safe_values'])
    if 'replacement' in file_data:
        config.custom_replacement = str(file_data['replacement'])
