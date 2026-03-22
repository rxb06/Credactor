"""
Configuration loading from ``.credactor.toml`` files.

Addresses: #25 (config file support)
"""

from __future__ import annotations

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
    no_color: bool = False
    fail_on_error: bool = False
    replace_mode: str = 'sentinel'  # 'sentinel' | 'env' | 'custom'
    custom_replacement: str = 'REDACTED_BY_CREDACTOR'
    output_format: str = 'text'  # 'text' | 'json' | 'sarif'
    target: str = '.'
    config_path: Optional[str] = None


def load_config_file(root: str, explicit_path: Optional[str] = None) -> dict:
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

    for candidate in candidates:
        if candidate.is_file():
            return _parse_toml(candidate)

    return {}


def _parse_toml(path: Path) -> dict:
    """Parse a TOML file. Uses tomllib (3.11+) or tomli as fallback."""
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
    except (OSError, PermissionError):
        pass
    return result


def apply_config_file(config: Config, file_data: dict) -> None:
    """Merge values from a parsed config file into the Config object."""
    if 'entropy_threshold' in file_data:
        config.entropy_threshold = float(file_data['entropy_threshold'])
    if 'min_value_length' in file_data:
        config.min_value_length = int(file_data['min_value_length'])
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
