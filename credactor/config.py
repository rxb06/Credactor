"""
Configuration loading from ``.credactor.toml`` files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ._log import logger


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
    config_path: str | None = None
    from_gitleaks: str | None = None
    from_trufflehog: str | None = None
    backup_warn_shown: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.entropy_threshold <= 6.0:
            raise ValueError(
                f'entropy_threshold must be in [0.0, 6.0], '
                f'got {self.entropy_threshold}')
        if not 1 <= self.min_value_length <= 200:
            raise ValueError(
                f'min_value_length must be in [1, 200], '
                f'got {self.min_value_length}')
        if self.replace_mode not in ('sentinel', 'env', 'custom'):
            raise ValueError(
                f'replace_mode must be sentinel|env|custom, '
                f'got {self.replace_mode!r}')
        if self.output_format not in ('text', 'json', 'sarif'):
            raise ValueError(
                f'output_format must be text|json|sarif, '
                f'got {self.output_format!r}')


def _find_project_root(start: Path) -> Path | None:
    """Walk up from *start* looking for a ``.git`` directory.

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
    explicit_path: str | None = None,
    ci_mode: bool = False,
) -> dict:
    """Load a .credactor.toml config file and return the raw dict.

    Searches for .credactor.toml in root, then parent dirs up to /.
    If explicit_path is given, only that path is tried.
    """
    if explicit_path:
        candidates = [Path(explicit_path)]
    else:
        # Limit traversal depth to prevent picking up config files
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

    project_root = _find_project_root(Path(root).resolve())

    for candidate in candidates:
        if candidate.is_file():
            # Normpath for cross-platform separator normalisation, then
            # append os.sep AFTER normpath to prevent prefix collision.
            _cand = os.path.normpath(str(candidate.resolve()))
            _scan = os.path.normpath(str(Path(root).resolve()))

            if project_root:
                _root = os.path.normpath(str(project_root))
                outside = not (
                    _cand == _root or _cand.startswith(_root + os.sep)
                )
            else:
                outside = not (
                    _cand == _scan or _cand.startswith(_scan + os.sep)
                )

            if outside:
                if ci_mode:
                    logger.error(
                        'Refusing to load config from outside project '
                        'root in CI mode: %s', candidate,
                    )
                    return {}
                ref = project_root or root
                logger.warning(
                    'Config loaded from outside project root: '
                    '%s (project root: %s)', candidate, ref,
                )
            return _parse_toml(candidate)

    return {}


def _parse_toml(path: Path) -> dict:
    """Parse a TOML file using stdlib tomllib (Python 3.11+)."""
    import tomllib
    try:
        with open(path, 'rb') as fh:
            return tomllib.load(fh)
    except OSError as exc:
        logger.warning('Could not read config %s: %s', path, exc)
        return {}
    except tomllib.TOMLDecodeError as exc:
        logger.warning('Invalid TOML in %s: %s', path, exc)
        return {}


def apply_config_file(config: Config, file_data: dict) -> None:
    """Merge values from a parsed config file into the Config object."""
    if 'entropy_threshold' in file_data:
        try:
            val = float(file_data['entropy_threshold'])
        except (ValueError, TypeError):
            logger.warning('entropy_threshold has invalid type, using default 3.5')
            val = 3.5
        if not 0.0 <= val <= 6.0:
            logger.warning(
                'entropy_threshold=%s out of valid range (0.0-6.0), using default 3.5', val)
            val = 3.5
        config.entropy_threshold = val
    if 'min_value_length' in file_data:
        try:
            val_i = int(file_data['min_value_length'])
        except (ValueError, TypeError):
            logger.warning('min_value_length has invalid type, using default 8')
            val_i = 8
        if not 1 <= val_i <= 200:
            logger.warning(
                'min_value_length=%s out of valid range (1-200), using default 8', val_i)
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
    ingest = file_data.get('ingest', {})
    if not isinstance(ingest, dict):
        logger.warning('[ingest] config section must be a table, ignoring')
    else:
        if 'from_gitleaks' in ingest:
            val = ingest['from_gitleaks']
            if not isinstance(val, str):
                logger.warning('ingest.from_gitleaks must be a string path, ignoring')
            else:
                config.from_gitleaks = val
        if 'from_trufflehog' in ingest:
            val = ingest['from_trufflehog']
            if not isinstance(val, str):
                logger.warning('ingest.from_trufflehog must be a string path, ignoring')
            else:
                config.from_trufflehog = val
