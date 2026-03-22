"""
CLI entry point using argparse.

Addresses: #6 (--staged), #7 (--format), #8 (--dry-run), #24 (argparse),
           #33 (--fix-all), #34 (exit codes: 0=clean, 1=findings, 2=error)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .config import Config, apply_config_file, load_config_file
from .redactor import fix_all, interactive_review
from .report import json_report, print_gitignore_skipped, print_report, sarif_report
from .scanner import scan_file
from .suppressions import AllowList
from .walker import scan_git_history, scan_staged_files, select_json_files, walk_and_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='credactor',
        description='Scan source files for hardcoded credentials and optionally redact them.',
        epilog='Exit codes: 0 = clean, 1 = unresolved findings, 2 = error',
    )

    parser.add_argument(
        'target', nargs='?', default='.',
        help='Directory or file to scan (default: current directory)',
    )

    # Mode flags
    mode = parser.add_argument_group('mode')
    mode.add_argument(
        '--ci', action='store_true',
        help='CI mode: report only (no prompts), exit 1 on findings',
    )
    mode.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be found/replaced without modifying files',
    )
    mode.add_argument(
        '--fix-all', action='store_true',
        help='Replace all findings without prompting',
    )
    mode.add_argument(
        '--staged', action='store_true',
        help='Scan only git-staged files (for pre-commit hooks)',
    )
    mode.add_argument(
        '--scan-history', action='store_true',
        help='Scan git commit history for leaked credentials',
    )

    # Output flags
    output = parser.add_argument_group('output')
    output.add_argument(
        '--format', '-f', choices=['text', 'json', 'sarif'], default='text',
        dest='output_format',
        help='Output format (default: text)',
    )
    output.add_argument(
        '--no-color', action='store_true',
        help='Disable ANSI color output',
    )

    # Replacement flags
    replace = parser.add_argument_group('replacement')
    replace.add_argument(
        '--replace-with', choices=['sentinel', 'env', 'custom'], default='sentinel',
        dest='replace_mode',
        help='Replacement strategy: sentinel (default), env (language-aware env var ref), custom',
    )
    replace.add_argument(
        '--replacement', type=str, default='REDACTED_BY_CREDACTOR',
        help='Custom replacement string (used with --replace-with=sentinel or custom)',
    )
    replace.add_argument(
        '--no-backup', action='store_true',
        help='Skip creating .bak backup files before modifying',
    )

    # Configuration
    config_group = parser.add_argument_group('configuration')
    config_group.add_argument(
        '--config', type=str, default=None,
        help='Path to .credactor.toml config file',
    )
    config_group.add_argument(
        '--scan-json', action='store_true',
        help='Include .json files in the scan',
    )
    config_group.add_argument(
        '--fail-on-error', action='store_true',
        help='Exit with code 2 if any files could not be scanned (e.g. permission errors)',
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Build Config
    config = Config(
        ci_mode=args.ci,
        dry_run=args.dry_run,
        fix_all=args.fix_all,
        staged_only=args.staged,
        scan_history=args.scan_history,
        scan_json=args.scan_json,
        no_backup=args.no_backup,
        no_color=args.no_color,
        fail_on_error=args.fail_on_error,
        replace_mode=args.replace_mode,
        custom_replacement=args.replacement,
        output_format=args.output_format,
        target=args.target,
        config_path=args.config,
    )

    # Load config file (#25)
    target = config.target
    if not os.path.exists(target):
        print(f'Error: path not found: {target}', file=sys.stderr)
        sys.exit(2)

    # Guard against scanning system directories
    _PROTECTED_DIRS = {'/', '/etc', '/usr', '/var', '/boot', '/sys', '/proc',
                       '/bin', '/sbin', '/lib', '/opt', '/root',
                       'C:\\', 'C:\\Windows', 'C:\\Program Files'}
    resolved = str(Path(target).resolve())
    if resolved in _PROTECTED_DIRS:
        print(f'Error: refusing to scan system directory: {resolved}',
              file=sys.stderr)
        print('  Use a project directory instead.', file=sys.stderr)
        sys.exit(2)

    file_data = load_config_file(target, config.config_path)
    if file_data:
        apply_config_file(config, file_data)

    # Suppressions (#3, #4)
    allowlist = AllowList(target)

    print(f'Scanning: {Path(target).resolve()}', file=sys.stderr)

    # --- Dispatch based on mode ---
    findings: list[dict] = []
    errored_files: list[str] = []

    if config.staged_only:
        # #6 — staged files only
        findings, errored_files = scan_staged_files(target, config, allowlist)
    elif config.scan_history:
        # #11 — git history
        findings = scan_git_history(target, config, allowlist)
    else:
        # Normal directory scan (#26 single walk)
        dir_findings, gitignore_skipped, json_files, errored_files = walk_and_scan(
            target, config, allowlist,
        )
        findings = dir_findings

        # Report gitignored files
        if config.output_format == 'text':
            print_gitignore_skipped(gitignore_skipped, target, no_color=config.no_color)

        # Optionally scan JSON files
        if config.scan_json and json_files:
            # Skip interactive selection when non-interactive
            if (config.ci_mode or config.dry_run or config.fix_all
                    or config.output_format != 'text'):
                json_paths = json_files
            else:
                json_paths = select_json_files(json_files, target)

            for path in json_paths:
                findings.extend(scan_file(path, config=config, allowlist=allowlist))

    # Report errored files and fail if --fail-on-error
    if errored_files:
        print(f'\n[WARN] {len(errored_files)} file(s) could not be scanned:',
              file=sys.stderr)
        for fp in errored_files:
            print(f'  - {fp}', file=sys.stderr)
        if config.fail_on_error:
            print('[ERROR] Exiting due to --fail-on-error.', file=sys.stderr)
            sys.exit(2)

    # --- Output ---
    if not findings:
        if config.output_format == 'json':
            print(json_report(findings, target))
        elif config.output_format == 'sarif':
            print(sarif_report(findings, target))
        else:
            print('\n[OK] No hardcoded credentials detected. Safe for commits.\n')
        sys.exit(0)

    # We have findings — report them
    if config.output_format == 'json':
        print(json_report(findings, target))
    elif config.output_format == 'sarif':
        print(sarif_report(findings, target))
    else:
        print_report(findings, target, no_color=config.no_color)

    # #34 — exit code semantics (consistent across all formats)
    if config.ci_mode or config.dry_run:
        sys.exit(1)

    if config.fix_all:
        # Confirmation before destructive batch operation
        by_file: dict[str, list] = {}
        for f in findings:
            by_file.setdefault(f['file'], []).append(f)
        print(f'\n  --fix-all will modify {len(by_file)} file(s) '
              f'with {len(findings)} replacement(s).')
        if not config.no_backup:
            print('  .bak backups will be created (contain original secrets).')
        else:
            print('  WARNING: --no-backup is set. No backups will be created.')
        try:
            answer = input('  Proceed? [y/N]: ').strip().lower()
        except (KeyboardInterrupt, EOFError):
            print('\n  Aborted.')
            sys.exit(1)
        if answer not in ('y', 'yes'):
            print('  Aborted.')
            sys.exit(1)

        unresolved = fix_all(findings, target, config)
        sys.exit(1 if unresolved > 0 else 0)

    # Non-text formats in non-CI mode: report and exit 1
    if config.output_format != 'text':
        sys.exit(1)

    # Interactive mode (default, text only)
    unresolved = interactive_review(findings, target, config)
    sys.exit(1 if unresolved > 0 else 0)
