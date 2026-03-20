"""
Output formatting: text (with colors), JSON, SARIF.

Addresses: #2/#29 (masked secrets), #7 (JSON/SARIF), #31 (ANSI color),
           #32 (progress indicator)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from . import __version__
from .utils import mask_secret

# ---------------------------------------------------------------------------
# ANSI color helpers (#31)
# ---------------------------------------------------------------------------
_COLORS = {
    'reset':    '\033[0m',
    'bold':     '\033[1m',
    'red':      '\033[91m',
    'yellow':   '\033[93m',
    'cyan':     '\033[96m',
    'green':    '\033[92m',
    'dim':      '\033[2m',
}

_SEVERITY_COLOR = {
    'critical': 'red',
    'high':     'red',
    'medium':   'yellow',
    'low':      'cyan',
}


def _c(text: str, color: str, *, use_color: bool = True) -> str:
    """Wrap text in ANSI color codes if use_color is True."""
    if not use_color:
        return text
    code = _COLORS.get(color, '')
    return f'{code}{text}{_COLORS["reset"]}' if code else text


def _should_use_color(no_color: bool) -> bool:
    """Determine whether to use ANSI color output."""
    if no_color:
        return False
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Text report (#2, #29 — masked secrets)
# ---------------------------------------------------------------------------
def print_report(
    findings: list[dict],
    root: str,
    *,
    no_color: bool = False,
    stream: TextIO = sys.stdout,
) -> None:
    if not findings:
        print('\n[OK] No hardcoded credentials detected.\n', file=stream)
        return

    color = _should_use_color(no_color)
    root_path = Path(root).resolve()
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f['file'], []).append(f)

    print(f'\n{"=" * 70}', file=stream)
    header = f'  CREDENTIAL SCAN REPORT  --  {len(findings)} finding(s) in {len(by_file)} file(s)'
    print(_c(header, 'bold', use_color=color), file=stream)
    print(f'{"=" * 70}\n', file=stream)

    for filepath, file_findings in sorted(by_file.items()):
        try:
            rel = Path(filepath).relative_to(root_path)
        except ValueError:
            rel = Path(filepath)
        print(_c(f'  FILE: {rel}', 'bold', use_color=color), file=stream)
        print(f'  {"─" * 60}', file=stream)
        for finding in file_findings:
            severity = finding.get('severity', 'medium')
            sev_color = _SEVERITY_COLOR.get(severity, 'dim')

            # #2/#29 — mask the credential in the raw line display
            masked_raw = _mask_in_line(finding['raw'], finding['full_value'])

            sev_label = _c(f'[{severity.upper()}]', sev_color, use_color=color)
            print(f'  Line {finding["line"]:>4}  {sev_label}  [{finding["type"]}]', file=stream)
            print(f'           {masked_raw[:120]}', file=stream)
        print(file=stream)

    print(f'{"=" * 70}', file=stream)
    print('  ACTION REQUIRED: Rotate/revoke any real credentials above.', file=stream)
    print('  Use environment variables or a secrets manager instead.', file=stream)
    print(f'{"=" * 70}\n', file=stream)


def _mask_in_line(raw_line: str, full_value: str) -> str:
    """Replace the credential in the raw line with a masked version."""
    masked = mask_secret(full_value)
    return raw_line.replace(full_value, masked, 1)


# ---------------------------------------------------------------------------
# JSON output (#7)
# ---------------------------------------------------------------------------
def json_report(findings: list[dict], root: str) -> str:
    """Return findings as a JSON string."""
    root_path = Path(root).resolve()
    output = []
    for f in findings:
        try:
            rel = str(Path(f['file']).relative_to(root_path))
        except ValueError:
            rel = f['file']
        output.append({
            'file':     rel,
            'line':     f['line'],
            'type':     f['type'],
            'severity': f.get('severity', 'medium'),
            'value':    mask_secret(f['full_value']),
            'commit':   f.get('commit'),
        })
    return json.dumps({'findings': output, 'count': len(output)}, indent=2)


# ---------------------------------------------------------------------------
# SARIF output (#7)
# ---------------------------------------------------------------------------
def sarif_report(findings: list[dict], root: str) -> str:
    """Return findings as a SARIF 2.1.0 JSON string."""
    root_path = Path(root).resolve()

    rules: dict[str, dict] = {}
    results = []

    for f in findings:
        rule_id = f['type'].replace(':', '-')
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'shortDescription': {'text': f['type']},
                'defaultConfiguration': {
                    'level': _sarif_level(f.get('severity', 'medium')),
                },
            }

        try:
            rel = str(Path(f['file']).relative_to(root_path))
        except ValueError:
            rel = f['file']

        results.append({
            'ruleId': rule_id,
            'level': _sarif_level(f.get('severity', 'medium')),
            'message': {
                'text': (
                    f'Potential credential detected: {f["type"]}'
                    f' ({mask_secret(f["full_value"])})'
                ),
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': rel},
                    'region': {'startLine': f['line']},
                },
            }],
        })

    sarif = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Credactor',
                    'version': __version__,
                    'rules': list(rules.values()),
                },
            },
            'results': results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    """Map our severity to SARIF level."""
    return {
        'critical': 'error',
        'high':     'error',
        'medium':   'warning',
        'low':      'note',
    }.get(severity, 'warning')


# ---------------------------------------------------------------------------
# Gitignore skip report
# ---------------------------------------------------------------------------
def print_gitignore_skipped(skipped: list[str], root: str, *, no_color: bool = False) -> None:
    if not skipped:
        return
    root_path = Path(root).resolve()
    color = _should_use_color(no_color)
    print(_c(f'\n  [{len(skipped)} file(s) not scanned -- covered by .gitignore]',
             'dim', use_color=color))
    for s in sorted(skipped):
        try:
            rel = Path(s).relative_to(root_path)
        except ValueError:
            rel = Path(s)
        print(f'    {rel}')
    print()
