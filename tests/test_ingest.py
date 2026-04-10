"""
Tests for credactor/ingest.py — Phase 1: Gitleaks parser.
Target: ~23 tests for the Gitleaks ingestion path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credactor.ingest import _gitleaks_severity, _synthesise_raw, ingest_gitleaks

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gitleaks_finding(**kwargs) -> dict:
    """Return a minimal valid Gitleaks finding, overriding with kwargs."""
    base = {
        'File': 'src/config.py',
        'StartLine': 10,
        'EndLine': 10,
        'Secret': 'AKIAIOSFODNN7EXAMPLE',
        'Match': 'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        'RuleID': 'aws-access-token',
        'Tags': [],
        'Commit': '',
        'SymlinkFile': '',
    }
    base.update(kwargs)
    return base


def _write_report(tmp_path: Path, findings: list) -> Path:
    """Write a Gitleaks JSON report to a temp file."""
    report = tmp_path / 'gitleaks_report.json'
    report.write_text(json.dumps(findings), encoding='utf-8')
    return report


def _make_target(tmp_path: Path) -> tuple[Path, Path]:
    """Create a target directory with a dummy src/config.py file.

    Returns (target_dir, config_py_path).
    """
    target = tmp_path / 'repo'
    src = target / 'src'
    src.mkdir(parents=True)
    config_py = src / 'config.py'
    config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
    return target, config_py


# ---------------------------------------------------------------------------
# 8.1 Gitleaks Parser Tests
# ---------------------------------------------------------------------------

class TestGitleaksBasicFinding:
    def test_gitleaks_basic_finding(self, tmp_path):
        """Single finding with all fields present — verify all dict keys."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(
            File='src/config.py',
            StartLine=1,
            Secret='AKIAIOSFODNN7EXAMPLE',
            Match='aws_key = "AKIAIOSFODNN7EXAMPLE"',
            RuleID='aws-access-token',
            Commit='abc123def456789',
        )
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))

        assert len(results) == 1
        r = results[0]
        assert r['file'] == str((target / 'src' / 'config.py').resolve())
        assert r['line'] == 1
        assert r['type'] == 'external:gitleaks:aws-access-token'
        assert r['severity'] == 'critical'
        assert r['full_value'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['value_preview'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        assert r['commit'] == 'abc123def456'  # truncated to 12

    def test_gitleaks_multiple_findings(self, tmp_path):
        """Array with 3 findings all parsed."""
        target, _ = _make_target(tmp_path)
        findings = [
            _make_gitleaks_finding(Secret='SECRET1', Match='a = "SECRET1"', StartLine=1),
            _make_gitleaks_finding(Secret='SECRET2', Match='b = "SECRET2"', StartLine=2),
            _make_gitleaks_finding(Secret='SECRET3', Match='c = "SECRET3"', StartLine=3),
        ]
        report = _write_report(tmp_path, findings)
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 3
        assert results[0]['full_value'] == 'SECRET1'
        assert results[1]['full_value'] == 'SECRET2'
        assert results[2]['full_value'] == 'SECRET3'

    def test_gitleaks_empty_array(self, tmp_path):
        """Empty JSON array returns empty list."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []


class TestGitleaksInputValidation:
    def test_gitleaks_not_array(self, tmp_path):
        """Top-level dict raises ValueError."""
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'report.json'
        report.write_text('{"Secret": "foo"}', encoding='utf-8')
        with pytest.raises(ValueError, match='array'):
            ingest_gitleaks(str(report), str(target))

    def test_gitleaks_missing_secret(self, tmp_path):
        """Finding without Secret key is skipped."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        del finding['Secret']
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_empty_secret(self, tmp_path):
        """Finding with Secret='' is skipped."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(Secret='')])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_non_string_secret_skipped(self, tmp_path):
        """Finding with a non-string Secret (e.g. int) is skipped, not crashed."""
        target, _ = _make_target(tmp_path)
        for bad_value in (12345, True, [], {}):
            finding = _make_gitleaks_finding()
            finding['Secret'] = bad_value
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert results == [], f'Expected skip for Secret={bad_value!r}'

    def test_gitleaks_missing_file(self, tmp_path):
        """Finding without File key is skipped."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        del finding['File']
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_empty_file(self, tmp_path):
        """Finding with File='' is skipped."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(File='', SymlinkFile='')])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_invalid_json(self, tmp_path):
        """Non-JSON file raises ValueError."""
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'bad.json'
        report.write_text('not json at all', encoding='utf-8')
        with pytest.raises(ValueError, match='not valid JSON'):
            ingest_gitleaks(str(report), str(target))


class TestGitleaksSymlinkAndPath:
    def test_gitleaks_symlink_file_used(self, tmp_path):
        """SymlinkFile takes precedence over File."""
        target, _ = _make_target(tmp_path)
        # Create the symlink target file
        (target / 'src' / 'real.py').write_text('x = "AKIAIOSFODNN7EXAMPLE"\n')
        finding = _make_gitleaks_finding(
            File='src/config.py',
            SymlinkFile='src/real.py',
            Secret='AKIAIOSFODNN7EXAMPLE',
        )
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'].endswith('real.py')

    def test_gitleaks_path_resolution(self, tmp_path):
        """Relative File resolved against target directory."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='src/config.py')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert os.path.isabs(results[0]['file'])
        assert results[0]['file'] == str(config_py.resolve())

    def test_gitleaks_path_traversal_blocked(self, tmp_path, capsys):
        """File='../../etc/passwd' rejected — path traversal (SEC-40c)."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='../../etc/passwd')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []
        captured = capsys.readouterr()
        assert 'traversal' in captured.err.lower() or 'outside' in captured.err.lower()


class TestGitleaksFieldMapping:
    def test_gitleaks_multiline_finding(self, tmp_path):
        """StartLine != EndLine still produces a finding (known limitation)."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(StartLine=1, EndLine=3)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['line'] == 1

    def test_gitleaks_commit_present(self, tmp_path):
        """Commit mapped and truncated to 12 chars."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit='deadbeef12345678')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert 'commit' in results[0]
        assert results[0]['commit'] == 'deadbeef1234'

    def test_gitleaks_commit_empty(self, tmp_path):
        """Empty Commit omits the commit key."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit='')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert 'commit' not in results[0]

    def test_gitleaks_type_prefix(self, tmp_path):
        """Type is external:gitleaks:{RuleID}."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(RuleID='jwt')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['type'] == 'external:gitleaks:jwt'

    def test_gitleaks_match_as_raw(self, tmp_path):
        """Match field used as raw context line."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Match='the_match_line = "SECRET"')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['raw'] == 'the_match_line = "SECRET"'

    def test_gitleaks_match_empty_synthesised(self, tmp_path):
        """Empty Match triggers file read to synthesise raw."""
        target, _ = _make_target(tmp_path)
        # Write a known line to the file
        (target / 'src' / 'config.py').write_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8'
        )
        finding = _make_gitleaks_finding(Match='', StartLine=1)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'

    def test_gitleaks_finding_dict_shape(self, tmp_path):
        """All required keys present in output finding dict."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        r = results[0]
        for key in ('file', 'line', 'type', 'severity', 'full_value', 'value_preview', 'raw'):
            assert key in r, f'Missing key: {key}'


class TestGitleaksSeverity:
    def test_gitleaks_severity_mapping(self, tmp_path):
        """Known RuleIDs get correct severity from table."""
        target, _ = _make_target(tmp_path)
        cases = [
            ('aws-access-token', 'critical'),
            ('slack-webhook-url', 'high'),
            ('generic-api-key', 'medium'),
            ('jwt', 'high'),
            ('password-in-url', 'high'),
            ('private-key', 'critical'),
        ]
        for rule_id, expected in cases:
            finding = _make_gitleaks_finding(RuleID=rule_id, Tags=[])
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert len(results) == 1
            assert results[0]['severity'] == expected, (
                f'RuleID {rule_id!r}: expected {expected!r}, got {results[0]["severity"]!r}'
            )

    def test_gitleaks_severity_unknown_rule(self, tmp_path):
        """Unknown RuleID defaults to medium."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(RuleID='some-new-detector')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['severity'] == 'medium'

    def test_gitleaks_severity_tags_override(self, tmp_path):
        """Tags containing severity level overrides table."""
        target, _ = _make_target(tmp_path)
        # generic-api-key is 'medium' in table, but Tag says 'critical'
        finding = _make_gitleaks_finding(RuleID='generic-api-key', Tags=['critical'])
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['severity'] == 'critical'


class TestGitleaksCap:
    def test_gitleaks_cap_10000(self, tmp_path, capsys):
        """Array with 10,001 items is truncated to 10,000 with warning."""
        target, _ = _make_target(tmp_path)
        findings = [_make_gitleaks_finding(Secret=f'SECRET{i}') for i in range(10_001)]
        report = _write_report(tmp_path, findings)
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 10_000
        captured = capsys.readouterr()
        assert 'truncating' in captured.err.lower() or 'truncated' in captured.err.lower()


# ---------------------------------------------------------------------------
# Severity helper unit tests
# ---------------------------------------------------------------------------

class TestGitleaksSeverityHelper:
    def test_gitleaks_severity_all_known_rules(self):
        """Each entry in _GITLEAKS_SEVERITY table returns expected value."""
        from credactor.ingest import _GITLEAKS_SEVERITY
        for rule_id, expected in _GITLEAKS_SEVERITY.items():
            assert _gitleaks_severity(rule_id) == expected

    def test_gitleaks_tags_case_insensitive(self):
        """Tags severity check is case-insensitive."""
        assert _gitleaks_severity('generic-api-key', ['HIGH']) == 'high'
        assert _gitleaks_severity('generic-api-key', ['Critical']) == 'critical'

    def test_gitleaks_severity_unknown_default(self):
        """Completely unknown RuleID returns medium."""
        assert _gitleaks_severity('totally-unknown-rule-xyz') == 'medium'


# ---------------------------------------------------------------------------
# _synthesise_raw unit tests
# ---------------------------------------------------------------------------

class TestSynthesiseRaw:
    def test_reads_correct_line(self, tmp_path):
        f = tmp_path / 'myfile.py'
        f.write_text('line1\nline2\nline3\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(f), 2) == 'line2'

    def test_out_of_range_returns_empty(self, tmp_path):
        f = tmp_path / 'short.py'
        f.write_text('only_one_line\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(f), 999) == ''

    def test_missing_file_returns_empty(self, tmp_path):
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(tmp_path / 'nonexistent.py'), 1) == ''
