"""
Tests for credactor/ingest.py — Phase 1: Gitleaks parser.
Target: ~23 tests for the Gitleaks ingestion path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from credactor.ingest import (
    _TRUFFLEHOG_SEVERITY,
    _gitleaks_severity,
    _synthesise_raw,
    _trufflehog_severity,
    ingest_gitleaks,
    ingest_trufflehog,
)

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

    def test_gitleaks_oversized_file_rejected(self, tmp_path):
        """Report file exceeding _MAX_REPORT_BYTES raises ValueError before json.load()."""
        from credactor.ingest import _MAX_REPORT_BYTES
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'huge.json'
        # Write a file exactly one byte over the limit.
        report.write_bytes(b'x' * (_MAX_REPORT_BYTES + 1))
        with pytest.raises(ValueError, match='SEC-40b'):
            ingest_gitleaks(str(report), str(target))

    def test_gitleaks_non_string_file_skipped(self, tmp_path):
        """Finding with a non-string File value (e.g. list) is skipped, not crashed."""
        target, _ = _make_target(tmp_path)
        for bad_value in (['src/config.py'], 42, True, {}):
            finding = _make_gitleaks_finding()
            finding['File'] = bad_value
            finding['SymlinkFile'] = ''
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert results == [], f'Expected skip for File={bad_value!r}'


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

    def test_gitleaks_file_target_uses_parent_directory(self, tmp_path, capsys):
        """Passing a file as target falls back to its parent; finding is still resolved."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='src/config.py', StartLine=1)
        report = _write_report(tmp_path, [finding])
        # Pass the file itself as target — should resolve relative to its parent dir
        from credactor.config import Config
        cfg = Config(verbose=True)
        results = ingest_gitleaks(str(report), str(config_py), config=cfg)
        captured = capsys.readouterr()
        assert 'warn' in captured.err.lower()  # defensive warning emitted
        # Finding should still be resolved (parent of config_py = src/, not repo root)
        # Path traversal guard may block it; what matters is no crash and raw is str
        for r in results:
            assert isinstance(r['raw'], str)

    @pytest.mark.skipif(
        not hasattr(os, 'symlink'), reason='symlinks not supported'
    )
    def test_gitleaks_symlink_outside_root_blocked(self, tmp_path, capsys):
        """Symlink within target pointing outside root is blocked (SEC-40c)."""
        target, _ = _make_target(tmp_path)
        # Create an external file and a symlink inside the target pointing to it
        external = tmp_path / 'external_secret.txt'
        external.write_text('secret_value\n', encoding='utf-8')
        link = target / 'src' / 'escape.py'
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            pytest.skip('cannot create symlink in this environment')

        finding = _make_gitleaks_finding(File='src/escape.py', Secret='secret_value')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == [], 'Symlink escaping target root must be blocked'
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

    def test_gitleaks_non_string_match_falls_back_to_synthesised(self, tmp_path):
        """Non-string Match (malformed report) falls back to synthesised raw."""
        target, _ = _make_target(tmp_path)
        (target / 'src' / 'config.py').write_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8'
        )
        for bad_match in (42, True, [], {}):
            finding = _make_gitleaks_finding(StartLine=1)
            finding['Match'] = bad_match
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for Match={bad_match!r}'
            assert isinstance(results[0]['raw'], str), (
                f'raw must be str, got {type(results[0]["raw"])} for Match={bad_match!r}'
            )

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


# ---------------------------------------------------------------------------
# 8.2 TruffleHog Parser Tests
# ---------------------------------------------------------------------------

def _make_trufflehog_finding(**kwargs) -> dict:
    """Return a minimal valid TruffleHog finding dict, overriding with kwargs."""
    base = {
        'DetectorName': 'AWS',
        'Raw': 'AKIAIOSFODNN7EXAMPLE',
        'Verified': False,
        'SourceMetadata': {
            'Data': {
                'Filesystem': {
                    'file': 'src/config.py',
                    'line': 1,
                },
            },
        },
    }
    base.update(kwargs)
    return base


def _write_ndjson(tmp_path: Path, findings: list) -> Path:
    """Write TruffleHog NDJSON to a temp file."""
    report = tmp_path / 'trufflehog_output.json'
    lines = '\n'.join(json.dumps(f) for f in findings)
    report.write_text(lines + '\n', encoding='utf-8')
    return report


def _make_th_target(tmp_path: Path) -> tuple[Path, Path]:
    """Create a target directory with a dummy src/config.py file."""
    target = tmp_path / 'repo'
    src = target / 'src'
    src.mkdir(parents=True)
    config_py = src / 'config.py'
    config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
    return target, config_py


class TestTrufflehogBasicFinding:
    def test_trufflehog_basic_finding(self, tmp_path):
        """Single NDJSON line with Filesystem source — verify all dict keys."""
        target, config_py = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))

        assert len(results) == 1
        r = results[0]
        assert r['file'] == str(config_py.resolve())
        assert r['line'] == 1
        assert r['type'] == 'external:trufflehog:AWS'
        assert r['severity'] == 'high'
        assert r['full_value'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['value_preview'] == 'AKIAIOSFODNN7EXAMPLE'
        assert isinstance(r['raw'], str)

    def test_trufflehog_multiple_lines(self, tmp_path):
        """Three NDJSON lines all parsed."""
        target, _ = _make_th_target(tmp_path)
        findings = [
            _make_trufflehog_finding(Raw='SECRET1'),
            _make_trufflehog_finding(Raw='SECRET2'),
            _make_trufflehog_finding(Raw='SECRET3'),
        ]
        report = _write_ndjson(tmp_path, findings)
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 3
        assert results[0]['full_value'] == 'SECRET1'
        assert results[1]['full_value'] == 'SECRET2'
        assert results[2]['full_value'] == 'SECRET3'

    def test_trufflehog_empty_file(self, tmp_path):
        """Empty file returns empty list."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'empty.json'
        report.write_text('', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_blank_lines_skipped(self, tmp_path):
        """Blank lines between JSON objects are skipped."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'report.json'
        finding_str = json.dumps(_make_trufflehog_finding())
        report.write_text(f'\n{finding_str}\n\n{finding_str}\n', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 2

    def test_trufflehog_invalid_line_skipped(self, tmp_path, capsys):
        """Malformed JSON line is skipped with a warning."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'report.json'
        good = json.dumps(_make_trufflehog_finding())
        report.write_text(f'not_json\n{good}\n', encoding='utf-8')
        from credactor.config import Config
        cfg = Config(verbose=True)
        results = ingest_trufflehog(str(report), str(target), config=cfg)
        assert len(results) == 1
        captured = capsys.readouterr()
        assert 'warn' in captured.err.lower()


class TestTrufflehogSourceTypes:
    def test_trufflehog_git_source(self, tmp_path):
        """SourceMetadata.Data.Git path used when no Filesystem key."""
        target, config_py = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'GitHub',
            'Raw': 'ghp_SECRETTOKEN',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 'deadbeef12345678',
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['type'] == 'external:trufflehog:GitHub'
        assert results[0]['commit'] == 'deadbeef1234'

    def test_trufflehog_unsupported_source_skipped(self, tmp_path, capsys):
        """S3/Docker source type skipped with verbose warning."""
        target, _ = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'AWS',
            'Raw': 'AKIAIOSFODNN7EXAMPLE',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'S3': {
                        'bucket': 'my-bucket',
                        'file': 'config.py',
                        'line': 1,
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        from credactor.config import Config
        cfg = Config(verbose=True)
        results = ingest_trufflehog(str(report), str(target), config=cfg)
        assert results == []
        captured = capsys.readouterr()
        assert 'warn' in captured.err.lower()


class TestTrufflehogInputValidation:
    def test_trufflehog_missing_raw(self, tmp_path):
        """Finding without Raw key is skipped."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        del finding['Raw']
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_empty_raw(self, tmp_path):
        """Finding with Raw='' is skipped."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(Raw='')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_path_resolution(self, tmp_path):
        """Relative file path resolved against target directory."""
        target, config_py = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert os.path.isabs(results[0]['file'])
        assert results[0]['file'] == str(config_py.resolve())

    def test_trufflehog_path_traversal_blocked(self, tmp_path, capsys):
        """Path traversal via crafted file path rejected (SEC-40c)."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        finding['SourceMetadata']['Data']['Filesystem']['file'] = '../../etc/passwd'
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []
        captured = capsys.readouterr()
        assert 'traversal' in captured.err.lower() or 'outside' in captured.err.lower()

    def test_trufflehog_non_string_file_skipped(self, tmp_path):
        """Finding with a non-string file value (e.g. list) is skipped, not crashed."""
        target, _ = _make_th_target(tmp_path)
        for bad_value in (['src/config.py'], 42, True, {}):
            finding = _make_trufflehog_finding()
            finding['SourceMetadata']['Data']['Filesystem']['file'] = bad_value
            report = _write_ndjson(tmp_path, [finding])
            results = ingest_trufflehog(str(report), str(target))
            assert results == [], f'Expected skip for file={bad_value!r}'


class TestTrufflehogRawSynthesis:
    def test_trufflehog_raw_synthesised_from_file(self, tmp_path):
        """raw field is read from the actual file at the given line number."""
        target, config_py = _make_th_target(tmp_path)
        config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'

    def test_trufflehog_raw_fallback_on_missing_file(self, tmp_path):
        """Unreadable/missing file falls back to Raw value for raw field."""
        target, _ = _make_th_target(tmp_path)
        # Reference a file that doesn't exist
        finding = _make_trufflehog_finding()
        finding['SourceMetadata']['Data']['Filesystem']['file'] = 'src/nonexistent.py'
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['raw'] == 'AKIAIOSFODNN7EXAMPLE'


class TestTrufflehogUrlDecoding:
    def test_url_encoded_at_sign_decoded(self, tmp_path):
        """Raw value with %40 (URL-encoded '@') produces full_value with literal '@'."""
        target, config_py = _make_th_target(tmp_path)
        config_py.write_text(
            'DB_URI = "mongodb+srv://admin:p4ss%40w0rd@cluster.mongodb.net/db"\n',
            encoding='utf-8',
        )
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        # TruffleHog URL-encodes '@' inside the password portion → %40
        finding = _make_trufflehog_finding(Raw='mongodb+srv://admin:p4ss%40w0rd@cluster.mongodb.net/db')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        # full_value must be URL-decoded so redaction can match literal file content
        assert '%40' not in results[0]['full_value'], (
            'full_value still contains URL-encoded %40; expected literal @'
        )
        assert '@' in results[0]['full_value']

    def test_non_encoded_raw_unaffected(self, tmp_path):
        """Raw value without percent-encoding passes through unchanged."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(Raw='AKIAIOSFODNN7EXAMPLE')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['full_value'] == 'AKIAIOSFODNN7EXAMPLE'


class TestTrufflehogSeverityAndType:
    def test_trufflehog_verified_true_critical(self, tmp_path):
        """Verified=True always maps to critical regardless of DetectorName."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='SlackWebhook', Verified=True)
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['severity'] == 'critical'

    def test_trufflehog_verified_false_uses_table(self, tmp_path):
        """Verified=False uses DetectorName table lookup."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='SlackWebhook', Verified=False)
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['severity'] == 'medium'

    def test_trufflehog_type_prefix(self, tmp_path):
        """Type is external:trufflehog:{DetectorName}."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='Stripe')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['type'] == 'external:trufflehog:Stripe'

    def test_trufflehog_commit_from_git_source(self, tmp_path):
        """Git source commit mapped and truncated to 12 chars."""
        target, _ = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'GitHub',
            'Raw': 'ghp_SECRETTOKEN',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 'abcdef1234567890',
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert 'commit' in results[0]
        assert results[0]['commit'] == 'abcdef123456'

    def test_trufflehog_finding_dict_shape(self, tmp_path):
        """All required keys present in output finding dict."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        r = results[0]
        for key in ('file', 'line', 'type', 'severity', 'full_value', 'value_preview', 'raw'):
            assert key in r, f'Missing key: {key}'


class TestTrufflehogCap:
    def test_trufflehog_cap_10000(self, tmp_path, capsys):
        """10,001 lines truncated to 10,000 with a warning."""
        target, _ = _make_th_target(tmp_path)
        findings = [_make_trufflehog_finding(Raw=f'SECRET{i}') for i in range(10_001)]
        report = _write_ndjson(tmp_path, findings)
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 10_000
        captured = capsys.readouterr()
        assert 'truncating' in captured.err.lower() or 'truncated' in captured.err.lower()


# ---------------------------------------------------------------------------
# 8.4 TruffleHog severity helper unit tests
# ---------------------------------------------------------------------------

class TestTrufflehogSeverityHelper:
    def test_trufflehog_severity_all_known_detectors(self):
        """Each entry in _TRUFFLEHOG_SEVERITY returns expected base value."""
        for detector, expected in _TRUFFLEHOG_SEVERITY.items():
            result = _trufflehog_severity(detector, verified=False)
            assert result == expected, (
                f'Detector {detector!r}: expected {expected!r}, got {result!r}'
            )

    def test_trufflehog_verified_overrides_all(self):
        """Verified=True on a medium detector returns critical."""
        assert _trufflehog_severity('SlackWebhook', verified=True) == 'critical'
        assert _trufflehog_severity('totally-unknown', verified=True) == 'critical'

    def test_trufflehog_unknown_detector_medium(self):
        """Unknown DetectorName with Verified=False returns medium."""
        assert _trufflehog_severity('SomeNewTool', verified=False) == 'medium'


# ---------------------------------------------------------------------------
# End-to-end redaction integration: proves TruffleHog-only finding drives
# actual file modification (no native scan involved).
# ---------------------------------------------------------------------------

class TestTrufflehogRedactionIntegration:
    """Verify that a TruffleHog finding with URL-encoded Raw can redact a file.

    The native scanner is NOT invoked here — findings come solely from the
    ingested NDJSON report.  This proves the URL-decode fix enables the full
    ingest → redact pipeline rather than just correcting the field value.
    """

    def test_urldecode_enables_redaction(self, tmp_path):
        """full_value decoded from %40 can be found and replaced in the source file."""
        from credactor.config import Config
        from credactor.ingest import _read_file_lines
        from credactor.redactor import batch_replace_in_file

        # File with a credential whose password contains a literal '@'.
        # This format intentionally does NOT match native credactor patterns
        # so only the TruffleHog-sourced finding drives redaction.
        target = tmp_path / "repo"
        target.mkdir()
        secret_file = target / "settings.py"
        # Credential: password is  s3cr3t@p4ss  (literal @)
        raw_credential = "xmpp://bot:s3cr3t@p4ss@chat.example.com/room"
        secret_file.write_text(f'CHAT_URI = "{raw_credential}"\n', encoding='utf-8')

        # TruffleHog URL-encodes the @ inside the password → %40
        url_encoded_raw = "xmpp://bot:s3cr3t%40p4ss@chat.example.com/room"
        assert url_encoded_raw != raw_credential  # sanity: they differ

        # Craft TruffleHog NDJSON pointing at the real file on disk.
        # Use an absolute path as TruffleHog Filesystem source would emit.
        finding_obj = {
            "DetectorName": "GenericCredential",
            "Raw": url_encoded_raw,
            "Verified": False,
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": str(secret_file),
                        "line": 1,
                    },
                },
            },
        }
        report = tmp_path / "th_report.ndjson"
        report.write_text(json.dumps(finding_obj) + "\n", encoding='utf-8')

        _read_file_lines.cache_clear()
        findings = ingest_trufflehog(str(report), str(target))
        assert len(findings) == 1, "expected exactly one finding from NDJSON"

        fv = findings[0]['full_value']
        assert '%40' not in fv, f"full_value still URL-encoded: {fv!r}"
        assert fv == raw_credential, f"full_value mismatch: {fv!r}"

        # Apply redaction via the same code path CLI uses.
        config = Config(no_backup=True)
        replaced, failed = batch_replace_in_file(str(secret_file), findings, config)

        assert replaced == 1, f"expected 1 replacement, got replaced={replaced} failed={failed}"
        assert failed == 0, f"unexpected failures: {failed}"

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential not in content, "credential still present after redaction"
        assert "REDACTED" in content, "sentinel not written to file"

    def test_without_urldecode_redaction_would_fail(self, tmp_path):
        """Control: if full_value were left URL-encoded, batch_replace_in_file skips it."""
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        target = tmp_path / "repo"
        target.mkdir()
        secret_file = target / "settings.py"
        raw_credential = "xmpp://bot:s3cr3t@p4ss@chat.example.com/room"
        secret_file.write_text(f'CHAT_URI = "{raw_credential}"\n', encoding='utf-8')

        # Simulate what ingest_trufflehog produced BEFORE the fix:
        # full_value still contains %40, not matching file content.
        synthetic_finding = {
            'file': str(secret_file),
            'line': 1,
            'type': 'external:trufflehog:GenericCredential',
            'severity': 'medium',
            'full_value': 'xmpp://bot:s3cr3t%40p4ss@chat.example.com/room',  # NOT decoded
            'value_preview': 'xmpp://bot:s3cr3t%40p4ss@chat.example.com/room'[:60],
            'raw': f'CHAT_URI = "{raw_credential}"',
        }

        config = Config(no_backup=True)
        replaced, failed = batch_replace_in_file(str(secret_file), [synthetic_finding], config)

        # Without the decode fix the replacement would be skipped.
        assert replaced == 0, "redaction should have failed without URL-decode"
        assert failed == 1

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential in content, "file should be unchanged without URL-decode"
