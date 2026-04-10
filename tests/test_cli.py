"""Tests for CLI argument parsing and main entry point."""

import json
import os

import pytest

from credactor.cli import build_parser, main


class TestBuildParser:
    def test_default_target(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.target == '.'

    def test_explicit_target(self):
        parser = build_parser()
        args = parser.parse_args(['/some/path'])
        assert args.target == '/some/path'

    def test_ci_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--ci', '.'])
        assert args.ci is True

    def test_dry_run_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--dry-run', '.'])
        assert args.dry_run is True

    def test_fix_all_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--fix-all', '.'])
        assert args.fix_all is True

    def test_staged_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--staged'])
        assert args.staged is True

    def test_scan_history_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--scan-history'])
        assert args.scan_history is True

    def test_format_json(self):
        parser = build_parser()
        args = parser.parse_args(['--format', 'json'])
        assert args.output_format == 'json'

    def test_format_sarif(self):
        parser = build_parser()
        args = parser.parse_args(['-f', 'sarif'])
        assert args.output_format == 'sarif'

    def test_no_color_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--no-color'])
        assert args.no_color is True

    def test_replace_mode(self):
        parser = build_parser()
        args = parser.parse_args(['--replace-with', 'env'])
        assert args.replace_mode == 'env'

    def test_custom_replacement(self):
        parser = build_parser()
        args = parser.parse_args(['--replacement', 'REMOVED'])
        assert args.replacement == 'REMOVED'

    def test_no_backup_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--no-backup'])
        assert args.no_backup is True

    def test_config_path(self):
        parser = build_parser()
        args = parser.parse_args(['--config', '/path/to/config.toml'])
        assert args.config == '/path/to/config.toml'

    def test_scan_json_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--scan-json'])
        assert args.scan_json is True

    def test_fail_on_error_flag(self):
        parser = build_parser()
        args = parser.parse_args(['--fail-on-error'])
        assert args.fail_on_error is True

    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.ci is False
        assert args.dry_run is False
        assert args.fix_all is False
        assert args.staged is False
        assert args.scan_history is False
        assert args.no_color is False
        assert args.no_backup is False
        assert args.scan_json is False
        assert args.fail_on_error is False
        assert args.output_format == 'text'
        assert args.replace_mode == 'sentinel'
        assert args.replacement == 'REDACTED_BY_CREDACTOR'
        assert args.config is None


class TestMainExitCodes:
    def test_nonexistent_path_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(['/nonexistent/path/that/does/not/exist'])
        assert exc_info.value.code == 2

    def test_system_directory_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(['/'])
        assert exc_info.value.code == 2

    def test_clean_directory_exits_0(self, tmp_dir):
        """A directory with no credential files should exit 0."""
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', tmp_dir])
        assert exc_info.value.code == 0

    def test_ci_mode_with_findings_exits_1(self, make_file):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        target = os.path.dirname(path)
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', target])
        assert exc_info.value.code == 1

    def test_dry_run_with_findings_exits_1(self, make_file):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        target = os.path.dirname(path)
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', target])
        assert exc_info.value.code == 1

    def test_json_output_clean(self, tmp_dir):
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--format', 'json', tmp_dir])
        assert exc_info.value.code == 0

    def test_sarif_output_clean(self, tmp_dir):
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--format', 'sarif', tmp_dir])
        assert exc_info.value.code == 0


class TestGitleaksFileTargetRejection:
    """--from-gitleaks with a file target must be rejected with exit code 2."""

    def test_file_target_exits_2(self, tmp_dir):
        repo = os.path.join(tmp_dir, 'repo')
        os.makedirs(repo)
        src_file = os.path.join(repo, 'config.py')
        with open(src_file, 'w') as f:
            f.write('x = 1\n')
        report = os.path.join(tmp_dir, 'report.json')
        with open(report, 'w') as f:
            json.dump([], f)
        with pytest.raises(SystemExit) as exc_info:
            main(['--from-gitleaks', report, src_file])
        assert exc_info.value.code == 2


class TestGitleaksAllowlistIntegration:
    """Allowlist suppression must apply to --from-gitleaks findings."""

    def _make_repo(self, tmp_dir: str) -> tuple[str, str]:
        """Create a minimal repo dir with one source file; return (repo, src_file)."""
        repo = os.path.join(tmp_dir, 'repo')
        src = os.path.join(repo, 'src')
        os.makedirs(src)
        src_file = os.path.join(src, 'config.py')
        with open(src_file, 'w') as f:
            f.write('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        return repo, src_file

    def _write_report(self, tmp_dir: str, findings: list) -> str:
        path = os.path.join(tmp_dir, 'report.json')
        with open(path, 'w') as f:
            json.dump(findings, f)
        return path

    def test_gitleaks_suppressed_value_not_reported(self, tmp_dir):
        """A value suppressed in .credactorignore must not surface as a finding."""
        repo, src_file = self._make_repo(tmp_dir)
        secret = 'AKIAIOSFODNN7EXAMPLE'

        # Suppress by value literal
        with open(os.path.join(repo, '.credactorignore'), 'w') as f:
            f.write(f'{secret}\n')

        finding = {
            'File': 'src/config.py',
            'StartLine': 1,
            'Secret': secret,
            'Match': f'aws_key = "{secret}"',
            'RuleID': 'aws-access-token',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report = self._write_report(tmp_dir, [finding])

        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', report, repo])
        # No unsuppressed findings → exit 0
        assert exc_info.value.code == 0

    def test_gitleaks_unsuppressed_value_is_reported(self, tmp_dir):
        """Without a suppression entry the finding should be reported (exit 1)."""
        repo, src_file = self._make_repo(tmp_dir)
        secret = 'AKIAIOSFODNN7EXAMPLE'

        finding = {
            'File': 'src/config.py',
            'StartLine': 1,
            'Secret': secret,
            'Match': f'aws_key = "{secret}"',
            'RuleID': 'aws-access-token',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report = self._write_report(tmp_dir, [finding])

        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', report, repo])
        assert exc_info.value.code == 1
