"""Security-focused tests for confirmed vulnerability mitigations."""

import json
import os
import sys
import tempfile
from io import StringIO

import pytest

from credactor.cli import main
from credactor.config import Config, apply_config_file, load_config_file
from credactor.report import print_report, sarif_report
from credactor.scanner import _is_safe_value
from credactor.walker import _is_within_root, walk_and_scan


class TestPathContainment:
    """SEC-33: Verify _is_within_root prevents prefix collisions."""

    def test_child_path_is_within_root(self):
        assert _is_within_root('/tmp/repo/file.py', '/tmp/repo/')

    def test_exact_root_is_within(self):
        assert _is_within_root('/tmp/repo', '/tmp/repo/')

    def test_prefix_collision_blocked(self):
        """repo_evil must NOT match repo — this was a regression in SEC-33."""
        assert not _is_within_root('/tmp/repo_evil/file.py', '/tmp/repo/')

    def test_prefix_collision_no_trailing_sep(self):
        assert not _is_within_root('/tmp/repo_evil/file.py', '/tmp/repo')

    def test_sibling_dir_blocked(self):
        assert not _is_within_root('/tmp/repo2/file.py', '/tmp/repo/')

    def test_parent_dir_blocked(self):
        assert not _is_within_root('/tmp/file.py', '/tmp/repo/')

    def test_unrelated_path_blocked(self):
        assert not _is_within_root('/etc/passwd', '/tmp/repo/')


class TestSymlinkBoundary:
    """SEC-23: File symlinks resolving outside scan root are skipped."""

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason='Symlinks require admin on Windows')
    def test_external_symlink_skipped(self, tmp_dir):
        """A symlink pointing outside the scan root must not be scanned."""
        # Create an external file with a credential
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False
        ) as ext:
            # credactor:ignore
            ext.write('api_key = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
            ext_path = ext.name

        try:
            # Create symlink inside scan root pointing to external file
            link_path = os.path.join(tmp_dir, 'leak.py')
            os.symlink(ext_path, link_path)

            config = Config(no_color=True)
            findings, _, _, _ = walk_and_scan(tmp_dir, config)

            # The external file's credential must NOT appear in findings
            assert all(f['file'] != link_path for f in findings)
        finally:
            os.unlink(ext_path)

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason='Symlinks require admin on Windows')
    def test_internal_symlink_scanned(self, tmp_dir):
        """A symlink pointing within the scan root should be scanned."""
        # Resolve tmp_dir to handle macOS /var -> /private/var
        resolved_dir = os.path.realpath(tmp_dir)

        real_path = os.path.join(resolved_dir, 'real.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(real_path, 'w') as f:
            f.write(f'api_key = "{key}"\n')

        link_path = os.path.join(resolved_dir, 'link.py')
        os.symlink(real_path, link_path)

        config = Config(no_color=True)
        findings, _, _, _ = walk_and_scan(resolved_dir, config)

        # Both the real file and the internal symlink should produce findings
        found_files = {f['file'] for f in findings}
        assert real_path in found_files
        assert link_path in found_files


class TestCIReadOnly:
    """SEC-26: --ci blocks --fix-all and forces --dry-run."""

    def test_ci_fix_all_rejected(self, tmp_dir):
        """--ci --fix-all must exit 2."""
        clean = os.path.join(tmp_dir, 'clean.py')
        with open(clean, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', '--fix-all', tmp_dir])
        assert exc_info.value.code == 2


class TestTemplateSafeValue:
    """SEC-34: Unclosed template delimiters must not bypass detection."""

    def test_closed_template_is_safe(self):
        assert _is_safe_value('${DATABASE_URL}', None)

    def test_closed_jinja_is_safe(self):
        assert _is_safe_value('{%- set key -%}', None)

    def test_closed_helm_is_safe(self):
        assert _is_safe_value('{{ .Values.key }}', None)

    def test_unclosed_dollar_brace_not_safe(self):
        """${AKIA... without closing } must NOT be marked safe."""
        # credactor:ignore
        assert not _is_safe_value('${AKIA' + 'IOSFODNN7EXAMPLE', None)

    def test_unclosed_jinja_not_safe(self):
        assert not _is_safe_value('{%AKIA1234567890123456', None)

    def test_unclosed_helm_not_safe(self):
        assert not _is_safe_value('{{AKIA1234567890123456', None)


class TestSarifOutputInjection:
    """SEC-35: SARIF rule fields must HTML-escape attacker-controlled content."""

    def _make_finding(self, ftype, value='sk_live_test123456789abc'):
        return {
            'file': '/tmp/test.xml',
            'line': 1,
            'type': ftype,
            'severity': 'high',
            'full_value': value,
            'value_preview': value[:20],
            'raw': f'name="{ftype}" value="{value}"',
        }

    def test_sarif_rule_id_escapes_html(self):
        """HTML in finding type must be escaped in SARIF rule id."""
        finding = self._make_finding('xml-attr:key<img/onerror=alert(1)>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            assert '<img' not in rule['id']
            assert '&lt;' in rule['id'] or '<' not in rule['id']

    def test_sarif_short_description_escapes_html(self):
        """HTML in finding type must be escaped in SARIF shortDescription."""
        finding = self._make_finding('xml-attr:key<script>alert(1)</script>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            desc = rule['shortDescription']['text']
            assert '<script>' not in desc

    def test_sarif_full_description_escapes_html(self):
        """HTML in finding type must be escaped in SARIF fullDescription."""
        finding = self._make_finding('xml-attr:key"><script>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            desc = rule['fullDescription']['text']
            assert '<script>' not in desc


class TestTerminalEscapeInjection:
    """SEC-36: Text report must sanitise ANSI escape sequences."""

    def test_ansi_in_filepath_sanitised(self):
        """ANSI escape codes in file paths must not reach the terminal."""
        finding = {
            'file': '/tmp/\x1b[31mevil\x1b[0m.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': 'secret123456',
            'value_preview': 'secret...',
            'raw': 'api_key = "secret123456"',
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert '\x1b[' not in output

    def test_ansi_in_type_sanitised(self):
        """ANSI escape codes in finding type must not reach the terminal."""
        finding = {
            'file': '/tmp/test.xml',
            'line': 1,
            'type': 'xml-attr:\x1b[32mfake\x1b[0m',
            'severity': 'high',
            'full_value': 'secret123456',
            'value_preview': 'secret...',
            'raw': 'name="fake" value="secret123456"',
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        # Strip the known ANSI codes from the report itself (color=False
        # disables them, but verify no injected codes remain)
        assert '\x1b[32m' not in output

    def test_ansi_in_raw_line_sanitised(self):
        """ANSI escape codes in raw source lines must not reach the terminal."""
        raw = 'api_key = "\x1b[5mBLINKING_SECRET\x1b[0m"'
        finding = {
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': '\x1b[5mBLINKING_SECRET\x1b[0m',
            'value_preview': 'BLINK...',
            'raw': raw,
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert '\x1b[5m' not in output


class TestBareDollarPrefixBypass:
    """SEC-37: Bare $ prefix must validate env var name syntax."""

    def test_valid_env_var_is_safe(self):
        """$DATABASE_URL is a valid env var reference — still safe."""
        assert _is_safe_value('$DATABASE_URL', None)

    def test_valid_short_env_var_is_safe(self):
        assert _is_safe_value('$HOME', None)

    def test_valid_underscore_prefix_is_safe(self):
        assert _is_safe_value('$_PRIVATE_KEY', None)

    def test_dollar_env_var_with_suffix_is_safe(self):
        """$HOME/.aws/credentials is a dynamic reference — safe."""
        assert _is_safe_value('$HOME/.aws/credentials', None)

    def test_dollar_env_var_with_colon_suffix_is_safe(self):
        """$TOKEN:prefix is a dynamic reference — safe."""
        assert _is_safe_value('$TOKEN:prefix', None)

    def test_dollar_env_var_with_dash_suffix_is_safe(self):
        """$VAR-suffix is a dynamic reference — safe."""
        assert _is_safe_value('$VAR-suffix', None)

    def test_dollar_slash_not_safe(self):
        """$/path/to/thing does not start with an identifier — not safe."""
        assert not _is_safe_value('$/path/to/secret', None)

    def test_dollar_plus_not_safe(self):
        """$+something does not start with an identifier — not safe."""
        assert not _is_safe_value('$+something', None)

    def test_bare_dollar_alone_not_safe(self):
        """Lone $ with nothing after it is not a valid env var."""
        assert not _is_safe_value('$', None)

    def test_dollar_starting_with_digit_not_safe(self):
        """$123abc does not match env var syntax (must start with letter/_)."""
        assert not _is_safe_value('$123abcdef', None)


class TestConfigTypeConfusion:
    """SEC-38: Malformed config values must not crash the scan."""

    def test_entropy_threshold_non_numeric(self):
        """String value for entropy_threshold falls back to default."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': 'not_a_number'})
        assert config.entropy_threshold == 3.5

    def test_min_value_length_non_numeric(self):
        """String value for min_value_length falls back to default."""
        config = Config()
        apply_config_file(config, {'min_value_length': 'abc'})
        assert config.min_value_length == 8

    def test_entropy_threshold_list_type(self):
        """Array value for entropy_threshold falls back to default."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': [1, 2, 3]})
        assert config.entropy_threshold == 3.5

    def test_min_value_length_dict_type(self):
        """Dict value for min_value_length falls back to default."""
        config = Config()
        apply_config_file(config, {'min_value_length': {'nested': 5}})
        assert config.min_value_length == 8

    def test_valid_values_still_work(self):
        """Valid numeric values must still be applied correctly."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': 4.0, 'min_value_length': 12})
        assert config.entropy_threshold == 4.0
        assert config.min_value_length == 12


class TestConfigTrustBoundaryNonGit:
    """SEC-39: Config from parent dirs warned even without .git."""

    def test_parent_config_warns_without_git(self, tmp_dir):
        """Config in parent dir should warn when no .git exists."""
        resolved = os.path.realpath(tmp_dir)
        child = os.path.join(resolved, 'subdir')
        os.makedirs(child)
        # Place config in parent (tmp_dir), scan from child
        config_path = os.path.join(resolved, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        # No .git in either directory
        result = load_config_file(child)
        # Config should still load (we just want the warning path exercised)
        assert result.get('entropy_threshold') == 4.0
