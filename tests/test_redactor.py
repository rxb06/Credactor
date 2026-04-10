"""Tests for the redaction/replacement logic."""

import os
import sys

import pytest

from credactor.config import Config
from credactor.redactor import _derive_env_var_name, batch_replace_in_file

# Construct test credentials via concatenation so the tool doesn't self-redact
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
_PASSWORD = 'xK9#mL2' + '$vQ7@nR5'


class TestBackup:
    def test_backup_created(self, make_file):
        config = Config(no_backup=False)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }
        batch_replace_in_file(path, [finding], config)
        assert os.path.exists(path + '.bak')
        with open(path + '.bak') as f:
            assert _AWS_KEY in f.read()

    def test_no_backup_flag(self, make_file):
        config = Config(no_backup=True)
        path = make_file('secret2.py', f'api_key = "{_AWS_KEY}"\n')
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }
        batch_replace_in_file(path, [finding], config)
        assert not os.path.exists(path + '.bak')


class TestBatchReplace:
    def test_multiple_findings_same_file(self, make_file):
        config = Config(no_backup=True)
        content = f'api_key = "{_AWS_KEY}"\npassword = "{_PASSWORD}"\n'
        path = make_file('multi.py', content)
        findings = [
            {'file': path, 'line': 1, 'type': 'variable:api_key', 'severity': 'high',
             'full_value': _AWS_KEY, 'value_preview': '', 'raw': ''},
            {'file': path, 'line': 2, 'type': 'variable:password', 'severity': 'high',
             'full_value': _PASSWORD, 'value_preview': '', 'raw': ''},
        ]
        replaced, failed = batch_replace_in_file(path, findings, config)
        assert replaced == 2
        assert failed == 0
        with open(path) as f:
            text = f.read()
        assert _AWS_KEY not in text
        assert _PASSWORD not in text
        assert 'REDACTED_BY_CREDACTOR' in text

    def test_sentinel_replacement(self, make_file):
        config = Config(no_backup=True, replace_mode='sentinel',
                        custom_replacement='REDACTED_BY_CREDACTOR')
        path = make_file('sent.py', 'api_key = "mysecretkey123456"\n')
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            assert 'REDACTED_BY_CREDACTOR' in f.read()

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason='Windows does not support Unix-style permission bits')
    def test_preserves_file_permissions(self, make_file):
        config = Config(no_backup=True)
        path = make_file('perms.py', 'api_key = "mysecretkey123456"\n')
        os.chmod(path, 0o644)
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        stat = os.stat(path)
        assert stat.st_mode & 0o777 == 0o644


class TestEnvVarReplacement:
    def test_python_env_ref(self, make_file):
        config = Config(no_backup=True, replace_mode='env')
        path = make_file('envtest.py', 'api_key = "mysecretkey123456"\n')
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            content = f.read()
        assert 'os.environ["API_KEY"]' in content

    def test_js_env_ref(self, make_file):
        config = Config(no_backup=True, replace_mode='env')
        path = make_file('envtest.js', 'const api_key = "mysecretkey123456";\n')
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            content = f.read()
        assert 'process.env["API_KEY"]' in content


class TestDeriveEnvVarName:
    def test_variable_type(self):
        assert _derive_env_var_name({'type': 'variable:api_key'}) == 'API_KEY'

    def test_dotted_variable(self):
        assert _derive_env_var_name({'type': 'variable:self.api_key'}) == 'API_KEY'

    def test_pattern_type(self):
        assert _derive_env_var_name({'type': 'pattern:AWS access key'}) == 'AWS_ACCESS_KEY'

    def test_sec30_sanitizes_xml_injection(self):
        """SEC-30: Adversarial xml_key with JS syntax must be stripped."""
        result = _derive_env_var_name(
            {'type': 'xml-attr:password]);require("child_process").exec("pwned")//'}
        )
        # Only alphanumeric + underscore should survive
        assert result.isidentifier()
        assert ']' not in result
        assert ')' not in result
        assert ';' not in result
        assert '(' not in result
        assert '"' not in result

    def test_sec30_sanitizes_shell_injection(self):
        """SEC-30: Adversarial xml_key with shell metacharacters must be stripped."""
        result = _derive_env_var_name(
            {'type': 'xml-attr:password};rm -rf /;${x'}
        )
        assert result.isidentifier()
        assert ';' not in result
        assert ' ' not in result
        assert '{' not in result

    def test_sec30_empty_after_sanitize_returns_credential(self):
        """SEC-30: If sanitization strips everything, return fallback."""
        result = _derive_env_var_name({'type': 'xml-attr:]);()'})
        assert result == 'CREDENTIAL'

    def test_derive_env_var_external_gitleaks(self):
        """external:gitleaks:aws-access-token -> AWS_ACCESS_TOKEN"""
        result = _derive_env_var_name({'type': 'external:gitleaks:aws-access-token'})
        assert result == 'AWS_ACCESS_TOKEN'

    def test_derive_env_var_external_trufflehog(self):
        """external:trufflehog:AWS -> AWS"""
        assert _derive_env_var_name({'type': 'external:trufflehog:AWS'}) == 'AWS'

    def test_derive_env_var_external_sanitised(self):
        """Non-identifier chars stripped from external label."""
        result = _derive_env_var_name({'type': 'external:gitleaks:foo.bar@baz'})
        assert result.isidentifier()
        assert '.' not in result
        assert '@' not in result


class TestEnvRefForLanguage:
    """SEC-30: Verify bracket notation for JS and quoting for other languages."""

    def test_js_bracket_notation(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.js') == 'process.env["API_KEY"]'

    def test_ts_bracket_notation(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.ts') == 'process.env["API_KEY"]'

    def test_python_quoted(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.py') == 'os.environ["API_KEY"]'

    def test_go_quoted(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.go') == 'os.Getenv("API_KEY")'
