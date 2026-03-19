"""Tests for the redaction/replacement logic."""

import os

from credredactor.config import Config
from credredactor.redactor import _derive_env_var_name, batch_replace_in_file

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
        assert 'REDACTED_BY_CREDREDACTOR' in text

    def test_sentinel_replacement(self, make_file):
        config = Config(no_backup=True, replace_mode='sentinel',
                        custom_replacement='REDACTED_BY_CREDREDACTOR')
        path = make_file('sent.py', 'api_key = "mysecretkey123456"\n')
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            assert 'REDACTED_BY_CREDREDACTOR' in f.read()

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
        assert 'process.env.API_KEY' in content


class TestDeriveEnvVarName:
    def test_variable_type(self):
        assert _derive_env_var_name({'type': 'variable:api_key'}) == 'API_KEY'

    def test_dotted_variable(self):
        assert _derive_env_var_name({'type': 'variable:self.api_key'}) == 'API_KEY'

    def test_pattern_type(self):
        assert _derive_env_var_name({'type': 'pattern:AWS access key'}) == 'AWS_ACCESS_KEY'
