"""Tests for report output formatting."""

import io
import json

from credactor.report import json_report, print_report, sarif_report
from credactor.utils import mask_secret

# Construct test credential via concatenation to prevent self-redaction
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'


class TestMaskSecret:
    def test_long_value(self):
        assert mask_secret(_AWS_KEY) == 'AKIA[REDACTED]'

    def test_short_value(self):
        assert mask_secret('abc') == '[REDACTED]'

    def test_custom_visible(self):
        assert mask_secret(_AWS_KEY, visible=6) == 'AKIAIO[REDACTED]'


class TestTextReport:
    def test_no_findings(self):
        buf = io.StringIO()
        print_report([], '/tmp', no_color=True, stream=buf)
        assert 'No hardcoded credentials detected' in buf.getvalue()

    def test_secrets_masked_in_output(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        buf = io.StringIO()
        print_report(findings, '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        # The full credential should NOT appear in output
        assert _AWS_KEY not in output
        # But the masked version should
        assert 'AKIA[REDACTED]' in output


class TestJsonReport:
    def test_valid_json(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(json_report(findings, '/tmp'))
        assert result['count'] == 1
        assert result['findings'][0]['severity'] == 'high'
        # Secret should be masked
        assert _AWS_KEY not in result['findings'][0]['value']

    def test_empty(self):
        result = json.loads(json_report([], '/tmp'))
        assert result['count'] == 0
        assert result['findings'] == []


class TestSarifReport:
    def test_valid_sarif(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'critical',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        assert result['version'] == '2.1.0'
        assert len(result['runs']) == 1
        assert len(result['runs'][0]['results']) == 1
        assert result['runs'][0]['results'][0]['level'] == 'error'
        # Secret should be masked
        msg = result['runs'][0]['results'][0]['message']['text']
        assert _AWS_KEY not in msg
