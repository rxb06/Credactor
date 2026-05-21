"""Tests for directory walking and parallel scanning."""

import os
from unittest import mock

from credactor.config import Config
from credactor.walker import walk_and_scan


class TestWalkAndScan:
    def test_empty_directory(self, tmp_dir):
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
        assert findings == []
        assert json_files == []
        assert errored == []

    def test_clean_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'clean.py')
        with open(py_file, 'w') as f:
            f.write('x = 1\nprint("hello")\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
        assert findings == []
        assert errored == []

    def test_detects_credential(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
        assert len(findings) >= 1

    def test_skips_skip_dirs(self, tmp_dir):
        node_dir = os.path.join(tmp_dir, 'node_modules')
        os.makedirs(node_dir)
        py_file = os.path.join(node_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True)
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_collects_json_files(self, tmp_dir):
        json_file = os.path.join(tmp_dir, 'data.json')
        with open(json_file, 'w') as f:
            f.write('{"key": "value"}\n')
        config = Config(no_color=True)
        _, _, json_files, _ = walk_and_scan(tmp_dir, config)
        assert len(json_files) == 1
        assert json_files[0].endswith('data.json')

    def test_custom_skip_dirs(self, tmp_dir):
        custom_dir = os.path.join(tmp_dir, 'vendor')
        os.makedirs(custom_dir)
        py_file = os.path.join(custom_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True, skip_dirs={'vendor'})
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_custom_skip_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'generated.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True, skip_files={'generated.py'})
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_multiple_files(self, tmp_dir):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        for i in range(5):
            path = os.path.join(tmp_dir, f'file{i}.py')
            with open(path, 'w') as f:
                f.write(f'key{i} = "{key}"\n')
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config)
        assert len(findings) >= 5
        assert errored == []

    def test_permission_denied_handled_gracefully(self, tmp_dir):
        """A directory with no scannable files produces no errors."""
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config)
        assert errored == []

    def test_scan_error_populates_errored(self, tmp_dir):
        """scan_file raising an unexpected error populates the errored list."""
        py_file = os.path.join(tmp_dir, 'target.py')
        with open(py_file, 'w') as f:
            f.write('x = 1\n')
        config = Config(no_color=True)
        with mock.patch('credactor.walker.scan_file', side_effect=RuntimeError('injected')):
            _, _, _, errored = walk_and_scan(tmp_dir, config)
        resolved = os.path.realpath(py_file)
        assert any(os.path.realpath(e) == resolved for e in errored)
