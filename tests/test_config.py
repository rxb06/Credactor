"""Tests for configuration loading."""

import os

import pytest

from credactor.config import Config, apply_config_file, load_config_file


class TestConfigDefaults:
    def test_default_values(self):
        c = Config()
        assert c.entropy_threshold == 3.5
        assert c.min_value_length == 8
        assert c.skip_dirs == set()
        assert c.skip_files == set()
        assert c.extra_extensions == set()
        assert c.extra_safe_values == set()
        assert c.ci_mode is False
        assert c.dry_run is False
        assert c.fix_all is False
        assert c.staged_only is False
        assert c.scan_history is False
        assert c.scan_json is False
        assert c.no_backup is False
        assert c.no_color is False
        assert c.fail_on_error is False
        assert c.replace_mode == 'sentinel'
        assert c.custom_replacement == 'REDACTED_BY_CREDACTOR'
        assert c.output_format == 'text'
        assert c.target == '.'

    def test_custom_values(self):
        c = Config(entropy_threshold=4.0, min_value_length=12, ci_mode=True)
        assert c.entropy_threshold == 4.0
        assert c.min_value_length == 12
        assert c.ci_mode is True


class TestLoadConfigFile:
    def test_no_config_file(self, tmp_dir):
        result = load_config_file(tmp_dir)
        assert result == {}

    def test_explicit_path(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
            f.write('min_value_length = 12\n')
        result = load_config_file(tmp_dir, config_path)
        assert result['entropy_threshold'] == 4.0
        assert result['min_value_length'] == 12

    def test_auto_discovery(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('min_value_length = 10\n')
        result = load_config_file(tmp_dir)
        assert result['min_value_length'] == 10

    def test_parent_dir_discovery(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('min_value_length = 15\n')
        child = os.path.join(tmp_dir, 'sub', 'dir')
        os.makedirs(child)
        result = load_config_file(child)
        assert result['min_value_length'] == 15

    def test_explicit_missing_returns_empty(self, tmp_dir):
        result = load_config_file(tmp_dir, '/nonexistent/.credactor.toml')
        assert result == {}


class TestApplyConfigFile:
    def test_apply_threshold(self):
        c = Config()
        apply_config_file(c, {'entropy_threshold': 4.2})
        assert c.entropy_threshold == 4.2

    def test_apply_min_value_length(self):
        c = Config()
        apply_config_file(c, {'min_value_length': 16})
        assert c.min_value_length == 16

    def test_apply_skip_dirs(self):
        c = Config()
        apply_config_file(c, {'skip_dirs': ['vendor', '.terraform']})
        assert 'vendor' in c.skip_dirs
        assert '.terraform' in c.skip_dirs

    def test_apply_skip_files(self):
        c = Config()
        apply_config_file(c, {'skip_files': ['generated.py']})
        assert 'generated.py' in c.skip_files

    def test_apply_extra_extensions(self):
        c = Config()
        apply_config_file(c, {'extra_extensions': ['.env.encrypted']})
        assert '.env.encrypted' in c.extra_extensions

    def test_apply_extra_safe_values(self):
        c = Config()
        apply_config_file(c, {'extra_safe_values': ['TestToken123']})
        assert 'testtoken123' in c.extra_safe_values

    def test_apply_replacement(self):
        c = Config()
        apply_config_file(c, {'replacement': 'REMOVED'})
        assert c.custom_replacement == 'REMOVED'

    def test_unknown_keys_ignored(self):
        c = Config()
        apply_config_file(c, {'unknown_key': 'value'})
        assert not hasattr(c, 'unknown_key')

    def test_merges_with_existing(self):
        c = Config(skip_dirs={'existing'})
        apply_config_file(c, {'skip_dirs': ['new_dir']})
        assert 'existing' in c.skip_dirs
        assert 'new_dir' in c.skip_dirs
