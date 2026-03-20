"""Tests for suppression mechanisms."""

import os

from credactor.suppressions import AllowList, has_inline_suppression


class TestInlineSuppression:
    def test_hash_comment(self):
        assert has_inline_suppression('api_key = "secret"  # credactor:ignore')

    def test_slash_comment(self):
        assert has_inline_suppression('const key = "secret"; // credactor:ignore')

    def test_case_insensitive(self):
        assert has_inline_suppression('key = "val"  # CREDACTOR:IGNORE')

    def test_no_suppression(self):
        assert not has_inline_suppression('api_key = "secret"  # important')


class TestAllowList:
    def test_file_glob_suppression(self, tmp_dir):
        # Create .credactorignore
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixtures/*.py\n')

        al = AllowList(tmp_dir)

        # Create the file
        fixture_dir = os.path.join(tmp_dir, 'test_fixtures')
        os.makedirs(fixture_dir, exist_ok=True)
        fixture_file = os.path.join(fixture_dir, 'secrets.py')
        with open(fixture_file, 'w') as f:
            f.write('api_key = "secret"\n')

        assert al.is_file_suppressed(fixture_file)

    def test_file_line_suppression(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('config.py:42\n')

        al = AllowList(tmp_dir)
        config_file = os.path.join(tmp_dir, 'config.py')
        assert al.is_line_suppressed(config_file, 42)
        assert not al.is_line_suppressed(config_file, 43)

    def test_value_literal_suppression(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixture_value_abc123\n')

        al = AllowList(tmp_dir)
        assert al.is_value_suppressed('test_fixture_value_abc123')
        assert not al.is_value_suppressed('real_secret')

    def test_no_ignore_file(self, tmp_dir):
        al = AllowList(tmp_dir)
        fake_file = os.path.join(tmp_dir, 'anything.py')
        assert not al.is_file_suppressed(fake_file)
        assert not al.is_line_suppressed(fake_file, 1)
        assert not al.is_value_suppressed('anything')

    def test_combined_check(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('src/config.py:10\n')

        al = AllowList(tmp_dir)
        config_file = os.path.join(tmp_dir, 'src', 'config.py')
        assert al.is_suppressed(config_file, 10, 'any_value')
        assert not al.is_suppressed(config_file, 11, 'any_value')
