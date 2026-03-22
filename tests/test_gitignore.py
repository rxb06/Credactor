"""Tests for .gitignore pattern loading and matching."""

import os

from credactor.gitignore import load_gitignore_patterns, matches_gitignore


class TestLoadGitignorePatterns:
    def test_no_gitignore(self, tmp_dir):
        patterns = load_gitignore_patterns(tmp_dir)
        assert patterns == []

    def test_loads_patterns(self, tmp_dir):
        gi_path = os.path.join(tmp_dir, '.gitignore')
        with open(gi_path, 'w') as f:
            f.write('*.pyc\n__pycache__/\n')
        patterns = load_gitignore_patterns(tmp_dir)
        assert len(patterns) == 2
        assert patterns[0][0] == '*.pyc'
        assert patterns[1][0] == '__pycache__/'

    def test_skips_comments(self, tmp_dir):
        gi_path = os.path.join(tmp_dir, '.gitignore')
        with open(gi_path, 'w') as f:
            f.write('# This is a comment\n*.pyc\n')
        patterns = load_gitignore_patterns(tmp_dir)
        assert len(patterns) == 1
        assert patterns[0][0] == '*.pyc'

    def test_skips_empty_lines(self, tmp_dir):
        gi_path = os.path.join(tmp_dir, '.gitignore')
        with open(gi_path, 'w') as f:
            f.write('\n*.pyc\n\n*.log\n\n')
        patterns = load_gitignore_patterns(tmp_dir)
        assert len(patterns) == 2

    def test_skips_negation_patterns(self, tmp_dir):
        gi_path = os.path.join(tmp_dir, '.gitignore')
        with open(gi_path, 'w') as f:
            f.write('*.pyc\n!important.pyc\n')
        patterns = load_gitignore_patterns(tmp_dir)
        assert len(patterns) == 1
        assert patterns[0][0] == '*.pyc'

    def test_nested_gitignore(self, tmp_dir):
        # Root .gitignore
        gi_root = os.path.join(tmp_dir, '.gitignore')
        with open(gi_root, 'w') as f:
            f.write('*.log\n')
        # Sub-directory .gitignore
        sub_dir = os.path.join(tmp_dir, 'sub')
        os.makedirs(sub_dir)
        gi_sub = os.path.join(sub_dir, '.gitignore')
        with open(gi_sub, 'w') as f:
            f.write('*.tmp\n')
        patterns = load_gitignore_patterns(tmp_dir)
        assert len(patterns) == 2


class TestMatchesGitignore:
    def test_simple_extension_match(self, tmp_dir):
        patterns = [('*.pyc', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'module.pyc')
        assert matches_gitignore(filepath, patterns)

    def test_no_match(self, tmp_dir):
        patterns = [('*.pyc', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'module.py')
        assert not matches_gitignore(filepath, patterns)

    def test_directory_pattern(self, tmp_dir):
        patterns = [('__pycache__/', tmp_dir)]
        filepath = os.path.join(tmp_dir, '__pycache__', 'module.pyc')
        assert matches_gitignore(filepath, patterns)

    def test_directory_pattern_no_match_file(self, tmp_dir):
        patterns = [('logs/', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'logs.txt')
        assert not matches_gitignore(filepath, patterns)

    def test_anchored_pattern(self, tmp_dir):
        patterns = [('src/config.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'src', 'config.py')
        assert matches_gitignore(filepath, patterns)

    def test_anchored_no_match_wrong_dir(self, tmp_dir):
        patterns = [('src/config.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'lib', 'config.py')
        assert not matches_gitignore(filepath, patterns)

    def test_wildcard_in_dir(self, tmp_dir):
        patterns = [('*.log', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'sub', 'app.log')
        assert matches_gitignore(filepath, patterns)

    def test_outside_base_dir_no_match(self, tmp_dir):
        sub_dir = os.path.join(tmp_dir, 'project')
        os.makedirs(sub_dir)
        patterns = [('*.pyc', sub_dir)]
        filepath = os.path.join(tmp_dir, 'outside.pyc')
        assert not matches_gitignore(filepath, patterns)

    def test_double_star_pattern(self, tmp_dir):
        patterns = [('**/test_*.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'deep', 'nested', 'test_foo.py')
        assert matches_gitignore(filepath, patterns)

    def test_empty_patterns(self, tmp_dir):
        filepath = os.path.join(tmp_dir, 'anything.py')
        assert not matches_gitignore(filepath, [])
