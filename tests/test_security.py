"""Security-focused tests for confirmed vulnerability mitigations."""

import os
import sys
import tempfile

import pytest

from credactor.cli import main
from credactor.config import Config
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
