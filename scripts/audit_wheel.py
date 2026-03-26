"""Verify wheel contents match the source repo exactly."""
import os
import subprocess
import sys
import zipfile


def audit(dist_dir='dist'):
    errors = []

    for f in os.listdir(dist_dir):
        if not f.endswith('.whl'):
            continue

        with zipfile.ZipFile(os.path.join(dist_dir, f)) as z:
            wheel_files = set(z.namelist())

            # Get repo-tracked source files
            repo_files = set(
                subprocess.check_output(
                    ['git', 'ls-files', 'credactor/'],
                    text=True
                ).strip().splitlines()
            )

            # Wheel Python files under credactor/
            wheel_pkg_files = {
                name for name in wheel_files
                if name.startswith('credactor/') and not name.endswith('.pyc')
            }

            # Metadata (credactor-X.dist-info/) and legacy entry point
            expected_non_pkg = {
                name for name in wheel_files
                if name.startswith('credactor-') or name == 'credential_redactor.py'
            }

            unexpected = wheel_files - wheel_pkg_files - expected_non_pkg
            if unexpected:
                for uf in sorted(unexpected):
                    errors.append(f"UNEXPECTED: {uf}")

            extra_in_wheel = wheel_pkg_files - repo_files
            if extra_in_wheel:
                for ef in sorted(extra_in_wheel):
                    errors.append(f"NOT IN REPO: {ef}")

    if errors:
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
    print("Wheel audit passed")


if __name__ == '__main__':
    audit(sys.argv[1] if len(sys.argv) > 1 else 'dist')
