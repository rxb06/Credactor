"""Verify built artifacts (wheel and sdist) match the committed source exactly.

Run in CI on every push and again before the PyPI publish. Credactor ships a
single pure-Python package (``credactor/``) with no runtime dependencies and one
console script, so the legitimate contents of an artifact are a small, fixed,
knowable set. This gate enforces that set, failing closed on anything else:

  * fails unless ``dist/`` holds exactly one wheel and exactly one sdist (a
    vacuous pass is a failure);
  * compares every ``credactor/`` file in both artifacts, byte for byte (sha256),
    against its blob at the pinned HEAD commit, so a build that injected or
    altered code is caught (a file-name check alone would miss an in-place edit);
  * treats the wheel as a closed allowlist: every member must be a tracked
    ``credactor/`` file or one of the expected ``.dist-info`` files, and the
    ``.dist-info`` metadata that pip consumes is content-checked -- no
    install-time ``Requires-Dist``, the console entry point is unchanged, and a
    bundled licence matches HEAD -- so a build step cannot inject a dependency,
    repoint the entry point, or smuggle a ``.pth``/``.so``/module past the gate;
  * audits the sdist fail-closed: tracked files are byte-checked against HEAD,
    any untracked ``.py`` or ``credactor/`` member is rejected, and the only
    untracked members allowed are setuptools build metadata (``PKG-INFO``,
    ``setup.cfg``, ``*.egg-info/`` bookkeeping) -- itself content-checked for
    injected dependencies -- so the xz-style "fixture file in the tarball but not
    in git" class is rejected;
  * rejects duplicate archive members (a set collapses them and only one copy is
    hashed, so an evil-first/clean-last pair would otherwise pass) and any sdist
    member whose path escapes the version directory (tar-slip).

Scope limit: this proves ``artifact == HEAD``. It cannot prove ``HEAD`` itself is
trustworthy (malicious authorship), nor defend a fully compromised runner that
can patch this script or re-tamper ``dist/`` after the gate exits.
"""

import hashlib
import os
import posixpath
import subprocess
import sys
import tarfile
import zipfile

# Credactor's fixed identity. This gate audits Credactor's own artifacts, so the
# package name, console entry point, and top-level module are known constants.
PACKAGE = 'credactor'
EXPECTED_ENTRY_POINTS = '[console_scripts]\ncredactor = credactor.cli:main'
EXPECTED_TOP_LEVEL = PACKAGE

# The only files permitted inside the wheel's `credactor-<version>.dist-info/`
# directory. Anything else (a smuggled `.pth`, `.so`, or module) is rejected.
# Licence files under `dist-info/licenses/` are handled separately.
_WHEEL_DISTINFO_FILES = frozenset(
    {'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt'}
)

# The only setuptools bookkeeping files permitted inside the sdist's
# `credactor.egg-info/` directory.
_SDIST_EGGINFO_FILES = frozenset(
    {
        'PKG-INFO',
        'SOURCES.txt',
        'dependency_links.txt',
        'entry_points.txt',
        'requires.txt',
        'top_level.txt',
        'not-zip-safe',
        'namespace_packages.txt',
    }
)


def _blob_sha256(commit: str, path: str) -> str:
    """Return the sha256 of the file at *path* in *commit*."""
    blob = subprocess.check_output(['git', 'show', f'{commit}:{path}'])
    return hashlib.sha256(blob).hexdigest()


def _head_state() -> tuple[dict[str, str], set[str], str]:
    """Return (credactor/ path -> sha256, all tracked paths, pinned commit sha).

    HEAD is resolved to a single commit sha once and used for every blob read, so
    the audit cannot straddle two refs if HEAD moves mid-run.
    """
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    listing = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit], text=True)
    tracked = {p for p in listing.splitlines() if p}
    pkg = {
        p: _blob_sha256(commit, p)
        for p in tracked
        if p.startswith(f'{PACKAGE}/') and not p.endswith('.pyc')
    }
    return pkg, tracked, commit


def _metadata_errors(label: str, text: str) -> list[str]:
    """Check Core Metadata (wheel METADATA / sdist PKG-INFO) for injection.

    Credactor declares no runtime dependencies, so every ``Requires-Dist`` must
    be gated by an ``extra ==`` marker; an unconditional one would be installed
    on every ``pip install`` and is treated as injected. The ``Name`` field must
    also be Credactor's own.
    """
    errors: list[str] = []
    name_value: str | None = None
    for line in text.splitlines():
        # Core Metadata headers end at the first blank line; the body follows.
        if line == '':
            break
        if line.startswith('Name:'):
            name_value = line.split(':', 1)[1].strip()
        elif line.startswith('Requires-Dist:') and 'extra ==' not in line:
            errors.append(f'{label}: UNEXPECTED DEPENDENCY {line.strip()}')
    if name_value is not None and name_value != PACKAGE:
        errors.append(f'{label}: NAME MISMATCH {name_value!r} (expected {PACKAGE!r})')
    return errors


def _requires_txt_errors(label: str, text: str) -> list[str]:
    """Reject an unconditional dependency in an egg-info ``requires.txt``.

    Extras appear under ``[name]`` section headers; any requirement listed before
    the first section is an unconditional install-time dependency, which Credactor
    does not have.
    """
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('['):
            break  # reached the first extras section; nothing unconditional above
        return [f'{label}: UNEXPECTED DEPENDENCY {stripped}']
    return []


def _wheel_version(filename: str) -> str:
    """Return the version field of a wheel filename, or '' if not parseable.

    Wheel names are ``{name}-{version}(-{build})?-{py}-{abi}-{platform}.whl``;
    a PEP 440 version never contains '-', so the second field is the version.
    """
    stem = filename[:-4] if filename.endswith('.whl') else filename
    parts = stem.split('-')
    return parts[1] if len(parts) >= 2 else ''


def _audit_wheel_distinfo(
    name: str, z: zipfile.ZipFile, distinfo: str, members: set[str], commit: str, tracked: set[str]
) -> list[str]:
    """Content-check the wheel's `.dist-info` against an allowlist (fail-closed)."""
    errors: list[str] = []
    for member in sorted(members):
        rel = member[len(distinfo) :]
        if rel == 'METADATA':
            text = z.read(member).decode('utf-8', 'replace')
            errors.extend(_metadata_errors(f'{name}:{rel}', text))
        elif rel == 'entry_points.txt':
            if z.read(member).decode('utf-8', 'replace').strip() != EXPECTED_ENTRY_POINTS:
                errors.append(f'{name}: ENTRY POINTS ALTERED {rel}')
        elif rel == 'top_level.txt':
            if z.read(member).decode('utf-8', 'replace').strip() != EXPECTED_TOP_LEVEL:
                errors.append(f'{name}: TOP LEVEL ALTERED {rel}')
        elif rel in _WHEEL_DISTINFO_FILES:
            # WHEEL and RECORD carry no executable code; the closed member set
            # already bounds what can ship, so they are allowed without parsing.
            continue
        elif rel.startswith('licenses/'):
            licence = rel[len('licenses/') :]
            if licence not in tracked:
                errors.append(f'{name}: UNEXPECTED {member}')
            elif hashlib.sha256(z.read(member)).hexdigest() != _blob_sha256(commit, licence):
                errors.append(f'{name}: CONTENT MISMATCH {member} (does not match HEAD)')
        else:
            errors.append(f'{name}: UNEXPECTED {member}')
    return errors


def _audit_wheel(path: str, pkg: dict[str, str], tracked: set[str], commit: str) -> list[str]:
    """Verify a wheel: package files match HEAD, dist-info is an allowlist."""
    errors: list[str] = []
    name = os.path.basename(path)
    if not name.startswith(f'{PACKAGE}-'):
        return [f'{name}: unexpected wheel name (does not start with {PACKAGE}-)']
    distinfo = f'{PACKAGE}-{_wheel_version(name)}.dist-info/'

    with zipfile.ZipFile(path) as z:
        names = [i.filename for i in z.infolist() if not i.filename.endswith('/')]
        # A duplicate member name collapses in a set and `z.read()` returns only
        # the last entry, so an evil-first/clean-last pair would pass unseen.
        duplicates = sorted({n for n in names if names.count(n) > 1})
        errors.extend(f'{name}: DUPLICATE MEMBER {d}' for d in duplicates)

        members = set(names)
        pkg_files = {n for n in members if n.startswith(f'{PACKAGE}/') and not n.endswith('.pyc')}
        # Anchor to the exact `credactor-<version>.dist-info/` first segment: an
        # unanchored substring match would trust any path merely containing
        # `.dist-info/` mid-name (e.g. `...data/x.dist-info/evil`, traversal).
        distinfo_members = {n for n in members if n.startswith(distinfo)}

        # Everything that is neither a package file nor an anchored dist-info
        # member is unexpected: top-level smuggling, `.data/` payloads, zip-slip.
        errors.extend(
            f'{name}: UNEXPECTED {extra}'
            for extra in sorted(members - pkg_files - distinfo_members)
        )
        errors.extend(
            f'{name}: MISSING FROM WHEEL {missing}' for missing in sorted(set(pkg) - pkg_files)
        )
        for f in sorted(pkg_files):
            if f not in pkg:
                errors.append(f'{name}: NOT IN REPO {f}')
            elif hashlib.sha256(z.read(f)).hexdigest() != pkg[f]:
                errors.append(f'{name}: CONTENT MISMATCH {f} (does not match HEAD)')

        errors.extend(_audit_wheel_distinfo(name, z, distinfo, distinfo_members, commit, tracked))
    return errors


def _read_member(t: tarfile.TarFile, m: tarfile.TarInfo) -> bytes:
    """Return the bytes of a regular-file tar member.

    Callers filter to regular files first, so ``extractfile`` returns a stream;
    a ``None`` here means that guard was removed, so raise loudly rather than
    silently hash empty bytes (which could spoof an empty tracked file).
    """
    extracted = t.extractfile(m)
    if extracted is None:
        raise ValueError(f'cannot read tar member {m.name}')
    return extracted.read()


def _sdist_buildmeta_errors(name: str, rel: str, data: bytes) -> list[str]:
    """Classify an untracked, non-package sdist member, fail-closed.

    The only untracked members an sdist legitimately ships are setuptools build
    metadata; the dependency-bearing ones are content-checked. Everything else
    (the xz fixture class: untracked ``.sh``/``.so``/``.m4``) is rejected.
    """
    base = posixpath.basename(rel)
    if rel == 'PKG-INFO':
        return _metadata_errors(f'{name}:{rel}', data.decode('utf-8', 'replace'))
    if rel == 'setup.cfg':
        # Inert: pyproject's [project] table is byte-verified against HEAD and is
        # authoritative for the build, so a generated setup.cfg cannot inject a
        # dependency or entry point. Allowed without further parsing.
        return []
    if rel.startswith(f'{PACKAGE}.egg-info/') and base in _SDIST_EGGINFO_FILES:
        if base == 'PKG-INFO':
            return _metadata_errors(f'{name}:{rel}', data.decode('utf-8', 'replace'))
        if base == 'entry_points.txt':
            if data.decode('utf-8', 'replace').strip() != EXPECTED_ENTRY_POINTS:
                return [f'{name}: ENTRY POINTS ALTERED {rel}']
            return []
        if base == 'requires.txt':
            return _requires_txt_errors(f'{name}:{rel}', data.decode('utf-8', 'replace'))
        # SOURCES.txt, dependency_links.txt, top_level.txt: inert bookkeeping.
        return []
    return [f'{name}: UNEXPECTED {rel}']


def _audit_sdist(path: str, pkg: dict[str, str], tracked: set[str], commit: str) -> list[str]:
    """Verify an sdist: tracked files match HEAD, untracked allowed only if metadata."""
    errors: list[str] = []
    name = os.path.basename(path)
    base = name[: -len('.tar.gz')] if name.endswith('.tar.gz') else name
    prefix = f'{base}/'
    seen_pkg: set[str] = set()

    with tarfile.open(path) as t:
        members = t.getmembers()
        file_names = [m.name for m in members if m.isfile()]
        duplicates = sorted({n for n in file_names if file_names.count(n) > 1})
        errors.extend(f'{name}: DUPLICATE MEMBER {d}' for d in duplicates)

        for m in members:
            if not (m.isfile() or m.isdir()):
                errors.append(f'{name}: non-regular member {m.name}')
                continue
            # Normalize before the containment check: a raw startswith() accepts a
            # crafted `credactor-X/../evil` member whose normalized path escapes
            # the sdist root (tar-slip). Tar names are always forward-slash, so
            # posixpath.normpath is correct on every platform.
            norm = posixpath.normpath(m.name)
            if norm != base and not norm.startswith(prefix):
                errors.append(f'{name}: member escapes {prefix}: {m.name}')
                continue
            if m.isdir():
                continue
            rel = norm[len(prefix) :]
            if rel in pkg:
                seen_pkg.add(rel)
                if hashlib.sha256(_read_member(t, m)).hexdigest() != pkg[rel]:
                    errors.append(f'{name}: CONTENT MISMATCH {rel} (does not match HEAD)')
            elif rel.startswith(f'{PACKAGE}/'):
                # Inside the package directory but not a tracked package file: a
                # smuggled .so/.pyc/data file, as strict as the wheel.
                errors.append(f'{name}: UNEXPECTED {rel}')
            elif rel.endswith('.py'):
                # A real egg-info dir ships only bookkeeping text, never a module.
                errors.append(f'{name}: UNEXPECTED {rel}')
            elif rel in tracked:
                # A tracked non-package file (pyproject.toml, README, LICENSE).
                # Byte-check it against HEAD, not just its name: an sdist install
                # builds from its pyproject.toml, so a tampered build config must
                # not ride along unreviewed.
                if hashlib.sha256(_read_member(t, m)).hexdigest() != _blob_sha256(commit, rel):
                    errors.append(f'{name}: CONTENT MISMATCH {rel} (does not match HEAD)')
            else:
                errors.extend(_sdist_buildmeta_errors(name, rel, _read_member(t, m)))
        errors.extend(
            f'{name}: MISSING FROM SDIST {missing}' for missing in sorted(set(pkg) - seen_pkg)
        )
    return errors


def audit(dist_dir: str = 'dist') -> None:
    """Audit the wheel and sdist in *dist_dir*; print and exit 1 on any error."""
    try:
        entries = os.listdir(dist_dir)
    except FileNotFoundError:
        entries = []
    wheels = sorted(f for f in entries if f.endswith('.whl'))
    sdists = sorted(f for f in entries if f.endswith('.tar.gz'))

    errors: list[str] = []
    if len(wheels) != 1:
        errors.append(f'expected exactly one .whl in {dist_dir}, found {len(wheels)}')
    if len(sdists) != 1:
        errors.append(f'expected exactly one .tar.gz sdist in {dist_dir}, found {len(sdists)}')

    pkg, tracked, commit = _head_state()
    if not pkg:
        errors.append('HEAD has no tracked credactor/ files to audit against')

    for f in wheels:
        errors.extend(_audit_wheel(os.path.join(dist_dir, f), pkg, tracked, commit))
    for f in sdists:
        errors.extend(_audit_sdist(os.path.join(dist_dir, f), pkg, tracked, commit))

    if errors:
        for e in errors:
            print(f'::error::{e}', file=sys.stderr)
        sys.exit(1)
    print(
        f'Artifact audit passed: {len(wheels)} wheel(s), {len(sdists)} sdist(s); '
        f'{len(pkg)} credactor/ files match HEAD'
    )


if __name__ == '__main__':
    audit(sys.argv[1] if len(sys.argv) > 1 else 'dist')
