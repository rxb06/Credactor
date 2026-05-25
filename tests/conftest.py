"""Shared fixtures for Credactor tests."""

import os
import tempfile

import pytest

from credactor._log import configure as _configure_log
from credactor.config import Config


@pytest.fixture(autouse=True)
def _reset_log_level():
    """Reset the credactor logger to WARNING between tests.

    Tests that call main() with --verbose flip the handler to DEBUG; without
    this fixture the elevated level would leak into subsequent tests.
    """
    _configure_log(verbose=False)
    yield
    _configure_log(verbose=False)


@pytest.fixture
def config():
    """Default Config for testing."""
    return Config()


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def make_file(tmp_dir):
    """Factory to create a file with given content inside tmp_dir."""
    def _make(name: str, content: str) -> str:
        path = os.path.join(tmp_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
        return path
    return _make
