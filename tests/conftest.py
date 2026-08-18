"""Shared fixtures. Nothing here touches the network or Docker."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"

sys.path.insert(0, str(REPO_ROOT))

from mcpaudit.models import ServerSpec  # noqa: E402
from mcpaudit.storage import Store  # noqa: E402


@pytest.fixture
def store(tmp_path) -> Store:
    """A fresh database per test. Tests that share state are tests that lie."""
    return Store(tmp_path / "test.db")


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


def fixture_spec(server_id: str, tools_file: str, *extra: str) -> ServerSpec:
    return ServerSpec(
        id=server_id,
        name=server_id,
        transport="local",
        args=[sys.executable, str(FIXTURES / "fake_server.py"),
              str(FIXTURES / tools_file), *extra],
        source="test",
    )


@pytest.fixture
def benign_spec() -> ServerSpec:
    return fixture_spec("test:benign", "tools_benign.json")


@pytest.fixture
def poisoned_spec() -> ServerSpec:
    return fixture_spec("test:poisoned", "tools_poisoned.json")
