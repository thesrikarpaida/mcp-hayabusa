"""Shared pytest configuration and fixtures.

Two optional dependencies are probed once, at session start, and the tests that
need them are skipped rather than failed when they are absent:

* ``@pytest.mark.integration`` — needs the real hayabusa binary.
* ``@pytest.mark.mongo`` — needs a reachable MongoDB.

The Mongo probe is what keeps "Mongo is additive" honest: with the container
stopped the suite must still pass in full, so a stopped container has to read as
"skip", never as "fail".
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest


# Resolution order: HAYABUSA_PATH env var → ./hayabusa/hayabusa → PATH
def _locate_hayabusa() -> str | None:
    env_val = os.environ.get("HAYABUSA_PATH", "")
    if env_val and Path(env_val).is_file():
        return env_val
    local = Path(__file__).parent.parent / "hayabusa" / "hayabusa"
    if local.is_file():
        return str(local)
    return shutil.which("hayabusa")


HAYABUSA_BIN: str | None = _locate_hayabusa()


def _mongo_available() -> bool:
    """Ping MongoDB once per session. Never raises — a missing driver or a
    stopped container both mean the same thing here: skip."""
    try:
        from mcp_hayabusa import mongo
    except ImportError:  # pragma: no cover - the package is always importable
        return False
    return mongo.available()


MONGO_UP: bool = _mongo_available()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: requires the real hayabusa binary (auto-skipped when not installed)",
    )
    config.addinivalue_line(
        "markers",
        "mongo: requires a reachable MongoDB (auto-skipped when the container is stopped)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip_binary = pytest.mark.skip(
        reason=(
            "hayabusa binary not found. Run 'make setup' or "
            "'./scripts/install_hayabusa.sh' to install it, "
            "then set HAYABUSA_PATH if needed."
        )
    )
    skip_mongo = pytest.mark.skip(reason="MongoDB not reachable. Run 'make mongo-up' to start it.")
    for item in items:
        if HAYABUSA_BIN is None and "integration" in item.keywords:
            item.add_marker(skip_binary)
        if not MONGO_UP and "mongo" in item.keywords:
            item.add_marker(skip_mongo)


@pytest.fixture(scope="session")
def hayabusa_bin() -> str:
    """Return the path to the Hayabusa binary.

    Integration tests that need to invoke Hayabusa directly should use this
    fixture — it fails fast with a clear message if somehow called without the
    binary present.
    """
    if HAYABUSA_BIN is None:
        pytest.skip("hayabusa binary not available")
    return HAYABUSA_BIN
