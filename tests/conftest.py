"""Shared pytest configuration and fixtures.

Hayabusa binary detection happens here once, at session start. All integration
tests are marked with ``@pytest.mark.integration`` and are automatically skipped
when the binary is not found. Unit tests are unaffected.
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


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: requires the real hayabusa binary (auto-skipped when not installed)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if HAYABUSA_BIN is not None:
        return  # binary present — run everything
    skip = pytest.mark.skip(
        reason=(
            "hayabusa binary not found. Run 'make setup' or "
            "'./scripts/install_hayabusa.sh' to install it, "
            "then set HAYABUSA_PATH if needed."
        )
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


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
