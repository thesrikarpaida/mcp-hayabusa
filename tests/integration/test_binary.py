"""Integration tests that invoke the real Hayabusa binary.

All tests here are decorated with ``@pytest.mark.integration`` and are skipped
automatically by conftest.py when Hayabusa is not installed. Run the full suite
(including these) after ``make setup`` has confirmed the binary is present.
"""

from __future__ import annotations

import pytest

from mcp_hayabusa import hayabusa
from mcp_hayabusa.config import Config


def _use_real_binary(monkeypatch, hayabusa_bin: str) -> None:
    """Point the module-level CONFIG at the real binary for this test."""
    cfg = Config(binary=hayabusa_bin, timeout=30.0, workdir="")
    monkeypatch.setattr(hayabusa, "CONFIG", cfg)


@pytest.mark.integration
def test_version_returns_string(monkeypatch, hayabusa_bin):
    """``help`` exits 0 and prints a non-empty version string in the first line."""
    _use_real_binary(monkeypatch, hayabusa_bin)
    result = hayabusa.run(["help"])
    assert result.returncode == 0
    assert len(result.stdout.strip()) > 0


@pytest.mark.integration
def test_version_mentions_hayabusa(monkeypatch, hayabusa_bin):
    """First line of ``help`` output contains 'hayabusa' (case-insensitive)."""
    _use_real_binary(monkeypatch, hayabusa_bin)
    result = hayabusa.run(["help"])
    first_line = result.stdout.splitlines()[0].lower()
    assert "hayabusa" in first_line


@pytest.mark.integration
def test_list_profiles_exits_zero(monkeypatch, hayabusa_bin):
    """``list-profiles`` subcommand exits 0 and returns non-empty output."""
    _use_real_binary(monkeypatch, hayabusa_bin)
    result = hayabusa.run(["list-profiles"])
    assert result.returncode == 0
    assert result.stdout.strip()


@pytest.mark.integration
def test_scan_evtx_missing_file_raises(monkeypatch, hayabusa_bin, tmp_path):
    """``scan_evtx`` should raise HayabusaError for a non-existent path."""
    _use_real_binary(monkeypatch, hayabusa_bin)
    with pytest.raises(hayabusa.HayabusaError, match="does not exist"):
        hayabusa.safe_path(str(tmp_path / "nonexistent.evtx"))
