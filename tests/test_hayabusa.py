"""Tests for the subprocess wrapper. A fake hayabusa script stands in for the
real binary so the suite runs anywhere without the multi-hundred-MB download."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa
from mcp_hayabusa.config import Config


@pytest.fixture
def fake_binary(tmp_path: Path) -> Path:
    """A script that echoes its args to stdout and exits 0."""
    script = tmp_path / "hayabusa"
    script.write_text('#!/bin/sh\necho "args: $@"\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _configure(monkeypatch, **kwargs) -> None:
    cfg = Config(
        binary=kwargs.get("binary", "hayabusa"),
        timeout=kwargs.get("timeout", 30.0),
        workdir=kwargs.get("workdir", ""),
    )
    monkeypatch.setattr(hayabusa, "CONFIG", cfg)


def test_run_invokes_binary(monkeypatch, fake_binary):
    _configure(monkeypatch, binary=str(fake_binary))
    result = hayabusa.run(["--version"])
    assert result.returncode == 0
    assert "args: --version" in result.stdout


def test_missing_binary_raises(monkeypatch):
    _configure(monkeypatch, binary="definitely-not-a-real-binary")
    with pytest.raises(hayabusa.HayabusaError, match="not found"):
        hayabusa.run(["--version"])


def test_relative_binary_resolves_against_repo_root_not_cwd(monkeypatch, tmp_path, fake_binary):
    """An MCP client picks its own cwd, so './hayabusa/hayabusa' must still resolve.

    HAYABUSA_PATH in .mcp.json is relative; if resolution were cwd-relative the
    server would only work when launched from the project directory.
    """
    root = tmp_path / "repo"
    (root / "hayabusa").mkdir(parents=True)
    binary = root / "hayabusa" / "hayabusa"
    binary.write_text(fake_binary.read_text())
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    monkeypatch.setattr(hayabusa, "ROOT", root)
    _configure(monkeypatch, binary="./hayabusa/hayabusa")
    monkeypatch.chdir(tmp_path)  # a cwd that is NOT the repo root

    assert hayabusa.resolve_binary() == str(root / "hayabusa" / "hayabusa")
    assert hayabusa.run(["help"]).returncode == 0


def test_missing_relative_binary_error_names_both_paths_tried(monkeypatch, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(hayabusa, "ROOT", empty)
    _configure(monkeypatch, binary="./hayabusa/hayabusa")
    monkeypatch.chdir(empty)  # else the real ./hayabusa/hayabusa in the repo resolves

    with pytest.raises(hayabusa.HayabusaError, match="tried .*hayabusa"):
        hayabusa.resolve_binary()


def test_nonzero_exit_raises(monkeypatch, tmp_path):
    script = tmp_path / "hayabusa"
    script.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    _configure(monkeypatch, binary=str(script))
    with pytest.raises(hayabusa.HayabusaError, match="exited 3"):
        hayabusa.run(["scan"])


def test_input_flag_picks_d_for_dir(tmp_path):
    assert hayabusa.input_flag(tmp_path) == ["-d", str(tmp_path)]


def test_input_flag_picks_f_for_file(tmp_path):
    f = tmp_path / "one.evtx"
    f.write_text("")
    assert hayabusa.input_flag(f) == ["-f", str(f)]


def test_safe_path_confines_to_workdir(monkeypatch, tmp_path):
    _configure(monkeypatch, workdir=str(tmp_path))
    inside = tmp_path / "logs"
    inside.mkdir()
    assert hayabusa.safe_path(str(inside)) == inside.resolve()

    with pytest.raises(hayabusa.HayabusaError, match="outside the allowed workdir"):
        hayabusa.safe_path(os.path.dirname(str(tmp_path)))
