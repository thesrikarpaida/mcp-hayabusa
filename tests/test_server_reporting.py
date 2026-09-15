"""Tests for the reporting tools: logon_summary, metrics, search, list_profiles.

These wrap hayabusa subcommands that have no rule-selection wizard and no
results summary, so they reject ``-w`` and ``-N``. Passing ``_SCAN_BASE`` to
them makes the real binary exit 2 with "unexpected argument '-w' found" —
a fake binary that ignores its argv cannot catch that, so the fixture here
records argv instead and the assertions are about the command line itself.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa, server
from mcp_hayabusa.config import Config

# Flags only the scanning subcommands accept.
SCAN_ONLY_FLAGS = ("-w", "--no-wizard", "-N", "--no-summary")


@pytest.fixture
def argv_recorder(tmp_path: Path) -> tuple[Path, Path]:
    """A fake binary that appends its argv to a log file and prints ANSI-laden output."""
    log = tmp_path / "argv.log"
    script = tmp_path / "hayabusa"
    script.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\n'
        # Emit a colour code and a reset so _plain() has something to strip.
        'printf "\\033[38;2;0;255;0mTotal Event Records\\033[0m:  4\\n"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, log


@pytest.fixture(autouse=True)
def _configure(monkeypatch, argv_recorder):
    script, _ = argv_recorder
    monkeypatch.setattr(hayabusa, "CONFIG", Config(binary=str(script), timeout=30.0, workdir=""))


@pytest.fixture
def evtx(tmp_path: Path) -> str:
    path = tmp_path / "a.evtx"
    path.write_text("")
    return str(path)


def _argv(log: Path) -> str:
    return log.read_text().strip()


@pytest.mark.parametrize(
    ("call", "subcommand"),
    [
        (lambda p: server.logon_summary(p), "logon-summary"),
        (lambda p: server.metrics(p), "eid-metrics"),
        (lambda p: server.search(p, keyword="psexec"), "search"),
    ],
)
def test_reporting_tools_omit_scan_only_flags(argv_recorder, evtx, call, subcommand):
    """The regression guard: these subcommands exit 2 if handed -w or -N."""
    _, log = argv_recorder
    call(evtx)
    argv = _argv(log)
    assert argv.startswith(subcommand)
    for flag in SCAN_ONLY_FLAGS:
        assert f" {flag} " not in f" {argv} ", f"{subcommand} must not receive {flag}"


@pytest.mark.parametrize(
    ("call", "subcommand"),
    [
        (lambda p: server.logon_summary(p), "logon-summary"),
        (lambda p: server.metrics(p), "eid-metrics"),
        (lambda p: server.search(p, keyword="psexec"), "search"),
    ],
)
def test_reporting_tools_pass_quiet_and_no_color(argv_recorder, evtx, call, subcommand):
    """-q drops the banner, -K drops most colour; both are wanted on every report."""
    _, log = argv_recorder
    call(evtx)
    argv = _argv(log)
    assert " -q" in f" {argv}"
    assert " -K" in f" {argv}"


def test_scan_evtx_still_passes_the_wizard_flag(argv_recorder, evtx):
    """The scanning path must keep -w, or the subprocess blocks on the wizard."""
    _, log = argv_recorder
    # The recorder writes no JSONL, so scan_evtx sees zero detections — fine,
    # this asserts on argv, not on results.
    server.scan_evtx(evtx)
    assert " -w " in f" {_argv(log)} "


def test_search_requires_exactly_one_selector(evtx):
    with pytest.raises(hayabusa.HayabusaError):
        server.search(evtx)
    with pytest.raises(hayabusa.HayabusaError):
        server.search(evtx, keyword="a", regex="b")


def test_reporting_output_is_stripped_of_ansi_escapes(evtx):
    """stdout goes straight back to the caller, so escapes must not survive."""
    out = server.metrics(evtx)
    assert "\x1b[" not in out
    assert out == "Total Event Records:  4"
