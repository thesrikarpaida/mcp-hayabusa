"""Tests for scan_evtx's post-processing: rule_filter, output_format, max_results.

A fake hayabusa binary writes canned JSONL to whatever ``-o`` path it's given,
so these exercise the real filtering/formatting logic without the real binary.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa, server
from mcp_hayabusa.config import Config

DETECTIONS = [
    {
        "Timestamp": "2026-01-01",
        "RuleTitle": "Mimikatz Detected",
        "Level": "high",
        "Computer": "WS1",
        "Channel": "Security",
        "EventID": "1",
        "Details": "x",
        "RuleID": "r1",
    },
    {
        "Timestamp": "2026-01-02",
        "RuleTitle": "Lateral Movement via WMI",
        "Level": "medium",
        "Computer": "WS2",
        "Channel": "Security",
        "EventID": "2",
        "Details": "y",
        "RuleID": "r2",
    },
    {
        "Timestamp": "2026-01-03",
        "RuleTitle": "Suspicious Logon",
        "Level": "low",
        "Computer": "WS3",
        "Channel": "Security",
        "EventID": "3",
        "Details": "z",
        "RuleID": "r3",
    },
]


@pytest.fixture
def fake_binary(tmp_path: Path) -> Path:
    """A script that writes canned JSONL to the path given after ``-o``."""
    script = tmp_path / "hayabusa"
    lines = "\\n".join(json.dumps(d) for d in DETECTIONS)
    script.write_text(f"""#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
printf '{lines}\\n' > "$out"
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.fixture(autouse=True)
def _configure(monkeypatch, fake_binary):
    cfg = Config(binary=str(fake_binary), timeout=30.0, workdir="")
    monkeypatch.setattr(hayabusa, "CONFIG", cfg)


def test_scan_evtx_default_returns_summary_fields(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    result = server.scan_evtx(str(evtx))
    assert result["total"] == 3
    assert result["returned"] == 3
    assert set(result["detections"][0].keys()) <= set(server._SUMMARY_FIELDS)
    assert "RuleID" not in result["detections"][0]


def test_scan_evtx_output_format_full_keeps_all_fields(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    result = server.scan_evtx(str(evtx), output_format="full")
    assert result["detections"][0]["RuleID"] == "r1"


def test_scan_evtx_rule_filter_matches_substring_case_insensitive(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    result = server.scan_evtx(str(evtx), rule_filter="mimikatz")
    assert result["total"] == 1
    assert result["detections"][0]["RuleTitle"] == "Mimikatz Detected"


def test_scan_evtx_rule_filter_no_match_returns_empty(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    result = server.scan_evtx(str(evtx), rule_filter="nonexistent-rule-xyz")
    assert result["total"] == 0
    assert result["detections"] == []


def test_scan_evtx_max_results_truncates_but_total_reflects_all(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    result = server.scan_evtx(str(evtx), max_results=1)
    assert result["total"] == 3
    assert result["returned"] == 1
    assert len(result["detections"]) == 1
    assert result["counts"] == {"high": 1, "medium": 1, "low": 1}


def test_scan_evtx_invalid_output_format_raises(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    with pytest.raises(hayabusa.HayabusaError, match="output_format"):
        server.scan_evtx(str(evtx), output_format="weird")


def test_scan_evtx_invalid_max_results_raises(tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    with pytest.raises(hayabusa.HayabusaError, match="max_results"):
        server.scan_evtx(str(evtx), max_results=0)
