"""End-to-end tests: the real binary scanning real EVTX from samples/.

These are the only tests that prove the assumptions the unit tests have to take
on faith — above all that the ``RuleID`` a real scan emits actually matches the
Sigma ``id`` the rule index is keyed on. A fake binary can never falsify that.

Skipped automatically unless the binary is installed (conftest) *and* samples/
has been populated (./scripts/fetch_samples.sh) *and* the rule index is built
(make build-index). Run all three via ``make setup && ./scripts/fetch_samples.sh``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa, kb, server
from mcp_hayabusa.config import CONFIG, Config

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture
def real_scan(monkeypatch, hayabusa_bin):
    """Point the subprocess wrapper at the real binary; leave kb on real config."""
    if not list(SAMPLES.glob("*.evtx")):
        pytest.skip("no sample evtx — run ./scripts/fetch_samples.sh")
    if not kb.load_index().rules:
        pytest.skip("rule index empty — run 'make build-index'")
    monkeypatch.setattr(
        hayabusa,
        "CONFIG",
        Config(binary=hayabusa_bin, timeout=300.0, workdir=""),
    )
    return SAMPLES


@pytest.mark.integration
def test_scan_evtx_returns_detections_from_samples(real_scan):
    result = server.scan_evtx(str(real_scan), min_level="low")

    assert result["total"] > 0
    assert sum(result["counts"].values()) == result["total"]
    assert all("RuleTitle" in d for d in result["detections"])


@pytest.mark.integration
def test_scan_evtx_attack_maps_every_detection_to_a_rule(real_scan):
    """Every detection must join back to an indexed rule.

    A non-zero unmapped count means the index is missing a rules directory that
    hayabusa itself scans with — exactly how rules/hayabusa/ (193 built-in rules
    like "Log Cleared") was found to be missing.
    """
    result = server.scan_evtx_attack(str(real_scan), min_level="low")

    assert result["total"] > 0
    assert result["unmapped_detections"] == 0, (
        f"{result['unmapped_detections']} of {result['total']} detections did not match an "
        "indexed rule — a rules dir is missing from CONFIG.rules_dirs, or run 'make build-index'"
    )


@pytest.mark.integration
def test_scan_evtx_attack_observes_attack_techniques(real_scan):
    """The scan->ATT&CK rollup produces named techniques, not just bare ids."""
    result = server.scan_evtx_attack(str(real_scan), min_level="low")

    assert result["techniques_observed"], "samples should trigger ATT&CK-tagged rules"
    assert result["tactics_observed"]
    named = [t for t in result["techniques_observed"] if t["name"]]
    assert named, "no observed technique resolved to a name — mappings/attack.yaml missing?"
    assert sum(t["detections"] for t in result["techniques_observed"]) > 0


@pytest.mark.integration
def test_scan_evtx_attack_annotates_detections_with_their_techniques(real_scan):
    result = server.scan_evtx_attack(str(real_scan), min_level="low")

    tagged = [d for d in result["detections"] if d["techniques"]]
    assert tagged, "expected at least one detection annotated with a technique"
    for det in tagged:
        assert det["RuleID"]
        assert all(t.startswith("T") for t in det["techniques"])


@pytest.mark.integration
def test_bundled_rule_ids_are_unique_enough_to_join_on(real_scan):
    """The join assumes a rule id identifies one rule; check reality agrees.

    Duplicates are not fatal (first dir wins) but a large number would mean the
    id is not the key we think it is.
    """
    index = kb.load_index()
    ids = [r.id for r in index.rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids survived index assembly"


@pytest.mark.integration
def test_index_covers_every_bundled_rules_dir(real_scan):
    """Both bundled rule sets must be indexed, or detections go unmapped."""
    sources = {r.source for r in kb.load_index().rules}
    expected = {d.name for d in CONFIG.rules_dirs if d.is_dir() and list(d.rglob("*.yml"))}
    assert expected <= sources, f"rules dirs missing from the index: {expected - sources}"
