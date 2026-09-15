"""Tests for the knowledge-base tools and resources on the MCP server.

These cover the layer above kb.py: resource URI handlers, rule lookup by
id/stem/title, and scan_evtx_attack — the join from a Hayabusa detection back to
the Sigma rule that fired it. A fake binary emits canned JSONL keyed to the
rule ids in the fixture corpus, so the join is exercised without the real tool.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
import yaml

from mcp_hayabusa import hayabusa, kb, server
from mcp_hayabusa.config import Config
from tests.test_kb import ATTACK_YAML, TACTICS_TXT, write_rule

# Detections as hayabusa's 'standard' profile emits them: RuleID is the join key.
DETECTIONS = [
    {
        "Timestamp": "2026-01-01 00:00:00",
        "RuleTitle": "WMI Exec",
        "Level": "high",
        "Computer": "WS1",
        "Channel": "Security",
        "EventID": "4688",
        "Details": "x",
        "RuleID": "wmi",
    },
    {
        "Timestamp": "2026-01-02 00:00:00",
        "RuleTitle": "LSASS Dump",
        "Level": "critical",
        "Computer": "WS2",
        "Channel": "Security",
        "EventID": "10",
        "Details": "y",
        "RuleID": "lsass",
    },
    {
        "Timestamp": "2026-01-03 00:00:00",
        "RuleTitle": "Rule Not In Index",
        "Level": "low",
        "Computer": "WS3",
        "Channel": "Security",
        "EventID": "1",
        "Details": "z",
        "RuleID": "ghost",
    },
]


@pytest.fixture
def fake_binary(tmp_path: Path) -> Path:
    """Writes canned JSONL to whatever path follows ``-o``."""
    script = tmp_path / "hayabusa"
    lines = "\\n".join(json.dumps(d) for d in DETECTIONS)
    script.write_text(
        f"""#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
printf '{lines}\\n' > "$out"
"""
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


@pytest.fixture
def kb_server(tmp_path, monkeypatch, fake_binary):
    """A fixture corpus whose rule ids match the canned detections above."""
    rules = tmp_path / "rules"
    rules.mkdir()
    mappings = tmp_path / "mappings"
    mappings.mkdir()
    (mappings / "attack.yaml").write_text(yaml.safe_dump(ATTACK_YAML), encoding="utf-8")
    tactics = tmp_path / "mitre_tactics.txt"
    tactics.write_text(TACTICS_TXT, encoding="utf-8")

    write_rule(
        rules,
        "wmi",
        title="WMI Exec",
        tags=["attack.execution", "attack.lateral-movement", "attack.t1047"],
        level="high",
    )
    write_rule(
        rules,
        "lsass",
        title="LSASS Dump",
        tags=["attack.credential-access", "attack.t1003.001"],
        level="critical",
    )

    cfg = Config(
        binary=str(fake_binary),
        timeout=30.0,
        workdir="",
        rules_dirs=(rules,),
        mappings_dir=mappings,
        index_cache=tmp_path / ".cache" / "index.json",
        tactics_file=tactics,
    )
    monkeypatch.setattr(kb, "CONFIG", cfg)
    monkeypatch.setattr(hayabusa, "CONFIG", cfg)
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)
    return cfg


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------


def test_rules_catalog_lists_custom_rules_in_full(kb_server):
    cat = json.loads(server.rules_catalog())

    assert cat["total_rules"] == 2
    assert cat["custom_rules"]["count"] == 2
    assert {r["title"] for r in cat["custom_rules"]["rules"]} == {"WMI Exec", "LSASS Dump"}
    assert cat["by_level"] == {"high": 1, "critical": 1}


def test_rules_catalog_breaks_down_by_source_with_roles(kb_server, tmp_path, monkeypatch):
    """Each rules dir is reported separately — conflating them once hid a whole dir."""
    # Nested, because the fake_binary fixture already owns tmp_path/"hayabusa".
    # The dir's *name* is what becomes Rule.source, so it must be "hayabusa".
    builtin = tmp_path / "bundled" / "hayabusa"
    builtin.mkdir(parents=True)
    write_rule(builtin, "log-cleared", title="Log Cleared", tags=["attack.t1070.001"])
    monkeypatch.setattr(
        kb,
        "CONFIG",
        Config(**{**kb_server.__dict__, "rules_dirs": (kb_server.rules_dirs[0], builtin)}),
    )

    cat = json.loads(server.rules_catalog())

    assert cat["by_source"]["rules"]["count"] == 2
    assert cat["by_source"]["hayabusa"]["count"] == 1
    assert "built-in" in cat["by_source"]["hayabusa"]["role"]


def test_rules_catalog_breaks_down_by_platform_and_distinct_detections(
    kb_server, tmp_path, monkeypatch
):
    """ "What rules do we have?" must answer with the telemetry split, not just a total."""
    sigma = tmp_path / "bundled" / "sigma"
    for tree in ("sysmon", "builtin"):
        (sigma / tree / "process_creation").mkdir(parents=True)
        write_rule(
            sigma / tree / "process_creation",
            f"mimikatz-{tree}",
            title="Mimikatz",  # the same detection, compiled for both trees
            tags=["attack.t1003.001"],
            level="critical",
        )
    monkeypatch.setattr(
        kb,
        "CONFIG",
        Config(**{**kb_server.__dict__, "rules_dirs": (kb_server.rules_dirs[0], sigma)}),
    )

    cat = json.loads(server.rules_catalog())

    assert cat["total_rules"] == 4
    assert cat["by_platform"] == {"rules": 2, "sigma/sysmon": 1, "sigma/builtin": 1}
    # Mimikatz is indexed twice but is one detection.
    assert cat["distinct_detections"] == 3
    assert any("sysmon" in note for note in cat["notes"])


def test_rules_catalog_reports_status_logsource_and_attack_headline(kb_server):
    cat = json.loads(server.rules_catalog())

    assert cat["by_status"] == {"stable": 2}
    assert cat["top_log_sources"] == {"security": 2}
    assert cat["attack"]["techniques_covered"] == 2
    assert cat["attack"]["rules_without_technique"] == 0
    assert set(cat["attack"]["top_tactics"]) == {
        "execution",
        "lateral-movement",
        "credential-access",
    }


def test_rules_catalog_counts_rules_with_no_technique_tag(kb_server):
    """Untagged rules still fire but are invisible to coverage — say so."""
    write_rule(kb_server.rules_dirs[0], "untagged", title="No Tags", tags=["sysmon"])

    cat = json.loads(server.rules_catalog())

    assert cat["total_rules"] == 3
    assert cat["attack"]["rules_without_technique"] == 1
    assert any("not coverage" in n for n in cat["notes"])


def test_rule_content_resolves_by_id_stem_and_title(kb_server):
    by_id = server.rule_content("wmi")
    by_title = server.rule_content("WMI Exec")

    assert "title: WMI Exec" in by_id
    assert by_title == by_id


def test_rule_content_unknown_ref_raises(kb_server):
    with pytest.raises(kb.KnowledgeBaseError, match="no rule matching"):
        server.rule_content("does-not-exist")


def test_rules_by_technique_includes_subtechniques(kb_server):
    parent = json.loads(server.rules_by_technique("T1003"))
    exact = json.loads(server.rules_by_technique("T1003.001"))

    assert parent["matched_rules"] == 1  # matched via the sub-technique
    assert parent["name"] == "OS Credential Dumping"
    assert exact["matched_rules"] == 1
    assert json.loads(server.rules_by_technique("T1650"))["matched_rules"] == 0


def test_attack_technique_resource_reports_assessment(kb_server):
    detail = json.loads(server.attack_technique("T1047"))

    assert detail["id"] == "T1047"
    assert detail["name"] == "Windows Management Instrumentation"
    assert detail["coverage"]["assessment"] == "covered"
    assert [r["id"] for r in detail["rules"]] == ["wmi"]


def test_attack_coverage_resource_and_tactics_resource(kb_server):
    cov = json.loads(server.attack_coverage_overview())
    assert cov["techniques_covered"] == 2
    assert cov["rules_without_technique"] == 0

    tactics = json.loads(server.attack_tactics())
    counts = {t["slug"]: t["rules"] for t in tactics["tactics"]}
    assert counts == {"credential-access": 1, "execution": 1, "lateral-movement": 1}
    assert all(t["id"].startswith("TA") for t in tactics["tactics"])


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------


def test_search_rules_tool_filters_and_flags_truncation(kb_server):
    assert server.search_rules(technique="T1047")["returned"] == 1
    assert server.search_rules()["returned"] == 2
    assert server.search_rules(limit=1)["truncated"] is True
    assert server.search_rules()["truncated"] is False


def test_search_rules_does_not_flag_truncation_when_matches_exactly_fill_the_limit(kb_server):
    """2 matches at limit=2 is a complete result, not a truncated one."""
    result = server.search_rules(limit=2)

    assert result["matched"] == 2
    assert result["returned"] == 2
    assert result["truncated"] is False


def test_search_rules_breakdown_describes_all_matches_not_the_returned_page(kb_server):
    result = server.search_rules(limit=1)

    assert result["returned"] == 1
    assert result["matched"] == 2
    assert result["breakdown"]["total"] == 2
    assert result["breakdown"]["by_severity"] == {"critical": 1, "high": 1}


def test_search_rules_summary_carries_platform_and_log_source(kb_server):
    """Without these on the rule itself, a caller cannot break results down at all."""
    rule = server.search_rules(technique="T1047")["rules"][0]

    assert rule["platform"] == "rules"
    assert rule["log_source"] == "security"


def test_search_rules_rejects_bad_level(kb_server):
    with pytest.raises(hayabusa.HayabusaError, match="level must be one of"):
        server.search_rules(level="catastrophic")


def test_search_rules_rejects_bad_limit(kb_server):
    with pytest.raises(hayabusa.HayabusaError, match="limit must be"):
        server.search_rules(limit=0)


def test_get_rule_returns_metadata_yaml_and_technique_names(kb_server):
    rule = server.get_rule("lsass")

    assert rule["title"] == "LSASS Dump"
    assert rule["technique_names"] == {"T1003.001": "OS Credential Dumping: LSASS Memory"}
    assert rule["logsource"]["product"] == "windows"
    assert "title: LSASS Dump" in rule["yaml"]


def test_get_rule_unknown_raises(kb_server):
    with pytest.raises(hayabusa.HayabusaError, match="no rule matching"):
        server.get_rule("nope")


def test_attack_coverage_tool_rejects_bad_min_level(kb_server):
    with pytest.raises(hayabusa.HayabusaError, match="min_level must be one of"):
        server.attack_coverage(min_level="loud")


def test_coverage_gaps_excludes_covered_and_revoked(kb_server):
    gaps = server.coverage_gaps()
    ids = [g["id"] for g in gaps["gaps"]]

    assert "T1650" in ids  # nothing detects it
    assert "T1047" not in ids  # covered
    assert "T1003" not in ids  # partial via sub-technique, not a gap
    assert "T1086" not in ids  # revoked by ATT&CK — not a real gap
    assert "T1003.002" in ids  # an uncovered sub-technique is a gap


def test_coverage_gaps_filters_by_tactic_and_limit(kb_server):
    gaps = server.coverage_gaps(tactic="credential-access")
    assert all("credential-access" in g["tactics"] for g in gaps["gaps"])
    assert server.coverage_gaps(limit=1)["returned"] == 1


def test_rebuild_rule_index_reports_counts(kb_server):
    result = server.rebuild_rule_index()
    assert result["indexed_rules"] == 2
    assert result["notes"]


# --------------------------------------------------------------------------
# scan_evtx_attack — the scan/knowledge-base join
# --------------------------------------------------------------------------


def test_scan_evtx_attack_maps_detections_to_techniques(kb_server, tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")

    result = server.scan_evtx_attack(str(evtx))

    assert result["total"] == 3
    assert result["techniques_observed"] == [
        {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "detections": 1},
        {"id": "T1047", "name": "Windows Management Instrumentation", "detections": 1},
    ]
    assert result["tactics_observed"] == {
        "credential-access": 1,
        "execution": 1,
        "lateral-movement": 1,
    }


def test_scan_evtx_attack_counts_detections_missing_from_index(kb_server, tmp_path):
    """A detection whose rule id is not indexed must be reported, not dropped."""
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")

    result = server.scan_evtx_attack(str(evtx))

    assert result["unmapped_detections"] == 1
    ghost = [d for d in result["detections"] if d["RuleID"] == "ghost"]
    assert len(ghost) == 1
    assert ghost[0]["techniques"] == []


def test_scan_evtx_attack_annotates_detections_with_techniques(kb_server, tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")

    detections = server.scan_evtx_attack(str(evtx))["detections"]

    wmi = next(d for d in detections if d["RuleID"] == "wmi")
    assert wmi["techniques"] == ["T1047"]
    assert wmi["tactics"] == ["execution", "lateral-movement"]
    assert wmi["RuleTitle"] == "WMI Exec"


def test_scan_evtx_attack_max_results_caps_detections_but_not_rollup(kb_server, tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")

    result = server.scan_evtx_attack(str(evtx), max_results=1)

    assert result["returned"] == 1
    assert len(result["detections"]) == 1
    assert result["total"] == 3  # rollup still covers every detection
    assert len(result["techniques_observed"]) == 2


def test_scan_evtx_attack_rejects_bad_max_results(kb_server, tmp_path):
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    with pytest.raises(hayabusa.HayabusaError, match="max_results must be"):
        server.scan_evtx_attack(str(evtx), max_results=0)


def test_scan_evtx_attack_persists_the_run_when_mongo_is_enabled(kb_server, tmp_path, monkeypatch):
    """The scan/knowledge-base join is also where detection evidence enters the
    data model. The tool offers every detection for storage, not just the page
    it returns — truncating the caller's payload must not truncate the record."""
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")
    captured = {}

    def fake_persist(report, *, evtx_source, **kwargs):
        captured["report"] = report
        captured["evtx_source"] = evtx_source
        return {"run_id": "abc123", "detections_stored": len(report["detections"])}

    monkeypatch.setattr(server.mongo, "persist_scan", fake_persist)

    result = server.scan_evtx_attack(str(evtx), max_results=1)

    assert result["run"] == {"run_id": "abc123", "detections_stored": 3}
    assert result["returned"] == 1  # the caller's page is still capped...
    assert len(captured["report"]["detections"]) == 3  # ...the evidence is not
    assert captured["evtx_source"] == str(evtx.resolve())


def test_scan_evtx_attack_reports_nothing_extra_when_persistence_is_off(kb_server, tmp_path):
    """The default path: no 'run' key, and the scan is unaffected."""
    evtx = tmp_path / "a.evtx"
    evtx.write_text("")

    result = server.scan_evtx_attack(str(evtx))

    assert "run" not in result
    assert result["total"] == 3
