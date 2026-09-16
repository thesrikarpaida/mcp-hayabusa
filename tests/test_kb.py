"""Tests for the Sigma/ATT&CK knowledge base.

Everything runs against a small synthetic corpus in tmp_path with CONFIG
monkeypatched at it, so these need neither the hayabusa binary nor the real
4.8k-rule corpus. The fixtures mirror the shapes that matter in the real data:
hyphenated tactic slugs, group/software tags mixed in with techniques, and
sub-technique ids.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from mcp_hayabusa import kb
from mcp_hayabusa.config import Config

TACTICS_TXT = """tag_full_str,tag_output_str,html_tag_output_str
attack.execution,Exec,04. Execution
attack.credential-access,CredAccess,09. Credential Access
attack.lateral-movement,LatMov,11. Lateral Movement
"""

ATTACK_YAML = {
    "tactics": {
        "credential-access": {"id": "TA0006", "name": "Credential Access"},
        "execution": {"id": "TA0002", "name": "Execution"},
        "lateral-movement": {"id": "TA0008", "name": "Lateral Movement"},
    },
    "techniques": {
        "T1003": {
            "name": "OS Credential Dumping",
            "description": "Adversaries may dump credentials.",
            "tactics": ["credential-access"],
            "is_subtechnique": False,
            "subtechniques": ["T1003.001", "T1003.002"],
            "url": "https://attack.mitre.org/techniques/T1003/",
        },
        "T1003.001": {
            "name": "LSASS Memory",
            "description": "Adversaries may dump LSASS.",
            "tactics": ["credential-access"],
            "is_subtechnique": True,
        },
        "T1003.002": {
            "name": "Security Account Manager",
            "tactics": ["credential-access"],
            "is_subtechnique": True,
        },
        "T1047": {
            "name": "Windows Management Instrumentation",
            "tactics": ["execution", "lateral-movement"],
            "is_subtechnique": False,
        },
        "T1086": {
            "name": "PowerShell",
            "tactics": ["execution"],
            "is_subtechnique": False,
            "revoked": True,
            "superseded_by": "T1059.001",
        },
        "T1650": {"name": "Acquire Access", "tactics": ["execution"], "is_subtechnique": False},
    },
}


def write_rule(directory: Path, name: str, **over) -> Path:
    """Write a minimal but realistic Sigma rule; `over` replaces top-level keys."""
    doc = {
        "title": over.pop("title", name),
        "id": over.pop("id", name),
        "status": over.pop("status", "stable"),
        "description": over.pop("description", f"detects {name}"),
        "author": "test",
        "tags": over.pop("tags", []),
        "logsource": over.pop("logsource", {"product": "windows", "service": "security"}),
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
        "level": over.pop("level", "medium"),
    }
    doc.update(over)
    path = directory / f"{name}.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


@pytest.fixture
def kb_env(tmp_path, monkeypatch):
    """A rules dir, a mappings dir, and a CONFIG pointed at both."""
    rules = tmp_path / "rules"
    rules.mkdir()
    mappings = tmp_path / "mappings"
    mappings.mkdir()
    (mappings / "attack.yaml").write_text(yaml.safe_dump(ATTACK_YAML), encoding="utf-8")
    tactics = tmp_path / "mitre_tactics.txt"
    tactics.write_text(TACTICS_TXT, encoding="utf-8")

    cfg = Config(
        binary="hayabusa",
        timeout=30.0,
        workdir="",
        rules_dirs=(rules,),
        mappings_dir=mappings,
        index_cache=tmp_path / ".cache" / "index.json",
        tactics_file=tactics,
    )
    monkeypatch.setattr(kb, "CONFIG", cfg)
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)  # memo is keyed by path+mtime; start clean
    return cfg


# --------------------------------------------------------------------------
# Parsing and tag classification
# --------------------------------------------------------------------------


def test_parse_rule_splits_techniques_tactics_and_other_tags(kb_env):
    path = write_rule(
        kb_env.rules_dirs[0],
        "cred",
        tags=[
            "attack.credential-access",  # tactic
            "attack.t1003.001",  # technique (normalized to upper)
            "attack.g0016",  # intrusion group — not a tactic
            "attack.s0002",  # software — not a tactic
            "sysmon",  # plain tag
        ],
    )
    rule = kb.parse_rule(path, "rules", kb._load_tactic_slugs())

    assert rule.techniques == ["T1003.001"]
    assert rule.tactics == ["credential-access"]
    assert set(rule.other_tags) == {"attack.g0016", "attack.s0002", "sysmon"}


def test_parse_rules_reads_every_document_in_a_correlation_rule(kb_env, tmp_path):
    """Sigma correlation rules are multi-document YAML; both docs are real rules.

    yaml.load() raises on multi-document input, which silently dropped the whole
    brute-force family from the index until a real scan exposed it.
    """
    path = tmp_path / "correlation.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "title": "User Guessing",
                "id": "corr-1",
                "tags": ["attack.credential-access", "attack.t1110.003"],
                "level": "medium",
                "correlation": {"type": "value_count", "rules": ["base"]},
            }
        )
        + "\n---\n"
        + yaml.safe_dump(
            {
                "title": "Failed Logon",
                "id": "base-1",
                "name": "base",
                "level": "medium",
                "logsource": {"product": "windows", "service": "security"},
            }
        ),
        encoding="utf-8",
    )

    rules = kb.parse_rules(path, "rules", kb._load_tactic_slugs())

    assert [r.id for r in rules] == ["corr-1", "base-1"]
    assert rules[0].techniques == ["T1110.003"]
    # parse_rule stays the single-rule convenience wrapper.
    assert kb.parse_rule(path, "rules", {}).id == "corr-1"


def test_multi_document_rules_are_indexed_and_not_counted_as_skipped(kb_env):
    rules_dir = kb_env.rules_dirs[0]
    (rules_dir / "multi.yml").write_text(
        yaml.safe_dump({"title": "A", "id": "a", "level": "low", "tags": ["attack.t1047"]})
        + "\n---\n"
        + yaml.safe_dump({"title": "B", "id": "b", "level": "low", "tags": ["attack.t1003"]}),
        encoding="utf-8",
    )

    index = kb.load_index()

    assert {r.id for r in index.rules} == {"a", "b"}
    assert not any("skipped" in n for n in index.notes)


def test_parse_rules_returns_empty_for_non_rule_yaml(kb_env, tmp_path):
    junk = tmp_path / "notarule.yml"
    junk.write_text("just: a mapping\n", encoding="utf-8")
    assert kb.parse_rules(junk, "rules", {}) == []


def test_parse_rule_returns_none_for_non_rule_yaml(kb_env, tmp_path):
    junk = tmp_path / "notarule.yml"
    junk.write_text("just: a mapping\n", encoding="utf-8")
    assert kb.parse_rule(junk, "rules", {}) is None


def test_parse_rule_returns_none_for_malformed_yaml(kb_env, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: x\n  bad: [indent\n", encoding="utf-8")
    assert kb.parse_rule(bad, "rules", {}) is None


def test_malformed_rule_is_skipped_not_fatal(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "good", tags=["attack.t1047"])
    (rules / "broken.yml").write_text("title: x\n  bad: [indent\n", encoding="utf-8")

    index = kb.load_index()

    assert [r.id for r in index.rules] == ["good"]
    assert any("skipped 1 unparseable" in n for n in index.notes)


# --------------------------------------------------------------------------
# Index assembly
# --------------------------------------------------------------------------


def test_earlier_rules_dir_shadows_later_on_duplicate_id(kb_env, tmp_path, monkeypatch):
    custom, corpus = kb_env.rules_dirs[0], tmp_path / "corpus"
    corpus.mkdir()
    write_rule(custom, "dupe", title="Custom Version", level="critical")
    write_rule(corpus, "dupe", title="Corpus Version", level="low")
    monkeypatch.setattr(kb, "CONFIG", Config(**{**kb_env.__dict__, "rules_dirs": (custom, corpus)}))

    index = kb.load_index()

    assert len(index.rules) == 1
    assert index.rules[0].title == "Custom Version"


def test_missing_rules_dir_is_noted_not_fatal(kb_env, tmp_path, monkeypatch):
    monkeypatch.setattr(
        kb,
        "CONFIG",
        Config(**{**kb_env.__dict__, "rules_dirs": (tmp_path / "nope",)}),
    )
    index = kb.load_index()
    assert index.rules == []
    assert any("not found" in n for n in index.notes)


def test_small_dir_is_rescanned_live_so_edits_appear(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "one", tags=["attack.t1047"])
    assert len(kb.load_index().rules) == 1

    write_rule(rules, "two", tags=["attack.t1003"])
    assert len(kb.load_index().rules) == 2  # no rebuild needed


def test_large_dir_is_cached_and_not_reparsed(kb_env, monkeypatch):
    """A dir over the live threshold is parsed once, then served from cache."""
    rules = kb_env.rules_dirs[0]
    monkeypatch.setattr(kb, "LIVE_DIR_MAX_FILES", 1)
    write_rule(rules, "a", tags=["attack.t1047"])
    write_rule(rules, "b", tags=["attack.t1003"])

    first = kb.load_index()
    assert len(first.rules) == 2
    assert kb_env.index_cache.is_file()

    # Any later parse would be a bug: the cache must answer instead.
    monkeypatch.setattr(kb, "parse_rule", lambda *a, **k: pytest.fail("re-parsed a pinned dir"))
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)  # force a real read of the cache file
    cached = kb.load_index()

    assert {r.id for r in cached.rules} == {"a", "b"}
    assert any("cached" in n for n in cached.notes)


def test_rebuild_reparses_pinned_dir(kb_env, monkeypatch):
    rules = kb_env.rules_dirs[0]
    monkeypatch.setattr(kb, "LIVE_DIR_MAX_FILES", 0)
    write_rule(rules, "a", tags=["attack.t1047"])
    kb.load_index()

    write_rule(rules, "b", tags=["attack.t1003"])
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)
    assert len(kb.load_index().rules) == 1  # cached: still stale
    assert len(kb.load_index(rebuild=True).rules) == 2  # rebuild picks up the new rule


def test_corrupt_cache_falls_back_to_parsing(kb_env, monkeypatch):
    monkeypatch.setattr(kb, "LIVE_DIR_MAX_FILES", 0)
    write_rule(kb_env.rules_dirs[0], "a", tags=["attack.t1047"])
    kb_env.index_cache.parent.mkdir(parents=True, exist_ok=True)
    kb_env.index_cache.write_text("{not json", encoding="utf-8")

    assert len(kb.load_index().rules) == 1


def test_cache_entry_with_unknown_rule_fields_falls_back_to_parsing(kb_env, monkeypatch):
    """A Rule schema change without a CACHE_VERSION bump must re-parse, not crash."""
    monkeypatch.setattr(kb, "LIVE_DIR_MAX_FILES", 0)
    write_rule(kb_env.rules_dirs[0], "a", tags=["attack.t1047"])
    kb.load_index()  # writes the cache

    stale = json.loads(kb_env.index_cache.read_text())
    for entry in stale["dirs"].values():
        for rule in entry["rules"]:
            rule["field_from_the_future"] = "boom"
    kb_env.index_cache.write_text(json.dumps(stale), encoding="utf-8")
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)

    index = kb.load_index()

    assert [r.id for r in index.rules] == ["a"]


def test_stale_cache_version_is_ignored(kb_env, monkeypatch):
    monkeypatch.setattr(kb, "LIVE_DIR_MAX_FILES", 0)
    write_rule(kb_env.rules_dirs[0], "a", tags=["attack.t1047"])
    kb_env.index_cache.parent.mkdir(parents=True, exist_ok=True)
    kb_env.index_cache.write_text(
        json.dumps({"version": kb.CACHE_VERSION + 99, "dirs": {}}), encoding="utf-8"
    )

    assert len(kb.load_index().rules) == 1


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------


def test_search_filters_combine_with_and(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "hi", title="WMI Lateral", tags=["attack.t1047"], level="high")
    write_rule(rules, "lo", title="WMI Quiet", tags=["attack.t1047"], level="low")

    index = kb.load_index()
    assert {r.id for r in kb.search(index, technique="T1047")} == {"hi", "lo"}
    assert [r.id for r in kb.search(index, technique="T1047", level="high")] == ["hi"]
    assert [r.id for r in kb.search(index, query="quiet")] == ["lo"]
    assert kb.search(index, technique="T1047", level="critical") == []


def test_search_parent_technique_matches_subtechniques(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "sub", tags=["attack.t1003.001"])
    write_rule(rules, "other", tags=["attack.t1047"])

    index = kb.load_index()
    assert [r.id for r in kb.search(index, technique="T1003")] == ["sub"]
    # ...but a sub-technique query must not match its siblings or parent-only rules.
    assert kb.search(index, technique="T1003.002") == []


def test_search_matches_description_and_respects_limit(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "a", description="mimikatz style theft", tags=["attack.t1003.001"])
    write_rule(rules, "b", description="mimikatz again", tags=["attack.t1003.001"])

    index = kb.load_index()
    assert len(kb.search(index, query="mimikatz")) == 2
    assert len(kb.search(index, query="mimikatz", limit=1)) == 1


# --------------------------------------------------------------------------
# Platform and breakdown
# --------------------------------------------------------------------------


@pytest.fixture
def two_tree_corpus(kb_env, tmp_path, monkeypatch):
    """A corpus shaped like the real one: parallel sysmon/ and builtin/ trees.

    The bundled corpus mirrors the same detections across both trees, so the
    fixture gives "Mimikatz" a rule in each — that duplication is what
    distinct_detections exists to expose.
    """
    sigma = tmp_path / "bundled" / "sigma"
    for tree, category in (("sysmon", "process_access"), ("builtin", "process_creation")):
        (sigma / tree / category).mkdir(parents=True)
        write_rule(
            sigma / tree / category,
            f"mimikatz-{tree}",
            title="Mimikatz",  # same detection, both trees
            tags=["attack.t1003.001"],
            level="critical",
            logsource={"product": "windows", "category": category},
        )
    write_rule(
        sigma / "sysmon" / "process_access",
        "handlekatz",
        title="HandleKatz",
        tags=["attack.t1003.001"],
        level="high",
        status="deprecated",
        logsource={"product": "windows", "category": "process_access"},
    )
    cfg = Config(**{**kb_env.__dict__, "rules_dirs": (kb_env.rules_dirs[0], sigma)})
    monkeypatch.setattr(kb, "CONFIG", cfg)
    return cfg


def test_rule_platform_derives_telemetry_tree_from_path(two_tree_corpus):
    """Which tree a rule sits in decides whether it can fire; it is only in the path."""
    by_id = kb.load_index().by_id()

    assert by_id["mimikatz-sysmon"].platform == "sigma/sysmon"
    assert by_id["mimikatz-builtin"].platform == "sigma/builtin"


def test_rule_platform_falls_back_to_source_for_a_flat_rules_dir(kb_env):
    """A hand-authored rules/ has no tree below it — the source is the whole answer."""
    write_rule(kb_env.rules_dirs[0], "custom", tags=["attack.t1047"])

    assert kb.load_index().by_id()["custom"].platform == "rules"


def test_rule_platform_ignores_a_matching_dir_name_above_the_rules_dir(
    kb_env, tmp_path, monkeypatch
):
    """The real corpus lives at hayabusa/rules/hayabusa/builtin — the install dir
    shares the rules dir's name, so a forward search would return the wrong tree."""
    nested = tmp_path / "hayabusa" / "rules" / "hayabusa" / "builtin"
    nested.mkdir(parents=True)
    write_rule(nested, "log-cleared", tags=["attack.t1070.001"])
    monkeypatch.setattr(kb, "CONFIG", Config(**{**kb_env.__dict__, "rules_dirs": (nested.parent,)}))

    assert kb.load_index().by_id()["log-cleared"].platform == "hayabusa/builtin"


def test_breakdown_counts_every_axis_and_orders_severity_high_first(two_tree_corpus):
    counts = kb.breakdown(kb.load_index().rules)

    assert counts["total"] == 3
    # "Mimikatz" is one detection compiled twice — the raw total double-counts it.
    assert counts["distinct_detections"] == 2
    assert counts["by_platform"] == {"sigma/sysmon": 2, "sigma/builtin": 1}
    assert counts["by_log_source"] == {"process_access": 2, "process_creation": 1}
    assert counts["by_status"] == {"stable": 2, "deprecated": 1}
    # Severity reads critical-first, not by count — triage order, not popularity.
    assert list(counts["by_severity"]) == ["critical", "high"]


def test_breakdown_of_nothing_is_empty_not_an_error(kb_env):
    assert kb.breakdown([]) == {
        "total": 0,
        "distinct_detections": 0,
        "by_severity": {},
        "by_platform": {},
        "by_log_source": {},
        "by_status": {},
        "by_source": {},
    }


# --------------------------------------------------------------------------
# ATT&CK metadata and coverage
# --------------------------------------------------------------------------


def test_technique_name_renders_subtechnique_under_parent(kb_env):
    meta = kb.load_attack_metadata()
    assert kb.technique_name("T1003.001", meta) == "OS Credential Dumping: LSASS Memory"
    assert kb.technique_name("T1003", meta) == "OS Credential Dumping"


def test_technique_name_falls_back_to_parent_for_unknown_subtechnique(kb_env):
    meta = kb.load_attack_metadata()
    assert kb.technique_name("T1003.999", meta) == "OS Credential Dumping"
    assert kb.technique_name("T9999", meta) is None


def test_missing_mappings_file_is_not_fatal(kb_env):
    (kb_env.mappings_dir / "attack.yaml").unlink()
    meta = kb.load_attack_metadata()
    assert meta == {"techniques": {}, "tactics": {}}


def test_coverage_counts_rules_per_technique_and_tactic(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "a", tags=["attack.credential-access", "attack.t1003.001"])
    write_rule(rules, "b", tags=["attack.credential-access", "attack.t1003.001"])
    write_rule(rules, "c", tags=["attack.execution", "attack.t1047"])
    write_rule(rules, "untagged", tags=["sysmon"])

    report = kb.coverage(kb.load_index(), kb.load_attack_metadata())

    assert report["rules_considered"] == 4
    assert report["rules_without_technique"] == 1
    assert report["techniques_covered"] == 2
    assert report["tactics"] == {"credential-access": 2, "execution": 1}
    assert report["techniques"][0] == {
        "id": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "rules": 2,
    }


def test_coverage_min_level_excludes_quieter_rules(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "loud", tags=["attack.t1047"], level="critical")
    write_rule(rules, "quiet", tags=["attack.t1003"], level="low")

    report = kb.coverage(kb.load_index(), kb.load_attack_metadata(), min_level="high")

    assert report["rules_considered"] == 1
    assert [t["id"] for t in report["techniques"]] == ["T1047"]


def test_coverage_tactic_filter(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "a", tags=["attack.credential-access", "attack.t1003"])
    write_rule(rules, "b", tags=["attack.execution", "attack.t1047"])

    report = kb.coverage(kb.load_index(), kb.load_attack_metadata(), tactic="execution")

    assert [t["id"] for t in report["techniques"]] == ["T1047"]


# --------------------------------------------------------------------------
# Per-technique assessment: covered / partial / gap
# --------------------------------------------------------------------------


def test_technique_detail_gap_when_nothing_cites_it(kb_env):
    write_rule(kb_env.rules_dirs[0], "a", tags=["attack.t1047"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1650")

    assert detail["coverage"]["assessment"] == "gap"
    assert detail["coverage"]["rules_total"] == 0
    assert detail["rules"] == []


def test_technique_detail_covered_reports_name_description_and_rules(kb_env):
    write_rule(kb_env.rules_dirs[0], "wmi", title="WMI Exec", tags=["attack.t1047"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1047")

    assert detail["coverage"]["assessment"] == "covered"
    assert detail["name"] == "Windows Management Instrumentation"
    assert detail["tactics"] == ["execution", "lateral-movement"]
    assert [r["title"] for r in detail["rules"]] == ["WMI Exec"]


def test_technique_detail_partial_when_some_subtechniques_uncovered(kb_env):
    write_rule(kb_env.rules_dirs[0], "lsass", tags=["attack.t1003.001"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1003")

    cov = detail["coverage"]
    assert cov["assessment"] == "partial"
    assert cov["subtechniques"] == {"total": 2, "covered": 1, "uncovered": ["T1003.002"]}
    assert "T1003.002" in cov["rationale"]


def test_technique_detail_partial_when_only_experimental_rules(kb_env):
    write_rule(kb_env.rules_dirs[0], "wmi", tags=["attack.t1047"], status="experimental")

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1047")

    assert detail["coverage"]["assessment"] == "partial"
    assert "experimental" in detail["coverage"]["rationale"]


def test_technique_detail_covered_when_all_subtechniques_covered(kb_env):
    rules = kb_env.rules_dirs[0]
    write_rule(rules, "parent", tags=["attack.t1003"])
    write_rule(rules, "s1", tags=["attack.t1003.001"])
    write_rule(rules, "s2", tags=["attack.t1003.002"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1003")

    assert detail["coverage"]["assessment"] == "covered"
    assert detail["coverage"]["rules_total"] == 3  # parent + both subs, deduped


def test_technique_detail_warns_on_revoked_technique(kb_env):
    write_rule(kb_env.rules_dirs[0], "ps", tags=["attack.t1086"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1086")

    assert "revoked" in detail["warning"]
    assert "T1059.001" in detail["warning"]


def test_technique_detail_warns_when_technique_unknown_to_attack(kb_env):
    write_rule(kb_env.rules_dirs[0], "typo", tags=["attack.t9999"])

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T9999")

    assert detail["known_to_attack"] is False
    assert "not present in mappings" in detail["warning"]
    # The rule is still reported — a bad tag must stay visible, not vanish.
    assert detail["coverage"]["rules_total"] == 1


def test_technique_detail_counts_subtechnique_cited_but_unknown_to_attack(kb_env):
    """A rule citing a sub-technique ATT&CK does not list still counts.

    T1003.999 is not in the mappings, but a rule detects it, so it must be
    counted against the parent rather than silently dropped.
    """
    write_rule(kb_env.rules_dirs[0], "odd", tags=["attack.t1003.999"])

    cov = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1003")["coverage"]

    # The two mapped subs plus the cited-but-unmapped one.
    assert cov["subtechniques"]["total"] == 3
    assert cov["subtechniques"]["covered"] == 1
    assert cov["subtechniques"]["uncovered"] == ["T1003.001", "T1003.002"]
    assert cov["rules_total"] == 1


def test_technique_detail_caps_rules_but_counts_all(kb_env):
    """Popular techniques have hundreds of rules; the payload must stay bounded."""
    rules = kb_env.rules_dirs[0]
    for i in range(6):
        write_rule(rules, f"r{i}", tags=["attack.t1047"], level="low")
    write_rule(rules, "loud", title="Loud", tags=["attack.t1047"], level="critical")

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1047", rule_limit=3)

    assert detail["coverage"]["rules_total"] == 7  # counts are complete
    assert detail["rules_returned"] == 3
    assert len(detail["rules"]) == 3
    assert detail["rules"][0]["title"] == "Loud"  # highest severity first
    assert "search_rules" in detail["rules_note"]


def test_technique_detail_breakdown_describes_all_rules_not_the_returned_page(kb_env):
    """The whole point of the breakdown: characterize the set without paging it.

    A breakdown of the truncated list would silently describe 3 rules while the
    coverage claim next to it is made over 7.
    """
    rules = kb_env.rules_dirs[0]
    for i in range(6):
        write_rule(rules, f"r{i}", tags=["attack.t1047"], level="low")
    write_rule(rules, "loud", title="Loud", tags=["attack.t1047"], level="critical")

    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1047", rule_limit=3)

    assert detail["rules_returned"] == 3
    assert detail["breakdown"]["total"] == 7
    assert detail["breakdown"]["by_severity"] == {"critical": 1, "low": 6}


def test_technique_detail_omits_rules_note_when_nothing_truncated(kb_env):
    write_rule(kb_env.rules_dirs[0], "wmi", tags=["attack.t1047"])
    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "T1047")
    assert "rules_note" not in detail


def test_technique_detail_is_case_insensitive(kb_env):
    write_rule(kb_env.rules_dirs[0], "wmi", tags=["attack.t1047"])
    detail = kb.technique_detail(kb.load_index(), kb.load_attack_metadata(), "t1047")
    assert detail["id"] == "T1047"
    assert detail["coverage"]["assessment"] == "covered"


# --------------------------------------------------------------------------
# The ATLAS bridge, Python side. No MongoDB — this is the path scan_evtx_attack
# takes, and it has to work with the container stopped.
# --------------------------------------------------------------------------

ATLAS_META = {
    "techniques": {
        # MITRE adopted these from ATT&CK and kept the ids.
        "AML.T0050": {
            "name": "Command and Scripting Interpreter",
            "tactics": ["execution"],
            "cross_refs": ["T1059"],
        },
        "AML.T0090": {"name": "OS Credential Dumping", "cross_refs": ["T1003"]},
        # AI-native: no conventional counterpart, so never observable here.
        "AML.T0051": {"name": "LLM Prompt Injection", "tactics": ["execution"]},
    }
}


def test_observed_atlas_credits_a_parent_from_its_subtechnique():
    """ATLAS cites T1059; the rule that fires tags T1059.001."""
    rolled = kb.observed_atlas({"T1059.001": 3}, ATLAS_META)
    assert [e["id"] for e in rolled] == ["AML.T0050"]
    assert rolled[0]["via"] == ["T1059.001"]
    assert rolled[0]["detections"] == 3
    assert rolled[0]["tactics"] == ["execution"]


def test_observed_atlas_sums_several_techniques_into_one_entry():
    rolled = kb.observed_atlas({"T1059.001": 2, "T1059.003": 1}, ATLAS_META)
    assert rolled[0]["detections"] == 3
    assert rolled[0]["via"] == ["T1059.001", "T1059.003"]


def test_observed_atlas_ignores_entries_with_no_cross_reference():
    """An AI-native ATLAS technique can never be evidenced by an EVTX scan."""
    rolled = kb.observed_atlas({"T1059.001": 1, "T1003.001": 1}, ATLAS_META)
    assert "AML.T0051" not in {e["id"] for e in rolled}
    assert {e["id"] for e in rolled} == {"AML.T0050", "AML.T0090"}


def test_observed_atlas_is_empty_without_atlas_metadata():
    """A missing mappings/atlas.yaml degrades to no rollup, not an error."""
    assert kb.observed_atlas({"T1059.001": 1}, {"techniques": {}}) == []
    assert kb.observed_atlas({}, ATLAS_META) == []


def test_atlas_from_attack_inverts_the_cross_references():
    inverted = kb.atlas_from_attack(ATLAS_META)
    assert inverted == {"T1059": ["AML.T0050"], "T1003": ["AML.T0090"]}
