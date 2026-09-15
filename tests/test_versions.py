"""Tests for STIX parsing and framework version comparison.

Everything here runs against small synthetic bundles built in-process — no
network, no 53MB download, no database. That is possible because
:mod:`mcp_hayabusa.versions` takes two already-parsed bundles and an injected
rule lookup; the downloading lives in ``scripts/``. Each of the four change
classes gets its own bundle pair, so a misclassification fails one test rather
than shifting a count in a large fixture.
"""

from __future__ import annotations

import pytest

from mcp_hayabusa import stix, versions


# --------------------------------------------------------------------------
# Synthetic bundle construction
# --------------------------------------------------------------------------


def technique(
    tid: str,
    name: str = "",
    *,
    stix_id: str = "",
    deprecated: bool = False,
    revoked: bool = False,
    tactics: tuple[str, ...] = ("execution",),
    source: str = "mitre-attack",
    extra_refs: tuple[dict, ...] = (),
) -> dict:
    """One attack-pattern, shaped as MITRE publishes them.

    The public id lives in external_references, not in the STIX id — getting
    that wrong is the single easiest way to parse a bundle into nonsense.
    """
    obj = {
        "type": "attack-pattern",
        "id": stix_id or f"attack-pattern--{tid}",
        "name": name or tid,
        "description": f"{tid} does something.",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics
        ],
        "x_mitre_is_subtechnique": "." in tid,
        "external_references": [
            {
                "source_name": source,
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid}/",
            },
            *extra_refs,
        ],
    }
    if deprecated:
        obj["x_mitre_deprecated"] = True
    if revoked:
        obj["revoked"] = True
    return obj


def bundle(*objects: dict, version: str = "1.0", name: str = "Enterprise ATT&CK") -> dict:
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--test",
                "name": name,
                "x_mitre_version": version,
            },
            *objects,
        ],
    }


def revoked_by(old_stix_id: str, new_stix_id: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{old_stix_id}",
        "relationship_type": "revoked-by",
        "source_ref": old_stix_id,
        "target_ref": new_stix_id,
    }


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_parse_bundle_reads_ids_tactics_and_the_release_version():
    parsed = stix.parse_bundle(bundle(technique("T1059", "Command Interpreter"), version="18.1"))

    assert parsed.version == "18.1"
    assert parsed.name == "Enterprise ATT&CK"
    assert parsed.ids() == {"T1059"}
    entry = parsed.techniques["T1059"]
    assert entry["name"] == "Command Interpreter"
    assert entry["tactics"] == ["execution"]
    assert entry["is_subtechnique"] is False
    assert entry["deprecated"] is False and entry["revoked"] is False


def test_parse_bundle_attaches_subtechniques_to_their_parent():
    parsed = stix.parse_bundle(
        bundle(technique("T1003"), technique("T1003.001"), technique("T1003.002"))
    )
    assert parsed.techniques["T1003"]["subtechniques"] == ["T1003.001", "T1003.002"]
    assert parsed.techniques["T1003.001"]["is_subtechnique"] is True
    assert "subtechniques" not in parsed.techniques["T1003.001"]


def test_parse_bundle_resolves_revoked_by_to_a_public_id():
    """The relationship names STIX ids; the report needs T-numbers."""
    parsed = stix.parse_bundle(
        bundle(
            technique("T1086", stix_id="attack-pattern--old", revoked=True),
            technique("T1059.001", stix_id="attack-pattern--new"),
            revoked_by("attack-pattern--old", "attack-pattern--new"),
        )
    )
    assert parsed.techniques["T1086"]["revoked"] is True
    assert parsed.techniques["T1086"]["superseded_by"] == "T1059.001"


def test_parse_bundle_keeps_revoked_techniques_rather_than_dropping_them():
    """Dropping them is the silent-coverage-loss bug: a rule tagged with the old
    id would stop resolving with no error anywhere."""
    parsed = stix.parse_bundle(bundle(technique("T1086", revoked=True)))
    assert "T1086" in parsed.techniques


def test_require_source_keeps_a_cross_referenced_id_from_winning():
    """An ATLAS technique also carries its ATT&CK analogue's id.

    Without require_source, AML.T0000 would be filed under T1596 and would
    overwrite the real T1596 document.
    """
    combined = bundle(
        technique(
            "AML.T0000",
            "Search Open Technical Databases",
            source="mitre-atlas",
            extra_refs=({"source_name": "mitre-attack", "external_id": "T1596", "url": "x"},),
        ),
        technique("T1596", "Search Open Technical Databases"),
    )

    lax = stix.parse_bundle(combined, sources=("mitre-attack", "mitre-atlas"))
    assert lax.ids() == {"T1596"}  # the ATLAS technique collided and vanished

    strict = stix.parse_bundle(combined, sources=("mitre-atlas",), require_source=True)
    assert strict.ids() == {"AML.T0000"}


def test_collection_selects_the_version_from_a_combined_bundle():
    combined = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "x-mitre-collection",
                "id": "c1",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "19.2",
            },
            {
                "type": "x-mitre-collection",
                "id": "c2",
                "name": "ATLAS",
                "x_mitre_version": "2026.08",
            },
        ],
    }
    assert stix.parse_bundle(combined, collection="ATLAS").version == "2026.08"
    assert stix.parse_bundle(combined, collection="Enterprise ATT&CK").version == "19.2"


# --------------------------------------------------------------------------
# The four change classes
# --------------------------------------------------------------------------


def test_added_is_an_id_present_only_in_the_new_release():
    old = stix.parse_bundle(bundle(technique("T1001"), version="18.1"))
    new = stix.parse_bundle(bundle(technique("T1001"), technique("T1002"), version="19.2"))

    result = versions.diff(old, new)
    assert result.old_version == "18.1" and result.new_version == "19.2"
    assert [c.id for c in result.added] == ["T1002"]
    assert result.counts() == {"added": 1, "removed": 0, "deprecated": 0, "revoked": 0}


def test_removed_is_an_id_present_only_in_the_old_release():
    old = stix.parse_bundle(bundle(technique("T1001"), technique("T1002")))
    new = stix.parse_bundle(bundle(technique("T1001")))

    result = versions.diff(old, new)
    assert [c.id for c in result.removed] == ["T1002"]
    assert result.counts()["removed"] == 1


def test_deprecated_is_a_flag_transition_not_a_standing_flag():
    old = stix.parse_bundle(bundle(technique("T1001"), technique("T1002", deprecated=True)))
    new = stix.parse_bundle(
        bundle(technique("T1001", deprecated=True), technique("T1002", deprecated=True))
    )

    result = versions.diff(old, new)
    # T1001 newly deprecated; T1002 was already deprecated, so it is carried,
    # not re-reported. ATT&CK keeps old deprecations forever — counting them
    # every release would bury the ones that actually moved.
    assert [c.id for c in result.deprecated] == ["T1001"]
    assert result.carried_deprecated == 1


def test_revoked_resolves_to_its_named_successor():
    old = stix.parse_bundle(bundle(technique("T1086"), technique("T1059.001", "PowerShell")))
    new = stix.parse_bundle(
        bundle(
            technique("T1086", stix_id="attack-pattern--old", revoked=True),
            technique("T1059.001", "PowerShell", stix_id="attack-pattern--new"),
            revoked_by("attack-pattern--old", "attack-pattern--new"),
        )
    )

    result = versions.diff(old, new)
    assert len(result.revoked) == 1
    change = result.revoked[0]
    assert change.id == "T1086"
    assert change.successor == "T1059.001"
    assert change.successor_name == "PowerShell"
    assert result.carried_revoked == 0


def test_revocation_without_a_successor_is_still_reported():
    new = stix.parse_bundle(bundle(technique("T1086", revoked=True)))
    old = stix.parse_bundle(bundle(technique("T1086")))

    change = versions.diff(old, new).revoked[0]
    assert change.successor is None
    assert "no successor recorded" in change.describe()


def test_categories_are_mutually_exclusive_so_counts_add_up():
    """Presence decides first: a technique in only one release is added or
    removed whatever its flags say, never counted twice."""
    old = stix.parse_bundle(
        bundle(technique("T1001"), technique("T1002"), technique("T1003"), version="18.1")
    )
    new = stix.parse_bundle(
        bundle(
            technique("T1001", deprecated=True),
            technique("T1002", stix_id="attack-pattern--old", revoked=True),
            technique("T1004", stix_id="attack-pattern--new", deprecated=True),
            revoked_by("attack-pattern--old", "attack-pattern--new"),
            version="19.2",
        )
    )

    result = versions.diff(old, new)
    assert result.counts() == {"added": 1, "removed": 1, "deprecated": 1, "revoked": 1}
    assert len(result.changes()) == 4
    ids = [c.id for c in result.changes()]
    assert len(ids) == len(set(ids))
    # T1004 arrives already deprecated but is new, so it is an addition.
    assert [c.id for c in result.added] == ["T1004"]
    assert [c.id for c in result.removed] == ["T1003"]


# --------------------------------------------------------------------------
# Mapping impact — the actual point
# --------------------------------------------------------------------------


@pytest.fixture
def four_way_diff():
    old = stix.parse_bundle(
        bundle(technique("T1001"), technique("T1002"), technique("T1003"), version="18.1")
    )
    new = stix.parse_bundle(
        bundle(
            technique("T1001", deprecated=True),
            technique("T1002", stix_id="attack-pattern--old", revoked=True),
            technique("T1004", stix_id="attack-pattern--new", name="Replacement"),
            revoked_by("attack-pattern--old", "attack-pattern--new"),
            version="19.2",
        )
    )
    return versions.diff(old, new)


def test_attach_rule_impact_reports_rule_ids_not_just_technique_ids(four_way_diff):
    lookup = {
        "T1001": ["rule-a", "rule-b", "rule-c"],
        "T1002": ["rule-d"],
        "T1003": [],
        "T1004": [],
    }
    versions.attach_rule_impact(four_way_diff, lookup)

    deprecated = four_way_diff.deprecated[0]
    assert deprecated.rules == ["rule-a", "rule-b", "rule-c"]
    assert "3 Sigma rule(s) still map to it" in deprecated.describe()

    revoked = four_way_diff.revoked[0]
    assert revoked.rules == ["rule-d"]
    assert "superseded by T1004 (Replacement)" in revoked.describe()
    assert "1 rule(s) need remapping" in revoked.describe()

    assert four_way_diff.affected_rule_ids() == {"rule-a", "rule-b", "rule-c", "rule-d"}


def test_attach_rule_impact_accepts_a_callable_for_one_batched_query(four_way_diff):
    calls = []

    def lookup(ids):
        calls.append(list(ids))
        return {"T1002": ["rule-d"]}

    versions.attach_rule_impact(four_way_diff, lookup)
    assert len(calls) == 1  # one round trip, not one per change
    assert set(calls[0]) == {"T1001", "T1002", "T1003", "T1004"}
    assert four_way_diff.revoked[0].rules == ["rule-d"]


def test_summary_separates_rules_needing_remap_from_rules_merely_affected(four_way_diff):
    versions.attach_rule_impact(four_way_diff, {"T1001": ["rule-a", "rule-b"], "T1002": ["rule-d"]})
    report = versions.summary(four_way_diff)

    assert report["old_version"] == "18.1" and report["new_version"] == "19.2"
    assert report["changes"] == {"added": 1, "removed": 1, "deprecated": 1, "revoked": 1}
    assert report["changes_total"] == 4
    assert report["rules_affected"] == 3
    assert report["rules_needing_remap"] == 1  # only the revocation forces a retag


def test_render_shows_every_category_and_names_affected_rules(four_way_diff):
    versions.attach_rule_impact(four_way_diff, {"T1001": ["rule-a"], "T1002": ["rule-d"]})
    text = versions.render(four_way_diff)

    for kind in versions.KINDS:
        assert f"--- {kind.upper()}" in text
    assert "18.1 -> 19.2" in text
    assert "rule-a" in text and "rule-d" in text
    assert "T1002 (T1002) revoked, superseded by T1004 (Replacement)." in text
    # Changes touching no rule are collapsed, not dropped.
    assert "no Sigma rule mapped" in text


def test_render_caps_the_rule_list_but_reports_the_full_count(four_way_diff):
    versions.attach_rule_impact(four_way_diff, {"T1001": [f"rule-{i:02d}" for i in range(25)]})
    text = versions.render(four_way_diff, rule_limit=3)

    assert "rule-00, rule-01, rule-02" in text
    assert "... and 22 more" in text
    assert "25 Sigma rule(s) still map to it" in text
