"""Tests for the MongoDB backing store.

Two tiers, mirroring the binary/no-binary split the rest of the suite uses:

* Tests that need a live server are marked ``@pytest.mark.mongo`` and are
  **auto-skipped** by ``conftest.py`` when nothing answers on the configured
  URI. That is what makes "``make test`` passes with Mongo stopped" a property
  of the suite rather than a hope — Mongo is additive, and the tests say so.
* Document shaping and the severity-floor translation are pure functions and
  are tested without a server at all.

Live tests run against a throwaway database (``hayabusa_test_<pid>``), never the
real ``hayabusa`` one, and drop it afterwards.
"""

from __future__ import annotations

import os

import pytest
import yaml

from mcp_hayabusa import kb, mongo
from mcp_hayabusa.config import Config
from tests.test_kb import ATTACK_YAML, TACTICS_TXT, write_rule

pymongo = pytest.importorskip("pymongo")

TEST_DB = f"hayabusa_test_{os.getpid()}"


@pytest.fixture
def mongo_db():
    """A clean throwaway database with the real indexes on it."""
    try:
        db = mongo.connect(db_name=TEST_DB)
    except mongo.MongoUnavailable as exc:  # pragma: no cover - conftest skips first
        pytest.skip(str(exc))
    client = db.client
    client.drop_database(TEST_DB)
    db = client[TEST_DB]
    mongo.ensure_indexes(db)
    yield db
    client.drop_database(TEST_DB)
    client.close()


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    """A synthetic rule index plus its ATT&CK metadata, as kb builds them.

    Deliberately the same fixture shapes as tests/test_kb.py: hyphenated tactic
    slugs, sub-technique ids, an untagged rule and a rule whose level is not a
    Sigma level. The last two are what make the kb/aggregation equality test
    meaningful — they are exactly where two implementations drift.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    mappings = tmp_path / "mappings"
    mappings.mkdir()
    (mappings / "attack.yaml").write_text(yaml.safe_dump(ATTACK_YAML), encoding="utf-8")
    tactics = tmp_path / "mitre_tactics.txt"
    tactics.write_text(TACTICS_TXT, encoding="utf-8")

    write_rule(
        rules_dir,
        "lsass",
        level="critical",
        tags=["attack.credential-access", "attack.t1003.001", "attack.g0016"],
    )
    write_rule(
        rules_dir,
        "sam",
        level="high",
        tags=["attack.credential-access", "attack.t1003.002"],
    )
    write_rule(
        rules_dir,
        "wmi",
        level="medium",
        tags=["attack.execution", "attack.lateral-movement", "attack.t1047"],
    )
    write_rule(rules_dir, "dump", level="low", tags=["attack.credential-access", "attack.t1003"])
    write_rule(rules_dir, "untagged", level="informational", tags=[])
    # A level outside kb.LEVELS: kb.coverage keeps it whatever the floor, so the
    # aggregation has to as well.
    write_rule(rules_dir, "oddlevel", level="unknown", tags=["attack.execution", "attack.t1047"])

    cfg = Config(
        binary="hayabusa",
        timeout=30.0,
        workdir="",
        rules_dirs=(rules_dir,),
        mappings_dir=mappings,
        index_cache=tmp_path / ".cache" / "index.json",
        tactics_file=tactics,
    )
    monkeypatch.setattr(kb, "CONFIG", cfg)
    monkeypatch.setattr(kb, "_CACHE_MEMO", None)
    return kb.load_index(), kb.load_attack_metadata()


# --------------------------------------------------------------------------
# Pure functions — no server needed
# --------------------------------------------------------------------------


def test_rule_document_mirrors_the_rule_dataclass(corpus):
    index, _ = corpus
    rule = index.by_id()["lsass"]
    doc = mongo.rule_document(rule, framework_version="19.2")

    assert doc["rule_id"] == rule.id  # Rule.id, stored under the queryable name
    assert doc["techniques"] == rule.techniques == ["T1003.001"]
    assert doc["tactics"] == rule.tactics == ["credential-access"]
    assert doc["other_tags"] == ["attack.g0016"]
    assert doc["level"] == "critical"
    assert doc["framework_version"] == "19.2"
    # platform/log_source are @property on Rule, not fields — the loader has to
    # call them, and storing them is the point (they are what operators filter on).
    assert doc["platform"] == rule.platform
    assert doc["log_source"] == rule.log_source == "security"
    assert "id" not in doc and "_id" not in doc


def test_level_match_keeps_levels_kb_does_not_recognize():
    clause = mongo._level_match("high")
    assert clause == {
        "$or": [{"level": {"$nin": kb.LEVELS}}, {"level": {"$in": ["high", "critical"]}}]
    }
    # No floor and an unknown floor both mean "no filter", as in kb.coverage.
    assert mongo._level_match("") is None
    assert mongo._level_match("informational") is None
    assert mongo._level_match("nonsense") is None


def test_version_sort_key_orders_numerically_not_lexically():
    assert sorted(["9.1", "19.0", "10.2"], key=mongo._version_sort_key) == ["9.1", "10.2", "19.0"]
    # A non-numeric release still sorts, after the numeric ones.
    assert sorted(["2026-01", "19.0"], key=mongo._version_sort_key) == ["19.0", "2026-01"]


def test_connect_to_a_dead_server_raises_mongo_unavailable():
    with pytest.raises(mongo.MongoUnavailable):
        # Port 1 has nothing on it; a short timeout keeps the test fast.
        mongo.connect("mongodb://127.0.0.1:1/", "nope", timeout_ms=200)


def test_available_is_false_rather_than_raising():
    assert mongo.available("mongodb://127.0.0.1:1/", "nope") is False


# --------------------------------------------------------------------------
# Live store
# --------------------------------------------------------------------------


@pytest.mark.mongo
def test_ensure_indexes_declares_every_index_and_is_idempotent(mongo_db):
    first = mongo.ensure_indexes(mongo_db)
    second = mongo.ensure_indexes(mongo_db)
    assert first == second  # create_index is a no-op when the index exists

    names = {i["name"] for i in mongo_db[mongo.SIGMA_RULES].list_indexes()}
    assert names == {"_id_", "rule_id_1", "techniques_1", "tactics_1", "level_1_source_1"}

    tech = {i["name"]: i for i in mongo_db[mongo.ATTACK_TECHNIQUES].list_indexes()}
    compound = tech["framework_1_framework_version_1_technique_id_1"]
    assert compound["unique"] is True
    assert list(compound["key"]) == ["framework", "framework_version", "technique_id"]


@pytest.mark.mongo
def test_load_rules_is_idempotent(mongo_db, corpus):
    index, _ = corpus
    first = mongo.load_rules(mongo_db, index, framework_version="19.2")
    assert first["upserted"] == len(index.rules)

    second = mongo.load_rules(mongo_db, index, framework_version="19.2")
    assert second["upserted"] == 0
    assert second["total_in_db"] == first["total_in_db"] == len(index.rules)


@pytest.mark.mongo
def test_rule_id_is_unique(mongo_db, corpus):
    index, _ = corpus
    mongo.load_rules(mongo_db, index)
    with pytest.raises(pymongo.errors.DuplicateKeyError):
        mongo_db[mongo.SIGMA_RULES].insert_one({"rule_id": "lsass", "title": "a clone"})


@pytest.mark.mongo
def test_techniques_array_is_queryable_by_element(mongo_db, corpus):
    """The multikey index means a technique lookup is a key lookup, not a scan."""
    index, _ = corpus
    mongo.load_rules(mongo_db, index)

    found = list(mongo_db[mongo.SIGMA_RULES].find({"techniques": "T1003.001"}))
    assert [d["rule_id"] for d in found] == ["lsass"]

    plan = mongo_db[mongo.SIGMA_RULES].find({"techniques": "T1003.001"}).explain()
    stages = str(plan["queryPlanner"]["winningPlan"])
    assert "IXSCAN" in stages and "COLLSCAN" not in stages


@pytest.mark.mongo
@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"min_level": "high"},
        {"min_level": "critical"},
        {"tactic": "credential-access"},
        {"tactic": "execution", "min_level": "medium"},
        {"tactic": "no-such-tactic"},
    ],
)
def test_aggregation_coverage_equals_kb_coverage(mongo_db, corpus, kwargs):
    """The two implementations must agree, filters and all.

    This is the load-bearing test of the whole store. Keeping a Python rollup
    and an aggregation pipeline side by side is only worth it if they provably
    return the same answer; without this assertion the pipeline is just a
    plausible-looking translation.
    """
    index, meta = corpus
    mongo.load_rules(mongo_db, index, framework_version="19.2")

    assert mongo.coverage(mongo_db, meta, **kwargs) == kb.coverage(index, meta, **kwargs)


@pytest.mark.mongo
def test_coverage_names_techniques_and_counts_untagged_rules(mongo_db, corpus):
    index, meta = corpus
    mongo.load_rules(mongo_db, index)
    report = mongo.coverage(mongo_db, meta)

    assert report["rules_considered"] == len(index.rules)
    assert report["rules_without_technique"] == 1  # the untagged fixture rule
    by_id = {t["id"]: t for t in report["techniques"]}
    assert by_id["T1003.001"]["name"] == "OS Credential Dumping: LSASS Memory"
    assert by_id["T1047"]["rules"] == 2
    # Sorted by count desc, then id asc — the same order kb.coverage returns.
    counts = [(-t["rules"], t["id"]) for t in report["techniques"]]
    assert counts == sorted(counts)


@pytest.mark.mongo
def test_rules_for_techniques_joins_back_to_rule_ids(mongo_db, corpus):
    index, _ = corpus
    mongo.load_rules(mongo_db, index)

    hits = mongo.rules_for_techniques(mongo_db, ["T1047", "T1003.001", "T9999"])
    assert hits["T1047"] == ["oddlevel", "wmi"]
    assert hits["T1003.001"] == ["lsass"]
    assert hits["T9999"] == []  # asked for, nothing maps — reported, not dropped
    assert mongo.rules_for_techniques(mongo_db, []) == {}


@pytest.mark.mongo
def test_framework_coverage_reports_gaps_a_rule_side_rollup_cannot_see(mongo_db, corpus):
    index, meta = corpus
    mongo.load_rules(mongo_db, index)
    entries = [{"technique_id": tid, **e} for tid, e in meta["techniques"].items()]
    mongo.load_techniques(
        mongo_db, entries, framework=mongo.FRAMEWORK_ATTACK, framework_version="19.2"
    )
    mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="19.2")

    report = mongo.framework_coverage(mongo_db, framework=mongo.FRAMEWORK_ATTACK)
    assert report["framework_version"] == "19.2"  # resolved from framework_versions
    assert report["entries_total"] == len(entries)
    covered = {e["id"] for e in report["entries"] if e["rules"]}
    assert covered == {"T1003", "T1003.001", "T1003.002", "T1047"}
    # T1650 is in ATT&CK and nothing detects it: a gap only a framework-side
    # walk can report.
    assert report["entries_gap"] == report["entries_total"] - len(covered)
    assert any(e["id"] == "T1650" and e["rules"] == 0 for e in report["entries"])


@pytest.mark.mongo
def test_record_framework_version_keeps_the_original_ingest_time(mongo_db):
    mongo.record_framework_version(
        mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="18.1", source_url="first"
    )
    first = mongo_db[mongo.FRAMEWORK_VERSIONS].find_one({"version": "18.1"})

    mongo.record_framework_version(
        mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="18.1", source_url="second"
    )
    again = mongo_db[mongo.FRAMEWORK_VERSIONS].find_one({"version": "18.1"})

    assert again["ingested_at"] == first["ingested_at"]  # $setOnInsert
    assert again["source_url"] == "second"  # provenance still refreshes
    assert mongo_db[mongo.FRAMEWORK_VERSIONS].count_documents({"version": "18.1"}) == 1


@pytest.mark.mongo
def test_record_scan_result_round_trips(mongo_db):
    mongo.record_scan_result(
        mongo_db,
        run_id="run-1",
        evtx_source="samples/",
        detections=[{"RuleID": "lsass", "Level": "critical"}],
        observed_techniques=["T1003.001"],
        framework_version="19.2",
    )
    mongo.record_scan_result(
        mongo_db,
        run_id="run-1",
        evtx_source="samples/",
        detections=[],
        observed_techniques=[],
        framework_version="19.2",
    )
    assert mongo_db[mongo.SCAN_RESULTS].count_documents({"run_id": "run-1"}) == 1


@pytest.mark.mongo
def test_stats_reports_counts_and_index_totals(mongo_db, corpus):
    index, meta = corpus
    mongo.load_rules(mongo_db, index)
    report = mongo.stats(mongo_db)

    assert report["documents"][mongo.SIGMA_RULES] == len(index.rules)
    assert report["indexes"][mongo.SIGMA_RULES] == 5  # four declared plus _id_
    assert report["server_version"]


# --------------------------------------------------------------------------
# Historical retention (Task 5)
#
# The guarantee: a new version's writes insert; they never overwrite another
# version's documents. It is enforced structurally by the compound unique index
# on (framework, framework_version, technique_id) — load_techniques filters on
# all three, so a write can only ever select a document of this framework at
# this version. These tests are the proof; without them the guarantee is an
# intention rather than a fact.
# --------------------------------------------------------------------------


def _release(version: str, *, renamed: bool = False) -> list[dict]:
    """Two 'releases' of a tiny framework, differing in a way that would be
    visible if a later ingest overwrote an earlier one."""
    return [
        {
            "technique_id": "T1001",
            "name": "Renamed In v19" if renamed else "Original Name",
            "tactics": ["execution"],
            "deprecated": renamed,
        },
        {"technique_id": "T1002", "name": "Stable", "tactics": ["execution"]},
    ]


@pytest.mark.mongo
def test_ingesting_a_new_version_leaves_the_previous_one_untouched(mongo_db):
    mongo.load_techniques(
        mongo_db, _release("18.1"), framework=mongo.FRAMEWORK_ATTACK, framework_version="18.1"
    )
    mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="18.1")
    before = sorted(
        mongo_db[mongo.ATTACK_TECHNIQUES].find(
            {"framework_version": "18.1"}, {"_id": 0, "technique_id": 1, "name": 1, "deprecated": 1}
        ),
        key=lambda d: d["technique_id"],
    )

    mongo.load_techniques(
        mongo_db,
        _release("19.2", renamed=True),
        framework=mongo.FRAMEWORK_ATTACK,
        framework_version="19.2",
    )
    mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="19.2")

    # The pinned historical read is byte-for-byte what it was before v19 landed.
    after = sorted(
        mongo_db[mongo.ATTACK_TECHNIQUES].find(
            {"framework_version": "18.1"}, {"_id": 0, "technique_id": 1, "name": 1, "deprecated": 1}
        ),
        key=lambda d: d["technique_id"],
    )
    assert after == before
    assert after[0] == {"technique_id": "T1001", "name": "Original Name", "deprecated": False}

    # ...and v19 really did land, so the test is not passing by doing nothing.
    v19 = mongo_db[mongo.ATTACK_TECHNIQUES].find_one(
        {"framework_version": "19.2", "technique_id": "T1001"}
    )
    assert v19["name"] == "Renamed In v19" and v19["deprecated"] is True

    both = mongo_db[mongo.ATTACK_TECHNIQUES].distinct("framework_version")
    assert sorted(both) == ["18.1", "19.2"]
    assert mongo_db[mongo.ATTACK_TECHNIQUES].count_documents({"technique_id": "T1001"}) == 2


@pytest.mark.mongo
def test_reingesting_the_same_version_is_idempotent_not_a_duplicate_key_crash(mongo_db):
    for _ in range(3):
        mongo.load_techniques(
            mongo_db, _release("18.1"), framework=mongo.FRAMEWORK_ATTACK, framework_version="18.1"
        )
    assert mongo_db[mongo.ATTACK_TECHNIQUES].count_documents({"framework_version": "18.1"}) == 2


@pytest.mark.mongo
def test_the_compound_index_is_what_keeps_versions_apart(mongo_db):
    """Same technique id, same framework, different version: allowed.
    Same all three: rejected. That distinction is the whole retention story."""
    doc = {"framework": mongo.FRAMEWORK_ATTACK, "technique_id": "T1001"}
    mongo_db[mongo.ATTACK_TECHNIQUES].insert_one({**doc, "framework_version": "18.1"})
    mongo_db[mongo.ATTACK_TECHNIQUES].insert_one({**doc, "framework_version": "19.2"})

    with pytest.raises(pymongo.errors.DuplicateKeyError):
        mongo_db[mongo.ATTACK_TECHNIQUES].insert_one({**doc, "framework_version": "19.2"})


@pytest.mark.mongo
def test_reads_default_to_the_newest_version_and_pin_explicitly_for_history(mongo_db):
    for version in ("18.1", "19.0", "19.2"):
        mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version=version)
        mongo.load_techniques(
            mongo_db,
            _release(version, renamed=version == "19.2"),
            framework=mongo.FRAMEWORK_ATTACK,
            framework_version=version,
        )

    # 19.2 beats 19.0 beats 18.1 numerically — not lexically, where "9" > "19".
    assert mongo.versions(mongo_db, mongo.FRAMEWORK_ATTACK) == ["18.1", "19.0", "19.2"]
    assert mongo.latest_version(mongo_db, mongo.FRAMEWORK_ATTACK) == "19.2"
    assert mongo.latest_version(mongo_db, "never-ingested") is None

    latest = mongo.framework_coverage(mongo_db, framework=mongo.FRAMEWORK_ATTACK)
    assert latest["framework_version"] == "19.2"
    # 19.2 deprecated T1001, and framework_coverage hides deprecated entries.
    assert {e["id"] for e in latest["entries"]} == {"T1002"}

    pinned = mongo.framework_coverage(
        mongo_db, framework=mongo.FRAMEWORK_ATTACK, framework_version="18.1"
    )
    assert pinned["framework_version"] == "18.1"
    assert {e["id"] for e in pinned["entries"]} == {"T1001", "T1002"}


@pytest.mark.mongo
def test_frameworks_and_versions_coexist_in_one_collection(mongo_db):
    """Four taxonomies and two ATT&CK releases, all keyed apart by the same index."""
    mongo.load_techniques(
        mongo_db, _release("18.1"), framework=mongo.FRAMEWORK_ATTACK, framework_version="18.1"
    )
    mongo.load_techniques(
        mongo_db, _release("19.2"), framework=mongo.FRAMEWORK_ATTACK, framework_version="19.2"
    )
    mongo.load_techniques(
        mongo_db,
        [{"technique_id": "AML.T0043", "name": "Craft Adversarial Data"}],
        framework=mongo.FRAMEWORK_ATLAS,
        framework_version="2026.08",
    )
    mongo.load_techniques(
        mongo_db,
        [{"technique_id": "LLM01", "name": "Prompt Injection"}],
        framework=mongo.FRAMEWORK_OWASP_LLM,
        framework_version="2026",
    )
    mongo.load_techniques(
        mongo_db,
        [{"technique_id": "ASI01", "name": "Agent Goal Hijack"}],
        framework=mongo.FRAMEWORK_OWASP_AGENTIC,
        framework_version="2026",
    )

    assert sorted(mongo_db[mongo.ATTACK_TECHNIQUES].distinct("framework")) == [
        mongo.FRAMEWORK_ATLAS,
        mongo.FRAMEWORK_ATTACK,
        mongo.FRAMEWORK_OWASP_AGENTIC,
        mongo.FRAMEWORK_OWASP_LLM,
    ]
    report = mongo.stats(mongo_db)["frameworks"]
    assert report[mongo.FRAMEWORK_ATTACK]["by_version"] == {"18.1": 2, "19.2": 2}
    assert report[mongo.FRAMEWORK_OWASP_LLM]["total"] == 1


# --------------------------------------------------------------------------
# Scan persistence — the detection-evidence half of the data model
# --------------------------------------------------------------------------

SCAN_REPORT = {
    "total": 2,
    "techniques_observed": [
        {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "detections": 1},
        {"id": "T1047", "name": "Windows Management Instrumentation", "detections": 1},
    ],
    "detections": [
        {"RuleID": "lsass", "Level": "critical", "techniques": ["T1003.001"]},
        {"RuleID": "wmi", "Level": "medium", "techniques": ["T1047"]},
    ],
}


def test_persist_scan_is_a_no_op_when_disabled(monkeypatch):
    """The default. Nothing is written and no socket is opened — a scan must not
    depend on an optional store even being installed."""
    monkeypatch.setattr(
        mongo, "CONFIG", Config(binary="hayabusa", timeout=30.0, workdir="", mongo_enabled=False)
    )
    monkeypatch.setattr(mongo, "connect", lambda *a, **k: pytest.fail("connected while disabled"))
    assert mongo.persist_scan(SCAN_REPORT, evtx_source="samples/") is None


def test_persist_scan_swallows_an_unreachable_server(monkeypatch):
    """Enabled but the container is stopped: still None, never an exception.
    Scanning is the product; scan history is bookkeeping."""
    monkeypatch.setattr(
        mongo,
        "CONFIG",
        Config(
            binary="hayabusa",
            timeout=30.0,
            workdir="",
            mongo_enabled=True,
            mongo_uri="mongodb://127.0.0.1:1/",
            mongo_timeout_ms=200,
        ),
    )
    assert mongo.persist_scan(SCAN_REPORT, evtx_source="samples/") is None


@pytest.mark.mongo
def test_persist_scan_writes_a_run_when_enabled(mongo_db, monkeypatch):
    monkeypatch.setattr(
        mongo,
        "CONFIG",
        Config(binary="hayabusa", timeout=30.0, workdir="", mongo_enabled=True, mongo_db=TEST_DB),
    )
    mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version="19.2")

    stored = mongo.persist_scan(SCAN_REPORT, evtx_source="samples/evil.evtx")
    assert stored is not None
    assert stored["detections_stored"] == 2
    assert stored["observed_techniques"] == 2
    # The run is stamped with the newest ingested framework, so a historical
    # scan can be re-scored against the framework it was actually judged by.
    assert stored["framework_version"] == "19.2"

    doc = mongo_db[mongo.SCAN_RESULTS].find_one({"run_id": stored["run_id"]})
    assert doc["evtx_source"] == "samples/evil.evtx"
    assert doc["observed_techniques"] == ["T1003.001", "T1047"]
    assert [d["RuleID"] for d in doc["detections"]] == ["lsass", "wmi"]
    assert doc["created_at"] is not None


@pytest.mark.mongo
def test_persist_scan_gives_each_run_its_own_id(mongo_db, monkeypatch):
    """Two scans of the same source are two events, not one overwritten row."""
    monkeypatch.setattr(
        mongo,
        "CONFIG",
        Config(binary="hayabusa", timeout=30.0, workdir="", mongo_enabled=True, mongo_db=TEST_DB),
    )
    first = mongo.persist_scan(SCAN_REPORT, evtx_source="samples/")
    second = mongo.persist_scan(SCAN_REPORT, evtx_source="samples/")

    assert first["run_id"] != second["run_id"]
    assert mongo_db[mongo.SCAN_RESULTS].count_documents({}) == 2
    # ...but replaying one explicitly is still idempotent.
    mongo.persist_scan(SCAN_REPORT, evtx_source="samples/", run_id=first["run_id"])
    assert mongo_db[mongo.SCAN_RESULTS].count_documents({}) == 2


@pytest.mark.mongo
def test_persist_scan_bounds_what_it_stores(mongo_db, monkeypatch):
    """A big case must not fail the write by exceeding the 16MB BSON limit."""
    monkeypatch.setattr(
        mongo,
        "CONFIG",
        Config(binary="hayabusa", timeout=30.0, workdir="", mongo_enabled=True, mongo_db=TEST_DB),
    )
    big = {**SCAN_REPORT, "detections": [{"RuleID": f"r{i}"} for i in range(50)]}

    stored = mongo.persist_scan(big, evtx_source="samples/", max_detections=10)
    assert stored["detections_stored"] == 10
    assert stored["detections_truncated"] == 40
    doc = mongo_db[mongo.SCAN_RESULTS].find_one({"run_id": stored["run_id"]})
    assert len(doc["detections"]) == 10


# --------------------------------------------------------------------------
# One query across every framework
# --------------------------------------------------------------------------


@pytest.mark.mongo
def test_all_frameworks_coverage_spans_every_taxonomy_in_one_query(mongo_db, corpus):
    """The query the shared collection exists for: conventional, AI and agentic
    risk answered in one round trip rather than three reconciled afterwards."""
    index, meta = corpus
    mongo.load_rules(mongo_db, index)

    attack_entries = [{"technique_id": tid, **e} for tid, e in meta["techniques"].items()]
    for framework, version, entries in (
        (mongo.FRAMEWORK_ATTACK, "19.2", attack_entries),
        (mongo.FRAMEWORK_ATLAS, "2026.08", [{"technique_id": "AML.T0043", "name": "Craft"}]),
        (mongo.FRAMEWORK_OWASP_LLM, "2026", [{"technique_id": "LLM01", "name": "Injection"}]),
        (mongo.FRAMEWORK_OWASP_AGENTIC, "2026", [{"technique_id": "ASI01", "name": "Hijack"}]),
    ):
        mongo.record_framework_version(mongo_db, framework=framework, version=version)
        mongo.load_techniques(mongo_db, entries, framework=framework, framework_version=version)

    report = mongo.all_frameworks_coverage(mongo_db)

    assert set(report["frameworks"]) == {
        mongo.FRAMEWORK_ATTACK,
        mongo.FRAMEWORK_ATLAS,
        mongo.FRAMEWORK_OWASP_LLM,
        mongo.FRAMEWORK_OWASP_AGENTIC,
    }
    attack = report["frameworks"][mongo.FRAMEWORK_ATTACK]
    assert attack["framework_version"] == "19.2"
    assert attack["entries_covered"] == 4  # T1003, .001, .002, T1047
    assert attack["entries_gap"] == attack["entries_total"] - 4

    # Sigma rules tag ATT&CK ids, so the AI and agentic taxonomies read as gaps.
    # That is a true statement about EVTX, and the reason gaps are reported.
    for framework in (
        mongo.FRAMEWORK_ATLAS,
        mongo.FRAMEWORK_OWASP_LLM,
        mongo.FRAMEWORK_OWASP_AGENTIC,
    ):
        assert report["frameworks"][framework]["entries_covered"] == 0
        assert report["frameworks"][framework]["entries_gap"] == 1

    assert report["entries_total"] == sum(f["entries_total"] for f in report["frameworks"].values())
    assert report["entries_covered"] == 4


@pytest.mark.mongo
def test_all_frameworks_coverage_reads_one_version_per_framework(mongo_db, corpus):
    """Two ATT&CK releases are in the collection; the rollup must not count both."""
    index, meta = corpus
    mongo.load_rules(mongo_db, index)
    entries = [{"technique_id": tid, **e} for tid, e in meta["techniques"].items()]
    for version in ("18.1", "19.2"):
        mongo.record_framework_version(mongo_db, framework=mongo.FRAMEWORK_ATTACK, version=version)
        mongo.load_techniques(
            mongo_db, entries, framework=mongo.FRAMEWORK_ATTACK, framework_version=version
        )

    latest = mongo.all_frameworks_coverage(mongo_db)["frameworks"][mongo.FRAMEWORK_ATTACK]
    assert latest["framework_version"] == "19.2"
    assert latest["entries_total"] == len(entries)  # not 2x

    pinned = mongo.all_frameworks_coverage(mongo_db, pinned={mongo.FRAMEWORK_ATTACK: "18.1"})[
        "frameworks"
    ][mongo.FRAMEWORK_ATTACK]
    assert pinned["framework_version"] == "18.1"
    assert pinned["entries_total"] == len(entries)


@pytest.mark.mongo
def test_all_frameworks_coverage_on_an_empty_store(mongo_db):
    assert mongo.all_frameworks_coverage(mongo_db) == {
        "frameworks": {},
        "entries_total": 0,
        "entries_covered": 0,
        "entries_gap": 0,
    }
