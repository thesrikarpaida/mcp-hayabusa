"""MongoDB backing store for the rule index and the threat frameworks.

This layer is **additive**. ``.cache/rule_index.json`` remains the authority the
MCP server reads, so every tool and every test keeps working with the Mongo
container stopped; nothing here is imported on the server's hot path unless
``CONFIG.mongo_enabled`` is set. What Mongo buys is the two things a flat JSON
cache cannot express:

* **Several frameworks in one place.** ATT&CK Enterprise, MITRE ATLAS and the
  two OWASP top-tens all live in ``attack_techniques``, keyed by ``framework``,
  so a single query spans conventional, AI and agentic risk taxonomies.
* **Several versions of the same framework, side by side.** The compound unique
  index ``(framework, framework_version, technique_id)`` is what makes that
  structural rather than aspirational: a v19 ingest cannot overwrite v18's
  documents because they are different keys. See :func:`ensure_indexes`.

Like :mod:`kb`, this module never spawns a subprocess and never touches the
network; ingestion scripts under ``scripts/`` do the downloading.

Schema note: MongoDB enforces none of the shapes below — the application does.
The document fields mirror the :class:`~mcp_hayabusa.kb.Rule` dataclass rather
than inventing parallel names, so a document and a ``Rule`` read the same.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .config import CONFIG
from .kb import LEVELS, Index, Rule, technique_name

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pymongo.database import Database

# Collection names. Four, and they are created implicitly on first write —
# there is no CREATE TABLE step anywhere in this codebase.
SIGMA_RULES = "sigma_rules"
ATTACK_TECHNIQUES = "attack_techniques"
FRAMEWORK_VERSIONS = "framework_versions"
SCAN_RESULTS = "scan_results"

COLLECTIONS = (SIGMA_RULES, ATTACK_TECHNIQUES, FRAMEWORK_VERSIONS, SCAN_RESULTS)

# Framework identifiers used in attack_techniques.framework. "enterprise-attack"
# matches MITRE's own collection name so the value is not a local invention.
FRAMEWORK_ATTACK = "enterprise-attack"
FRAMEWORK_ATLAS = "atlas"
FRAMEWORK_OWASP_LLM = "owasp-llm-top-10"
FRAMEWORK_OWASP_AGENTIC = "owasp-agentic-top-10"

# Stamped on sigma_rules and on techniques whose source records no version.
UNKNOWN_VERSION = "unknown"


class MongoUnavailable(RuntimeError):
    """Raised when MongoDB cannot be reached, or pymongo is not installed.

    Always catchable: no caller should crash because the container is stopped.
    """


def _pymongo():
    """Import pymongo lazily so a missing driver is a handled error, not a
    module-level ImportError that would take the whole server down."""
    try:
        import pymongo
    except ImportError as exc:  # pragma: no cover - pymongo is a declared dep
        raise MongoUnavailable(f"pymongo is not installed: {exc}") from exc
    return pymongo


def _write_errors() -> tuple[type[BaseException], ...]:
    """pymongo's error base class, resolved lazily like :func:`_pymongo`.

    Returned as a tuple so it can be used directly in an ``except`` clause, and
    empty when the driver is absent — there is then no pymongo error to catch.
    """
    try:
        from pymongo.errors import PyMongoError
    except ImportError:  # pragma: no cover - pymongo is a declared dep
        return ()
    return (PyMongoError,)


def connect(uri: str = "", db_name: str = "", *, timeout_ms: int = 0) -> Database:
    """Return a connected :class:`~pymongo.database.Database`, or raise.

    pymongo connects lazily, so this pings the server to turn "unreachable"
    into an error *here* rather than at the first query in the middle of a
    bulk load. ``CONFIG.mongo_timeout_ms`` keeps that check short.
    """
    pymongo = _pymongo()
    uri = uri or CONFIG.mongo_uri
    db_name = db_name or CONFIG.mongo_db
    timeout = timeout_ms or CONFIG.mongo_timeout_ms
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=timeout)
    try:
        client.admin.command("ping")
    except Exception as exc:  # pymongo raises several unrelated error types here
        client.close()
        raise MongoUnavailable(f"cannot reach MongoDB at {uri}: {exc}") from exc
    return client[db_name]


def available(uri: str = "", db_name: str = "") -> bool:
    """True if MongoDB answers a ping. Used to skip rather than fail."""
    try:
        connect(uri, db_name).client.close()
    except MongoUnavailable:
        return False
    return True


def ensure_indexes(db: Database) -> list[str]:
    """Create every index this store relies on. Idempotent by design.

    ``create_index`` is a no-op when an equivalent index already exists, which
    is why calling this on every connect is the normal MongoDB pattern rather
    than a migration step.

    Two of these carry the weight:

    * ``sigma_rules.techniques`` is a **multikey** index — the field holds an
      array and MongoDB indexes each element separately, turning "every rule
      covering T1003.003" from a collection scan into a lookup.
    * ``attack_techniques (framework, framework_version, technique_id)`` is
      unique over all three fields. Unique on ``technique_id`` alone would let
      an ATT&CK v19 ingest silently overwrite v18, which is exactly the
      historical-retention failure this store exists to prevent.
    """
    pymongo = _pymongo()
    asc = pymongo.ASCENDING
    created = [
        db[SIGMA_RULES].create_index("rule_id", unique=True),
        db[SIGMA_RULES].create_index("techniques"),  # multikey
        db[SIGMA_RULES].create_index("tactics"),  # multikey
        db[SIGMA_RULES].create_index([("level", asc), ("source", asc)]),
        db[ATTACK_TECHNIQUES].create_index(
            [("framework", asc), ("framework_version", asc), ("technique_id", asc)],
            unique=True,
        ),
        db[ATTACK_TECHNIQUES].create_index([("tactics", asc), ("deprecated", asc)]),
        db[FRAMEWORK_VERSIONS].create_index([("framework", asc), ("version", asc)], unique=True),
        db[SCAN_RESULTS].create_index("run_id", unique=True),
    ]
    return created


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Loaders
# --------------------------------------------------------------------------


def rule_document(rule: Rule, framework_version: str = UNKNOWN_VERSION) -> dict:
    """One ``sigma_rules`` document from a :class:`~mcp_hayabusa.kb.Rule`.

    ``platform`` and ``log_source`` are ``@property`` on ``Rule`` — derived from
    the rule's path and logsource block rather than stored — so they have to be
    called explicitly here. They are stored in Mongo because they are exactly
    what an operator filters on ("which of these can fire without Sysmon?").
    """
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "level": rule.level,
        "status": rule.status,
        "author": rule.author,
        "tags": list(rule.tags),
        "techniques": list(rule.techniques),
        "tactics": list(rule.tactics),
        "other_tags": list(rule.other_tags),
        "product": rule.product,
        "service": rule.service,
        "category": rule.category,
        "path": rule.path,
        "source": rule.source,
        "platform": rule.platform,
        "log_source": rule.log_source,
        "framework_version": framework_version,
    }


def _bulk(db: Database, collection: str, ops: Sequence[Any]) -> dict:
    """Run ``ops`` as one unordered bulk write, in chunks.

    ``ordered=False`` lets the server apply the batch in parallel and keeps one
    bad document from aborting the rest. Chunking keeps each command well under
    the 16MB BSON command limit for a ~5k-rule corpus.
    """
    if not ops:
        return {"matched": 0, "upserted": 0, "modified": 0}
    matched = upserted = modified = 0
    chunk = 1000
    for start in range(0, len(ops), chunk):
        result = db[collection].bulk_write(list(ops[start : start + chunk]), ordered=False)
        matched += result.matched_count
        upserted += result.upserted_count
        modified += result.modified_count
    return {"matched": matched, "upserted": upserted, "modified": modified}


def load_rules(db: Database, index: Index, *, framework_version: str = UNKNOWN_VERSION) -> dict:
    """Bulk-load every rule in ``index`` into ``sigma_rules``.

    Idempotent: each rule is a ``ReplaceOne(..., upsert=True)`` keyed on its
    unique ``rule_id``, so a second run updates in place instead of duplicating
    or tripping the unique index.
    """
    pymongo = _pymongo()
    ops = [
        pymongo.ReplaceOne(
            {"rule_id": rule.id}, rule_document(rule, framework_version), upsert=True
        )
        for rule in index.rules
    ]
    stats = _bulk(db, SIGMA_RULES, ops)
    stats["rules"] = len(ops)
    stats["total_in_db"] = db[SIGMA_RULES].count_documents({})
    return stats


def technique_document(
    entry: dict, *, framework: str, framework_version: str, technique_id: str = ""
) -> dict:
    """One ``attack_techniques`` document.

    ``entry`` is the metadata mapping produced by the ingestion scripts, i.e.
    the same shape ``mappings/attack.yaml`` stores per technique.
    """
    tid = technique_id or str(entry.get("technique_id") or entry.get("id") or "")
    return {
        "technique_id": tid,
        "name": str(entry.get("name") or ""),
        "description": str(entry.get("description") or ""),
        "tactics": list(entry.get("tactics") or []),
        "is_subtechnique": bool(entry.get("is_subtechnique", False)),
        "deprecated": bool(entry.get("deprecated", False)),
        "revoked": bool(entry.get("revoked", False)),
        # None rather than "" so `{"revoked_by": {"$ne": None}}` reads naturally.
        "revoked_by": entry.get("superseded_by") or entry.get("revoked_by") or None,
        "url": str(entry.get("url") or ""),
        "framework": framework,
        "framework_version": framework_version,
    }


def load_techniques(
    db: Database,
    entries: Iterable[dict],
    *,
    framework: str,
    framework_version: str,
) -> dict:
    """Load technique documents for one framework at one version.

    The filter spells out all three key fields, so a write can only ever match a
    document of *this* framework at *this* version. That is the historical
    retention guarantee: ingesting v19 cannot touch a v18 document, because the
    filter never selects one. Re-ingesting the same version replaces in place,
    which makes a repeat run idempotent rather than a duplicate-key crash.
    """
    pymongo = _pymongo()
    ops = []
    for entry in entries:
        doc = technique_document(entry, framework=framework, framework_version=framework_version)
        if not doc["technique_id"]:
            continue
        ops.append(
            pymongo.ReplaceOne(
                {
                    "framework": framework,
                    "framework_version": framework_version,
                    "technique_id": doc["technique_id"],
                },
                doc,
                upsert=True,
            )
        )
    stats = _bulk(db, ATTACK_TECHNIQUES, ops)
    stats["techniques"] = len(ops)
    stats["total_for_framework"] = db[ATTACK_TECHNIQUES].count_documents(
        {"framework": framework, "framework_version": framework_version}
    )
    return stats


def record_framework_version(
    db: Database,
    *,
    framework: str,
    version: str,
    released: str = "",
    source_url: str = "",
    bundle_sha256: str = "",
) -> dict:
    """Register one ingested framework release in ``framework_versions``.

    ``ingested_at`` is set only on insert, so re-running an ingest refreshes the
    provenance fields without rewriting when the version first arrived.
    """
    doc = {
        "framework": framework,
        "version": version,
        "released": released,
        "source_url": source_url,
        "bundle_sha256": bundle_sha256,
    }
    db[FRAMEWORK_VERSIONS].update_one(
        {"framework": framework, "version": version},
        {"$set": doc, "$setOnInsert": {"ingested_at": _now()}},
        upsert=True,
    )
    return doc


def record_scan_result(
    db: Database,
    *,
    run_id: str,
    evtx_source: str,
    detections: Sequence[dict],
    observed_techniques: Sequence[str],
    framework_version: str = UNKNOWN_VERSION,
) -> dict:
    """Persist one hayabusa run. Keyed on ``run_id`` so a replay is idempotent."""
    doc = {
        "run_id": run_id,
        "evtx_source": evtx_source,
        "detections": list(detections),
        "observed_techniques": list(observed_techniques),
        "framework_version": framework_version,
        "created_at": _now(),
    }
    db[SCAN_RESULTS].replace_one({"run_id": run_id}, doc, upsert=True)
    return doc


# A forensic scan over a large EVTX set can produce tens of thousands of hits,
# and a BSON document is capped at 16MB. Store a bounded slice and say so,
# rather than letting a big case fail the write outright.
MAX_STORED_DETECTIONS = 5000


def persist_scan(
    report: dict,
    *,
    evtx_source: str,
    run_id: str = "",
    max_detections: int = MAX_STORED_DETECTIONS,
) -> dict | None:
    """Persist a ``scan_evtx_attack`` report, if persistence is switched on.

    This is the **only** function the MCP server calls into Mongo, and it is the
    consumer of ``CONFIG.mongo_enabled``: with the flag off it returns ``None``
    without so much as opening a socket. With the flag on but the container
    stopped it still returns ``None`` — a DFIR answer must never fail because an
    optional backing store is down. Scanning is the product; scan history is
    bookkeeping, and bookkeeping does not get to break the product.

    Returns the stored document's summary (``run_id`` and what was written), or
    None if nothing was persisted.
    """
    if not CONFIG.mongo_enabled:
        return None
    try:
        db = connect()
        ensure_indexes(db)
        detections = list(report.get("detections") or [])
        stored = detections[:max_detections]
        doc = record_scan_result(
            db,
            run_id=run_id or uuid.uuid4().hex,
            evtx_source=evtx_source,
            detections=stored,
            observed_techniques=[t["id"] for t in report.get("techniques_observed") or []],
            framework_version=latest_version(db, FRAMEWORK_ATTACK) or UNKNOWN_VERSION,
        )
    except MongoUnavailable:
        return None
    except _write_errors():
        # A write that fails for any other reason (document too large, a lost
        # primary) is still bookkeeping. Never let it surface as a scan failure.
        return None
    summary = {
        "run_id": doc["run_id"],
        "framework_version": doc["framework_version"],
        "detections_stored": len(stored),
        "observed_techniques": len(doc["observed_techniques"]),
    }
    if len(detections) > len(stored):
        summary["detections_truncated"] = len(detections) - len(stored)
    return summary


# --------------------------------------------------------------------------
# Version resolution
# --------------------------------------------------------------------------


def _version_sort_key(version: str) -> tuple:
    """Sort ATT&CK-style dotted versions numerically: 19.0 after 9.1, not before.

    Falls back to a string compare for anything non-numeric (e.g. an ATLAS
    date-style release), which keeps ordering total rather than raising.
    """
    parts = str(version).split(".")
    try:
        return (0, tuple(int(p) for p in parts))
    except ValueError:
        return (1, str(version))


def versions(db: Database, framework: str) -> list[str]:
    """Every ingested version of ``framework``, oldest first."""
    found = db[FRAMEWORK_VERSIONS].distinct("version", {"framework": framework})
    return sorted((str(v) for v in found), key=_version_sort_key)


def latest_version(db: Database, framework: str = FRAMEWORK_ATTACK) -> str | None:
    """Newest ingested version of ``framework``, or None if none is recorded.

    Reads default to this; a historical read pins a version explicitly instead.
    """
    found = versions(db, framework)
    return found[-1] if found else None


def _resolve_version(db: Database, framework: str, version: str | None) -> str | None:
    return version if version else latest_version(db, framework)


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------


def _level_match(min_level: str) -> dict | None:
    """Mongo equivalent of kb.coverage's severity floor.

    kb.coverage only filters rules whose level it recognizes — an "unknown"
    level is kept, not dropped — so the $or below has to keep unrecognized
    levels too, or the two implementations would disagree on exactly the rules
    that are hardest to notice.
    """
    if min_level not in LEVELS:
        return None
    floor = LEVELS.index(min_level)
    if floor == 0:
        return None
    return {"$or": [{"level": {"$nin": LEVELS}}, {"level": {"$in": LEVELS[floor:]}}]}


def coverage(
    db: Database,
    meta: dict,
    *,
    tactic: str = "",
    min_level: str = "",
    framework_version: str | None = None,
) -> dict:
    """Aggregation port of :func:`mcp_hayabusa.kb.coverage`, same return shape.

    Both implementations are kept deliberately. ``kb.coverage`` walks the
    in-memory index in Python; this one pushes the same rollup into MongoDB as a
    ``$facet`` of three parallel pipelines — totals, per-technique, per-tactic —
    so the corpus is traversed once rather than three times. A test asserts the
    two return equal results, which is the strongest data-integrity evidence
    this project can offer about the store: the aggregation is not merely
    plausible, it is provably the same answer.

    ``framework_version=None`` means every version, which is what makes the
    equality test a fair comparison against an index that has no version axis.
    """
    match: dict = {}
    level_clause = _level_match(min_level)
    if level_clause:
        match.update(level_clause)
    if tactic:
        match["tactics"] = tactic
    if framework_version:
        match["framework_version"] = framework_version

    pipeline: list[dict] = []
    if match:
        pipeline.append({"$match": match})
    pipeline.append(
        {
            "$facet": {
                "totals": [
                    {
                        "$group": {
                            "_id": None,
                            "counted": {"$sum": 1},
                            "untagged": {
                                "$sum": {
                                    "$cond": [
                                        {
                                            "$eq": [
                                                {"$size": {"$ifNull": ["$techniques", []]}},
                                                0,
                                            ]
                                        },
                                        1,
                                        0,
                                    ]
                                }
                            },
                        }
                    }
                ],
                # $unwind explodes each rule's technique array into one row per
                # technique; the $group then counts rules per technique.
                "techniques": [
                    {"$unwind": "$techniques"},
                    {"$group": {"_id": "$techniques", "rules": {"$sum": 1}}},
                    {"$sort": {"rules": -1, "_id": 1}},
                ],
                "tactics": [
                    {"$unwind": "$tactics"},
                    {"$group": {"_id": "$tactics", "rules": {"$sum": 1}}},
                    {"$sort": {"rules": -1, "_id": 1}},
                ],
            }
        }
    )

    facet = next(iter(db[SIGMA_RULES].aggregate(pipeline)), {})
    totals = (facet.get("totals") or [{}])[0]

    return {
        "rules_considered": int(totals.get("counted", 0)),
        "techniques_covered": len(facet.get("techniques") or []),
        "rules_without_technique": int(totals.get("untagged", 0)),
        "tactics": {row["_id"]: row["rules"] for row in facet.get("tactics") or []},
        "techniques": [
            {"id": row["_id"], "name": technique_name(row["_id"], meta), "rules": row["rules"]}
            for row in facet.get("techniques") or []
        ],
    }


def framework_coverage(
    db: Database,
    *,
    framework: str = FRAMEWORK_ATTACK,
    framework_version: str | None = None,
    include_deprecated: bool = False,
    limit: int = 0,
) -> dict:
    """Rule coverage of one framework, joined across collections in the server.

    Unlike :func:`coverage`, which rolls up the rules' own tags, this walks the
    *framework* and asks how many rules reach each of its entries — so it
    reports gaps (entries nothing detects), which a rule-side rollup cannot see.
    Pointing it at ``owasp-agentic-top-10`` rather than ATT&CK is a framework
    argument, not a different query: that is the payoff of keeping all four
    taxonomies in one collection.

    The ``$lookup`` joins ``attack_techniques.technique_id`` against the
    ``sigma_rules.techniques`` **array**, which the multikey index serves.
    """
    version = _resolve_version(db, framework, framework_version)
    match: dict = {"framework": framework}
    if version:
        match["framework_version"] = version
    if not include_deprecated:
        match["deprecated"] = {"$ne": True}

    pipeline: list[dict] = [
        {"$match": match},
        {
            "$lookup": {
                "from": SIGMA_RULES,
                "localField": "technique_id",
                "foreignField": "techniques",
                "as": "matched",
            }
        },
        {
            "$project": {
                "_id": 0,
                "id": "$technique_id",
                "name": 1,
                "tactics": 1,
                "is_subtechnique": 1,
                "rules": {"$size": "$matched"},
            }
        },
        {"$sort": {"rules": -1, "id": 1}},
    ]
    rows = list(db[ATTACK_TECHNIQUES].aggregate(pipeline))

    covered = [r for r in rows if r["rules"]]
    per_tactic: dict[str, int] = {}
    for row in covered:
        for tac in row.get("tactics") or []:
            per_tactic[tac] = per_tactic.get(tac, 0) + 1

    report = {
        "framework": framework,
        "framework_version": version,
        "entries_total": len(rows),
        "entries_covered": len(covered),
        "entries_gap": len(rows) - len(covered),
        "rules_mapped": sum(r["rules"] for r in covered),
        "tactics": dict(sorted(per_tactic.items(), key=lambda kv: -kv[1])),
        "entries": rows[:limit] if limit else rows,
    }
    if limit and len(rows) > limit:
        report["entries_note"] = f"showing {limit} of {len(rows)} entries, most-covered first"
    return report


def frameworks(db: Database) -> list[str]:
    """Every framework present in ``attack_techniques``, alphabetically."""
    return sorted(str(f) for f in db[ATTACK_TECHNIQUES].distinct("framework") if f)


def all_frameworks_coverage(
    db: Database,
    *,
    pinned: Mapping[str, str] | None = None,
    include_deprecated: bool = False,
) -> dict:
    """Coverage across **every** framework at once, in a single aggregation.

    This is the query the shared collection exists for. ATT&CK, ATLAS and both
    OWASP top-tens have different id shapes (``T1003.003``, ``AML.T0043``,
    ``LLM01``, ``ASI01``) and different provenance, but they are one document
    shape in one collection — so "how much of our threat model do we detect?"
    is one round trip spanning conventional, AI and agentic risk, not three
    queries against three stores that someone has to reconcile afterwards.

    Each framework is read at its newest ingested version unless ``pinned``
    names one, so ATT&CK 19.2 is compared without 18.1's documents being
    double-counted alongside it. That pairing is why the ``$match`` is an
    ``$or`` of (framework, version) pairs rather than a flat version filter.

    Expect most frameworks to read as gaps: Sigma rules tag ATT&CK ids, so
    nothing maps to ``AML.*`` or ``LLM01``. That is a true statement about what
    Windows EVTX can observe, and the reason the rollup reports gaps at all.
    """
    pinned = dict(pinned or {})
    pairs = []
    for framework in frameworks(db):
        version = pinned.get(framework) or latest_version(db, framework)
        clause: dict = {"framework": framework}
        if version:
            clause["framework_version"] = version
        pairs.append(clause)

    if not pairs:
        return {"frameworks": {}, "entries_total": 0, "entries_covered": 0, "entries_gap": 0}

    match: dict = {"$or": pairs}
    if not include_deprecated:
        match["deprecated"] = {"$ne": True}

    rows = list(
        db[ATTACK_TECHNIQUES].aggregate(
            [
                {"$match": match},
                {
                    "$lookup": {
                        "from": SIGMA_RULES,
                        "localField": "technique_id",
                        "foreignField": "techniques",
                        "as": "matched",
                    }
                },
                {
                    "$group": {
                        "_id": {"framework": "$framework", "version": "$framework_version"},
                        "entries_total": {"$sum": 1},
                        "entries_covered": {
                            "$sum": {"$cond": [{"$gt": [{"$size": "$matched"}, 0]}, 1, 0]}
                        },
                        "rules_mapped": {"$sum": {"$size": "$matched"}},
                    }
                },
                {"$sort": {"_id.framework": 1}},
            ]
        )
    )

    report: dict = {"frameworks": {}}
    for row in rows:
        total, covered = row["entries_total"], row["entries_covered"]
        report["frameworks"][row["_id"]["framework"]] = {
            "framework_version": row["_id"]["version"],
            "entries_total": total,
            "entries_covered": covered,
            "entries_gap": total - covered,
            "rules_mapped": row["rules_mapped"],
        }
    report["entries_total"] = sum(f["entries_total"] for f in report["frameworks"].values())
    report["entries_covered"] = sum(f["entries_covered"] for f in report["frameworks"].values())
    report["entries_gap"] = report["entries_total"] - report["entries_covered"]
    return report


def rules_for_techniques(db: Database, technique_ids: Iterable[str]) -> dict[str, list[str]]:
    """Map each technique id to the Sigma rule ids citing it.

    This is the join behind framework-diff mapping impact: a technique that
    ATT&CK deprecated matters only in proportion to the rules still pointing at
    it. Served by the multikey index on ``techniques``.
    """
    wanted = [t for t in technique_ids if t]
    if not wanted:
        return {}
    hits: dict[str, list[str]] = {t: [] for t in wanted}
    cursor = db[SIGMA_RULES].find(
        {"techniques": {"$in": wanted}}, {"_id": 0, "rule_id": 1, "techniques": 1}
    )
    for doc in cursor:
        for tech in doc.get("techniques") or []:
            if tech in hits:
                hits[tech].append(doc["rule_id"])
    for rule_ids in hits.values():
        rule_ids.sort()
    return hits


def stats(db: Database) -> dict:
    """Document counts, index counts and framework inventory — the numbers to
    quote when asked what is actually in the store."""
    inventory = {}
    for framework in frameworks(db):
        per_version = {
            str(v): db[ATTACK_TECHNIQUES].count_documents(
                {"framework": framework, "framework_version": v}
            )
            for v in sorted(
                db[ATTACK_TECHNIQUES].distinct("framework_version", {"framework": framework}),
                key=_version_sort_key,
            )
        }
        inventory[framework] = {
            "total": db[ATTACK_TECHNIQUES].count_documents({"framework": framework}),
            "by_version": per_version,
        }
    return {
        "database": db.name,
        "server_version": db.client.server_info()["version"],
        "documents": {name: db[name].count_documents({}) for name in COLLECTIONS},
        "indexes": {name: len(list(db[name].list_indexes())) for name in COLLECTIONS},
        "frameworks": inventory,
    }


def timed_coverage(db: Database, meta: dict, **kwargs) -> tuple[dict, float]:
    """:func:`coverage` plus its wall-clock runtime in milliseconds."""
    start = time.perf_counter()
    report = coverage(db, meta, **kwargs)
    return report, (time.perf_counter() - start) * 1000.0
