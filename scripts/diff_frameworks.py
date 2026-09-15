#!/usr/bin/env python3
"""Compare two ATT&CK releases and report which Sigma rules the changes affect.

    uv run python scripts/diff_frameworks.py --old 18.1 --new 19.2
    uv run python scripts/diff_frameworks.py --old 18.1 --new 19.2 --ingest
    uv run python scripts/diff_frameworks.py --list
    uv run python scripts/diff_frameworks.py --old-stix a.json --new-stix b.json

Versions are validated against MITRE's live ``index.json`` rather than
hardcoded, because a hardcoded list is wrong the day after the next release.

``--ingest`` writes both releases into ``attack_techniques`` and registers them
in ``framework_versions``. Ingesting a second version never overwrites the
first: the writes are keyed on ``(framework, framework_version, technique_id)``,
so v19's documents and v18's are different keys, not the same key twice. That is
the historical-retention guarantee, enforced by the index rather than by anyone
remembering to be careful.

Mapping impact comes from MongoDB when it is reachable — one indexed query over
``sigma_rules.techniques`` — and falls back to the local rule index otherwise,
so the report still works with the container stopped.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attack_data import (  # noqa: E402
    COLLECTION,
    bundle_url,
    fetch,
    list_versions,
    release_date,
    resolve_version,
    sha256,
)

from mcp_hayabusa import kb, mongo, stix, versions  # noqa: E402


def rule_lookup_from_index() -> dict[str, list[str]]:
    """Technique id -> rule ids, straight from the local rule index.

    The fallback when Mongo is down. Builds the whole inverted map because the
    index is already in memory and the caller wants many ids at once.
    """
    index = kb.load_index()
    hits: dict[str, list[str]] = {}
    for rule in index.rules:
        for tech in rule.techniques:
            hits.setdefault(tech, []).append(rule.id)
    return hits


def build_lookup(db) -> tuple[object, str]:
    """Return (lookup, source-label) for :func:`versions.attach_rule_impact`."""
    if db is not None:
        return (lambda ids: mongo.rules_for_techniques(db, ids)), "MongoDB sigma_rules"
    hits = rule_lookup_from_index()
    return hits, ".cache/rule_index.json"


def load_side(stix_path: Path | None, version: str, label: str) -> tuple[stix.ParsedBundle, Path]:
    if stix_path:
        print(f"reading {label} bundle from {stix_path}", file=sys.stderr)
        path = stix_path
    else:
        path = fetch(bundle_url(version))
    return stix.parse_bundle(stix.load_bundle(path)), path


def ingest(db, parsed: stix.ParsedBundle, path: Path, version: str) -> None:
    entries = [{"technique_id": tid, **entry} for tid, entry in parsed.techniques.items()]
    stats = mongo.load_techniques(
        db, entries, framework=mongo.FRAMEWORK_ATTACK, framework_version=version
    )
    mongo.record_framework_version(
        db,
        framework=mongo.FRAMEWORK_ATTACK,
        version=version,
        released=release_date(version),
        source_url=bundle_url(version),
        bundle_sha256=sha256(path),
    )
    print(
        f"ingested {mongo.FRAMEWORK_ATTACK} v{version}: {stats['techniques']} techniques "
        f"({stats['total_for_framework']} in collection for this version)",
        file=sys.stderr,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--old", default="", help="older ATT&CK release, e.g. 18.1")
    ap.add_argument("--new", default="latest", help="newer ATT&CK release (default: latest)")
    ap.add_argument("--old-stix", type=Path, help="use a local bundle instead of downloading")
    ap.add_argument("--new-stix", type=Path, help="use a local bundle instead of downloading")
    ap.add_argument("--list", action="store_true", help="list published releases and exit")
    ap.add_argument("--ingest", action="store_true", help="write both releases into MongoDB")
    ap.add_argument(
        "--show-unaffected",
        action="store_true",
        help="list changes that touch no Sigma rule (they are the majority)",
    )
    ap.add_argument("--rule-limit", type=int, default=10, help="rule ids shown per change")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    ap.add_argument("--mongo-uri", default="")
    ap.add_argument("--mongo-db", default="")
    args = ap.parse_args()

    if args.list:
        for entry in list_versions():
            print(f"{entry['version']:<8} {entry.get('modified', '')}")
        return 0

    # Check before resolving, so a missing --old fails without a network round trip.
    if not args.old_stix and not args.old:
        print("error: --old is required (see --list for published releases)", file=sys.stderr)
        return 1

    old_version = args.old if args.old_stix else resolve_version(args.old, COLLECTION)
    new_version = args.new if args.new_stix else resolve_version(args.new, COLLECTION)
    if old_version == new_version:
        print(f"error: --old and --new are both {old_version}", file=sys.stderr)
        return 1

    old, old_path = load_side(args.old_stix, old_version, "old")
    new, new_path = load_side(args.new_stix, new_version, "new")
    # A local bundle knows its own release; prefer that over the CLI label.
    old_version = old.version or old_version
    new_version = new.version or new_version

    # Connect even without --ingest: Mongo serves the mapping-impact join far
    # better than re-parsing the rule index. Only --ingest actually needs it.
    db = None
    try:
        db = mongo.connect(args.mongo_uri, args.mongo_db)
        mongo.ensure_indexes(db)
    except mongo.MongoUnavailable as exc:
        if args.ingest:
            print(f"error: {exc}\nStart it with 'make mongo-up'.", file=sys.stderr)
            return 1
        print(f"note: {exc} — using the local rule index instead", file=sys.stderr)

    if args.ingest and db is not None:
        ingest(db, old, old_path, old_version)
        ingest(db, new, new_path, new_version)

    result = versions.diff(old, new, framework=mongo.FRAMEWORK_ATTACK)
    lookup, source = build_lookup(db)
    versions.attach_rule_impact(result, lookup)

    if args.json:
        import json

        print(json.dumps(versions.summary(result), indent=2))
    else:
        print(f"mapping impact resolved against {source}\n", file=sys.stderr)
        print(
            versions.render(
                result, rule_limit=args.rule_limit, show_unaffected=args.show_unaffected
            )
        )

    if db is not None:
        found = mongo.versions(db, mongo.FRAMEWORK_ATTACK)
        print(
            f"\nattack_techniques now holds {mongo.FRAMEWORK_ATTACK} versions: {', '.join(found)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
