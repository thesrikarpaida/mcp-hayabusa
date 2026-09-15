#!/usr/bin/env python3
"""Load the Sigma rule index and the ATT&CK mappings into MongoDB.

    uv run python scripts/load_mongo.py                    # rules + ATT&CK
    uv run python scripts/load_mongo.py --rules-only
    uv run python scripts/load_mongo.py --framework-version 18.1

Reads only files that are already on disk — ``.cache/rule_index.json`` via
``kb.load_index()`` and ``mappings/attack.yaml`` — so this never downloads
anything. Run ``make build-index`` and ``make mappings`` first if either is
missing.

Idempotent: every write is an upsert keyed on the collection's unique index, so
running it twice updates in place rather than duplicating or crashing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_hayabusa import kb, mongo  # noqa: E402
from mcp_hayabusa.config import CONFIG  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def attack_version_from_mappings() -> str:
    """The ATT&CK release mappings/attack.yaml was generated from.

    Recorded by build_attack_mappings.py as ``_attack_version``. Falls back to
    "unknown" for a mappings file generated before that field existed, which is
    honest — an invented version number would be worse than an absent one.
    """
    path = CONFIG.mappings_dir / "attack.yaml"
    if not path.is_file():
        return mongo.UNKNOWN_VERSION
    with path.open(encoding="utf-8") as fh:
        for line in fh:  # the header sits in the first few lines; don't parse 565KB
            if line.startswith("_attack_version:"):
                value = line.split(":", 1)[1].strip().strip("'\"")
                return value or mongo.UNKNOWN_VERSION
            if line.startswith("tactics:"):
                break
    return mongo.UNKNOWN_VERSION


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mongo-uri", default="", help=f"default: {CONFIG.mongo_uri}")
    ap.add_argument("--mongo-db", default="", help=f"default: {CONFIG.mongo_db}")
    ap.add_argument(
        "--framework-version",
        default="",
        help="ATT&CK release to stamp on the loaded documents; "
        "default is mappings/attack.yaml's _attack_version",
    )
    ap.add_argument("--rules-only", action="store_true", help="skip the ATT&CK techniques")
    ap.add_argument(
        "--rebuild-index",
        action="store_true",
        help="re-parse the rule corpus first (slow: ~150s on WSL2 over /mnt/c)",
    )
    args = ap.parse_args()

    try:
        db = mongo.connect(args.mongo_uri, args.mongo_db)
    except mongo.MongoUnavailable as exc:
        print(f"error: {exc}\nStart it with 'make mongo-up'.", file=sys.stderr)
        return 1

    created = mongo.ensure_indexes(db)
    print(f"indexes ensured ({len(created)} declared)", file=sys.stderr)

    version = args.framework_version or attack_version_from_mappings()
    print(f"framework version: {version}", file=sys.stderr)

    index = kb.load_index(rebuild=args.rebuild_index)
    for note in index.notes:
        print(f"  {note}", file=sys.stderr)
    if not index.rules:
        print("error: no rules indexed — run 'make build-index' first", file=sys.stderr)
        return 1

    stats = mongo.load_rules(db, index, framework_version=version)
    print(
        f"sigma_rules: {stats['rules']} written "
        f"({stats['upserted']} inserted, {stats['modified']} updated), "
        f"{stats['total_in_db']} in collection",
        file=sys.stderr,
    )

    if not args.rules_only:
        path = CONFIG.mappings_dir / "attack.yaml"
        if not path.is_file():
            print(f"warning: {path} missing — run 'make mappings'", file=sys.stderr)
        else:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            techniques = doc.get("techniques") or {}
            entries = [{"technique_id": tid, **entry} for tid, entry in techniques.items()]
            tech_stats = mongo.load_techniques(
                db,
                entries,
                framework=mongo.FRAMEWORK_ATTACK,
                framework_version=version,
            )
            mongo.record_framework_version(
                db,
                framework=mongo.FRAMEWORK_ATTACK,
                version=version,
                source_url=str(doc.get("_source") or ""),
            )
            print(
                f"attack_techniques: {tech_stats['techniques']} written for "
                f"{mongo.FRAMEWORK_ATTACK} v{version} "
                f"({tech_stats['total_for_framework']} in collection)",
                file=sys.stderr,
            )

    meta = kb.load_attack_metadata()
    report, elapsed = mongo.timed_coverage(db, meta)
    print(
        f"coverage aggregation: {elapsed:.0f}ms over {report['rules_considered']} rules, "
        f"{report['techniques_covered']} techniques, {len(report['tactics'])} tactics",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
