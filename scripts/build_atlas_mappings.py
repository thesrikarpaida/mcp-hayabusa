#!/usr/bin/env python3
"""Generate mappings/atlas.yaml from MITRE ATLAS's STIX bundle, and load it.

ATLAS is ATT&CK's adversarial-ML sibling: the same object model, the same STIX
2.1 encoding, different threat surface. So this mirrors
``build_attack_mappings.py`` — same CLI, same output shape, the same parser from
:mod:`mcp_hayabusa.stix` — rather than growing a second way to read a bundle.

    ./scripts/fetch_atlas_bundle.sh                            # build the bundle
    uv run python scripts/build_atlas_mappings.py              # write mappings/atlas.yaml
    uv run python scripts/build_atlas_mappings.py --load       # ...and ingest into Mongo
    uv run python scripts/build_atlas_mappings.py --stix path/to/bundle.json

ATLAS does not publish STIX directly, so unlike the ATT&CK script there is no
URL to download: ``fetch_atlas_bundle.sh`` runs ATLAS's own ``atlas_to_stix.py``
to produce one. Point ``--stix`` at the result.

The bundle is the ``--include-attack`` combined export, holding both frameworks,
and ATLAS techniques cross-reference their ATT&CK analogues (``AML.T0000`` also
lists ``T1596``). Reading it with the default id precedence would file every
ATLAS technique under an ATT&CK id and overwrite real ATT&CK documents, so the
ATLAS source is pinned as the only acceptable one below.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attack_data import sha256  # noqa: E402

from mcp_hayabusa import mongo, stix  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "mappings" / "atlas.yaml"

# Where fetch_atlas_bundle.sh puts its output.
DEFAULT_BUNDLE = (
    Path(tempfile.gettempdir()) / "mcp-hayabusa-stix" / "stix-atlas-attack-enterprise.json"
)

# ATLAS is authoritative about its own AML.T#### ids, and only those.
ATLAS_SOURCES = ("mitre-atlas", "atlas")
ATLAS_COLLECTION = "ATLAS"
SOURCE_URL = "https://github.com/mitre-atlas/atlas-data"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--stix",
        type=Path,
        default=DEFAULT_BUNDLE,
        help=f"path to the combined ATLAS+ATT&CK bundle (default: {DEFAULT_BUNDLE})",
    )
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--load", action="store_true", help="also ingest into MongoDB")
    ap.add_argument("--mongo-uri", default="")
    ap.add_argument("--mongo-db", default="")
    ap.add_argument("--version", default="", help="override the release read from the bundle")
    args = ap.parse_args()

    if not args.stix.is_file():
        print(
            f"error: {args.stix} not found.\n"
            "Build it first with ./scripts/fetch_atlas_bundle.sh (or 'make atlas-bundle').",
            file=sys.stderr,
        )
        return 1

    parsed = stix.parse_bundle(
        stix.load_bundle(args.stix),
        sources=ATLAS_SOURCES,
        require_source=True,
        collection=ATLAS_COLLECTION,
        # Keep the ATT&CK ids ATLAS cites on its own techniques. require_source
        # above stops them being used as the *identity* (which would overwrite
        # real ATT&CK entries); this records them as a relationship instead, so
        # an ATLAS entry can inherit coverage from the rules detecting its
        # conventional counterpart.
        cross_reference="mitre-attack",
    )
    version = args.version or parsed.version or mongo.UNKNOWN_VERSION

    if not parsed.techniques:
        print(
            f"error: no ATLAS techniques found in {args.stix}. "
            "Was the bundle built with --include-attack from ATLAS's own tool?",
            file=sys.stderr,
        )
        return 1

    doc = {
        "_generated_by": "scripts/build_atlas_mappings.py",
        "_source": SOURCE_URL,
        "_spec_version": parsed.spec_version,
        "_atlas_version": version,
        "_note": (
            "Generated file — do not hand-edit; re-run the script to refresh. "
            "The MCP server reads this offline and never fetches ATLAS at runtime."
        ),
        "tactics": dict(sorted(parsed.tactics.items())),
        "techniques": dict(sorted(parsed.techniques.items())),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=100)

    subs = sum(1 for t in parsed.techniques.values() if t["is_subtechnique"])
    print(
        f"wrote {args.out.relative_to(ROOT)}: ATLAS {version}, "
        f"{len(parsed.techniques)} techniques ({subs} sub-techniques), "
        f"{len(parsed.tactics)} tactics",
        file=sys.stderr,
    )

    if not args.load:
        return 0

    try:
        db = mongo.connect(args.mongo_uri, args.mongo_db)
    except mongo.MongoUnavailable as exc:
        print(f"error: {exc}\nStart it with 'make mongo-up'.", file=sys.stderr)
        return 1
    mongo.ensure_indexes(db)

    entries = [{"technique_id": tid, **entry} for tid, entry in parsed.techniques.items()]
    stats = mongo.load_techniques(
        db, entries, framework=mongo.FRAMEWORK_ATLAS, framework_version=version
    )
    mongo.record_framework_version(
        db,
        framework=mongo.FRAMEWORK_ATLAS,
        version=version,
        released=version,  # ATLAS releases are dated: "2026.08" is both
        source_url=SOURCE_URL,
        bundle_sha256=sha256(args.stix),
    )
    print(
        f"attack_techniques: {stats['techniques']} written for "
        f"{mongo.FRAMEWORK_ATLAS} {version} "
        f"({stats['total_for_framework']} in collection)",
        file=sys.stderr,
    )
    frameworks = sorted(db[mongo.ATTACK_TECHNIQUES].distinct("framework"))
    print(f"frameworks now in attack_techniques: {', '.join(frameworks)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
