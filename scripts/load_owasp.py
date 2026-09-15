#!/usr/bin/env python3
"""Load the OWASP LLM and Agentic top-tens into MongoDB.

    uv run python scripts/load_owasp.py
    uv run python scripts/load_owasp.py --data path/to/owasp_frameworks.yaml

Unlike ATT&CK and ATLAS there is nothing to download: twenty items do not
warrant a feed, so ``data/owasp_frameworks.yaml`` is the source and this just
ingests it.

They land in the **same** ``attack_techniques`` collection as ATT&CK and ATLAS,
with ``technique_id`` set to ``LLM01`` / ``ASI01``. That is deliberate. Four
taxonomies in one collection means one coverage query spans conventional, AI and
agentic risk instead of three queries against three shapes — and the compound
unique index on ``(framework, framework_version, technique_id)`` keeps them from
colliding, exactly as it keeps two ATT&CK versions apart.

Expect the coverage answer to be ten gaps per list. No Sigma rule maps to
``LLM01``, because Windows EVTX is not where prompt injection is observable.
That is an honest statement about the detection surface, not a broken query.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_hayabusa import mongo  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "owasp_frameworks.yaml"


def read_frameworks(path: Path) -> list[dict]:
    """Parse the seed file, failing loudly on a shape the loader cannot use."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, list):
        raise SystemExit(f"{path}: expected a list of frameworks, got {type(doc).__name__}")
    for framework in doc:
        if not isinstance(framework, dict) or not framework.get("framework"):
            raise SystemExit(f"{path}: every entry needs a 'framework' key")
        if not framework.get("entries"):
            raise SystemExit(f"{path}: {framework['framework']} has no entries")
    return doc


def to_technique_entries(framework: dict) -> list[dict]:
    """Reshape ``{id, name}`` pairs into the technique shape the loader stores.

    ``tactics`` is empty and ``is_subtechnique`` false: OWASP publishes a flat
    list of risk categories, with no kill chain and no hierarchy. Storing the
    fields as empty rather than omitting them keeps every document in the
    collection the same shape, so a query does not have to know which framework
    it is reading.
    """
    return [
        {
            "technique_id": str(entry["id"]),
            "name": str(entry.get("name") or ""),
            "description": str(entry.get("description") or ""),
            "tactics": list(entry.get("tactics") or []),
            "is_subtechnique": False,
            "deprecated": False,
            "revoked": False,
            "url": str(entry.get("url") or framework.get("url") or ""),
        }
        for entry in framework["entries"]
        if entry.get("id")
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=DATA, help=f"default: {DATA}")
    ap.add_argument("--mongo-uri", default="")
    ap.add_argument("--mongo-db", default="")
    args = ap.parse_args()

    if not args.data.is_file():
        print(f"error: {args.data} not found", file=sys.stderr)
        return 1

    frameworks = read_frameworks(args.data)

    try:
        db = mongo.connect(args.mongo_uri, args.mongo_db)
    except mongo.MongoUnavailable as exc:
        print(f"error: {exc}\nStart it with 'make mongo-up'.", file=sys.stderr)
        return 1
    mongo.ensure_indexes(db)

    for framework in frameworks:
        name = str(framework["framework"])
        version = str(framework.get("version") or mongo.UNKNOWN_VERSION)
        entries = to_technique_entries(framework)

        stats = mongo.load_techniques(db, entries, framework=name, framework_version=version)
        mongo.record_framework_version(
            db,
            framework=name,
            version=version,
            released=version,
            source_url=str(framework.get("url") or ""),
        )
        print(
            f"attack_techniques: {stats['techniques']} written for {name} {version} "
            f"({stats['total_for_framework']} in collection)",
            file=sys.stderr,
        )

    found = sorted(db[mongo.ATTACK_TECHNIQUES].distinct("framework"))
    print(f"frameworks now in attack_techniques: {', '.join(found)}", file=sys.stderr)

    for framework in frameworks:
        report = mongo.framework_coverage(db, framework=str(framework["framework"]))
        print(
            f"  {report['framework']}: {report['entries_covered']}/{report['entries_total']} "
            f"entries have a Sigma rule mapped ({report['entries_gap']} gaps)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
