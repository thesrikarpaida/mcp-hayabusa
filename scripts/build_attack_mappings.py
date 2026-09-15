#!/usr/bin/env python3
"""Generate mappings/attack.yaml from MITRE's ATT&CK STIX bundle.

Run this to create or refresh the ATT&CK metadata the MCP server serves. It is
a *build-time* step on purpose: the server itself never touches the network, so
technique names and descriptions are reproducible and reviewable in git, and
DFIR answers do not depend on GitHub being up.

    uv run python scripts/build_attack_mappings.py            # download + write
    uv run python scripts/build_attack_mappings.py --stix path/to/bundle.json
    uv run python scripts/build_attack_mappings.py --version 18.1   # a pinned release

The bundle is ~53MB, so it is streamed to a temp file rather than held in memory
twice. Parsing lives in :mod:`mcp_hayabusa.stix` so the ATLAS ingester and the
version differ read bundles exactly the same way.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Run as a script, so the package and the sibling helper both need a path entry.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from attack_data import STIX_URL, bundle_url, fetch, resolve_version  # noqa: E402

from mcp_hayabusa import stix  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "mappings" / "attack.yaml"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stix", type=Path, help="path to a local enterprise-attack.json")
    ap.add_argument(
        "--version",
        default="",
        help="ATT&CK release to download (e.g. 18.1); default is master's current bundle",
    )
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    if args.stix:
        path, url = args.stix, str(args.stix)
    elif args.version:
        version = resolve_version(args.version)
        url = bundle_url(version)
        path = fetch(url)
    else:
        url = STIX_URL
        path = fetch(url)

    parsed = stix.parse_bundle(stix.load_bundle(path))

    doc = {
        "_generated_by": "scripts/build_attack_mappings.py",
        "_source": url,
        "_spec_version": parsed.spec_version,
        # The ATT&CK release these mappings describe. Everything downstream —
        # the Mongo loader's framework_version stamp, the version differ —
        # reads this rather than guessing which release is on disk.
        "_attack_version": parsed.version,
        "_note": (
            "Generated file — do not hand-edit; re-run the script to refresh. "
            "The MCP server reads this offline and never fetches ATT&CK at runtime."
        ),
        "tactics": dict(sorted(parsed.tactics.items())),
        "techniques": dict(sorted(parsed.techniques.items())),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=100)

    subs = sum(1 for t in parsed.techniques.values() if t["is_subtechnique"])
    print(
        f"wrote {args.out.relative_to(ROOT)}: ATT&CK v{parsed.version or '?'}, "
        f"{len(parsed.techniques)} techniques ({subs} sub-techniques), "
        f"{len(parsed.tactics)} tactics",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
