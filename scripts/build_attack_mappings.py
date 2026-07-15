#!/usr/bin/env python3
"""Generate mappings/attack.yaml from MITRE's ATT&CK STIX bundle.

Run this to create or refresh the ATT&CK metadata the MCP server serves. It is
a *build-time* step on purpose: the server itself never touches the network, so
technique names and descriptions are reproducible and reviewable in git, and
DFIR answers do not depend on GitHub being up.

    uv run python scripts/build_attack_mappings.py            # download + write
    uv run python scripts/build_attack_mappings.py --stix path/to/bundle.json

The bundle is ~53MB, so it is streamed to a temp file rather than held in memory
twice. Only the fields the server actually serves are kept.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

import yaml

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "mappings" / "attack.yaml"

# ATT&CK descriptions are long-form markdown; keep the lede so a technique
# resource stays readable inline without shipping a 5KB blob per entry.
DESCRIPTION_CHARS = 600


def fetch(url: str) -> Path:
    tmp = Path(tempfile.gettempdir()) / "enterprise-attack.json"
    if tmp.is_file() and tmp.stat().st_size > 1_000_000:
        print(f"using cached {tmp} ({tmp.stat().st_size / 1e6:.0f}MB)", file=sys.stderr)
        return tmp
    print(f"downloading {url} ...", file=sys.stderr)
    with urllib.request.urlopen(url) as resp, tmp.open("wb") as fh:  # noqa: S310 - fixed https URL
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    return tmp


def shorten(text: str) -> str:
    """First paragraph of a technique description, trimmed at a sentence."""
    para = (text or "").strip().split("\n\n")[0].strip()
    if len(para) <= DESCRIPTION_CHARS:
        return para
    cut = para[:DESCRIPTION_CHARS]
    stop = cut.rfind(". ")
    return (cut[: stop + 1] if stop > 200 else cut.rstrip() + " …").strip()


def attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def attack_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref.get("url", ""))
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stix", type=Path, help="path to a local enterprise-attack.json")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    path = args.stix or fetch(STIX_URL)
    bundle = json.loads(path.read_text(encoding="utf-8"))

    techniques: dict[str, dict] = {}
    tactics: dict[str, dict] = {}
    # STIX ids of revoked techniques -> their attack id, resolved via
    # "revoked-by" relationships so legacy Sigma tags (T1086) can point at the
    # technique that replaced them.
    stix_to_id: dict[str, str] = {}
    revoked_by: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        otype = obj.get("type")

        if otype == "x-mitre-tactic":
            slug = obj.get("x_mitre_shortname")
            if slug:
                tactics[slug] = {
                    "id": attack_id(obj) or "",
                    "name": obj.get("name", ""),
                    "url": attack_url(obj),
                }

        elif otype == "attack-pattern":
            tid = attack_id(obj)
            if not tid:
                continue
            stix_to_id[obj["id"]] = tid
            techniques[tid] = {
                "name": obj.get("name", ""),
                "description": shorten(obj.get("description", "")),
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
                ],
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "url": attack_url(obj),
                # Sigma corpora cite ids that ATT&CK has since retired; keep the
                # flags so the server can say so instead of silently 404ing.
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "revoked": bool(obj.get("revoked", False)),
            }

        elif otype == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[obj["source_ref"]] = obj["target_ref"]

    for src, dst in revoked_by.items():
        old, new = stix_to_id.get(src), stix_to_id.get(dst)
        if old and new and old in techniques:
            techniques[old]["superseded_by"] = new

    # Attach sub-technique lists to parents so coverage can reason about
    # "we detect 2 of this technique's 5 sub-techniques".
    for tid in techniques:
        if "." in tid:
            parent = tid.split(".")[0]
            if parent in techniques:
                techniques[parent].setdefault("subtechniques", []).append(tid)
    for entry in techniques.values():
        if "subtechniques" in entry:
            entry["subtechniques"].sort()

    doc = {
        "_generated_by": "scripts/build_attack_mappings.py",
        "_source": STIX_URL,
        "_spec_version": bundle.get("spec_version", ""),
        "_note": (
            "Generated file — do not hand-edit; re-run the script to refresh. "
            "The MCP server reads this offline and never fetches ATT&CK at runtime."
        ),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=100)

    subs = sum(1 for t in techniques.values() if t["is_subtechnique"])
    print(
        f"wrote {args.out.relative_to(ROOT)}: {len(techniques)} techniques "
        f"({subs} sub-techniques), {len(tactics)} tactics",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
