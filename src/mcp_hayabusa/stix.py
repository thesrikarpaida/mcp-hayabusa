"""STIX 2.1 bundle parsing, shared by every framework ingester.

MITRE publishes ATT&CK, and MITRE ATLAS publishes its combined ATLAS+ATT&CK
export, as STIX 2.1 bundles with the same object model. Writing a second parser
for the second framework would guarantee the two drift, so the parsing lives
here once and ``scripts/build_attack_mappings.py``, ``scripts/build_atlas_mappings.py``
and :mod:`mcp_hayabusa.versions` all call it.

**This module never touches the network.** Downloading bundles is the scripts'
job; everything here takes an already-parsed ``dict``. That keeps the rule from
CLAUDE.md intact — the server resolves technique names offline, so a DFIR answer
never depends on GitHub being reachable.

The parts of the object model that matter:

``attack-pattern``
    A technique. Its public id (``T1003.003``, ``AML.T0043``) lives in
    ``external_references``, not in the STIX ``id``.
``x-mitre-tactic``
    A tactic. ``x_mitre_shortname`` is the slug Sigma tags use.
``x-mitre-collection``
    The bundle's own metadata; ``x_mitre_version`` is the framework release
    ("19.2"), which is otherwise nowhere in the file.
``relationship`` with ``relationship_type: "revoked-by"``
    The successor pointer for a renamed technique. Both ends are STIX ids, so
    resolving it to public ids needs the whole bundle in hand — which is why
    it happens here and not at the call site.

One trap is worth spelling out. ATLAS's combined export carries **both**
frameworks, and an ATLAS technique cross-references its ATT&CK analogue:
``AML.T0000`` also lists ``T1596``. So "the object's id" is only well defined
once you say whose id you want. ``sources`` sets that precedence and
``require_source`` makes it exclusive — without it, ingesting ATLAS would file
every ATLAS technique under an ATT&CK id and overwrite real ATT&CK entries.
The bundle also holds two ``x-mitre-collection`` objects, hence ``collection``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ATT&CK descriptions are long-form markdown; keep the lede so a technique
# resource stays readable inline without shipping a 5KB blob per entry.
DESCRIPTION_CHARS = 600

# external_references source names carrying the public technique id, in the
# order they are trusted. ATLAS's combined bundle contains both, and an ATLAS
# object is authoritative about its own AML.T#### id.
ID_SOURCES = ("mitre-attack", "mitre-atlas", "atlas")


@dataclass
class ParsedBundle:
    """Everything the ingesters need out of one STIX bundle."""

    techniques: dict[str, dict] = field(default_factory=dict)
    tactics: dict[str, dict] = field(default_factory=dict)
    # Framework release, e.g. "19.2". Empty when the bundle carries no
    # x-mitre-collection object (some ATLAS exports do not).
    version: str = ""
    name: str = ""
    spec_version: str = ""

    def ids(self) -> set[str]:
        return set(self.techniques)


def load_bundle(path: Path) -> dict:
    """Read a STIX bundle off disk. ~53MB for ATT&CK Enterprise."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def shorten(text: str, limit: int = DESCRIPTION_CHARS) -> str:
    """First paragraph of a technique description, trimmed at a sentence."""
    para = (text or "").strip().split("\n\n")[0].strip()
    if len(para) <= limit:
        return para
    cut = para[:limit]
    stop = cut.rfind(". ")
    return (cut[: stop + 1] if stop > 200 else cut.rstrip() + " …").strip()


def external_id(obj: dict[str, Any], sources: tuple[str, ...] = ID_SOURCES) -> str | None:
    """Public id of a STIX object (``T1059.001``, ``AML.T0043``), or None.

    Prefers a reference from a known MITRE source; falls back to any reference
    that carries an ``external_id`` so an unfamiliar source name costs a
    less-precise answer rather than a dropped technique.
    """
    refs = obj.get("external_references") or []
    for source in sources:
        for ref in refs:
            if ref.get("source_name") == source and ref.get("external_id"):
                return str(ref["external_id"])
    for ref in refs:
        if ref.get("external_id"):
            return str(ref["external_id"])
    return None


def external_url(obj: dict[str, Any], sources: tuple[str, ...] = ID_SOURCES) -> str:
    refs = obj.get("external_references") or []
    for source in sources:
        for ref in refs:
            if ref.get("source_name") == source and ref.get("url"):
                return str(ref["url"])
    return ""


def _has_source(obj: dict[str, Any], sources: tuple[str, ...]) -> bool:
    """True if the object carries a public id from one of ``sources``."""
    return any(
        ref.get("source_name") in sources and ref.get("external_id")
        for ref in obj.get("external_references") or []
    )


def _tactic_slugs(obj: dict[str, Any]) -> list[str]:
    """Tactic slugs from a technique's kill chain phases.

    ATT&CK phases sit under ``mitre-attack``; ATLAS uses its own kill chain
    name, so accept any phase rather than filtering to one chain — the slug is
    what Sigma tags match on and it is unambiguous either way.
    """
    return [str(p["phase_name"]) for p in obj.get("kill_chain_phases") or [] if p.get("phase_name")]


def parse_bundle(
    bundle: dict,
    *,
    sources: tuple[str, ...] = ID_SOURCES,
    require_source: bool = False,
    collection: str = "",
    description_chars: int = DESCRIPTION_CHARS,
    attach_subtechniques: bool = True,
) -> ParsedBundle:
    """Reduce a STIX bundle to techniques, tactics and the release version.

    The per-technique shape is exactly what ``mappings/attack.yaml`` stores, so
    the YAML generator, the Mongo loader and the version differ all read the
    same records.

    :param sources: ``external_references`` source names carrying the public id,
        most authoritative first.
    :param require_source: drop objects that carry no id from ``sources``,
        instead of falling back to any external id. Set this when reading a
        bundle that holds more than one framework — see the module docstring.
    :param collection: name of the ``x-mitre-collection`` to read the release
        version from, when the bundle contains several.

    Revoked techniques keep their entry and gain ``superseded_by``. Dropping
    them instead would be the silent-coverage-loss bug this whole exercise is
    about: a Sigma rule tagged with a revoked id would simply stop resolving,
    with no error anywhere to say so.
    """
    parsed = ParsedBundle(spec_version=str(bundle.get("spec_version") or ""))

    # STIX id -> public id, needed to resolve revoked-by relationships, whose
    # endpoints are STIX ids rather than T-numbers.
    stix_to_id: dict[str, str] = {}
    revoked_by: dict[str, str] = {}

    for obj in bundle.get("objects") or []:
        otype = obj.get("type")

        if otype == "x-mitre-collection":
            # The only place the framework release number appears. A combined
            # bundle has one per framework, so honour the requested name.
            if collection and str(obj.get("name") or "") != collection:
                continue
            parsed.version = str(obj.get("x_mitre_version") or "")
            parsed.name = str(obj.get("name") or "")

        elif otype == "x-mitre-tactic":
            slug = obj.get("x_mitre_shortname")
            if require_source and not _has_source(obj, sources):
                continue
            if slug:
                parsed.tactics[str(slug)] = {
                    "id": external_id(obj, sources) or "",
                    "name": str(obj.get("name") or ""),
                    "url": external_url(obj, sources),
                }

        elif otype == "attack-pattern":
            if require_source and not _has_source(obj, sources):
                continue
            tid = external_id(obj, sources)
            if not tid:
                continue
            stix_to_id[obj["id"]] = tid
            parsed.techniques[tid] = {
                "name": str(obj.get("name") or ""),
                "description": shorten(obj.get("description", ""), description_chars),
                "tactics": _tactic_slugs(obj),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "url": external_url(obj, sources),
                # Corpora cite ids ATT&CK has since retired; keep the flags so
                # the server can say so instead of silently 404ing.
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "revoked": bool(obj.get("revoked", False)),
            }

        elif otype == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[obj["source_ref"]] = obj["target_ref"]

    for src, dst in revoked_by.items():
        old, new = stix_to_id.get(src), stix_to_id.get(dst)
        if old and new and old in parsed.techniques:
            parsed.techniques[old]["superseded_by"] = new

    if attach_subtechniques:
        _attach_subtechniques(parsed.techniques)

    return parsed


def _attach_subtechniques(techniques: dict[str, dict]) -> None:
    """Give each parent the sorted list of its sub-techniques.

    Coverage needs this to reason about "we detect 2 of this technique's 5
    sub-techniques" without re-deriving the hierarchy from id strings.
    """
    for tid in techniques:
        if "." in tid:
            parent = tid.split(".")[0]
            if parent in techniques:
                techniques[parent].setdefault("subtechniques", []).append(tid)
    for entry in techniques.values():
        if "subtechniques" in entry:
            entry["subtechniques"].sort()
