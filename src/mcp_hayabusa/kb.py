"""Sigma rule knowledge base: parsing, indexing, and ATT&CK coverage.

This is the detection-engineering layer. It is pure data — unlike
:mod:`hayabusa` it never spawns a subprocess; it only reads YAML off disk.
Keeping it separate means coverage questions can be answered without the
hayabusa binary installed at all.

Indexing strategy
-----------------
Parsing the bundled corpus (~4.8k rules) takes minutes on a slow filesystem
(WSL2 over /mnt/c: ~150s), which is far too slow to do when a server starts.
So each rules directory is cached independently in a JSON file:

* **Live dirs** (<= ``LIVE_DIR_MAX_FILES`` files, i.e. a hand-authored
  ``rules/``) are re-scanned on every load, so edits show up immediately.
* **Pinned dirs** (anything larger, i.e. the bundled corpus) are read straight
  from cache and only re-parsed when explicitly asked — ``make build-index``,
  the ``rebuild_rule_index`` tool, or after ``update_rules`` changes the corpus.

``load_index()`` reports what it did in ``Index.notes`` so a stale pinned cache
is visible rather than silent.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

try:  # libyaml is ~10x faster than the pure-python loader and is usually present
    from yaml import CSafeLoader as _Loader
except ImportError:  # pragma: no cover - depends on the local libyaml build
    from yaml import SafeLoader as _Loader  # type: ignore[assignment]

from .config import CONFIG

# Sigma severity levels, lowest to highest.
LEVELS = ["informational", "low", "medium", "high", "critical"]

# Sigma "attack.*" tags are a grab bag: tactics (attack.credential-access),
# techniques (attack.t1003.003), intrusion groups (attack.g0016) and software
# (attack.s0002). Only the first two are useful for coverage, so techniques are
# matched structurally and tactics against the authoritative list shipped with
# hayabusa; everything else is kept verbatim under Rule.other_tags.
_TECHNIQUE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)

CACHE_VERSION = 1

# A directory with at most this many rule files is cheap enough to re-scan on
# every load. Parsing costs ~30ms/file on WSL2 over /mnt/c, so this buys a hand-
# authored rules/ dir (a handful of files, milliseconds) live reloads while
# keeping both bundled sets — rules/hayabusa (193 files, ~6s) and rules/sigma
# (~4.8k, ~150s) — on the cached path.
LIVE_DIR_MAX_FILES = 50


class KnowledgeBaseError(RuntimeError):
    """Raised when the rule index or ATT&CK mappings cannot be loaded."""


@dataclass
class Rule:
    """One parsed Sigma rule, reduced to the fields the KB answers about."""

    id: str
    title: str
    description: str
    level: str
    status: str
    author: str
    tags: list[str]
    techniques: list[str]  # normalized upper case, e.g. ["T1003.003"]
    tactics: list[str]  # slugs, e.g. ["credential-access"]
    other_tags: list[str]  # attack.g0016 / attack.s0002 / sysmon / ...
    product: str
    service: str
    category: str
    path: str
    source: str  # label of the rules dir this came from

    @property
    def platform(self) -> str:
        """Telemetry tree this rule was compiled for, e.g. ``"sigma/sysmon"``.

        Both bundled sets are split into parallel ``sysmon/`` and ``builtin/``
        trees holding the same detections against different event sources, so
        the tree decides whether a rule can fire at all on a given EVTX set: a
        sysmon rule is inert without Sysmon deployed. That is not recorded in
        any Sigma field — only in the rule's location — so derive it from the
        first directory below the rules dir (whose basename is ``source``).

        Derived rather than stored so the on-disk index cache stays valid.
        """
        parts = Path(self.path).parts
        for i in range(len(parts) - 2, -1, -1):
            # Search backwards: the corpus lives at hayabusa/rules/hayabusa/...,
            # so the *last* match is the rules dir, not the install dir above it.
            # Require a further directory below, or this is a flat dir (rules/).
            if parts[i] == self.source and i + 2 <= len(parts) - 1:
                return f"{self.source}/{parts[i + 1]}"
        return self.source

    @property
    def log_source(self) -> str:
        """Sigma logsource category/service, e.g. ``"process_creation"``."""
        return self.category or self.service or "unspecified"

    def summary(self) -> dict:
        """The compact form returned by list/search tools."""
        return {
            "id": self.id,
            "title": self.title,
            "level": self.level,
            "status": self.status,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "source": self.source,
            "platform": self.platform,
            "log_source": self.log_source,
        }


@dataclass
class Index:
    """An in-memory view of every known rule, plus how it was assembled."""

    rules: list[Rule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    built_at: float = 0.0

    def by_id(self) -> dict[str, Rule]:
        return {r.id: r for r in self.rules}


def _load_tactic_slugs() -> dict[str, str]:
    """Map tactic slug -> display name, from hayabusa's mitre_tactics.txt.

    Falls back to an empty map if the file is missing (hayabusa not installed);
    callers then treat unknown non-technique tags as plain tags.
    """
    path = CONFIG.tactics_file
    if not path.is_file():
        return {}
    slugs: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2 or not parts[0].startswith("attack."):
            continue
        slugs[parts[0][len("attack.") :]] = parts[1]
    return slugs


def _classify_tags(
    tags: list[str], tactic_slugs: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    """Split raw Sigma tags into (techniques, tactics, other)."""
    techniques: list[str] = []
    tactics: list[str] = []
    other: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        if not tag.startswith("attack."):
            other.append(tag)
            continue
        value = tag[len("attack.") :]
        if _TECHNIQUE_RE.match(value):
            techniques.append(value.upper())
        elif value in tactic_slugs or not tactic_slugs:
            # With no tactics file we cannot distinguish a tactic from a group,
            # so anything non-technique falls through to `other` below.
            if value in tactic_slugs:
                tactics.append(value)
            else:
                other.append(tag)
        else:
            other.append(tag)
    return techniques, tactics, other


def parse_rules(path: Path, source: str, tactic_slugs: dict[str, str]) -> list[Rule]:
    """Parse a Sigma YAML file into every :class:`Rule` it defines.

    One file can hold several rules: Sigma **correlation** rules are multi-document
    YAML (``---``-separated), pairing a correlation over a named base rule. Both
    documents carry an id and can fire, so both must be indexed — ``yaml.load``
    raises on multi-document input, which silently cost us the whole brute-force
    family (T1110.x) until an unmapped detection gave it away.

    Returns [] rather than raising: one malformed rule in a 5k-file corpus must
    not take down the index.
    """
    try:
        docs = list(
            yaml.load_all(path.read_text(encoding="utf-8", errors="replace"), Loader=_Loader)
        )
    except (yaml.YAMLError, OSError):
        return []
    rules = [_rule_from_doc(d, path, source, tactic_slugs) for d in docs]
    return [r for r in rules if r is not None]


def parse_rule(path: Path, source: str, tactic_slugs: dict[str, str]) -> Rule | None:
    """The first rule defined in ``path``, or None. See :func:`parse_rules`."""
    rules = parse_rules(path, source, tactic_slugs)
    return rules[0] if rules else None


def _rule_from_doc(
    doc: object, path: Path, source: str, tactic_slugs: dict[str, str]
) -> Rule | None:
    """Build a Rule from one parsed YAML document, or None if it isn't a rule."""
    if not isinstance(doc, dict):
        return None
    rule_id = doc.get("id")
    title = doc.get("title")
    if not rule_id or not title:
        return None  # not a rule (could be a config/collection doc)

    tags = [t for t in (doc.get("tags") or []) if isinstance(t, str)]
    techniques, tactics, other = _classify_tags(tags, tactic_slugs)
    logsource = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}

    return Rule(
        id=str(rule_id),
        title=str(title),
        description=str(doc.get("description") or "").strip(),
        level=str(doc.get("level") or "unknown").lower(),
        status=str(doc.get("status") or "unknown").lower(),
        author=str(doc.get("author") or ""),
        tags=tags,
        techniques=techniques,
        tactics=tactics,
        other_tags=other,
        product=str(logsource.get("product") or ""),
        service=str(logsource.get("service") or ""),
        category=str(logsource.get("category") or ""),
        path=str(path),
        source=source,
    )


def _rule_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.rglob("*.yml") if p.is_file())


def _scan_dir(directory: Path, tactic_slugs: dict[str, str]) -> tuple[list[Rule], int]:
    """Parse every rule under ``directory``. Returns (rules, skipped_file_count).

    A file can define more than one rule, so "skipped" counts files that yielded
    nothing at all — malformed YAML, or a non-rule doc like a config file.
    """
    label = directory.name
    rules: list[Rule] = []
    skipped = 0
    for path in _rule_files(directory):
        found = parse_rules(path, label, tactic_slugs)
        if not found:
            skipped += 1
        rules.extend(found)
    return rules, skipped


# Memoized view of the on-disk cache, keyed by (path, mtime) so a rebuild in
# another process is picked up while repeat calls in this one stay free. Without
# this every tool call would re-parse a multi-megabyte JSON blob.
_CACHE_MEMO: tuple[tuple[str, float], dict] | None = None


def _read_cache() -> dict:
    """Return the cache payload ({} if absent, unreadable, or a stale schema)."""
    global _CACHE_MEMO
    path = CONFIG.index_cache
    if not path.is_file():
        return {}
    key = (str(path), path.stat().st_mtime)
    if _CACHE_MEMO is not None and _CACHE_MEMO[0] == key:
        return _CACHE_MEMO[1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        return {}  # stale schema — rebuild rather than guess
    _CACHE_MEMO = (key, data)
    return data


def _rules_from_entry(entry: dict) -> list[Rule] | None:
    """Rebuild Rules from a cache entry, or None if its shape no longer fits.

    Guards against a Rule field being added/renamed without bumping
    CACHE_VERSION: the cache is derived data, so drift must cost a re-parse, not
    a TypeError on every tool call.
    """
    try:
        return [Rule(**r) for r in entry.get("rules", [])]
    except (TypeError, AttributeError):
        return None


def _ago(then: float) -> str:
    """Coarse human age of a timestamp, for staleness notes."""
    seconds = max(0.0, time.time() - float(then))
    for size, unit in ((86400.0, "d"), (3600.0, "h"), (60.0, "m")):
        if seconds >= size:
            return f"{int(seconds // size)}{unit} ago"
    return "just now"


def _write_cache(dirs: dict[str, dict]) -> None:
    path = CONFIG.index_cache
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": CACHE_VERSION, "built_at": time.time(), "dirs": dirs}
    path.write_text(json.dumps(payload), encoding="utf-8")


def load_index(*, rebuild: bool = False) -> Index:
    """Assemble the rule index from every configured rules dir.

    Small dirs are re-scanned every call; large ones come from the cache unless
    ``rebuild`` is set. Rules from an earlier dir win on duplicate rule id, so a
    custom rules/ shadows the bundled corpus.
    """
    tactic_slugs = _load_tactic_slugs()
    cache = _read_cache()
    cached_dirs: dict[str, dict] = cache.get("dirs", {}) if cache else {}
    built_at = cache.get("built_at")
    pinned_dirs: dict[str, dict] = {}

    index = Index(built_at=time.time())
    seen: set[str] = set()
    cache_dirty = False

    for directory in CONFIG.rules_dirs:
        key = str(directory)
        entry = cached_dirs.get(key)
        cached = (
            _rules_from_entry(entry)
            if entry is not None and not entry.get("live", False) and not rebuild
            else None
        )

        # A dir already known to be pinned is served from cache without touching
        # the filesystem: walking the bundled corpus alone costs ~7s.
        if cached is not None:
            rules = cached
            skipped = int(entry.get("skipped", 0))
            age = f", built {_ago(built_at)}" if built_at else ""
            index.notes.append(
                f"{directory}: {len(rules)} rules (cached{age}; "
                "run rebuild_rule_index after changing these rules)"
            )
            pinned_dirs[key] = entry
        elif not directory.is_dir():
            index.notes.append(f"rules dir not found, skipped: {directory}")
            continue
        else:
            live = len(_rule_files(directory)) <= LIVE_DIR_MAX_FILES
            rules, skipped = _scan_dir(directory, tactic_slugs)
            index.notes.append(
                f"{directory}: scanned {len(rules)} rules "
                f"({'live' if live else 'cached for next time'})"
            )
            if not live:
                pinned_dirs[key] = {
                    "rules": [asdict(r) for r in rules],
                    "skipped": skipped,
                    "live": False,
                }
                cache_dirty = True

        if skipped:
            index.notes.append(f"{directory}: skipped {skipped} unparseable file(s)")

        for rule in rules:
            if rule.id in seen:
                continue  # first dir wins — custom rules shadow the corpus
            seen.add(rule.id)
            index.rules.append(rule)

    if cache_dirty:
        # Persist only the pinned (expensive) dirs; live dirs are cheap to redo.
        _write_cache(pinned_dirs)

    if not index.rules:
        index.notes.append("no rules indexed — check HAYABUSA_RULES_DIR, or run 'make build-index'")
    return index


# --------------------------------------------------------------------------
# ATT&CK metadata
# --------------------------------------------------------------------------


def load_attack_metadata() -> dict:
    """Load curated ATT&CK technique metadata from mappings/attack.yaml.

    Shape: {"techniques": {id: {"name": str, "tactics": [slug]}},
            "tactics": {slug: {"id": str, "name": str}}}
    Missing file is not fatal — techniques then render with a null name.
    """
    path = CONFIG.mappings_dir / "attack.yaml"
    if not path.is_file():
        return {"techniques": {}, "tactics": {}}
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
    except (yaml.YAMLError, OSError) as exc:
        raise KnowledgeBaseError(f"could not read {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise KnowledgeBaseError(f"{path} must contain a YAML mapping")
    techniques = doc.get("techniques") or {}
    tactics = doc.get("tactics") or {}
    return {
        "techniques": {str(k).upper(): v for k, v in techniques.items() if isinstance(v, dict)},
        "tactics": tactics if isinstance(tactics, dict) else {},
    }


def load_atlas_metadata() -> dict:
    """Load MITRE ATLAS metadata from mappings/atlas.yaml.

    Same shape as :func:`load_attack_metadata`, plus ``cross_refs`` on the 44
    ATLAS techniques MITRE adopted from ATT&CK. Missing file is not fatal: the
    ATLAS rollup is then simply absent, exactly as before the bridge existed.
    """
    path = CONFIG.mappings_dir / "atlas.yaml"
    if not path.is_file():
        return {"techniques": {}, "tactics": {}}
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)
    except (yaml.YAMLError, OSError) as exc:
        raise KnowledgeBaseError(f"could not read {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise KnowledgeBaseError(f"{path} must contain a YAML mapping")
    techniques = doc.get("techniques") or {}
    tactics = doc.get("tactics") or {}
    return {
        "techniques": {str(k).upper(): v for k, v in techniques.items() if isinstance(v, dict)},
        "tactics": tactics if isinstance(tactics, dict) else {},
    }


def atlas_from_attack(atlas_meta: dict) -> dict[str, list[str]]:
    """Invert ATLAS's ``cross_refs`` into ATT&CK id -> ATLAS ids.

    Built once per call rather than stored, because it is derived from
    ``atlas.yaml`` and would otherwise be a second thing to keep in step.
    """
    out: dict[str, list[str]] = {}
    for aid, entry in (atlas_meta.get("techniques") or {}).items():
        for ref in entry.get("cross_refs") or []:
            out.setdefault(str(ref).upper(), []).append(aid)
    return {k: sorted(set(v)) for k, v in out.items()}


def observed_atlas(technique_counts: dict[str, int], atlas_meta: dict) -> list[dict]:
    """Roll observed ATT&CK techniques up into the ATLAS entries that cite them.

    A sub-technique credits its parent's cross-reference too: ATLAS cites
    ``T1059``, while a rule that fires tags ``T1059.001``. Without the parent
    walk the bridge would miss almost every real detection.

    The result says *"the conventional technique this ATLAS entry adopted was
    observed"* — never that an AI-specific attack was detected. Callers must
    keep that distinction in the wording they present.
    """
    by_attack = atlas_from_attack(atlas_meta)
    rolled: dict[str, dict] = {}
    for tid, count in technique_counts.items():
        candidates = [tid.upper()]
        if "." in tid:
            candidates.append(tid.split(".", 1)[0].upper())
        for cand in candidates:
            for aid in by_attack.get(cand, []):
                row = rolled.setdefault(aid, {"id": aid, "via": set(), "detections": 0})
                row["via"].add(tid)
                row["detections"] += count
    entries = atlas_meta.get("techniques") or {}
    return [
        {
            "id": aid,
            "name": str(entries.get(aid, {}).get("name") or ""),
            "tactics": list(entries.get(aid, {}).get("tactics") or []),
            "via": sorted(row["via"]),
            "detections": row["detections"],
        }
        for aid, row in sorted(rolled.items(), key=lambda kv: (-kv[1]["detections"], kv[0]))
    ]


def technique_name(tech_id: str, meta: dict) -> str | None:
    """Human-readable name for a technique id, or None if not in the mappings.

    ATT&CK names sub-techniques tersely (T1003.003 is just "NTDS"), so a
    sub-technique is rendered under its parent: "OS Credential Dumping: NTDS".
    An unknown sub-technique falls back to its parent's name.
    """
    tid = tech_id.upper()
    entry = meta["techniques"].get(tid)
    parent = meta["techniques"].get(tid.split(".")[0]) if "." in tid else None
    if entry:
        name = entry.get("name")
        if entry.get("is_subtechnique") and parent and parent.get("name") and name:
            return f"{parent['name']}: {name}"
        return name
    if parent:
        return parent.get("name")
    return None


# Rule statuses that are not yet trustworthy enough to call a technique covered.
_WEAK_STATUS = {"experimental", "deprecated", "unsupported"}


def technique_detail(index: Index, meta: dict, tech_id: str, *, rule_limit: int = 50) -> dict:
    """Full picture of one technique: metadata, the rules that detect it, and
    a coverage assessment.

    The assessment is deliberately conservative — it answers "can we claim to
    detect this?", not "does a rule mention it?":

    * ``gap``     — nothing cites it, directly or via a sub-technique.
    * ``partial`` — cited, but incompletely: only some sub-techniques are
      covered, or only sub-techniques are (with no rule for the parent itself),
      or every citing rule is still experimental/deprecated.
    * ``covered`` — at least one non-experimental rule cites it directly, and
      any sub-techniques it has are all covered too.

    Popular techniques attract hundreds of rules (T1003 has 218 in the bundled
    corpus), so the ``rules`` list is capped at ``rule_limit``, highest severity
    first. The counts under ``coverage`` and ``breakdown`` always reflect every
    match, so the caller can characterize the whole set without paging it in.
    """
    tid = tech_id.upper()
    entry = meta["techniques"].get(tid, {})

    direct = [r for r in index.rules if tid in r.techniques]

    # Sub-techniques known to ATT&CK, plus any the corpus cites that ATT&CK
    # does not list (keeps a bad tag visible rather than dropping it).
    known_subs = set(entry.get("subtechniques") or [])
    cited_subs = {t for r in index.rules for t in r.techniques if t.startswith(tid + ".")}
    subs = sorted(known_subs | cited_subs)

    sub_rules = {s: [r for r in index.rules if s in r.techniques] for s in subs}
    covered_subs = sorted(s for s, rules in sub_rules.items() if rules)

    seen: dict[str, Rule] = {r.id: r for r in direct}
    for rules in sub_rules.values():
        for r in rules:
            seen.setdefault(r.id, r)
    all_rules = list(seen.values())

    strong = [r for r in all_rules if r.status not in _WEAK_STATUS]

    if not all_rules:
        assessment = "gap"
        rationale = "no rule in the index cites this technique or any sub-technique"
    elif subs and len(covered_subs) < len(subs):
        assessment = "partial"
        rationale = (
            f"{len(covered_subs)} of {len(subs)} sub-techniques covered; "
            f"uncovered: {', '.join(s for s in subs if s not in covered_subs)}"
        )
    elif not direct and any(sub_rules.values()):
        assessment = "partial"
        rationale = "covered only via sub-techniques; no rule cites the parent technique directly"
    elif not strong:
        assessment = "partial"
        rationale = (
            f"{len(all_rules)} rule(s) cite it, but all are "
            f"{'/'.join(sorted({r.status for r in all_rules}))} — not production-ready"
        )
    else:
        assessment = "covered"
        rationale = f"{len(strong)} non-experimental rule(s) detect this technique"

    detail = {
        "id": tid,
        "name": technique_name(tid, meta),
        "description": entry.get("description"),
        "tactics": entry.get("tactics", []),
        "url": entry.get("url"),
        "is_subtechnique": entry.get("is_subtechnique", False),
        "known_to_attack": bool(entry),
        "coverage": {
            "assessment": assessment,
            "rationale": rationale,
            "rules_direct": len(direct),
            "rules_total": len(all_rules),
            "subtechniques": {
                "total": len(subs),
                "covered": len(covered_subs),
                "uncovered": [s for s in subs if s not in covered_subs],
            },
        },
        # Over every matching rule, not just the ones that survive rule_limit —
        # a breakdown of a truncated list would misstate the coverage it claims.
        "breakdown": breakdown(all_rules),
        "rules_returned": min(len(all_rules), rule_limit),
        "rules": [
            r.summary()
            for r in sorted(all_rules, key=lambda r: (-_level_rank(r), r.title))[:rule_limit]
        ],
    }
    if len(all_rules) > rule_limit:
        detail["rules_note"] = (
            f"showing the {rule_limit} highest-severity of {len(all_rules)} rules; "
            f"use search_rules(technique={tid!r}) to page through the rest"
        )

    if not entry:
        detail["warning"] = (
            f"{tid} is not present in mappings/attack.yaml — it may be a typo in a rule tag, "
            "or the mappings may predate it (re-run scripts/build_attack_mappings.py)"
        )
    if entry.get("revoked"):
        detail["warning"] = (
            f"ATT&CK has revoked {tid}"
            + (
                f"; it is superseded by {entry['superseded_by']}"
                if entry.get("superseded_by")
                else ""
            )
            + " — rules citing it should be retagged"
        )
    elif entry.get("deprecated"):
        detail["warning"] = f"ATT&CK has deprecated {tid} — rules citing it should be retagged"
    return detail


def _level_rank(rule: Rule) -> int:
    return LEVELS.index(rule.level) if rule.level in LEVELS else -1


def tally(
    values: Iterable[str], *, order: list[str] | None = None, limit: int | None = None
) -> dict[str, int]:
    """Count occurrences, dropping empties and zeroes.

    Ordered by ``order`` when given (so severities read critical-first rather
    than by count), otherwise most-common first, then cut to ``limit``.
    """
    counts = Counter(v for v in values if v)
    if order is not None:
        return {k: counts[k] for k in order if counts[k]}
    return dict(counts.most_common(limit))


def breakdown(rules: Iterable[Rule]) -> dict:
    """Count a rule set along the axes a detection engineer triages by.

    Every query that answers "what rules do we have" returns this, because a
    bare total is not actionable. The axes that carry the weight:

    * ``by_platform`` — what fraction of the count is inert without Sysmon.
      See :attr:`Rule.platform`.
    * ``distinct_detections`` — titles, not rules. The two telemetry trees
      mirror each other, so a raw count roughly double-counts; this is the
      honest number of distinct ideas.
    * ``by_status`` — ``deprecated``/``experimental`` rules are included in the
      total but must not back a coverage claim (see :func:`technique_detail`).
    """
    rules = list(rules)
    return {
        "total": len(rules),
        "distinct_detections": len({r.title for r in rules}),
        "by_severity": tally((r.level for r in rules), order=list(reversed(LEVELS))),
        "by_platform": tally(r.platform for r in rules),
        "by_log_source": tally(r.log_source for r in rules),
        "by_status": tally(r.status for r in rules),
        "by_source": tally(r.source for r in rules),
    }


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------


def search_all(
    index: Index,
    *,
    query: str = "",
    technique: str = "",
    tactic: str = "",
    level: str = "",
    product: str = "",
    status: str = "",
) -> list[Rule]:
    """Every rule matching the filters, unpaged. All filters AND together.

    Callers page this themselves rather than passing a limit down, so that the
    match count and :func:`breakdown` can describe the whole result set while
    only a slice of it is returned. The index is already in memory, so scanning
    all of it costs nothing worth optimizing.
    """
    needle = query.lower()
    tech = technique.upper()
    results: list[Rule] = []
    for rule in index.rules:
        if needle and needle not in rule.title.lower() and needle not in rule.description.lower():
            continue
        if tech and not matches_technique(rule, tech):
            continue
        if tactic and tactic not in rule.tactics:
            continue
        if level and rule.level != level:
            continue
        if product and rule.product != product:
            continue
        if status and rule.status != status:
            continue
        results.append(rule)
    return results


def search(
    index: Index,
    *,
    query: str = "",
    technique: str = "",
    tactic: str = "",
    level: str = "",
    product: str = "",
    status: str = "",
    limit: int = 50,
) -> list[Rule]:
    """The first ``limit`` rules matching the filters. See :func:`search_all`."""
    return search_all(
        index,
        query=query,
        technique=technique,
        tactic=tactic,
        level=level,
        product=product,
        status=status,
    )[:limit]


def matches_technique(rule: Rule, tech: str) -> bool:
    """True if the rule cites ``tech``; a parent id also matches its subs."""
    for owned in rule.techniques:
        if owned == tech or owned.startswith(tech + "."):
            return True
    return False


def coverage(index: Index, meta: dict, *, tactic: str = "", min_level: str = "") -> dict:
    """Aggregate rule counts per ATT&CK technique and tactic.

    Returns per-technique rule counts (with names where curated) and per-tactic
    totals, plus how many rules carry no technique tag at all — the honest
    denominator for "what do we actually cover".
    """
    floor = LEVELS.index(min_level) if min_level in LEVELS else 0

    per_tech: dict[str, int] = {}
    per_tactic: dict[str, int] = {}
    untagged = 0
    counted = 0

    for rule in index.rules:
        if rule.level in LEVELS and LEVELS.index(rule.level) < floor:
            continue
        if tactic and tactic not in rule.tactics:
            continue
        counted += 1
        if not rule.techniques:
            untagged += 1
        for tech in rule.techniques:
            per_tech[tech] = per_tech.get(tech, 0) + 1
        for tac in rule.tactics:
            per_tactic[tac] = per_tactic.get(tac, 0) + 1

    techniques = [
        {"id": tid, "name": technique_name(tid, meta), "rules": count}
        for tid, count in sorted(per_tech.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    return {
        "rules_considered": counted,
        "techniques_covered": len(per_tech),
        "rules_without_technique": untagged,
        "tactics": dict(sorted(per_tactic.items(), key=lambda kv: -kv[1])),
        "techniques": techniques,
    }
