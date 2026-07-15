"""FastMCP server: Hayabusa scanning plus a Sigma/ATT&CK knowledge base.

Two surfaces share one server:

* **Tools that scan** map to a hayabusa subcommand and run non-interactively
  (``--no-wizard`` disables the rule-selection wizard, ``--quiet`` the banner).
  Output is returned inline when small and written to a caller-supplied file
  when it is a full timeline.
* **Tools and resources that answer detection-engineering questions** read the
  Sigma corpus through :mod:`kb` and need no binary at all.

``scan_evtx_attack`` is where the two meet: it scans, then joins each detection
back to the rule that fired it to report which ATT&CK techniques were observed.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterable
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import kb
from .hayabusa import HayabusaError, input_flag, run, safe_path

mcp = FastMCP("hayabusa")

# Non-interactive defaults shared by every scanning subcommand.
# -w / --no-wizard  skips the interactive rule-selection wizard (required for
#                   non-interactive use — without it the subprocess blocks).
# -q / --quiet      suppresses the ASCII art banner.
# -N / --no-summary suppresses the results summary table for cleaner output.
_SCAN_BASE = ["-w", "-q", "-N"]

# Hayabusa alert levels and Sigma rule levels are the same vocabulary, lowest
# to highest; kb.LEVELS is the single definition.
_LEVELS = kb.LEVELS


@mcp.tool()
def version() -> str:
    """Return the installed Hayabusa version string.

    Hayabusa prints the version in the banner on any invocation; we capture it
    from the ``help`` subcommand since there is no dedicated ``--version`` flag.
    """
    result = run(["help"])
    # First line is always "Hayabusa vX.Y.Z - ..."
    first_line = (
        result.stdout.splitlines()[0] if result.stdout.strip() else result.stderr.splitlines()[0]
    )
    return first_line.strip()


@mcp.tool()
def list_profiles() -> str:
    """List the available output profiles (minimal, standard, verbose, all-field-info, ...)."""
    return run(["list-profiles"]).stdout.strip()


@mcp.tool()
def update_rules() -> str:
    """Update the bundled Sigma detection rules from the Hayabusa rules repo."""
    return run(["update-rules"]).stdout.strip()


@mcp.tool()
def csv_timeline(
    input_path: str,
    output_path: str,
    profile: str = "standard",
    min_level: str = "low",
    utc: bool = False,
) -> dict:
    """Generate a CSV forensic timeline from EVTX logs.

    Args:
        input_path: A single .evtx file or a directory of .evtx files.
        output_path: CSV file to write (overwritten if it exists).
        profile: Output profile, e.g. minimal | standard | verbose | all-field-info.
        min_level: Minimum alert level to include: informational|low|medium|high|critical.
        utc: Emit timestamps in UTC instead of the local timezone.
    """
    src = safe_path(input_path)
    out = safe_path(output_path, must_exist=False)
    args = [
        "csv-timeline",
        *input_flag(src),
        "-o",
        str(out),
        "-p",
        profile,
        "--min-level",
        min_level,
        "--clobber",
        *_SCAN_BASE,
    ]
    if utc:
        args.append("--UTC")
    result = run(args)
    return {"output": str(out), "log": result.stdout.strip()}


@mcp.tool()
def json_timeline(
    input_path: str,
    output_path: str,
    profile: str = "standard",
    min_level: str = "low",
    jsonl: bool = True,
) -> dict:
    """Generate a JSON (or JSONL) forensic timeline from EVTX logs.

    Args:
        input_path: A single .evtx file or a directory of .evtx files.
        output_path: JSON/JSONL file to write (overwritten if it exists).
        profile: Output profile, e.g. minimal | standard | verbose | all-field-info.
        min_level: Minimum alert level to include: informational|low|medium|high|critical.
        jsonl: Emit newline-delimited JSON (recommended for streaming/large sets).
    """
    src = safe_path(input_path)
    out = safe_path(output_path, must_exist=False)
    args = [
        "json-timeline",
        *input_flag(src),
        "-o",
        str(out),
        "-p",
        profile,
        "--min-level",
        min_level,
        "--clobber",
        *_SCAN_BASE,
    ]
    if jsonl:
        args.append("--JSONL-output")
    result = run(args)
    return {"output": str(out), "log": result.stdout.strip()}


_SUMMARY_FIELDS = ("Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID", "Details")


@mcp.tool()
def scan_evtx(
    input_path: str,
    min_level: str = "low",
    profile: str = "standard",
    rule_filter: str = "",
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan EVTX logs with Hayabusa's Sigma rules and return structured detections.

    This is the primary triage tool: it runs a JSONL timeline into a temp file,
    parses each detection into a JSON object, and returns them (plus a per-level
    count summary) inline — no output file to manage.

    Args:
        input_path: A single .evtx file or a directory of .evtx files.
        min_level: Lowest alert level to include: informational|low|medium|high|critical.
        profile: Output profile: minimal | standard | verbose | all-field-info.
        rule_filter: Only keep detections whose rule title contains this substring
            (case-insensitive), e.g. "lateral" or "mimikatz". Hayabusa has no
            native rule-title filter, so this is applied after scanning.
        output_format: "summary" (a handful of key fields per detection) or
            "full" (the entire parsed record).
        max_results: If set, cap the number of detections returned (highest-level
            first order is preserved from Hayabusa's own output).

    Returns:
        {"total": int, "counts": {level: int}, "returned": int,
         "detections": [ {...}, ... ]}
        "total"/"counts" reflect all matches after rule_filter, before max_results
        truncation; "returned" is the length of "detections".
    """
    if min_level not in _LEVELS:
        raise HayabusaError(f"min_level must be one of {_LEVELS}, got {min_level!r}")
    if output_format not in ("summary", "full"):
        raise HayabusaError(f"output_format must be 'summary' or 'full', got {output_format!r}")
    if max_results is not None and max_results < 1:
        raise HayabusaError(f"max_results must be a positive integer, got {max_results!r}")
    src = safe_path(input_path)

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "timeline.jsonl"
        run(
            [
                "json-timeline",
                *input_flag(src),
                "-o",
                str(out),
                "-p",
                profile,
                "--min-level",
                min_level,
                "--JSONL-output",
                "--clobber",
                *_SCAN_BASE,
            ]
        )
        detections = _parse_jsonl(out)

    if rule_filter:
        needle = rule_filter.lower()
        detections = [d for d in detections if needle in str(d.get("RuleTitle", "")).lower()]

    counts: dict[str, int] = {}
    for det in detections:
        level = str(det.get("Level", "unknown")).lower()
        counts[level] = counts.get(level, 0) + 1
    total = len(detections)

    if max_results is not None:
        detections = detections[:max_results]
    if output_format == "summary":
        detections = [{k: d[k] for k in _SUMMARY_FIELDS if k in d} for d in detections]

    return {"total": total, "counts": counts, "returned": len(detections), "detections": detections}


def _parse_jsonl(path: Path) -> list[dict]:
    """Parse a Hayabusa JSONL timeline into a list of detection dicts.

    Malformed lines are skipped rather than aborting the whole scan.
    """
    if not path.exists():
        return []
    detections: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            detections.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return detections


@mcp.tool()
def logon_summary(input_path: str) -> str:
    """Summarize successful and failed logon events across the EVTX logs."""
    src = safe_path(input_path)
    return run(["logon-summary", *input_flag(src), *_SCAN_BASE]).stdout.strip()


@mcp.tool()
def metrics(input_path: str) -> str:
    """Report event-ID frequency metrics across the EVTX logs (channel/EID counts)."""
    src = safe_path(input_path)
    return run(["eid-metrics", *input_flag(src), *_SCAN_BASE]).stdout.strip()


@mcp.tool()
def search(input_path: str, keyword: str = "", regex: str = "") -> dict:
    """Full-text search the raw EVTX records by keyword or regex.

    Provide exactly one of ``keyword`` or ``regex``.
    """
    if bool(keyword) == bool(regex):
        raise HayabusaError("provide exactly one of 'keyword' or 'regex'")
    src = safe_path(input_path)
    selector = ["-k", keyword] if keyword else ["-r", regex]
    result = run(["search", *input_flag(src), *selector, *_SCAN_BASE])
    return {"matches": result.stdout.strip()}


# --------------------------------------------------------------------------
# Detection knowledge base — resources
#
# Resources are for browsing (stable URIs, no arguments beyond the path); the
# tools below are for querying with filters. Both read the same index.
# --------------------------------------------------------------------------


# What each rules dir is, keyed by its directory name (kb.Rule.source). Purely
# descriptive — used to label the catalog so "hayabusa" vs "sigma" isn't a riddle.
_SOURCE_ROLES = {
    "rules": "custom rules authored in this repo; override bundled rules by reusing their id",
    "sigma": "the Sigma corpus bundled with hayabusa",
    "hayabusa": "hayabusa's own built-in rules; it scans with these alongside the Sigma corpus",
}


def _json(payload: object) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _find_rule(index: kb.Index, ref: str) -> kb.Rule | None:
    """Resolve a rule by id, filename stem, or exact title (in that order)."""
    by_id = index.by_id()
    if ref in by_id:
        return by_id[ref]
    needle = ref.lower()
    for rule in index.rules:
        if Path(rule.path).stem.lower() == needle:
            return rule
    for rule in index.rules:
        if rule.title.lower() == needle:
            return rule
    return None


def _tally(values: Iterable[str], limit: int | None = None) -> dict[str, int]:
    """Count occurrences, highest first, optionally keeping only the top N."""
    return kb.tally(values, limit=limit)


@mcp.resource("detection://rules", mime_type="application/json")
def rules_catalog() -> str:
    """Catalog of every indexed detection rule: what exists, and how it breaks down.

    Answers "what rules do we have?" on its own — counts by source, severity,
    maturity, and log source, plus the ATT&CK headline. Custom rules from rules/
    are listed in full; the bundled sets are thousands of rules and are
    summarized instead — reach into them with the search_rules tool or
    detection://rules/by-technique/{id}.
    """
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    custom = [r for r in index.rules if r.source == "rules"]

    # Each source is a rules dir. They are NOT interchangeable: hayabusa scans
    # with both its Sigma corpus and its own built-in rules, and conflating them
    # is what once hid a whole rules dir from the index.
    by_source = {
        source: {
            "count": sum(1 for r in index.rules if r.source == source),
            "role": _SOURCE_ROLES.get(source, "rules directory"),
        }
        for source in sorted({r.source for r in index.rules})
    }

    cov = kb.coverage(index, meta)
    counts = kb.breakdown(index.rules)

    return _json(
        {
            "total_rules": len(index.rules),
            "distinct_detections": counts["distinct_detections"],
            "by_source": by_source,
            "by_platform": counts["by_platform"],
            "by_level": counts["by_severity"],
            "by_status": counts["by_status"],
            "top_log_sources": _tally((r.log_source for r in index.rules), limit=10),
            "attack": {
                "techniques_covered": cov["techniques_covered"],
                "rules_without_technique": cov["rules_without_technique"],
                "top_tactics": dict(list(cov["tactics"].items())[:10]),
                "detail": "detection://attack/coverage",
            },
            "custom_rules": {
                "count": len(custom),
                "source_dir": "rules/",
                "rules": [r.summary() for r in custom],
            },
            "notes": [
                "Rule count is not coverage: rules under 'rules_without_technique' still "
                "fire during a scan but are invisible to ATT&CK coverage queries.",
                "Check 'by_status' before trusting a count — 'experimental'/'deprecated' "
                "rules are included here but do not make a technique 'covered'.",
                "'by_platform' splits rules by the telemetry they need: a */sysmon rule "
                "cannot fire on an EVTX set collected without Sysmon deployed.",
                "The sysmon and builtin trees mirror each other, so 'total_rules' "
                "double-counts; 'distinct_detections' counts unique rule titles.",
                "Bundled rules are not enumerated. Use search_rules or "
                "detection://rules/by-technique/{technique_id}.",
            ],
            "index_notes": index.notes,
        }
    )


@mcp.resource("detection://rules/{rule_ref}", mime_type="text/yaml")
def rule_content(rule_ref: str) -> str:
    """Raw YAML of one rule, addressed by rule id, filename stem, or title."""
    index = kb.load_index()
    rule = _find_rule(index, rule_ref)
    if rule is None:
        raise kb.KnowledgeBaseError(
            f"no rule matching {rule_ref!r} (try a rule id, filename stem, or exact title; "
            "use search_rules to find one)"
        )
    return Path(rule.path).read_text(encoding="utf-8", errors="replace")


@mcp.resource("detection://rules/by-technique/{technique_id}", mime_type="application/json")
def rules_by_technique(technique_id: str) -> str:
    """Every rule detecting an ATT&CK technique. A parent id also matches its
    sub-techniques, so T1003 includes T1003.001 etc.
    """
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    tid = technique_id.upper()
    matches = [r for r in index.rules if kb.matches_technique(r, tid)]
    return _json(
        {
            "technique": tid,
            "name": kb.technique_name(tid, meta),
            "matched_rules": len(matches),
            "note": "Includes rules tagged with sub-techniques of this technique.",
            "breakdown": kb.breakdown(matches),
            "rules": [r.summary() for r in matches],
        }
    )


@mcp.resource("detection://attack/techniques/{technique_id}", mime_type="application/json")
def attack_technique(technique_id: str) -> str:
    """ATT&CK technique detail: name, description, the rules that detect it, and
    a coverage assessment of covered | partial | gap.
    """
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    return _json(kb.technique_detail(index, meta, technique_id))


@mcp.resource("detection://attack/coverage", mime_type="application/json")
def attack_coverage_overview() -> str:
    """Detection coverage across ATT&CK: rules per technique and per tactic."""
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    report = kb.coverage(index, meta)
    report["index_notes"] = index.notes
    report["note"] = (
        "'techniques' counts rules per technique, best-covered first. A technique "
        "absent here has no rule at all; detection://attack/techniques/{id} "
        "assesses any single technique as covered/partial/gap."
    )
    return _json(report)


@mcp.resource("detection://attack/tactics", mime_type="application/json")
def attack_tactics() -> str:
    """ATT&CK tactics with how many indexed rules cover each."""
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    counts = kb.coverage(index, meta)["tactics"]
    return _json(
        {
            "tactics": [
                {
                    "slug": slug,
                    "id": info.get("id", ""),
                    "name": info.get("name", ""),
                    "rules": counts.get(slug, 0),
                }
                for slug, info in sorted(meta["tactics"].items())
            ],
            "note": (
                "Hayabusa splits ATT&CK's Defense Evasion into 'stealth' and "
                "'defense-impairment'; rules tagged attack.defense-evasion are counted "
                "under their own slug."
            ),
        }
    )


# --------------------------------------------------------------------------
# Detection knowledge base — tools
# --------------------------------------------------------------------------


@mcp.tool()
def search_rules(
    query: str = "",
    technique: str = "",
    tactic: str = "",
    level: str = "",
    product: str = "",
    status: str = "",
    limit: int = 50,
) -> dict:
    """Search indexed Sigma rules. All filters AND together; omit all to list.

    Args:
        query: Case-insensitive substring matched against rule title and description.
        technique: ATT&CK id, e.g. "T1003.003". A parent id also matches its sub-techniques.
        tactic: Tactic slug, e.g. "credential-access" (see detection://attack/tactics).
        level: informational|low|medium|high|critical.
        product: logsource product, e.g. "windows".
        status: Sigma status, e.g. "stable" | "test" | "experimental".
        limit: Maximum rules to return. 'breakdown' still describes every match.
    """
    if level and level not in _LEVELS:
        raise HayabusaError(f"level must be one of {_LEVELS}, got {level!r}")
    if limit < 1:
        raise HayabusaError(f"limit must be a positive integer, got {limit!r}")
    index = kb.load_index()
    matches = kb.search_all(
        index,
        query=query,
        technique=technique,
        tactic=tactic,
        level=level,
        product=product,
        status=status,
    )
    hits = matches[:limit]
    return {
        "matched": len(matches),
        "returned": len(hits),
        "truncated": len(matches) > limit,
        # Over every match, not the returned page: the caller must be able to
        # characterize the whole result set without paging through it.
        "breakdown": kb.breakdown(matches),
        "rules": [r.summary() for r in hits],
    }


@mcp.tool()
def get_rule(rule_ref: str) -> dict:
    """Fetch one rule's metadata and its raw YAML.

    Args:
        rule_ref: Rule id (UUID), filename stem, or exact title.
    """
    index = kb.load_index()
    rule = _find_rule(index, rule_ref)
    if rule is None:
        raise HayabusaError(f"no rule matching {rule_ref!r} — use search_rules to find one")
    meta = kb.load_attack_metadata()
    return {
        **rule.summary(),
        "description": rule.description,
        "author": rule.author,
        "logsource": {"product": rule.product, "service": rule.service, "category": rule.category},
        "technique_names": {t: kb.technique_name(t, meta) for t in rule.techniques},
        "other_tags": rule.other_tags,
        "path": rule.path,
        "yaml": Path(rule.path).read_text(encoding="utf-8", errors="replace"),
    }


@mcp.tool()
def attack_coverage(tactic: str = "", min_level: str = "") -> dict:
    """Report detection coverage across ATT&CK techniques.

    Args:
        tactic: Restrict to one tactic slug, e.g. "lateral-movement".
        min_level: Only count rules at this level or above.
    """
    if min_level and min_level not in _LEVELS:
        raise HayabusaError(f"min_level must be one of {_LEVELS}, got {min_level!r}")
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    return kb.coverage(index, meta, tactic=tactic, min_level=min_level)


@mcp.tool()
def technique_coverage(technique_id: str) -> dict:
    """Assess coverage of a single ATT&CK technique: covered, partial, or gap.

    Args:
        technique_id: e.g. "T1003" or "T1003.003".
    """
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    return kb.technique_detail(index, meta, technique_id)


@mcp.tool()
def coverage_gaps(tactic: str = "", limit: int = 50) -> dict:
    """List ATT&CK techniques with no detection rule — the coverage gaps.

    Only techniques ATT&CK still considers current are reported; revoked and
    deprecated ids are excluded so they are not mistaken for real gaps.

    Args:
        tactic: Restrict to one tactic slug, e.g. "credential-access".
        limit: Maximum gaps to return.
    """
    if limit < 1:
        raise HayabusaError(f"limit must be a positive integer, got {limit!r}")
    index = kb.load_index()
    meta = kb.load_attack_metadata()

    covered: set[str] = {t for rule in index.rules for t in rule.techniques}
    gaps = []
    for tid, entry in sorted(meta["techniques"].items()):
        if tid in covered or entry.get("revoked") or entry.get("deprecated"):
            continue
        if tactic and tactic not in entry.get("tactics", []):
            continue
        # A parent whose sub-techniques are covered is partial, not a gap.
        if any(c.startswith(tid + ".") for c in covered):
            continue
        gaps.append(
            {"id": tid, "name": kb.technique_name(tid, meta), "tactics": entry.get("tactics", [])}
        )

    return {
        "total_gaps": len(gaps),
        "returned": min(len(gaps), limit),
        "note": (
            "A 'gap' means no indexed rule cites the technique. Some techniques are "
            "not observable in Windows event logs at all, so this is a starting point "
            "for review, not a to-do list."
        ),
        "gaps": gaps[:limit],
    }


@mcp.tool()
def rebuild_rule_index() -> dict:
    """Re-parse every Sigma rule and refresh the on-disk index cache.

    Slow (minutes for the bundled corpus) — needed only after the corpus changes,
    e.g. following update_rules. Edits to rules/ are picked up automatically.
    """
    index = kb.load_index(rebuild=True)
    return {"indexed_rules": len(index.rules), "notes": index.notes}


@mcp.tool()
def scan_evtx_attack(
    input_path: str,
    min_level: str = "low",
    max_results: int | None = 100,
) -> dict:
    """Scan EVTX logs and report which ATT&CK techniques were observed.

    Joins each Hayabusa detection back to the Sigma rule that fired it (by rule
    id) and rolls the results up by technique and tactic — the bridge between
    scanning and the knowledge base.

    Args:
        input_path: A single .evtx file or a directory of .evtx files.
        min_level: Lowest alert level to include: informational|low|medium|high|critical.
        max_results: Cap on annotated detections returned; the rollup always
            covers every detection. None returns all.

    Returns:
        Per-technique and per-tactic observation counts, plus detections
        annotated with their techniques. "unmapped_detections" counts hits whose
        rule id is absent from the index — a stale index cache usually explains it.
    """
    if max_results is not None and max_results < 1:
        raise HayabusaError(f"max_results must be a positive integer, got {max_results!r}")
    # The 'standard' profile is the leanest one carrying RuleID, which is the
    # join key back to the rule index.
    scan = scan_evtx(
        input_path,
        min_level=min_level,
        profile="standard",
        output_format="full",
    )
    index = kb.load_index()
    meta = kb.load_attack_metadata()
    by_id = index.by_id()

    per_tech: dict[str, int] = {}
    per_tactic: dict[str, int] = {}
    annotated: list[dict] = []
    unmapped = 0

    for det in scan["detections"]:
        rule = by_id.get(str(det.get("RuleID", "")))
        if rule is None:
            unmapped += 1
        for tech in rule.techniques if rule else []:
            per_tech[tech] = per_tech.get(tech, 0) + 1
        for tac in rule.tactics if rule else []:
            per_tactic[tac] = per_tactic.get(tac, 0) + 1
        annotated.append(
            {
                **{k: det[k] for k in _SUMMARY_FIELDS if k in det},
                "RuleID": det.get("RuleID", ""),
                "techniques": rule.techniques if rule else [],
                "tactics": rule.tactics if rule else [],
            }
        )

    techniques = [
        {"id": tid, "name": kb.technique_name(tid, meta), "detections": count}
        for tid, count in sorted(per_tech.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    return {
        "total": scan["total"],
        "counts": scan["counts"],
        "techniques_observed": techniques,
        "tactics_observed": dict(sorted(per_tactic.items(), key=lambda kv: -kv[1])),
        "unmapped_detections": unmapped,
        "returned": len(annotated[:max_results] if max_results else annotated),
        "detections": annotated[:max_results] if max_results else annotated,
    }


def main() -> None:
    """Console entry point — run the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
