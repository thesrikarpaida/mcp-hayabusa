"""Comparing two releases of a framework, and what the changes cost us.

A changelog is not the interesting artifact. **Mapping impact** is: when ATT&CK
revokes a technique, every Sigma rule still tagged with the old id quietly stops
resolving. Nothing errors. Coverage just drops, and the first sign is a coverage
report that looks slightly better than reality. The whole point of this module
is to turn that silence into a list of rule ids.

    T1234 deprecated in 19.2. 12 Sigma rules still map to it.
    T5678 revoked, superseded by T9012. 3 rules need remapping.

Four kinds of change, per ``TODO.md``:

======================  ======================================================
Added                   id in new, absent in old
Removed                 id in old, absent in new
Deprecated              ``x_mitre_deprecated: true`` in new
Revoked / renamed       ``revoked: true``, plus a ``relationship`` of type
                        ``revoked-by`` naming the successor
======================  ======================================================

Revoked is the case that matters, because a revoked technique is not gone — it
points at a replacement, and following that pointer is the difference between
"3 rules need remapping" and silent loss. :func:`mcp_hayabusa.stix.parse_bundle`
has already resolved the ``revoked-by`` relationship into ``superseded_by``, so
this module reads a field rather than walking relationships a second time.

Pure and offline: everything here takes two already-parsed bundles and a plain
mapping of technique id to rule ids. Downloading is ``scripts/`` work, and the
rule lookup is injected, so the whole module is unit-testable against small
synthetic bundles with neither a network nor a database.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from .stix import ParsedBundle

# The four change classes, in report order: what appeared, what vanished, what
# is on its way out, and what moved.
ADDED = "added"
REMOVED = "removed"
DEPRECATED = "deprecated"
REVOKED = "revoked"
KINDS = (ADDED, REMOVED, DEPRECATED, REVOKED)


@dataclass
class Change:
    """One technique-level change between two releases."""

    id: str
    kind: str
    name: str = ""
    # Set only for REVOKED: the id that replaces this one.
    successor: str | None = None
    successor_name: str = ""
    # Sigma rule ids still citing this technique. Filled by
    # :func:`attach_rule_impact`; empty until then, which is not the same as
    # "no rules" — see that function.
    rules: list[str] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def describe(self) -> str:
        """The one-line form the report prints."""
        label = f"{self.id}" + (f" ({self.name})" if self.name else "")
        if self.kind == REVOKED and self.successor:
            successor = self.successor + (
                f" ({self.successor_name})" if self.successor_name else ""
            )
            head = f"{label} revoked, superseded by {successor}."
            tail = (
                f" {self.rule_count} rule(s) need remapping."
                if self.rules
                else " No rules map to it."
            )
        elif self.kind == REVOKED:
            head = f"{label} revoked, with no successor recorded."
            tail = f" {self.rule_count} rule(s) still map to it." if self.rules else ""
        elif self.kind == DEPRECATED:
            head = f"{label} deprecated."
            tail = (
                f" {self.rule_count} Sigma rule(s) still map to it."
                if self.rules
                else " No rules map to it."
            )
        elif self.kind == REMOVED:
            head = f"{label} removed from the bundle."
            tail = f" {self.rule_count} rule(s) still map to it." if self.rules else ""
        else:
            head = f"{label} added."
            tail = f" {self.rule_count} rule(s) already map to it." if self.rules else ""
        return head + tail


@dataclass
class FrameworkDiff:
    """Every change between two releases of one framework."""

    framework: str = ""
    old_version: str = ""
    new_version: str = ""
    added: list[Change] = field(default_factory=list)
    removed: list[Change] = field(default_factory=list)
    deprecated: list[Change] = field(default_factory=list)
    revoked: list[Change] = field(default_factory=list)
    # Techniques already deprecated/revoked in the old release. Not changes, so
    # not in the lists above, but counted so the report cannot be mistaken for
    # "these are the only retired ids in the bundle".
    carried_deprecated: int = 0
    carried_revoked: int = 0

    def changes(self) -> list[Change]:
        return [*self.added, *self.removed, *self.deprecated, *self.revoked]

    def by_kind(self) -> dict[str, list[Change]]:
        return {
            ADDED: self.added,
            REMOVED: self.removed,
            DEPRECATED: self.deprecated,
            REVOKED: self.revoked,
        }

    def counts(self) -> dict[str, int]:
        return {kind: len(changes) for kind, changes in self.by_kind().items()}

    def affected_rule_ids(self) -> set[str]:
        """Every Sigma rule touched by any change in this diff."""
        return {rule_id for change in self.changes() for rule_id in change.rules}


def diff(
    old: ParsedBundle,
    new: ParsedBundle,
    *,
    framework: str = "enterprise-attack",
) -> FrameworkDiff:
    """Classify every technique-level change from ``old`` to ``new``.

    The four categories are mutually exclusive, so the counts add up rather than
    double-reporting: presence decides first (a technique that only exists in
    one release is *added* or *removed*, whatever its flags say), and
    deprecated/revoked are then judged over the techniques present in both.

    Only a **transition** counts as a change. ATT&CK carries old deprecations
    forward forever, so reporting every deprecated id in the new bundle would
    bury the handful that actually moved under hundreds that did not. The
    carried-forward ones are counted in ``carried_deprecated`` /
    ``carried_revoked`` instead of being dropped.
    """
    result = FrameworkDiff(
        framework=framework,
        old_version=old.version,
        new_version=new.version,
    )

    old_ids, new_ids = old.ids(), new.ids()

    for tid in sorted(new_ids - old_ids):
        result.added.append(Change(id=tid, kind=ADDED, name=new.techniques[tid].get("name", "")))

    for tid in sorted(old_ids - new_ids):
        result.removed.append(
            Change(id=tid, kind=REMOVED, name=old.techniques[tid].get("name", ""))
        )

    for tid in sorted(old_ids & new_ids):
        before, after = old.techniques[tid], new.techniques[tid]

        if after.get("revoked"):
            if before.get("revoked"):
                result.carried_revoked += 1
                continue
            successor = after.get("superseded_by")
            result.revoked.append(
                Change(
                    id=tid,
                    kind=REVOKED,
                    name=after.get("name", ""),
                    successor=successor,
                    successor_name=(new.techniques.get(successor, {}).get("name", "")),
                )
            )
        elif after.get("deprecated"):
            if before.get("deprecated"):
                result.carried_deprecated += 1
                continue
            result.deprecated.append(Change(id=tid, kind=DEPRECATED, name=after.get("name", "")))

    return result


def attach_rule_impact(
    result: FrameworkDiff,
    lookup: Mapping[str, list[str]] | Callable[[list[str]], Mapping[str, list[str]]],
) -> FrameworkDiff:
    """Fill in the Sigma rules each change affects. Mutates and returns ``result``.

    ``lookup`` is either a plain mapping of technique id to rule ids, or a
    callable taking every id at once — the callable form lets the caller do a
    single indexed query (see :func:`mcp_hayabusa.mongo.rules_for_techniques`)
    instead of one round trip per change.

    A change whose technique no rule cites keeps an empty list. That is a real
    answer, not a missing one: "ATT&CK revoked this and it costs us nothing" is
    exactly as useful as the alternative, and is most of the diff.
    """
    changes = result.changes()
    ids = [change.id for change in changes]
    hits = lookup(ids) if callable(lookup) else lookup
    for change in changes:
        change.rules = sorted(hits.get(change.id, []) or [])
    return result


def summary(result: FrameworkDiff) -> dict:
    """Machine-readable rollup: counts per category and the mapping impact."""
    counts = result.counts()
    return {
        "framework": result.framework,
        "old_version": result.old_version,
        "new_version": result.new_version,
        "changes": counts,
        "changes_total": sum(counts.values()),
        "carried_deprecated": result.carried_deprecated,
        "carried_revoked": result.carried_revoked,
        "rules_affected": len(result.affected_rule_ids()),
        "rules_needing_remap": len(
            {rule_id for change in result.revoked for rule_id in change.rules}
        ),
    }


def render(result: FrameworkDiff, *, rule_limit: int = 10, show_unaffected: bool = False) -> str:
    """The human report.

    Changes that affect at least one Sigma rule are listed first and in full;
    the rest are collapsed to a count unless ``show_unaffected`` is set. A diff
    of two adjacent ATT&CK releases runs to hundreds of additions, almost none
    of which touch this corpus — printing them all would bury the dozen lines
    that actually require work.
    """
    stats = summary(result)
    lines = [
        f"{result.framework}: {result.old_version} -> {result.new_version}",
        "=" * 60,
        "  ".join(f"{kind}: {stats['changes'][kind]}" for kind in KINDS),
        f"Sigma rules affected: {stats['rules_affected']} "
        f"({stats['rules_needing_remap']} need remapping after a revocation)",
    ]
    if result.carried_deprecated or result.carried_revoked:
        lines.append(
            f"(carried forward from {result.old_version or 'the old release'}: "
            f"{result.carried_deprecated} already deprecated, "
            f"{result.carried_revoked} already revoked — not changes)"
        )

    for kind, changes in result.by_kind().items():
        lines.append("")
        lines.append(f"--- {kind.upper()} ({len(changes)}) ---")
        if not changes:
            lines.append("  none")
            continue

        impactful = [c for c in changes if c.rules]
        quiet = [c for c in changes if not c.rules]

        for change in sorted(impactful, key=lambda c: (-c.rule_count, c.id)):
            lines.append(f"  {change.describe()}")
            shown = change.rules[:rule_limit]
            lines.append(f"      rules: {', '.join(shown)}")
            if change.rule_count > rule_limit:
                lines.append(f"      ... and {change.rule_count - rule_limit} more")

        if quiet and show_unaffected:
            for change in quiet:
                lines.append(f"  {change.describe()}")
        elif quiet:
            lines.append(
                f"  ({len(quiet)} more with no Sigma rule mapped; "
                "pass --show-unaffected to list them)"
            )

    return "\n".join(lines)
