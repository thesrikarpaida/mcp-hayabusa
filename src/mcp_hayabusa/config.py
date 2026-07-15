"""Runtime configuration, sourced from environment variables.

All settings are read once at import time so the values are stable for the
lifetime of the server process. See README.md for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Repo root: src/mcp_hayabusa/config.py -> src/mcp_hayabusa -> src -> root.
# Used only to anchor the knowledge-base defaults so the server works from any cwd.
ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Config:
    # Path to the hayabusa binary. Can be an absolute path or a name resolved
    # against PATH. Windows users typically point this at hayabusa-x.y.z-win-x64.exe.
    binary: str

    # Hard ceiling (seconds) on any single hayabusa invocation. Timelines over
    # large evtx sets are slow, so this defaults high.
    timeout: float

    # Directory the server is allowed to read evtx from / write output to.
    # When set, every path argument is resolved and confined beneath it to
    # keep the tools from touching arbitrary parts of the filesystem.
    # Empty string disables the sandbox (all paths allowed).
    workdir: str

    # The knowledge-base settings below default to the repo layout so tests (and
    # anything that only needs the scanning half of the server) can build a
    # Config without spelling them out.

    # Directories searched for Sigma rules, highest priority first. Rules in an
    # earlier directory shadow a later one with the same rule id, so custom
    # rules/ overrides the bundled corpus. Set via HAYABUSA_RULES_DIR as an
    # os.pathsep-separated list.
    rules_dirs: tuple[Path, ...] = ()

    # Directory holding generated ATT&CK metadata (attack.yaml).
    mappings_dir: Path = ROOT / "mappings"

    # Where the parsed rule index is cached. Parsing the ~4.8k-rule bundled
    # corpus takes minutes on a slow filesystem, so the index is built once
    # (make build-index) and reloaded from this JSON file thereafter.
    index_cache: Path = ROOT / ".cache" / "rule_index.json"

    # Tactic name/abbreviation table shipped with hayabusa. Authoritative source
    # for which "attack.*" tags are tactics rather than techniques/groups/software.
    tactics_file: Path = ROOT / "hayabusa" / "config" / "mitre_tactics.txt"


def _rules_dirs() -> tuple[Path, ...]:
    """Parse HAYABUSA_RULES_DIR, defaulting to custom rules/ + the bundled corpus.

    Hayabusa scans with *two* bundled rule sets and both must be indexed, or
    detections from the missing one cannot be joined back to a rule:
    ``rules/sigma`` (the Sigma corpus) and ``rules/hayabusa`` (Hayabusa's own
    built-in rules, e.g. "Log Cleared", "Possible LOLBIN").
    """
    raw = os.environ.get("HAYABUSA_RULES_DIR", "")
    if raw:
        return tuple(Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip())
    bundled = ROOT / "hayabusa" / "rules"
    return (ROOT / "rules", bundled / "hayabusa", bundled / "sigma")


def load_config() -> Config:
    return Config(
        binary=os.environ.get("HAYABUSA_PATH", "hayabusa"),
        timeout=float(os.environ.get("HAYABUSA_TIMEOUT", "1800")),
        workdir=os.environ.get("HAYABUSA_WORKDIR", ""),
        rules_dirs=_rules_dirs(),
        mappings_dir=Path(os.environ.get("HAYABUSA_MAPPINGS_DIR", str(ROOT / "mappings"))),
        index_cache=Path(
            os.environ.get("HAYABUSA_INDEX_CACHE", str(ROOT / ".cache" / "rule_index.json"))
        ),
        tactics_file=Path(
            os.environ.get(
                "HAYABUSA_TACTICS_FILE", str(ROOT / "hayabusa" / "config" / "mitre_tactics.txt")
            )
        ),
    )


CONFIG = load_config()
