# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server, built with **FastMCP** (`mcp[cli]`), serving two
related surfaces:

1. **Hayabusa scanning** — wraps the **Hayabusa** CLI (Yamato Security's Windows EVTX
   forensics timeline & Sigma threat-hunting tool). These tools shell out to a Hayabusa
   subcommand. Hayabusa is a standalone Rust binary, *not* a Python package; it is
   downloaded separately and located at runtime via `HAYABUSA_PATH`.
2. **A detection-engineering knowledge base** — indexes Sigma rules (custom `rules/` plus
   the corpus Hayabusa bundles), maps them to ATT&CK techniques, and answers coverage
   questions. Pure data: no binary needed for this half.

`scan_evtx_attack` joins the two, reporting which ATT&CK techniques a scan actually observed.

Defensive/DFIR context: this tooling analyzes event logs the operator is authorized to inspect.

## Commands

All Python tasks use **`uv`** — never call `pip` or `python` directly.

```bash
# First-time setup (Python deps + Hayabusa binary if missing + rule index)
make setup

# Individual steps
uv sync --extra dev                    # install Python deps into .venv
make install-hayabusa                  # download Hayabusa binary to ./hayabusa/
make build-index                       # parse rules -> .cache/rule_index.json (~2-3 min)
make mappings                          # regenerate mappings/attack.yaml from MITRE STIX
./scripts/fetch_samples.sh             # download sample .evtx into samples/ for e2e tests

# Run tests
HAYABUSA_PATH=./hayabusa/hayabusa uv run pytest -v   # all 93 (83 unit + 10 integration), ~3m20s
uv run pytest -m "not integration" -v                # 83 unit only, ~5s (no binary needed)
uv run pytest tests/test_kb.py tests/test_server_kb.py -v   # knowledge base (no binary)
uv run pytest -m integration -v                      # 10 integration tests only, ~1m20s

# Single test
uv run pytest tests/test_hayabusa.py::test_run_invokes_binary -v

# Lint / format
uv run ruff check .
uv run ruff format .

# Run the MCP server (stdio)
HAYABUSA_PATH=./hayabusa/hayabusa uv run python src/mcp_hayabusa/server.py
```

## Hayabusa binary setup

`make setup` checks for the binary automatically and installs it if missing. The install script
(`scripts/install_hayabusa.sh`) detects glibc version and picks the correct build:

| glibc   | Build           | When                                 |
|---------|-----------------|--------------------------------------|
| ≥ 2.38  | `lin-x64-gnu`   | Modern distros                       |
| < 2.38  | `lin-x64-musl`  | Ubuntu 22.04, WSL2 on Windows 11     |

The musl build is statically linked — no glibc dependency, runs anywhere on Linux x64.

After install, the binary is at `./hayabusa/hayabusa` (symlink to the versioned binary).

> **Hayabusa v3.10+ has no `--version` flag.** Use `hayabusa help` — the version appears in
> the first line of output. All server tools and tests use `help` for version detection.

## Architecture

Four layers — keep this separation when extending:

- **`config.py`** — a single frozen `Config` loaded from env at import (`CONFIG`).
  Env vars: `HAYABUSA_PATH`, `HAYABUSA_TIMEOUT` (default 1800s), `HAYABUSA_WORKDIR`,
  `HAYABUSA_RULES_DIR` (os.pathsep-separated), `HAYABUSA_MAPPINGS_DIR`,
  `HAYABUSA_INDEX_CACHE`, `HAYABUSA_TACTICS_FILE`.
  Tests override by monkeypatching the module-level `CONFIG`; never read `os.environ` elsewhere.
  KB fields have repo-relative defaults so a `Config` can be built without them.

- **`hayabusa.py`** — the *only* place that spawns a subprocess (`run()`). It is the choke
  point for binary resolution, timeout enforcement, `HayabusaError` shaping, and path safety.
  - `safe_path()`: resolves a caller-supplied path and, if `HAYABUSA_WORKDIR` is set, confines
    it beneath that root. Call this on **all** caller-supplied paths.
  - `input_flag()`: picks `-d` (directory) vs `-f` (single file). Hayabusa distinguishes these.

- **`kb.py`** — the knowledge base. Parses Sigma YAML, indexes rules, maps ATT&CK tags,
  computes coverage. **Never spawns a subprocess**; it only reads files. Owns `LEVELS`
  (`server._LEVELS` aliases it — don't redefine).

- **`server.py`** — FastMCP surface: `@mcp.tool()` for actions/queries, `@mcp.resource()`
  for browsable `detection://` URIs. Scanning subcommands include `_SCAN_BASE = ["-w", "-q", "-N"]`:
  - `-w` / `--no-wizard`: skips interactive rule-selection wizard — **required** for non-interactive
    use; without it the subprocess blocks indefinitely.
  - `-q` / `--quiet`: suppresses the ASCII banner.
  - `-N` / `--no-summary`: suppresses the results summary table.

## Knowledge base (`kb.py`)

### Hayabusa ships TWO rule sets — index both

`hayabusa/rules/` contains **`sigma/`** (4,767 Sigma rules) *and* **`hayabusa/`** (196 of
Hayabusa's own built-in rules, parsed from 193 files: "Log Cleared", "Possible LOLBIN", …).
Hayabusa scans with both. Indexing only `sigma/` makes `scan_evtx_attack` silently fail to
map any built-in rule's detections — that bug was real and is caught by
`tests/integration/test_samples.py::test_scan_evtx_attack_maps_every_detection_to_a_rule`.
Both are in `CONFIG.rules_dirs` by default; if you override `HAYABUSA_RULES_DIR`, include both.

Note the units: **193 files, 196 rules** — the three correlation files define two rules each
(see the multi-document note below). `LIVE_DIR_MAX_FILES` compares against the file count;
the index reports the rule count. Both are right; don't reconcile them.

`hayabusa/` is **gitignored** — ~70MB of third-party licensed content that `make setup`
downloads. A fresh clone indexes only `rules/` until then.

### The two trees are a platform split, and it is load-bearing

Both bundled sets are split into parallel `sysmon/` and `builtin/` trees carrying the *same*
detections against different event sources (sigma: 2,386 / 2,381). So:

- A `*/sysmon` rule is **inert** on an EVTX set collected without Sysmon deployed. A raw rule
  count therefore overstates what will actually fire — `by_platform` is the number that says
  how much of a count is real for a given case.
- The mirroring means totals **double-count**: 4,965 rules are 3,207 distinct detections.
  `distinct_detections` (unique titles) is the honest size.

No Sigma field records the tree — it is only in the rule's path, so `Rule.platform` derives it
from the first directory below the rules dir (whose basename is `Rule.source`). It searches the
path **backwards**, because the corpus lives at `hayabusa/rules/hayabusa/builtin/…` where the
install dir shares the rules dir's name. It's a property, not a field, so the index cache stays
valid — don't move it into the dataclass without bumping `CACHE_VERSION`.

### Breakdowns — every "what rules do we have" answer carries one

`kb.breakdown(rules)` counts a rule set by severity, platform, log source, status, and source,
plus `distinct_detections`. Every surface that answers "what rules exist" returns it:
`detection://rules`, `detection://rules/by-technique/{id}`, `detection://attack/techniques/{id}`,
and `search_rules`. A bare total is not actionable for detection engineering — the operator's
next question is always "which of those can fire, and how bad are they?".

**A breakdown always describes every match, never the returned page.** Payloads are capped
(`rule_limit`, `limit`) but the counts are computed before truncation — a breakdown of a
truncated list would silently describe 50 rules next to a coverage claim made over 123. This is
why `kb.search_all()` exists and `kb.search()` is a thin slice of it: the old `search()` broke
out of its loop at `limit`, which made an honest total impossible.

### Indexing — why there is a cache

Parsing the bundled corpus (~4.8k rules) takes **~150s** on WSL2 over `/mnt/c`; even just
walking it costs 7s and stat-ing every file 22s. So the index is cached per rules directory
in `.cache/rule_index.json`:

| Dir kind | Rule | Behavior |
|----------|------|----------|
| **Live** (≤ `LIVE_DIR_MAX_FILES`, i.e. `rules/`) | re-scanned every `load_index()` | edits appear immediately, no rebuild |
| **Pinned** (larger, i.e. the bundled corpus) | served from cache, never re-walked | rebuild only via `make build-index` / `rebuild_rule_index` |

A pinned dir is identified from the cache's own `live: false` flag, so its directory is
**not walked** at load — that's the whole point. Don't add a stat-based freshness check;
it would cost more than it saves. `load_index()` reports what it did in `Index.notes`.

`_read_cache()` memoizes on (path, mtime). Tests that write the cache directly must reset
`kb._CACHE_MEMO`.

### ATT&CK mappings

`mappings/attack.yaml` is **generated** by `scripts/build_attack_mappings.py` from MITRE's
STIX bundle, and **committed**. The server never fetches at runtime — DFIR answers must not
depend on GitHub being reachable. Regenerate with `make mappings`; don't hand-edit.

Facts that bit, confirmed against the real data:

- Sigma `attack.*` tags are a grab bag: tactics (`attack.credential-access`), techniques
  (`attack.t1003.003`), **groups** (`attack.g0016`) and **software** (`attack.s0002`).
  Only classify a tag as a tactic if it's in hayabusa's `config/mitre_tactics.txt`.
- Current ATT&CK has **revoked** ids the corpus still cites (`T1086`→`T1059.001`,
  `T1035`→`T1569.002`). The generator records `superseded_by`; coverage excludes them from
  gaps and `technique_detail` warns.
- ATT&CK split Defense Evasion into **`stealth`** and **`defense-impairment`**; there is no
  `defense-evasion` tactic in the current bundle, though rules still tag it. Hayabusa's
  tactics file lists both, so it stays the authority for tag classification.
- STIX names sub-techniques tersely (`T1003.003` = "NTDS"), so `technique_name()` renders
  them under the parent: "OS Credential Dumping: NTDS".

### Primary tool: `scan_evtx`

The main triage entry point. Runs `json-timeline` into a temp directory, parses each JSONL
detection into a Python dict (skipping malformed lines), and returns inline:

```json
{"total": 12, "counts": {"low": 8, "high": 4}, "detections": [{...}, ...]}
```

Severity filter (`min_level`) is passed directly to Hayabusa via `--min-level`.
Valid values low-to-high: `informational`, `low`, `medium`, `high`, `critical`.

### Bridging tool: `scan_evtx_attack`

Scans, then joins each detection back to its Sigma rule **by `RuleID`** and rolls results up
by technique/tactic. It forces `profile="standard"` — the leanest profile carrying `RuleID`
(`minimal` does not have it). Detections whose rule id isn't indexed are counted in
`unmapped_detections` rather than dropped; a stale index cache is the usual cause.

### Resources

| URI | Returns |
|-----|---------|
| `detection://rules` | Catalog: every custom rule in full, corpus summarized (too big to enumerate) |
| `detection://rules/{rule_ref}` | Raw YAML; `rule_ref` = rule id, filename stem, or exact title |
| `detection://rules/by-technique/{technique_id}` | Rules detecting a technique (parent id includes its subs) |
| `detection://attack/techniques/{technique_id}` | Name, description, detecting rules, coverage assessment |
| `detection://attack/coverage` | Rules per technique and per tactic |
| `detection://attack/tactics` | Tactics with rule counts |

### Coverage assessment

`covered` / `partial` / `gap` is deliberately conservative — it answers "can we claim to
detect this?", not "does a rule mention it?". `partial` covers three distinct cases: only
some sub-techniques covered, covered *only* via sub-techniques, or every citing rule still
`experimental`. See `kb.technique_detail`.

Beware: a `gap` is not automatically a to-do. Many ATT&CK techniques (e.g. `T1003.007`
Proc Filesystem) are Linux-only and unobservable in Windows EVTX.

Payloads are capped (`rule_limit`, default 50) because popular techniques attract hundreds
of rules — T1003 has 218. Counts (`coverage` and `breakdown`) always reflect every match;
only the list truncates.

### Adding a tool

1. `@mcp.tool()` in `server.py`. Run `safe_path()` on all path args; use `input_flag()` for evtx input.
2. Include `*_SCAN_BASE` for any scanning subcommand.
3. Small results: return inline. Large timelines: write to a caller-supplied file, return its path
   (see `csv_timeline` / `json_timeline`).
4. Raise `HayabusaError` for invalid input — `run()` already converts non-zero exits and timeouts.
5. For KB tools, put the logic in `kb.py` and keep `server.py` a thin adapter; cap any
   unbounded list before returning it.
6. If the tool returns a set of rules, return `kb.breakdown()` over **all** matches alongside
   the capped list — a caller must never have to page the corpus to characterize a result.

## Tests

Two tiers, both run with `uv run pytest`:

- **Unit tests** — no binary, no corpus download:
  - `tests/test_hayabusa.py`: points `CONFIG` at a fake shell script via `monkeypatch`.
    Wrapper error handling (bad exit, missing binary, path sandboxing).
  - `tests/test_server.py`: `scan_evtx` post-processing against a fake binary emitting
    canned JSONL.
  - `tests/test_kb.py`: the knowledge base against a synthetic corpus in `tmp_path`.
    `ATTACK_YAML` / `TACTICS_TXT` / `write_rule()` there are reused by `test_server_kb.py`.
  - `tests/test_server_kb.py`: KB tools/resources, and the `scan_evtx_attack` join (the fake
    binary emits detections whose `RuleID`s match the fixture rules).

- **Integration tests** (`tests/integration/`): marked `@pytest.mark.integration`. Auto-skipped
  by `conftest.py` when `HAYABUSA_PATH` / `./hayabusa/hayabusa` / `hayabusa` on PATH is all
  absent. When the binary is present they run against the real tool.
  - `test_binary.py` — the binary itself (version, profiles, error paths).
  - `test_samples.py` — **real scans over `samples/`**. Skips unless samples are fetched and
    the index is built. These earn their runtime: they're the only tests that can falsify the
    `RuleID`-join assumption, and they caught two bugs the fake-binary tests passed straight
    through (missing `rules/hayabusa` dir; multi-document correlation rules). The assertion
    that matters is `unmapped_detections == 0`.

`conftest.py` resolves the binary once at session start (env var → `./hayabusa/hayabusa` →
PATH) and exposes it via the `hayabusa_bin` session fixture.

KB **unit** tests never touch the real corpus or `.cache/` — they monkeypatch `kb.CONFIG` at a
`tmp_path`. Keep it that way, or the suite inherits the 150s parse. `test_samples.py` is the
deliberate exception: it uses the real index, which is why it skips when that isn't built.

## MCP server registration

**`.mcp.json` at the repo root** registers the server — that is the file Claude Code reads
for project-scoped MCP servers. An `mcpServers` block in `.claude/settings.json` is **not**
read and is silently ignored (this repo had one; it never worked). `.claude/settings.json`
only opts the server in via `enabledMcpjsonServers`.

```json
{
  "mcpServers": {
    "hayabusa": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "${CLAUDE_PROJECT_DIR:-.}", "mcp-hayabusa"],
      "env": { "HAYABUSA_PATH": "./hayabusa/hayabusa" }
    }
  }
}
```

This is committed and portable — **don't regenerate it with `claude mcp add`**, which
hardcodes an absolute machine-specific path. If you do, restore `${CLAUDE_PROJECT_DIR:-.}`
afterwards.

Why it looks like that:

- **`uv run`, not `python`** — the deps (`mcp`, `PyYAML`) live in `.venv`; a bare `python`
  won't have them.
- **`--directory "${CLAUDE_PROJECT_DIR:-.}"`** — an MCP client picks its own cwd, so the
  server must not assume it starts in the repo. `.mcp.json` expands `${VAR}` /
  `${VAR:-default}` in `command`, `args`, `env`, `url`, `headers`. Claude Code sets
  `CLAUDE_PROJECT_DIR` in the **spawned server's** env, not its own, so **the `:-.` default
  is mandatory** — an unset var with no default is left as the literal `${VAR}` and the
  server won't start. The `.` is what actually resolves: Claude Code launches the server
  with cwd already at the project root (confirmed via `/proc/<pid>/cwd`). Other clients
  should pass an absolute path or export `CLAUDE_PROJECT_DIR`.
- **`HAYABUSA_PATH` stays relative** — `resolve_binary()` retries a relative path against
  the repo root, so this works from any cwd. The KB paths in `config.py` are anchored to
  `ROOT` for the same reason.

A project-scoped server prompts for approval on first use — expected, not a fault.

Set `HAYABUSA_WORKDIR` to confine all path arguments to a specific case directory.

## WSL notes

- The musl build is the correct one for WSL2 on Windows 11 (Ubuntu 22.04, glibc 2.35).
- Do not use the Windows `.exe` build under WSL — WSL runs a real Linux kernel.
- `.gitignore` excludes `*.evtx`, `*.csv`, `*.jsonl`, `output/`, `timelines/` — never commit
  evidence or timeline artifacts. It also excludes `hayabusa/` (third-party, `make setup`
  fetches it) and `.cache/` (derived). `uv.lock` and `mappings/attack.yaml` *are* committed.
