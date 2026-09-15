# mcp-hayabusa

A [Model Context Protocol](https://modelcontextprotocol.io) server for Windows
event log detection & response. It combines two things:

- **Scanning** — [Hayabusa](https://github.com/Yamato-Security/hayabusa), Yamato
  Security's fast EVTX forensics timeline generator and Sigma-based threat hunter,
  exposed as MCP tools so an AI assistant can drive DFIR triage over your logs.
- **A detection-engineering knowledge base** — your Sigma rules and the ~4.8k rules
  Hayabusa bundles, indexed, browsable as MCP resources, and mapped to MITRE ATT&CK
  so you can ask *"do we detect T1003?"* and *"where are our gaps?"*.

The two meet in `scan_evtx_attack`: scan a log, get back the ATT&CK techniques
actually observed.

> **Defensive / authorized use.** This wraps a forensics tool. Point it only at
> event logs you are authorized to analyze.

## Before you start

Two things to check, because `make setup` cannot work around either:

| Requirement | Why |
| --- | --- |
| **Linux x64, or WSL2 on Windows** | The installer fetches a Linux x64 Hayabusa build only. `make setup` does **not** work on native Windows or macOS. |
| **[`uv`](https://docs.astral.sh/uv/)** | The only thing you must install by hand. It bootstraps Python for you (`uv python install`), so Python 3.10+ is not a separate step. |

<details>
<summary>On macOS or native Windows, or you'd rather use <code>pip</code></summary>

The knowledge base is pure Python and runs anywhere — only the *scanning* half needs
the binary. Download a `win-x64` or `mac-*` build from
[Hayabusa's releases](https://github.com/Yamato-Security/hayabusa/releases) and point
`HAYABUSA_PATH` at it.

`pip` reads `pyproject.toml` directly — no `uv`, no `requirements.txt`:

```bash
pip install -e ".[dev]"                                               # deps + the mcp-hayabusa entry point
./scripts/install_hayabusa.sh                                         # fetch the binary (Linux x64)
python -c "from mcp_hayabusa import kb; kb.load_index(rebuild=True)"  # build the rule index
```

Unlike `uv`, `pip` won't install an interpreter for you — you need Python 3.10+ on `PATH`.
</details>

## Setup

```bash
git clone https://github.com/thesrikarpaida/mcp-hayabusa.git && cd mcp-hayabusa
make setup                  # deps + hayabusa binary + rule index  (~3-4 min)
./scripts/fetch_samples.sh  # optional: sample EVTX, so you have something to scan
```

`make setup` ends by building the rule index, which is most of that time — it parses
every Sigma rule once so the server answers instantly afterwards. Skip it and the first
knowledge-base call pays the cost instead.

`scripts/install_hayabusa.sh` detects your glibc version and picks the right build:
`gnu` for glibc ≥ 2.38, `musl` below that (which covers Ubuntu 22.04 and WSL2 on
Windows 11). The musl build is statically linked and runs anywhere on Linux x64.

## Verify it works

Before wiring up an MCP client, confirm the two halves independently:

```bash
# 1. The knowledge base — no binary needed. Expect 4,965 rules across 3 dirs.
uv run python -c "from mcp_hayabusa import kb; i = kb.load_index(); \
print(len(i.rules), 'rules'); [print(' ', n) for n in i.notes]"

# 2. The scanner — expect "Hayabusa v3.10.0 - ..."
HAYABUSA_PATH=./hayabusa/hayabusa uv run python -c \
  "from mcp_hayabusa.server import version; print(version())"

# 3. Both together, on a real log. Expect total 5, unmapped_detections 0.
HAYABUSA_PATH=./hayabusa/hayabusa uv run python -c \
  "from mcp_hayabusa.server import scan_evtx_attack as s; \
r = s('./samples/Powershell-Invoke-Obfuscation-string-menu.evtx', min_level='informational'); \
print(r['total'], 'detections,', r['unmapped_detections'], 'unmapped'); \
print(r['techniques_observed'])"
```

Step 3 is the one that matters: `unmapped_detections: 0` proves the scanner, the rule
index and the ATT&CK mappings all agree. Anything above zero means a stale cache.

Then open the repo in Claude Code and approve the `hayabusa` server when prompted.
`.mcp.json` is committed and needs no editing — details in
[Register with Claude Code](#register-with-claude-code).

```bash
claude mcp list        # hayabusa: connected  ("Pending approval" on first use is expected)
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| A scan hangs forever, no output | The rule-selection wizard is waiting on stdin | Every scanning subcommand needs `-w`. If you added a tool, include `_SCAN_BASE`. |
| `error: unexpected argument '-w' found` | `logon-summary`, `eid-metrics` and `search` have no wizard and reject `-w`/`-N` | Use `_REPORT_BASE`, not `_SCAN_BASE`. |
| `unmapped_detections` > 0 | Stale index — a rule fired that isn't in the cache | `make build-index` |
| KB tools return only 2 rules | `hayabusa/` isn't downloaded yet; you're seeing just `rules/` | `make setup` |
| `version` fails with "no such file" | `HAYABUSA_PATH` unset and no binary on `PATH` | `make install-hayabusa`, or set `HAYABUSA_PATH` |
| Binary won't run: `GLIBC_2.38 not found` | glibc too old for the `gnu` build | Re-run `./scripts/install_hayabusa.sh` — it picks `musl` automatically |
| Integration tests all skip | No binary, or samples not fetched | `make setup && ./scripts/fetch_samples.sh` |
| 27 tests skip | MongoDB isn't running. **This is correct** — the store is optional | `make mongo-up` only if you want it |
| A rule you expect never fires | It may be `deprecated`, `unsupported` or `noisy` (disabled by default), or filtered out because its channel isn't in the EVTX | Check the `log` field from `json_timeline` |

<details>
<summary>Without <code>make</code> (the individual steps)</summary>

```bash
uv sync --extra dev      # install Python deps into .venv
make install-hayabusa    # download the Hayabusa binary to ./hayabusa/
make build-index         # parse rules -> .cache/rule_index.json (~2-3 min)
```
</details>

## Layout

| Path            | What                                                             |
| --------------- | ---------------------------------------------------------------- |
| `rules/`        | Your custom Sigma rules. Re-scanned on every load — edits are live. |
| `mappings/`     | `attack.yaml` / `atlas.yaml`: framework metadata, generated from STIX bundles and committed. |
| `data/`         | `owasp_frameworks.yaml`: the two OWASP top-tens. Hand-maintained — twenty items need no feed. |
| `samples/`      | Sample EVTX for end-to-end testing (`./scripts/fetch_samples.sh`). Logs are gitignored. |
| `hayabusa/rules/sigma/` | The bundled Sigma corpus (4,767 rules). Indexed, cached, rebuilt on demand. |
| `hayabusa/rules/hayabusa/` | Hayabusa's own built-in rules (196, from 193 files). **Also indexed** — it scans with these too. |
| `.cache/`       | Derived rule index. Not committed; rebuild with `make build-index`. |

> **`hayabusa/` is not committed.** It's ~70MB of third-party content (the binary plus
> the bundled rule corpus, each under its own licence — see [Third-party
> components](#third-party-components)) and `make setup` downloads it. A fresh clone
> therefore indexes only the 2 custom rules until you run it.

A rule in `rules/` with the same `id` as a bundled rule **shadows** it — that's how
you override a corpus rule.

Once `make setup` has run, the index holds **4,965 rules** citing **332 ATT&CK
techniques**, all of which resolve against ATT&CK.

## Configuration

The server reads these environment variables:

| Variable                | Default                            | Purpose                                                         |
| ----------------------- | ---------------------------------- | ---------------------------------------------------------------- |
| `HAYABUSA_PATH`         | `hayabusa`                         | Path to (or PATH name of) the hayabusa binary.                  |
| `HAYABUSA_TIMEOUT`      | `1800`                             | Max seconds for any single hayabusa run.                        |
| `HAYABUSA_WORKDIR`      | *(unset)*                          | If set, confines all input/output paths beneath this directory. |
| `HAYABUSA_RULES_DIR`    | `rules/` + the bundled corpus      | Rule dirs to index, `:`-separated. Earlier dirs win on duplicate rule id. |
| `HAYABUSA_MAPPINGS_DIR` | `mappings/`                        | Where `attack.yaml` lives.                                      |
| `HAYABUSA_INDEX_CACHE`  | `.cache/rule_index.json`           | Parsed rule index.                                              |
| `HAYABUSA_TACTICS_FILE` | `hayabusa/config/mitre_tactics.txt`| Tactic list used to classify `attack.*` tags.                   |
| `HAYABUSA_MONGO_URI`    | `mongodb://localhost:27017/`       | MongoDB connection string for the optional backing store.       |
| `HAYABUSA_MONGO_DB`     | `hayabusa`                         | Database name inside that server.                               |
| `HAYABUSA_MONGO_ENABLED`| `false`                            | Opt-in flag. The only thing it switches on is scan-run persistence; nothing else in the server path touches Mongo. |
| `HAYABUSA_MONGO_TIMEOUT_MS` | `3000`                         | Server-selection ceiling, kept short so a stopped container falls back fast. |

The knowledge base never spawns the binary — only the scanning tools need it. It does
read two things `make setup` downloads, though: the rule corpus it indexes, and
`hayabusa/config/mitre_tactics.txt` (the authority for classifying `attack.*` tags).
Without them the KB still runs, but it sees only your `rules/` and cannot label tactics.

## Run

Normally your MCP client launches the server; run it by hand only to debug:

```bash
uv run mcp-hayabusa
```

It's a stdio server, so it will sit silently waiting for JSON-RPC on stdin. That is
correct behaviour, not a hang.

### Register with Claude Code

**Nothing to do — `.mcp.json` is committed and portable.** Open the repo in Claude
Code and approve the `hayabusa` server when prompted (project-scoped servers always
prompt on first use; that's expected, not a fault). Verify with:

```bash
claude mcp list        # "Pending approval" on first use is expected
```

That file lives at the repo root — **not** `.claude/settings.json`, which Claude Code
does not read MCP servers from; it only *enables* them via `enabledMcpjsonServers`.

Two details make it work from any machine without editing:

- **`uv run`, not `python`** — `mcp`/`PyYAML` live in `.venv`, so a bare interpreter
  fails on `import mcp`.
- **`--directory "${CLAUDE_PROJECT_DIR:-.}"`** — the client picks its own cwd, so the
  repo root has to be passed explicitly. Claude Code sets `CLAUDE_PROJECT_DIR` in the
  spawned server's environment, and `.mcp.json` expands `${VAR:-default}` in `args`.
  Because that variable is set in the *server's* environment rather than Claude Code's
  own, the `:-.` default is required — and it is also what actually resolves, since
  Claude Code launches the server with its cwd already at the project root.

If another client launches the server from a different cwd, export the override:

```bash
export CLAUDE_PROJECT_DIR=/path/to/mcp-hayabusa
```

<details>
<summary>Regenerating <code>.mcp.json</code> from scratch</summary>

`claude mcp add` hardcodes an absolute, machine-specific path. If you regenerate the
file, replace that path with `${CLAUDE_PROJECT_DIR:-.}` afterwards:

```bash
claude mcp add hayabusa -s project -e HAYABUSA_PATH=./hayabusa/hayabusa -- \
  uv run --directory "$(pwd)" mcp-hayabusa
```
</details>

### Register with another MCP client

Other clients don't set `CLAUDE_PROJECT_DIR`, so give the repo root explicitly:

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "uv",
      "args": ["run", "--directory", "/abs/path/to/mcp-hayabusa", "mcp-hayabusa"],
      "env": {
        "HAYABUSA_PATH": "./hayabusa/hayabusa",
        "HAYABUSA_WORKDIR": "/cases"
      }
    }
  }
}
```

`HAYABUSA_PATH` can stay relative: `resolve_binary()` retries a relative path against
the repo root, so it resolves regardless of the client's cwd. Setting
`HAYABUSA_WORKDIR` confines every path argument beneath that directory — worth doing
when pointing this at real case data.

<details>
<summary>Using the bare <code>mcp-hayabusa</code> command instead</summary>

The console script only works if the venv is active or the package is installed into
the environment on `PATH` (`uv sync --extra dev` puts it in `.venv/bin/`). `uv run`
avoids that entirely, which is why it's the default above.
</details>

## Tools

> **📖 [`docs/TOOLS.md`](docs/TOOLS.md) is the full reference** — every tool with its
> parameters, an example call, and its real captured output.

### Scanning tools

Need the Hayabusa binary.

| Tool             | Hayabusa subcommand | Purpose                                       |
| ---------------- | ------------------- | --------------------------------------------- |
| `scan_evtx`      | `json-timeline`     | Primary triage tool — scans with Sigma rules and returns structured detections inline. |
| `scan_evtx_attack` | `json-timeline`   | Scan **and** report which ATT&CK techniques were observed. |
| `csv_timeline`   | `csv-timeline`      | Build a CSV detection timeline.               |
| `json_timeline`  | `json-timeline`     | Build a JSON/JSONL detection timeline.        |
| `logon_summary`  | `logon-summary`     | Summarize logon successes/failures.           |
| `metrics`        | `eid-metrics`       | Event-ID frequency metrics. Run this first on unfamiliar evidence. |
| `search`         | `search`            | Keyword/regex search of raw records.          |
| `version`        | `help`              | Report installed version (v3.10+ has no `--version` flag; parsed from the banner). |
| `list_profiles`  | `list-profiles`     | List output profiles.                         |
| `update_rules`   | `update-rules`      | Pull latest Sigma rules. **Run `make build-index` afterwards** so the KB sees them. |

### Knowledge base tools

No Hayabusa binary required.

| Tool                 | Purpose                                                             |
| -------------------- | ------------------------------------------------------------------- |
| `search_rules`       | Find rules by text, technique, tactic, level, product, or status.   |
| `get_rule`           | One rule's metadata and raw YAML, by id, filename stem, or title.   |
| `attack_coverage`    | Rules per ATT&CK technique and tactic; filter by tactic/min level.   |
| `technique_coverage` | Assess one technique: `covered`, `partial`, or `gap`, with reasons.  |
| `coverage_gaps`      | Techniques with no rule at all.                                     |
| `framework_coverage` | Coverage of a whole framework — ATT&CK, **ATLAS**, or the **OWASP** top-tens — including entries nothing detects. Needs the optional MongoDB store. |
| `rebuild_rule_index` | Re-parse every rule and refresh the cache (slow; after `update_rules`). |

### Three worked examples

**Triage an unknown EVTX.** `metrics` first — it tells you which channels exist, and
therefore which rules can fire at all:

```json
// metrics
{"input_path": "./samples/metasploit-psexec-native-target-security.evtx"}
```
```
│ 3     ┆ 75.0% ┆ Sec     ┆ 4688 ┆ Process created   │
│ 1     ┆ 25.0% ┆ Sec     ┆ 1102 ┆ Audit log cleared │
```

**Scan and map to ATT&CK.** The number to read is `unmapped_detections`:

```json
// scan_evtx_attack
{"input_path": "./samples/", "min_level": "informational"}
```
```json
{"total": 5, "counts": {"info": 4, "high": 1},
 "techniques_observed": [{"id": "T1059.001", "name": "...PowerShell", "detections": 1}],
 "unmapped_detections": 0}
```

**Ask what you can detect.** Every rule-returning tool includes a `breakdown` computed
over *all* matches, never just the returned page:

```json
// search_rules
{"technique": "T1490", "limit": 3}
```
```json
{"matched": 38, "returned": 3, "truncated": true,
 "breakdown": {"total": 38, "distinct_detections": 23,
   "by_severity": {"critical": 6, "high": 21, "medium": 10, "low": 1},
   "by_platform": {"sigma/sysmon": 20, "sigma/builtin": 18}}}
```

Read `distinct_detections`, not `total` — the corpus mirrors most rules across parallel
`sysmon/` and `builtin/` trees, so totals double-count. And `by_platform` says how much
of the count is real: a `*/sysmon` rule is inert on evidence collected without Sysmon.

## Resources

| URI                                        | Returns                                                     |
| ------------------------------------------ | ----------------------------------------------------------- |
| `detection://rules`                        | Catalog: counts by source/severity/status/log source + ATT&CK headline; custom rules in full, bundled ones summarized. |
| `detection://rules/{rule_ref}`             | Raw rule YAML (`rule_ref` = id, filename stem, or title).    |
| `detection://rules/by-technique/{id}`      | Rules detecting a technique (a parent id includes its subs). |
| `detection://attack/techniques/{id}`       | Name, description, detecting rules, coverage assessment.     |
| `detection://attack/coverage`              | Coverage across all techniques and tactics.                  |
| `detection://attack/tactics`               | Tactics with rule counts.                                    |

### Coverage assessment

`detection://attack/techniques/T1003` returns a verdict, not just a rule list:

| Verdict   | Meaning                                                                            |
| --------- | ---------------------------------------------------------------------------------- |
| `covered` | A non-experimental rule detects it directly, and all its sub-techniques are covered. |
| `partial` | Only some sub-techniques are covered, or it's covered only *via* sub-techniques, or every citing rule is still experimental. |
| `gap`     | No rule cites it at all.                                                            |

Each verdict ships with a `rationale` explaining it. Treat gaps as review items, not a
to-do list — plenty of ATT&CK techniques (`T1003.007` Proc Filesystem, for one) are
Linux-only and simply unobservable in Windows event logs.

Rules citing an ATT&CK-revoked technique (`T1086` → `T1059.001`) are flagged with a
`warning` so they can be retagged.

### Tool parameters and output

Full parameter tables and real captured output for all sixteen tools are in
**[`docs/TOOLS.md`](docs/TOOLS.md)** — including the two that repay a close read:
[`scan_evtx`](docs/TOOLS.md#scan_evtx) (the `rule_filter` / `max_results` interaction,
and why `counts` says `med` when you asked for `medium`) and
[`scan_evtx_attack`](docs/TOOLS.md#scan_evtx_attack) (why it forces `profile=standard`,
and what `unmapped_detections` is telling you).

## MongoDB backing store (optional)

The rule index also has a MongoDB representation. It is **additive**:
`.cache/rule_index.json` stays the authority the MCP server reads, so with the container
stopped every tool, resource and test still works. Nothing here is on the server's hot
path unless `HAYABUSA_MONGO_ENABLED` is set.

```bash
make mongo-up       # start MongoDB 8.0 in Docker (named volume, so data survives)
make load-mongo     # ingest the rule index + ATT&CK mappings (~4,965 rules)
make load-atlas     # MITRE ATLAS (needs 'make atlas-bundle' first)
make load-owasp     # the two OWASP top-tens
make diff-versions  # compare two ATT&CK releases, report affected Sigma rules
make coverage-all   # coverage across all four frameworks in one aggregation
make mongo-stats    # counts per collection, index totals, per-framework inventory
make mongo-shell    # interactive mongosh against the hayabusa database
make mongo-down     # stop the container (the volume, and so the data, survives)
```

No authentication, which is correct for local development and wrong for anything shared.

### Why it exists

The JSON cache is a flat snapshot with no version axis and no framework axis. Two things
follow that it cannot express:

- **Four frameworks in one collection.** ATT&CK Enterprise, MITRE ATLAS and both OWASP
  top-tens share `attack_techniques`, keyed by `framework`, so one coverage query spans
  conventional, AI and agentic risk taxonomies.
- **Several releases of one framework, side by side.** When ATT&CK revokes a technique,
  every Sigma rule still tagged with the old id quietly stops resolving — nothing errors,
  coverage just drops. Keeping both releases is what lets you ask what a change cost.

### Collections

MongoDB creates a collection implicitly on first write; there is no schema step. The
database enforces nothing about these shapes — the application does. Field names mirror
the `Rule` dataclass in `kb.py` rather than inventing parallel ones.

| Collection | One document per | Notable fields |
| --- | --- | --- |
| `sigma_rules` | Sigma rule | `rule_id`, `techniques[]`, `tactics[]`, `level`, `source`, `platform`, `log_source` |
| `attack_techniques` | technique, per framework, per version | `technique_id`, `tactics[]`, `deprecated`, `revoked_by`, `framework`, `framework_version` |
| `framework_versions` | ingested release | `framework`, `version`, `released`, `source_url`, `bundle_sha256`, `ingested_at` |
| `scan_results` | hayabusa run | `run_id`, `evtx_source`, `detections[]`, `observed_techniques[]`, `framework_version`, `created_at` |

`platform` and `log_source` are `@property` on `Rule`, derived rather than stored, so the
loader calls them explicitly — they are stored in Mongo because they are what an operator
filters on ("which of these can fire without Sysmon?").

### Indexes

Eight declared, created idempotently on every connect by `mongo.ensure_indexes()`. Two
carry the weight:

- **`sigma_rules.techniques` is multikey.** The field holds an array and MongoDB indexes
  every element separately, so "every rule covering T1003.003" is a key lookup rather than
  a collection scan — `IXSCAN`, 34 keys examined for 34 documents returned.
- **`attack_techniques (framework, framework_version, technique_id)` is unique over all
  three fields.** That is what lets ATT&CK 18.1, ATT&CK 19.2 and ATLAS coexist. Unique on
  `technique_id` alone would let a newer release silently overwrite an older one, which is
  the exact failure this store exists to prevent. Historical retention is therefore
  structural, not a convention someone has to remember.

### Coverage, twice

`kb.coverage()` walks the in-memory index in Python. `mongo.coverage()` pushes the same
rollup into MongoDB as a `$facet` of three parallel pipelines. Both are kept, and a test
asserts they return **equal** results across every filter combination — which is stronger
evidence of data integrity than either implementation alone. `mongo.framework_coverage()`
adds what a rule-side rollup structurally cannot: a `$lookup` walk of the *framework*, so
it reports entries nothing detects.

### Scan history

With `HAYABUSA_MONGO_ENABLED=1`, `scan_evtx_attack` records each run in `scan_results`:
the detections, the techniques observed, and the framework version they were scored
against. That last field is what makes a stored run re-interpretable later — a scan judged
under ATT&CK 19.2 can be joined back to 19.2's technique documents even after 20 lands.

Persistence is deliberately subordinate to scanning. `mongo.persist_scan()` is a no-op when
the flag is off, returns `None` when the container is down, and swallows its own write
failures. A DFIR answer never fails because optional bookkeeping did. The stored detection
list is also bounded (`MAX_STORED_DETECTIONS`, 5000) so a large case cannot breach the 16MB
BSON document limit; the response reports `detections_truncated` when that bites.

### Frameworks

| Framework | `framework` value | Entries | Source |
| --- | --- | --- | --- |
| MITRE ATT&CK Enterprise | `enterprise-attack` | 858 (19.2), 835 (18.1) | STIX bundle from `mitre-attack/attack-stix-data` |
| MITRE ATLAS | `atlas` | 197 (2026.08) | ATLAS's own `atlas_to_stix.py --include-attack` export |
| OWASP LLM Top 10 | `owasp-llm-top-10` | 10 (2026) | `data/owasp_frameworks.yaml` |
| OWASP Agentic Top 10 | `owasp-agentic-top-10` | 10 (2026) | `data/owasp_frameworks.yaml` |

No Sigma rule maps to `LLM01`, so OWASP coverage reads as twenty gaps. That is an honest
statement about what Windows EVTX can observe, not a broken query.

### Comparing ATT&CK releases

```bash
uv run python scripts/diff_frameworks.py --list                    # published releases
make diff-versions                                                 # 18.1 -> 19.2, ingesting both
make diff-versions OLD=17.1 NEW=18.1
```

The report is not a changelog — it joins every change against `sigma_rules.techniques` and
names the **affected rule ids**:

```
T1562.001 (Disable or Modify Tools) revoked, superseded by T1685 (Disable or Modify Tools).
    10 rule(s) need remapping.
```

Four change classes are detected: added, removed, deprecated (`x_mitre_deprecated`) and
revoked (`revoked` plus the `revoked-by` relationship, resolved to the successor's public
id). Only *transitions* count — ATT&CK carries old deprecations forward forever, so
standing flags are reported separately as carried-forward rather than re-announced every
release.

## Updating rules & mappings

```bash
make build-index    # re-parse rules after the corpus changes (e.g. after update_rules)
make mappings       # regenerate mappings/attack.yaml from MITRE's ATT&CK STIX bundle
make atlas-bundle   # build the combined ATLAS + ATT&CK STIX bundle (clones atlas-data)
```

`mappings/attack.yaml` and `mappings/atlas.yaml` are generated but **committed**: the
server never fetches at runtime, so answers stay reproducible and work offline. Don't
hand-edit them. The downloaded STIX bundles themselves (~50MB each) are gitignored and
cached under the system temp dir; every network call lives in `scripts/`, never in
`src/`.

Editing `rules/` needs no rebuild — that directory is re-scanned on every load.

## Development

```bash
uv run pytest -m "not integration"   # 136 unit tests — fake binary, no download
uv run pytest -m "not integration and not mongo"   # 109 — no binary, no MongoDB
uv run ruff check .                  # lint
uv run ruff format .                 # format
```

**146 tests total: 136 unit + 10 integration.** The integration tests need the real
binary, sample logs, and a built index; they skip themselves otherwise. 27 of the unit
tests need MongoDB and skip the same way — with the container stopped the suite is
still green (109 passed, 27 skipped, 0 failed), which is how the "Mongo is additive"
constraint is enforced rather than merely intended:

```bash
make setup && ./scripts/fetch_samples.sh
HAYABUSA_PATH=./hayabusa/hayabusa uv run pytest   # 146 tests
```

`conftest.py` finds the binary via `HAYABUSA_PATH` → `./hayabusa/hayabusa` → `PATH`,
so once `make setup` has run, a bare `uv run pytest` (and `make test`) runs the
integration tests too — the env var is only needed when the binary is elsewhere. Use
`-m "not integration"` when you actually want unit-only.

They exist because a fake binary can't falsify the assumptions that matter. The
end-to-end `scan_evtx_attack` test caught two real bugs the unit tests happily
passed through: Hayabusa's own 196 built-in rules weren't being indexed, and Sigma
correlation rules (multi-document YAML) were being skipped, which silently dropped
brute-force (T1110.x) coverage. Both now assert `unmapped_detections == 0`.

## Licence

This repository's code is MIT — see [LICENSE](LICENSE).

### Third-party components

`make setup` **downloads** these; this repository does not redistribute them, and none
of them are covered by the licence above. Each carries its own terms:

| Component | Licence | Source |
| --------- | ------- | ------ |
| Hayabusa (the binary under `hayabusa/`) | AGPL-3.0, © Yamato Security | [Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa) |
| The bundled Sigma rule corpus (`hayabusa/rules/`) | Detection Rule License (DRL), plus per-rule notices | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |
| `mappings/attack.yaml` (generated, committed) | MITRE's Terms of Use; ATT&CK® is a registered trademark of The MITRE Corporation | [attack.mitre.org](https://attack.mitre.org/) |

Invoking Hayabusa as a separate process (which is all this server does) is not a
derivative work, which is why AGPL-3.0 doesn't reach this code.
