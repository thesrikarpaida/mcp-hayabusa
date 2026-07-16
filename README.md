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

## Quickstart

```bash
git clone <this repo> && cd mcp-hayabusa
make setup          # deps + hayabusa binary + rule index (~3-4 min)
```

Then open the repo in Claude Code and approve the `hayabusa` server when prompted —
`.mcp.json` is committed and needs no editing. Confirm it works by asking for
`detection://rules`, or from a shell:

```bash
claude mcp list                      # hayabusa: connected
uv run pytest -m "not integration"   # 83 unit tests, ~5s
```

Full detail in [Register with Claude Code](#register-with-claude-code) below.

## Prerequisites

- **Linux x64**, or **WSL2** on Windows. The installer fetches a Linux x64 Hayabusa
  build only, so `make setup` does **not** work on native Windows or macOS — Windows
  users should run everything inside WSL2. Hayabusa itself ships `win-x64` and `mac-*`
  builds; to use one, download it from
  [Hayabusa's releases](https://github.com/Yamato-Security/hayabusa/releases) and point
  `HAYABUSA_PATH` at it (the knowledge base is pure Python and runs on any OS regardless).
- **Python 3.10+** and [`uv`](https://docs.astral.sh/uv/). `uv` is the only thing you
  strictly need to install by hand — it can bootstrap Python for you (`uv python install`).
  No `uv`? Plain `pip` works too (see [Without `make` / `uv`](#install) below); it reads
  the same `pyproject.toml`.

`make setup` downloads the Hayabusa binary for you (`scripts/install_hayabusa.sh` detects
your glibc version and picks the `gnu` or `musl` build accordingly).

## Install

```bash
make setup          # deps + hayabusa binary + rule index (recommended)
```

`make setup` ends by building the rule index, which takes **2–3 minutes** — it parses
every Sigma rule once so the server can answer instantly afterwards. Without it, the
first knowledge-base call pays that cost instead.

<details>
<summary>Without <code>make</code> / <code>uv</code> (plain pip)</summary>

`pip` reads `pyproject.toml` directly — no `uv`, no `requirements.txt`:

```bash
pip install -e ".[dev]"                                            # deps + the mcp-hayabusa entry point
./scripts/install_hayabusa.sh                                      # fetch the Hayabusa binary (Linux x64)
python -c "from mcp_hayabusa import kb; kb.load_index(rebuild=True)"  # build the rule index
```

Note `pip` won't install a Python interpreter for you the way `uv` does — you need
Python 3.10+ already on `PATH`.
</details>

## Layout

| Path            | What                                                             |
| --------------- | ---------------------------------------------------------------- |
| `rules/`        | Your custom Sigma rules. Re-scanned on every load — edits are live. |
| `mappings/`     | `attack.yaml`: ATT&CK metadata, generated from MITRE's STIX bundle and committed. |
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

## Scanning tools

| Tool             | Hayabusa subcommand | Purpose                                       |
| ---------------- | ------------------- | --------------------------------------------- |
| `version`        | `help`               | Report installed version (v3.10+ has no `--version` flag; parsed from the banner). |
| `list_profiles`  | `list-profiles`     | List output profiles.                         |
| `update_rules`   | `update-rules`      | Pull latest Sigma rules. **Run `make build-index` afterwards** so the KB sees them. |
| `scan_evtx`      | `json-timeline`     | Primary triage tool — scans with Sigma rules and returns structured detections inline. See below. |
| `scan_evtx_attack` | `json-timeline`   | Scan **and** report which ATT&CK techniques were observed. See below. |
| `csv_timeline`   | `csv-timeline`      | Build a CSV detection timeline.               |
| `json_timeline`  | `json-timeline`     | Build a JSON/JSONL detection timeline.        |
| `logon_summary`  | `logon-summary`     | Summarize logon successes/failures.           |
| `metrics`        | `eid-metrics`       | Event-ID frequency metrics.                   |
| `search`         | `search`            | Keyword/regex search of raw records.          |

## Knowledge base tools

No Hayabusa binary required.

| Tool                 | Purpose                                                             |
| -------------------- | ------------------------------------------------------------------- |
| `search_rules`       | Find rules by text, technique, tactic, level, product, or status.   |
| `get_rule`           | One rule's metadata and raw YAML, by id, filename stem, or title.   |
| `attack_coverage`    | Rules per ATT&CK technique and tactic; filter by tactic/min level.   |
| `technique_coverage` | Assess one technique: `covered`, `partial`, or `gap`, with reasons.  |
| `coverage_gaps`      | Techniques with no rule at all.                                     |
| `rebuild_rule_index` | Re-parse every rule and refresh the cache (slow; after `update_rules`). |

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

### `scan_evtx` parameters

| Parameter       | Default     | Purpose                                                                 |
| --------------- | ----------- | ------------------------------------------------------------------------ |
| `input_path`    | *(required)*| A single `.evtx` file or a directory of them.                          |
| `min_level`     | `"low"`     | Lowest alert level to include: `informational`\|`low`\|`medium`\|`high`\|`critical`. |
| `profile`       | `"standard"`| Output profile: `minimal`\|`standard`\|`verbose`\|`all-field-info`.     |
| `rule_filter`   | *(none)*    | Only keep detections whose rule title contains this substring (case-insensitive), e.g. `"lateral"` or `"mimikatz"`. Hayabusa has no native rule-title filter, so this is applied after scanning. |
| `output_format` | `"summary"` | `"summary"` returns a handful of key fields per detection; `"full"` returns the entire parsed record. |
| `max_results`   | *(none)*    | Caps the number of detections returned. `total`/`counts` in the response still reflect all matches (after `rule_filter`, before truncation); `returned` gives the actual count in `detections`. |

### `scan_evtx_attack`

Scans, then joins every detection back to the Sigma rule that fired it (by rule id)
and rolls the results up by ATT&CK technique and tactic:

```json
{
  "total": 41,
  "counts": {"high": 12, "low": 29},
  "techniques_observed": [
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "detections": 7}
  ],
  "tactics_observed": {"credential-access": 7, "execution": 3},
  "unmapped_detections": 0,
  "detections": [{"RuleTitle": "...", "techniques": ["T1003.001"], "...": "..."}]
}
```

`unmapped_detections` counts hits whose rule id isn't in the index — usually a stale
cache, so run `make build-index`. `max_results` (default 100) caps `detections`; the
rollup always covers every hit.

## Updating rules & mappings

```bash
make build-index    # re-parse rules after the corpus changes (e.g. after update_rules)
make mappings       # regenerate mappings/attack.yaml from MITRE's ATT&CK STIX bundle
```

`mappings/attack.yaml` is generated but **committed**: the server never fetches ATT&CK at
runtime, so answers stay reproducible and work offline. Don't hand-edit it.

Editing `rules/` needs no rebuild — that directory is re-scanned on every load.

## Development

```bash
uv run pytest -m "not integration"   # 83 unit tests, ~5s — fake binary, no download
uv run ruff check .                  # lint
uv run ruff format .                 # format
```

**93 tests total: 83 unit + 10 integration.** The integration tests need the real
binary, sample logs, and a built index; they skip themselves otherwise:

```bash
make setup && ./scripts/fetch_samples.sh
HAYABUSA_PATH=./hayabusa/hayabusa uv run pytest   # 93 tests, ~3m20s
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
