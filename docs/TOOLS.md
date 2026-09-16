# Tool reference

Every MCP tool this server exposes, with a real call and its real output. All
output below was captured from an actual run against the files in `samples/`
(`./scripts/fetch_samples.sh`) with Hayabusa v3.10.0 — nothing here is
illustrative.

Calls are written as JSON arguments, which is what an MCP client sends. In
Claude Code you normally just ask in English ("scan that EVTX"); the shapes here
are what the model fills in, and what you'd write when driving the server from
your own client.

- [At a glance](#at-a-glance)
- [Scanning tools](#scanning-tools) — need the Hayabusa binary
- [Reporting tools](#reporting-tools) — need the binary
- [Knowledge base tools](#knowledge-base-tools) — no binary
- [Housekeeping tools](#housekeeping-tools)
- [Resources](#resources)
- [Conventions](#conventions)

## At a glance

| Tool | Needs binary | Needs index | Returns |
| --- | :--: | :--: | --- |
| [`scan_evtx`](#scan_evtx) | ✅ | — | detections inline |
| [`scan_evtx_attack`](#scan_evtx_attack) | ✅ | ✅ | detections + ATT&CK rollup |
| [`csv_timeline`](#csv_timeline) | ✅ | — | path to a CSV |
| [`json_timeline`](#json_timeline) | ✅ | — | path to a JSON/JSONL file |
| [`logon_summary`](#logon_summary) | ✅ | — | text table |
| [`metrics`](#metrics) | ✅ | — | text table |
| [`search`](#search) | ✅ | — | text table |
| [`search_rules`](#search_rules) | — | ✅ | rules + breakdown |
| [`get_rule`](#get_rule) | — | ✅ | one rule + raw YAML |
| [`attack_coverage`](#attack_coverage) | — | ✅ | rules per technique/tactic |
| [`technique_coverage`](#technique_coverage) | — | ✅ | verdict + rationale |
| [`coverage_gaps`](#coverage_gaps) | — | ✅ | techniques with no rule |
| [`framework_coverage`](#framework_coverage) | — | — | coverage of ATT&CK, ATLAS or OWASP (needs MongoDB) |
| [`version`](#version) | ✅ | — | version string |
| [`list_profiles`](#list_profiles) | ✅ | — | profile list |
| [`update_rules`](#update_rules) | ✅ | — | update log |
| [`rebuild_rule_index`](#rebuild_rule_index) | — | — | index stats |

**"Needs binary"** is the Hayabusa CLI — the Rust executable at `./hayabusa/hayabusa`,
resolved via `HAYABUSA_PATH`. Without it these tools cannot run at all.

**"Needs index"** is `.cache/rule_index.json` — every Sigma rule in your rule
directories, pre-parsed into `{id, title, level, status, techniques, tactics, source,
path}`. It is a **cache, not a database**: it exists because parsing the ~4.8k-rule
corpus takes roughly 150 seconds, so the result is written once and reused. Build it
with `make setup` or `make build-index`.

Without the index, a KB tool silently pays that 150s on its first call, and
`scan_evtx_attack` reports rising `unmapped_detections` because it cannot join a
detection back to a rule it has never parsed. Your own `rules/` directory is exempt —
under 50 files it is re-walked every load, so edits there are live immediately.

`framework_coverage` needs neither: it reads MongoDB instead.

---

## Scanning tools

### `scan_evtx`

The primary triage entry point. Runs `json-timeline` into a temp directory,
parses each JSONL detection, and returns everything inline — no output file to
manage.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | A single `.evtx` file or a directory of them. |
| `min_level` | string | `"low"` | `informational` \| `low` \| `medium` \| `high` \| `critical`. Passed to Hayabusa as `--min-level`. |
| `profile` | string | `"standard"` | `minimal` \| `standard` \| `verbose` \| `all-field-info`. |
| `rule_filter` | string | `""` | Keep only detections whose rule title contains this substring (case-insensitive). Applied *after* scanning — Hayabusa has no native rule-title filter. |
| `output_format` | string | `"summary"` | `"summary"` = seven key fields per detection; `"full"` = the whole parsed record. |
| `max_results` | int \| null | `null` | Cap on detections returned. `total`/`counts` still describe every match. |

**Call**

```json
{"input_path": "./samples/disablestop-eventlog.evtx", "min_level": "low"}
```

**Output**

```json
{
  "total": 2,
  "counts": {"high": 1, "med": 1},
  "returned": 2,
  "detections": [
    {
      "Timestamp": "2019-04-27 17:04:25.733 -04:00",
      "RuleTitle": "Important Log File Cleared",
      "Level": "high",
      "Computer": "DESKTOP-JR78RLP",
      "Channel": "Sys",
      "EventID": 104,
      "Details": {"Log": "System", "User": "jwrig"}
    },
    {
      "Timestamp": "2019-04-27 17:04:32.373 -04:00",
      "RuleTitle": "Event Log Service Startup Type Changed To Disabled",
      "Level": "med",
      "Computer": "DESKTOP-JR78RLP",
      "Channel": "Sys",
      "EventID": 7040,
      "Details": {"OldSetting": "auto start", "NewSetting": "disabled"}
    }
  ]
}
```

**Notes**

- **`counts` uses Hayabusa's abbreviations, not the `min_level` vocabulary.**
  `medium` comes back as `med` and `informational` as `info`. You pass
  `min_level="medium"` but read `counts["med"]`.
- `Channel` is abbreviated too (`Sys`, `Sec`, `PwSh`).
- `total` counts every match after `rule_filter` but **before** `max_results`
  truncation; `returned` is the length of `detections`.
- Raise `min_level` before reaching for `max_results` — a level floor is applied
  by Hayabusa during the scan, truncation only after.

---

### `scan_evtx_attack`

Scans, then joins every detection back to the Sigma rule that fired it (by
`RuleID`) and rolls the result up by ATT&CK technique and tactic. This is where
the scanner and the knowledge base meet.

It forces `profile="standard"` — the leanest profile that carries `RuleID`.
`minimal` does not have it, so the join would be impossible.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | A single `.evtx` file or a directory. |
| `min_level` | string | `"low"` | As `scan_evtx`. |
| `max_results` | int \| null | `100` | Cap on annotated detections returned. The rollup always covers every detection. |

**Call**

```json
{
  "input_path": "./samples/Powershell-Invoke-Obfuscation-string-menu.evtx",
  "min_level": "informational",
  "max_results": 40
}
```

**Output** (detection bodies elided)

```json
{
  "total": 5,
  "counts": {"info": 4, "high": 1},
  "techniques_observed": [
    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "detections": 1}
  ],
  "tactics_observed": {"execution": 1},
  "unmapped_detections": 0,
  "returned": 5,
  "detections": [
    {
      "Timestamp": "2017-08-30 15:25:48.647 -04:00",
      "RuleTitle": "Malicious Nishang PowerShell Commandlets",
      "Level": "high",
      "Computer": "SEC511",
      "Channel": "PwSh",
      "EventID": 4104,
      "Details": {"ScriptBlock": "..."},
      "RuleID": "79769f3b-efb3-9463-e114-7446d4361146",
      "techniques": ["T1059.001"],
      "tactics": ["execution"]
    }
  ]
}
```

**Notes**

- **`unmapped_detections` is the number to watch.** It counts hits whose rule id
  isn't in the index. Anything above zero usually means a stale cache — run
  `make build-index`. Detections are never dropped, only counted here.
- **`atlas_observed` is inherited coverage, and the payload says so.** MITRE
  adopted 44 ATT&CK techniques into the ATLAS matrix keeping their ids, so an
  observed ATT&CK technique also evidences the ATLAS entry citing it. The scan
  above observed `T1059.001`, which rolls to `T1059`, which ATLAS adopted as
  `AML.T0050`:

  ```json
  "atlas_observed": [
    {"id": "AML.T0050", "name": "Command and Scripting Interpreter",
     "tactics": ["execution"], "via": ["T1059.001"], "detections": 1}
  ],
  "atlas_basis": "ATLAS entries whose adopted ATT&CK technique was observed; inherited coverage of conventional tradecraft against an AI target, not detection of an AI-specific attack"
  ```

  Read `atlas_basis` before quoting the number. This says conventional tradecraft
  was seen on a host that happens to be an AI target — **not** that an AI-specific
  attack was detected. Prompt injection, model poisoning and proxy-model
  extraction leave no Windows event and will never appear here.
- The ATLAS rollup needs `mappings/atlas.yaml` and no MongoDB. Missing file means
  `atlas_observed` is simply empty.
- **Untagged rules produce `"techniques": []`, and that is not a bug.** Four of
  the five detections above come from Hayabusa's `PwSh Scriptblock` rule, which
  carries no `tags:` at all. They are real events with no ATT&CK mapping to make.
- **A technique the payload obviously performs may not appear.** The sample above
  is an obfuscated `Invoke-Mimikatz -DumpCreds`, i.e. T1003.001 — but no rule
  matched the obfuscated text, so the scan honestly reports only what fired.
  `techniques_observed` is evidence, not interpretation.
- With `HAYABUSA_MONGO_ENABLED=1` this is the one tool that writes to MongoDB.
  It hands `persist_scan` **every** detection while returning only `max_results`
  — capping a payload must not cap the evidence.

---

### `csv_timeline`

Full forensic timeline to a CSV file. Use this instead of `scan_evtx` when the
result is too large to pass through a conversation.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | `.evtx` file or directory. |
| `output_path` | string | *(required)* | CSV to write. Overwritten if it exists (`--clobber`). |
| `profile` | string | `"standard"` | Output profile. |
| `min_level` | string | `"low"` | Level floor. |
| `utc` | bool | `false` | Emit UTC instead of local time. |

**Call**

```json
{"input_path": "./samples/", "output_path": "/cases/acme/timeline.csv", "utc": true}
```

**Output**

```json
{
  "output": "/cases/acme/timeline.csv",
  "log": "Start time: 2026/09/15 15:09\nTotal event log files: 1\n..."
}
```

**Notes**

- `output` is the resolved absolute path, after `safe_path()`. With
  `HAYABUSA_WORKDIR` set, a path outside that root is rejected here.
- `log` is Hayabusa's own progress output, ANSI-stripped. It carries the rule
  inventory — see [`json_timeline`](#json_timeline) for what's in it.
- Always pass `utc: true` when the timeline will be correlated with other
  evidence sources.

---

### `json_timeline`

Same as `csv_timeline`, but JSON or JSONL.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | `.evtx` file or directory. |
| `output_path` | string | *(required)* | File to write. Overwritten if it exists. |
| `profile` | string | `"standard"` | Output profile. |
| `min_level` | string | `"low"` | Level floor. |
| `jsonl` | bool | `true` | Newline-delimited JSON. Recommended — it streams. |

**Call**

```json
{"input_path": "./samples/disablestop-eventlog.evtx", "output_path": "./out/tl.jsonl"}
```

**Output**

```json
{
  "output": "/abs/path/out/tl.jsonl",
  "log": "Start time: 2026/09/15 15:09\nTotal event log files: 1\nTotal file size: 68.0 KiB\n\nLoading detection rules. Please wait.\n\nExcluded rules: 133\nNoisy rules: 12 (Disabled)\n\nDeprecated rules: 228 (5.03%) (Disabled)\nExperimental rules: 348 (7.67%)\nStable rules: 165 (3.64%)\nTest rules: 4,023 (88.69%)\nUnsupported rules: 42 (0.93%) (Disabled)\n\nCorrelation rules: 3 (0.07%)\n\nHayabusa rules: 91\nSigma rules: 4,445\nTotal detection rules: 4,536\n\nCreating the channel filter. Please wait.\nEvtx files loaded after channel filter: 1\nDetection rules enabled after channel filter: 85\n\nOutput profile: standard\n..."
}
```

**Notes**

- **Read the `log`, it answers "why didn't rule X fire?".** In the run above,
  Hayabusa loaded 4,536 rules of the 4,965 indexed and then narrowed to **85**
  after the channel filter — a rule for a channel not present in the EVTX is
  never evaluated.
- **Deprecated and unsupported rules are disabled by default** (228 + 42 here).
  So a deprecated rule counted in a `search_rules` breakdown will not fire in a
  scan. Do not treat the two numbers as the same population.
- Noisy rules (12) are disabled too.

---

## Reporting tools

These three wrap Hayabusa subcommands that have **no rule wizard and no results
summary**. They return Hayabusa's own text tables, ANSI-stripped.

### `logon_summary`

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | `.evtx` file or directory. |

**Call**

```json
{"input_path": "./samples/metasploit-psexec-native-target-security.evtx"}
```

**Output**

```
Generating Logon Summary

Start time: 2026/09/15 15:04
Total event log files: 1
Total file size: 68.0 KiB

Evtx File Path:  /abs/path/samples/metasploit-psexec-native-target-security.evtx

Total Event Records:  4

First Timestamp:  2016-09-20 23:40:37.088 -04:00
Last Timestamp:  2016-09-20 23:41:13.078 -04:00

Logon Summary:
-----------------------------------------
|     No logon events were detected.    |
-----------------------------------------

Elapsed time: 00:00:00.023
```

**Notes**

- Returns a **string**, not structured data. Parse it or read it; there is no
  JSON form.
- "No logon events were detected" on a file named `...-security.evtx` is
  correct here: the sample holds 4688 and 1102 records, no 4624/4625.

---

### `metrics`

Event-ID frequency across the logs. The fastest way to understand an unfamiliar
EVTX before scanning it.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | `.evtx` file or directory. |

**Call**

```json
{"input_path": "./samples/metasploit-psexec-native-target-security.evtx"}
```

**Output**

```
Generating Event ID Metrics

Start time: 2026/09/15 15:05
Total event log files: 1
Total file size: 68.0 KiB

Evtx File Path:  /abs/path/samples/metasploit-psexec-native-target-security.evtx

Total Event Records:  4

First Timestamp:  2016-09-20 23:40:37.088 -04:00
Last Timestamp:  2016-09-20 23:41:13.078 -04:00

╭───────┬───────┬─────────┬──────┬───────────────────╮
│ Total ┆   %   ┆ Channel ┆  ID  ┆       Event       │
╞═══════╪═══════╪═════════╪══════╪═══════════════════╡
│ 3     ┆ 75.0% ┆ Sec     ┆ 4688 ┆ Process created   │
├╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ 1     ┆ 25.0% ┆ Sec     ┆ 1102 ┆ Audit log cleared │
╰───────┴───────┴─────────┴──────┴───────────────────╯
Elapsed time: 00:00:00.025
```

**Notes**

- Run this **first** on unfamiliar evidence. It tells you which channels exist,
  which is what determines how many rules can fire at all.
- No 4104 in the list means PowerShell script-block logging was off, and every
  `ps_script` rule is inert on that evidence regardless of coverage figures.

---

### `search`

Full-text search over raw records — independent of the rule set. Use it when you
have an IOC and want to know whether it appears, whether or not a rule covers it.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `input_path` | string | *(required)* | `.evtx` file or directory. |
| `keyword` | string | `""` | Literal substring. |
| `regex` | string | `""` | Regular expression. |

Provide **exactly one** of `keyword` or `regex`. Passing both or neither raises
`HayabusaError`.

**Call**

```json
{"input_path": "./samples/disablestop-eventlog.evtx", "keyword": "jwrig"}
```

**Output**

```json
{
  "matches": "Searching...\n\nStart time: 2026/09/15 15:10\nTotal event log files: 1\nTotal file size: 68.0 KiB\n\nTimestamp · EventTitle · Hostname · Channel · Event ID · Record ID · AllFieldInfo · EvtxFile\n2019-04-27 17:04:25.733 -04:00 · Event log cleared · DESKTOP-JR78RLP · Sys · 104 · 9252 · BackupPath:  ¦ Channel: System ¦ SubjectDomainName: DESKTOP-JR78RLP ¦ SubjectUserName: jwrig · /abs/path/samples/disablestop-eventlog.evtx\n\nTotal findings: 1\nElapsed time: 00:00:00.027"
}
```

**Notes**

- Columns are `·`-separated, fields within `AllFieldInfo` are `¦`-separated.
- A miss prints `No matches found.` and `Total findings: 0` — not an error.
- This searches **records**, not rules. To search rules, use
  [`search_rules`](#search_rules).

---

## Knowledge base tools

No Hayabusa binary required. These read the rule index and `mappings/attack.yaml`.

### `search_rules`

Find rules by text, technique, tactic, level, product, or status. All filters
AND together; omit everything to list the corpus.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `query` | string | `""` | Case-insensitive **substring** of title or description. |
| `technique` | string | `""` | ATT&CK id, e.g. `"T1003.003"`. A parent id also matches its sub-techniques. |
| `tactic` | string | `""` | Tactic slug, e.g. `"credential-access"`. |
| `level` | string | `""` | `informational` \| `low` \| `medium` \| `high` \| `critical`. |
| `product` | string | `""` | Logsource product, e.g. `"windows"`. |
| `status` | string | `""` | `stable` \| `test` \| `experimental` \| `deprecated` \| `unsupported`. |
| `limit` | int | `50` | Max rules returned. **`breakdown` still describes every match.** |

**Call**

```json
{"technique": "T1490", "limit": 3}
```

**Output** (rule list truncated here for length)

```json
{
  "matched": 38,
  "returned": 3,
  "truncated": true,
  "breakdown": {
    "total": 38,
    "distinct_detections": 23,
    "by_severity": {"critical": 6, "high": 21, "medium": 10, "low": 1},
    "by_platform": {"sigma/sysmon": 20, "sigma/builtin": 18},
    "by_log_source": {"process_creation": 26, "registry_set": 4, "image_load": 4, "ps_script": 2, "ps_classic_start": 1, "file_delete": 1},
    "by_status": {"test": 26, "stable": 7, "experimental": 4, "deprecated": 1},
    "by_source": {"sigma": 38}
  },
  "rules": [
    {
      "id": "2660fe06-fcf6-19f2-3233-b50236d5ff13",
      "title": "Boot Configuration Tampering Via Bcdedit.EXE",
      "level": "high",
      "status": "stable",
      "techniques": ["T1490"],
      "tactics": ["impact"],
      "source": "sigma",
      "platform": "sigma/builtin",
      "log_source": "process_creation"
    }
  ]
}
```

**Notes**

- **`breakdown` always describes every match, never the returned page.** That is
  deliberate: a breakdown of a truncated list would silently describe 3 rules
  next to a claim made over 38.
- **`total` vs `distinct_detections`.** The corpus mirrors most rules across
  parallel `sysmon/` and `builtin/` trees, so totals double-count.
  `distinct_detections` (unique titles) is the honest size.
- **`by_platform` is the number that says how much of a count is real.** A
  `*/sysmon` rule is inert on evidence collected without Sysmon deployed.
- **`query` is a plain substring, not a word match.** `query: "tor"` returns 423
  rules because it matches his**tor**y, direc**tor**y, s**tor**e, moni**tor**.
  Even `"tor.exe"` matches "Agen**tExecutor.exe**". Prefer `technique=` whenever
  you have an id; use two-word phrases otherwise.

---

### `get_rule`

One rule's metadata plus its raw YAML.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `rule_ref` | string | *(required)* | Rule id (UUID), filename stem, or **exact** title. |

**Call**

```json
{"rule_ref": "Event Log Service Startup Type Changed To Disabled"}
```

**Output** (YAML abridged)

```json
{
  "id": "ab3507cf-5231-4af6-ab1d-5d3b3ad467b5",
  "title": "Event Log Service Startup Type Changed To Disabled",
  "level": "medium",
  "status": "test",
  "techniques": ["T1562.002"],
  "tactics": ["defense-evasion"],
  "source": "hayabusa",
  "platform": "hayabusa/builtin",
  "log_source": "system",
  "author": "Eric Conrad, Zach Mathis",
  "logsource": {"product": "windows", "service": "system", "category": ""},
  "technique_names": {"T1562.002": "Impair Defenses: Disable Windows Event Logging"},
  "path": "/abs/path/hayabusa/rules/hayabusa/builtin/System/Sys_7040_Med_EventLogServiceStartupDisabled.yml",
  "yaml": "title: Event Log Service Startup Type Changed To Disabled\nid: ab3507cf-...\ndetection:\n    selection:\n        Channel: System\n        EventID: 7040\n        param1: 'Windows Event Log'\n        param3: 'disabled'\n    condition: selection\n..."
}
```

**Notes**

- Title matching is **exact**. Use `search_rules` first to get the id, then
  `get_rule` with that.
- `yaml` is the rule as it exists on disk — the only way to see the actual
  `detection:` logic, which the index does not store.
- `technique_names` resolves each id against `mappings/attack.yaml`, so you see
  the current ATT&CK name even when the rule's own tag is out of date.

---

### `attack_coverage`

Rules per ATT&CK technique and tactic across the whole index.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `tactic` | string | `""` | Restrict to one tactic slug. |
| `min_level` | string | `""` | Only count rules at this level or above. |

**Call**

```json
{"tactic": "credential-access"}
```

**Output** (technique list truncated)

```json
{
  "rules_considered": 432,
  "techniques_covered": 101,
  "rules_without_technique": 14,
  "tactics": {
    "credential-access": 432,
    "stealth": 42,
    "collection": 40,
    "discovery": 33
  },
  "techniques": [
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "rules": 121},
    {"id": "T1003", "name": "OS Credential Dumping", "rules": 44},
    {"id": "T1003.002", "name": "OS Credential Dumping: Security Account Manager", "rules": 41}
  ]
}
```

**Notes**

- Techniques sort by rule count descending, then id ascending.
- The `tactics` map is **not** a partition of `rules_considered`: a rule tagged
  with three tactics is counted under each. Filtering by `credential-access`
  returns rules that cite it *and* whatever else they cite.
- `rules_without_technique` are rules with a tactic tag but no technique tag.

---

### `technique_coverage`

Assess **one** technique. This is the only tool that returns a verdict rather
than a count.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `technique_id` | string | *(required)* | e.g. `"T1003"` or `"T1003.003"`. |

| Verdict | Meaning |
| --- | --- |
| `covered` | A non-experimental rule detects it directly, and all sub-techniques are covered. |
| `partial` | Only some sub-techniques covered, **or** covered only *via* sub-techniques, **or** every citing rule is still `experimental`. |
| `gap` | No rule cites it at all. |

**Call**

```json
{"technique_id": "T1558.001"}
```

**Output**

```json
{
  "id": "T1558.001",
  "name": "Steal or Forge Kerberos Tickets: Golden Ticket",
  "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT)...",
  "tactics": ["credential-access"],
  "url": "https://attack.mitre.org/techniques/T1558/001",
  "is_subtechnique": true,
  "known_to_attack": true,
  "coverage": {
    "assessment": "gap",
    "rationale": "no rule in the index cites this technique or any sub-technique",
    "rules_direct": 0,
    "rules_total": 0,
    "subtechniques": {"total": 0, "covered": 0, "uncovered": []}
  },
  "breakdown": {"total": 0, "distinct_detections": 0, "by_severity": {}},
  "rules_returned": 0,
  "rules": []
}
```

**Notes**

- **Every verdict ships a `rationale`.** Read it — `partial` covers three
  distinct situations that need different responses.
- **Revoked ids get a `warning`.** Querying `T1562` returns
  `"ATT&CK has revoked T1562; it is superseded by T1685 — rules citing it should
  be retagged"` alongside a `partial` verdict computed over 13 rules, 11 of them
  `deprecated`. Without the warning that verdict is misleading in both
  directions.
- **A `gap` is not automatically a to-do.** Many techniques are unobservable in
  Windows EVTX — `T1003.007` (Proc Filesystem) is Linux-only.
- The rule list is capped at 50 (`rule_limit`); `coverage` and `breakdown`
  always reflect every match.

---

### `coverage_gaps`

Techniques with no rule at all. Revoked and deprecated ids are excluded so they
aren't mistaken for real gaps.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `tactic` | string | `""` | Restrict to one tactic slug. |
| `limit` | int | `50` | Max gaps returned. |

**Call**

```json
{"tactic": "credential-access", "limit": 5}
```

**Output**

```json
{
  "total_gaps": 30,
  "returned": 5,
  "note": "A 'gap' means no indexed rule cites the technique. Some techniques are not observable in Windows event logs at all, so this is a starting point for review, not a to-do list.",
  "gaps": [
    {"id": "T1003.007", "name": "OS Credential Dumping: Proc Filesystem", "tactics": ["credential-access"]},
    {"id": "T1003.008", "name": "OS Credential Dumping: /etc/passwd and /etc/shadow", "tactics": ["credential-access"]},
    {"id": "T1110.004", "name": "Brute Force: Credential Stuffing", "tactics": ["credential-access"]},
    {"id": "T1558.001", "name": "Steal or Forge Kerberos Tickets: Golden Ticket", "tactics": ["credential-access"]},
    {"id": "T1558.002", "name": "Steal or Forge Kerberos Tickets: Silver Ticket", "tactics": ["credential-access"]}
  ]
}
```

**Notes**

- Triage the list by platform before acting. Of the 30 credential-access gaps,
  most are Linux (`T1003.007/.008`), macOS (`T1555.001/.002`) or cloud
  (`T1552.005/.007`). The Windows-observable ones — Golden Ticket, Silver Ticket,
  ARP cache poisoning — are the real findings.
- Some gaps are structural rather than missing work. Golden and Silver Ticket
  are detected by the *absence* of an event or by cross-host correlation, which
  a single-event Sigma rule cannot express.

---

### `framework_coverage`

Coverage of a **whole framework**, including entries nothing detects. This is the only
tool that can query the non-ATT&CK frameworks: MITRE ATLAS and the two OWASP top-tens.

It is the inverse of `attack_coverage`. That one rolls up the *rules'* tags, so it can
only report techniques some rule already mentions. This one walks the *framework* and
asks how many rules reach each entry — so it can report zero.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `framework` | string | `""` | `enterprise-attack` \| `atlas` \| `owasp-llm-top-10` \| `owasp-agentic-top-10`. Omit for every framework at its newest version, in one aggregation. |
| `limit` | int | `25` | Max entries listed. Counts always describe all of them. |

**Requires the optional MongoDB store.** With `HAYABUSA_MONGO_ENABLED` unset, or the
container stopped, it returns an explanation rather than failing:

```json
{
  "available": false,
  "reason": "HAYABUSA_MONGO_ENABLED is not set",
  "hint": "Framework coverage needs the optional MongoDB store. Set HAYABUSA_MONGO_ENABLED=1 and run: make mongo-up && make load-mongo (plus make load-atlas / make load-owasp for the AI frameworks)."
}
```

**Call**

```json
{"framework": "owasp-llm-top-10"}
```

**Output**

```json
{
  "framework": "atlas",
  "framework_version": "2026.09",
  "entries_total": 208,
  "entries_covered": 29,
  "entries_gap": 179,
  "entries_covered_by_cross_reference": 29,
  "coverage_basis": "inherited from the ATT&CK techniques this framework adopted; conventional tradecraft against an AI target, not AI-specific detection",
  "rules_mapped": 1663,
  "entries": [
    {"id": "AML.T0050", "name": "Command and Scripting Interpreter", "cross_refs": ["T1059", "T1059.001", "…"], "rules": 604},
    {"id": "AML.T0090", "name": "OS Credential Dumping", "cross_refs": ["T1003", "…"], "rules": 219}
  ]
}
```

**Notes**

- **ATLAS coverage is *inherited*, never native.** All 29 covered entries come via
  `cross_refs` — the ATT&CK ids MITRE adopted into the ATLAS matrix. `coverage_basis`
  states this in the payload; quote it alongside the number. The remaining 179
  entries are AI-native (`LLM Prompt Injection`, `Create Proxy AI Model`) and have
  no conventional counterpart, so they stay gaps permanently.
- **OWASP reads as 20 gaps, and that is the honest answer.** Unlike ATLAS, OWASP
  publishes no ATT&CK cross-reference, so there is nothing to inherit from. Zero
  indexed rules cite an `LLM*` or `ASI*` id. Those two frameworks are an
  **inventory** here, not a detection surface.
- **Sub-technique widening happens at ingest.** ATLAS cites `T1059`; the rule that
  fires tags `T1059.001`. `load_techniques()` expands a parent cross-reference to
  the sub-technique ids the corpus actually cites, so the `$lookup` stays an exact
  multikey join rather than a per-entry prefix scan — and so this agrees with
  `kb.observed_atlas`, which walks parents in Python. A test asserts that equality.
- The `$lookup` joins `attack_techniques.technique_id` against the
  `sigma_rules.techniques` **array**, served by the multikey index.
- Omitting `framework` reads each framework at its newest ingested version, so two
  ATT&CK releases are never double-counted.
- This is the server's only Mongo **read**; `scan_evtx_attack` is the only write. Both
  are flag-gated, failure-swallowing and bounded, which is what keeps the store
  additive.

---

## Housekeeping tools

### `version`

No parameters. Returns the first line of `hayabusa help` — v3.10+ has no
`--version` flag.

**Output**

```
Hayabusa v3.10.0 - Independence Day Release
```

---

### `list_profiles`

No parameters. Lists output profiles and the fields each emits.

**Output** (abridged)

```
Start time: 2026/09/15 15:05
List of available profiles:
- minimal:                 %Timestamp%, %RuleTitle%, %Level%, %Computer%, %Channel%, %EventID%, %RecordID%, %Details%
- standard:                %Timestamp%, %RuleTitle%, %Level%, %Computer%, %Channel%, %EventID%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleID%
- verbose:                 %Timestamp%, %RuleTitle%, %Level%, %Computer%, %Channel%, %EventID%, %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%, %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%
- all-field-info:          %Timestamp%, %RuleTitle%, %Level%, %Computer%, %Channel%, %EventID%, %RecordID%, %AllFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%
- super-verbose:           ... %RuleAuthor%, %RuleModifiedDate%, %Status%, ...
- timesketch-minimal:      ... (Timesketch-compatible column order)
```

**Notes**

- **`%RuleID%` is why `scan_evtx_attack` forces `standard`.** `minimal` omits it,
  and without a rule id there is nothing to join a detection back to.
- `all-field-info` is the one to use when you need every raw event field for
  manual analysis.

---

### `update_rules`

No parameters. Pulls the latest Sigma rules from the Hayabusa rules repo into
`hayabusa/rules/`.

**Notes**

- **Network call, and it mutates the corpus on disk.**
- **Run `rebuild_rule_index` (or `make build-index`) afterwards.** The bundled
  corpus is a *pinned* directory — served from cache and never re-walked — so
  new rules are invisible to every KB tool until the index is rebuilt. Symptom
  if you forget: `scan_evtx_attack` starts reporting `unmapped_detections > 0`.

---

### `rebuild_rule_index`

No parameters. Re-parses every rule and refreshes `.cache/rule_index.json`.

**Output**

```json
{
  "indexed_rules": 4965,
  "notes": [
    "/abs/path/rules: scanned 2 rules (live)",
    "/abs/path/hayabusa/rules/hayabusa: 196 rules (cached, built 62d ago; run rebuild_rule_index after changing these rules)",
    "/abs/path/hayabusa/rules/sigma: 4767 rules (cached, built 62d ago; run rebuild_rule_index after changing these rules)"
  ]
}
```

**Notes**

- **Slow — roughly 150 seconds** for the bundled corpus on WSL2 over `/mnt/c`.
- **`notes` reports what actually happened per directory**, which is the fastest
  way to confirm your setup. `(live)` means re-scanned this call; `(cached)`
  means served from `.cache/rule_index.json` without walking the directory.
- Needed only after the corpus changes. **Edits to `rules/` need no rebuild**:
  that directory is under `LIVE_DIR_MAX_FILES` (50), so it is re-scanned on
  every load and your edits are live immediately.
- `196 rules` from the Hayabusa tree comes from **193 files** — three correlation
  files define two rules each. Both numbers are right; don't reconcile them.

---

## Resources

Browsable `detection://` URIs, for reading rather than querying. Same index as
the tools.

| URI | Returns |
| --- | --- |
| `detection://rules` | Catalog: counts by source/severity/status/log source, custom rules in full, corpus summarized. |
| `detection://rules/{rule_ref}` | Raw rule YAML (`rule_ref` = id, filename stem, or exact title). |
| `detection://rules/by-technique/{id}` | Rules detecting a technique; a parent id includes its subs. |
| `detection://attack/techniques/{id}` | Name, description, detecting rules, coverage assessment. |
| `detection://attack/coverage` | Coverage across all techniques and tactics. |
| `detection://attack/tactics` | Tactics with rule counts. |

---

## Conventions

These hold across every tool.

**Counts describe all matches; lists are capped.** `matched`/`total`/`coverage`/
`breakdown` are computed before truncation. `returned` tells you how much of it
is in the payload. You never have to page the corpus to characterise a result.

**Paths are resolved and may be confined.** Every caller-supplied path goes
through `safe_path()`. If `HAYABUSA_WORKDIR` is set, paths outside that root are
rejected — worth setting when pointing this at real case data.

**Level vocabulary is shared but abbreviated on output.** You pass
`informational|low|medium|high|critical`; Hayabusa returns `info` and `med` in
`counts`.

**Errors raise `HayabusaError`.** Non-zero exits, timeouts (`HAYABUSA_TIMEOUT`,
default 1800s), invalid arguments and path-sandbox violations all surface as a
clean MCP error rather than a stack trace.

**Rules in the index are not the same population as rules that fire.** Hayabusa
disables deprecated, unsupported and noisy rules by default, and the channel
filter drops any rule for a channel absent from the evidence. Check a timeline
`log` when a count surprises you.
