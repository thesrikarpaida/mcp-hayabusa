# Sample EVTX logs

Public sample Windows event logs for exercising the scanning tools end to end,
from [hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)
(Yamato Security). Simulated attack traffic — not real evidence.

```bash
./scripts/fetch_samples.sh     # download them (a few hundred KB)
```

The `.evtx` files themselves are **gitignored**. They are re-fetchable in one
command, and the repo should never get in the habit of carrying event logs — the
same rule that keeps real case data out.

## Why these files

They trigger detections from **both** bundled rule sets:

- `hayabusa/rules/sigma/` — the Sigma corpus (~4.8k rules)
- `hayabusa/rules/hayabusa/` — Hayabusa's own built-in rules (193), which fire
  "Log Cleared", "Possible LOLBIN", etc.

That matters because `scan_evtx_attack` joins detections back to indexed rules by
rule id. When only the Sigma corpus was indexed, detections from the built-in
rules could not be mapped and landed in `unmapped_detections` — these samples are
what surfaced that. Keep at least one file that fires a built-in rule.

## Using them

```bash
HAYABUSA_PATH=./hayabusa/hayabusa uv run python -c "
from mcp_hayabusa import server
r = server.scan_evtx_attack('samples', min_level='low')
print(r['total'], 'detections |', r['unmapped_detections'], 'unmapped')
print([t['id'] for t in r['techniques_observed']])
"
```

`unmapped_detections` should be **0**. If it isn't, the rule index is stale or is
missing a rules dir — run `make build-index` and check `HAYABUSA_RULES_DIR`.

The integration tests in `tests/integration/test_samples.py` use this directory and
skip automatically when it is empty.
