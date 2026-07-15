# Custom Sigma rules

Detection rules authored for this environment. Everything here is indexed by the
MCP knowledge base alongside the bundled Hayabusa corpus
(`hayabusa/rules/sigma/`), and shows up in `search_rules` / `attack_coverage`
with `source: rules`.

## Conventions

- One rule per file, named `<product>_<what_it_detects>.yml`.
- `id` must be a UUID and must be unique. **A rule here with the same `id` as a
  bundled rule shadows it** in the index — that is the supported way to override
  a corpus rule.
- Tag ATT&CK coverage with both the tactic and the technique, using Sigma's
  hyphenated slugs, so coverage queries pick the rule up:

  ```yaml
  tags:
      - attack.credential-access
      - attack.t1003.001
  ```

  A rule with no `attack.tXXXX` tag still runs, but is invisible to technique
  coverage and lands in `rules_without_technique`.
- Add any new technique id to `mappings/attack.yaml`, otherwise it renders with
  a null name.

## After editing

This directory is re-scanned on every index load (it is small), so changes are
picked up with no rebuild. Only the bundled corpus is cached — see
`make build-index`.

Validate a rule actually parses and is tagged the way you expect:

```bash
uv run python -c "
from mcp_hayabusa import kb
i = kb.load_index()
print([r.summary() for r in i.rules if r.source == 'rules'])
"
```
