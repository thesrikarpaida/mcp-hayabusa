#!/usr/bin/env bash
# Build the combined MITRE ATLAS + ATT&CK Enterprise STIX bundle.
#
# ATLAS publishes its data as YAML, not STIX: dist/ holds ATLAS.yaml and no
# bundle. The STIX export is produced by their own tool, so this clones
# mitre-atlas/atlas-data and runs it rather than reimplementing the conversion.
#
# --include-attack makes the output carry ATT&CK Enterprise as well, which is
# why scripts/build_atlas_mappings.py has to say which framework's ids it wants
# (see mcp_hayabusa.stix): an ATLAS technique cross-references an ATT&CK one.
#
#   ./scripts/fetch_atlas_bundle.sh [output-path]
#
# Needs git and uv. The clone is shallow (~40MB) and lands in a temp dir; only
# the generated bundle is kept.
set -euo pipefail

CACHE_DIR="${TMPDIR:-/tmp}/mcp-hayabusa-stix"
OUT="${1:-$CACHE_DIR/stix-atlas-attack-enterprise.json}"
WORK="$CACHE_DIR/atlas-data"

mkdir -p "$CACHE_DIR"

if [ -d "$WORK/.git" ]; then
	echo "==> Updating $WORK"
	git -C "$WORK" fetch --depth 1 origin >/dev/null 2>&1
	git -C "$WORK" reset --hard origin/HEAD >/dev/null 2>&1
else
	echo "==> Cloning mitre-atlas/atlas-data"
	rm -rf "$WORK"
	git clone --depth 1 https://github.com/mitre-atlas/atlas-data "$WORK" >/dev/null 2>&1
fi

# dist/ATLAS-latest.yaml is a symlink to the current release; dist/manifest.yaml
# maps releases to files if a pinned one is ever needed.
echo "==> Generating STIX bundle (ATLAS + ATT&CK Enterprise)"
(cd "$WORK" && uv run tools/atlas_to_stix.py \
	-i dist/ATLAS-latest.yaml \
	--include-attack \
	-o "$OUT" >/dev/null)

echo "==> Wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "    Ingest it with: make load-atlas"
