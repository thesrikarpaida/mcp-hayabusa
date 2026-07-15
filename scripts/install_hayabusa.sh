#!/usr/bin/env bash
#
# Download the latest Hayabusa release for this platform and extract it to
# ./hayabusa/, leaving a stable ./hayabusa/hayabusa entrypoint.
#
# Platform detection:
#   - Linux x64, glibc >= 2.38 → lin-x64-gnu  (dynamically linked, slightly smaller)
#   - Linux x64, glibc <  2.38 → lin-x64-musl (statically linked, no glibc dep — correct for Ubuntu 22.04 / WSL2)
#
# Usage:  ./scripts/install_hayabusa.sh
# Requires: curl, unzip, python3
set -euo pipefail

REPO="Yamato-Security/hayabusa"
DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/hayabusa"

# Detect glibc version and pick the right Linux asset suffix.
_pick_asset_pattern() {
  local glibc_minor
  glibc_minor=$(ldd --version 2>&1 | awk '/ldd/{match($0,/[0-9]+\.[0-9]+/); print substr($0,RSTART,RLENGTH)}' | cut -d. -f2 | head -1)
  if [ -n "$glibc_minor" ] && [ "$glibc_minor" -ge 38 ] 2>/dev/null; then
    echo "lin-x64-gnu"
  else
    echo "lin-x64-musl"
  fi
}

for tool in curl unzip python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' is required" >&2; exit 1; }
done

ASSET_PATTERN="$(_pick_asset_pattern)"
echo "==> Platform: Linux x64 (${ASSET_PATTERN})"
echo "==> Querying latest release of $REPO ..."

api_json="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"

read -r tag url < <(printf '%s' "$api_json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
tag = data["tag_name"]
for asset in data["assets"]:
    name = asset["name"]
    if "'"$ASSET_PATTERN"'" in name and name.endswith(".zip"):
        print(tag, asset["browser_download_url"])
        break
else:
    sys.exit("no asset matching '"$ASSET_PATTERN"' found in release " + tag)
')

echo "==> Latest is $tag"
echo "==> Asset: $url"

tmpzip="$(mktemp --suffix=.zip)"
trap 'rm -f "$tmpzip"' EXIT
curl -fSL --progress-bar "$url" -o "$tmpzip"

echo "==> Extracting to $DEST ..."
rm -rf "$DEST"
mkdir -p "$DEST"
unzip -q "$tmpzip" -d "$DEST"

# The archive may nest everything under a top-level folder; flatten if so.
inner="$(find "$DEST" -mindepth 1 -maxdepth 1 -type d -name 'hayabusa*' | head -n1 || true)"
if [ -n "$inner" ] && [ ! -f "$DEST/config/config.yaml" ]; then
  shopt -s dotglob
  mv "$inner"/* "$DEST"/
  rmdir "$inner"
  shopt -u dotglob
fi

# Symlink the versioned binary to a stable name.
binary="$(find "$DEST" -maxdepth 1 -type f -name "hayabusa-*-${ASSET_PATTERN}" | head -n1 || true)"
if [ -z "$binary" ]; then
  binary="$(find "$DEST" -maxdepth 1 -type f -name 'hayabusa*' ! -name '*.zip' | head -n1 || true)"
fi
[ -n "$binary" ] || { echo "error: could not locate extracted hayabusa binary" >&2; exit 1; }

chmod +x "$binary"
ln -sf "$(basename "$binary")" "$DEST/hayabusa"

echo "==> Installed $tag (${ASSET_PATTERN})"
"$DEST/hayabusa" help 2>&1 | head -1
echo
echo "Set HAYABUSA_PATH to: $DEST/hayabusa"
