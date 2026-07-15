#!/usr/bin/env bash
# Download a few sample .evtx logs into ./samples/ for end-to-end testing.
#
# Source: https://github.com/Yamato-Security/hayabusa-sample-evtx (599 files,
# far more than we need). This grabs a small, deliberately noisy subset that
# triggers detections from BOTH bundled rule sets — the Sigma corpus and
# Hayabusa's own built-in rules — which is what makes it useful for checking
# that scan_evtx_attack can map every detection back to a rule.
#
# The .evtx files are gitignored: they are re-fetchable, and the repo must not
# get in the habit of carrying event logs.
set -euo pipefail

BASE="https://raw.githubusercontent.com/Yamato-Security/hayabusa-sample-evtx/main"
DEST="$(cd "$(dirname "$0")/.." && pwd)/samples"

FILES=(
  "DeepBlueCLI/metasploit-psexec-native-target-security.evtx"
  "DeepBlueCLI/Powershell-Invoke-Obfuscation-string-menu.evtx"
  "DeepBlueCLI/disablestop-eventlog.evtx"
)

mkdir -p "$DEST"
for f in "${FILES[@]}"; do
  out="$DEST/$(basename "$f")"
  if [ -f "$out" ]; then
    echo "==> have $(basename "$f")"
    continue
  fi
  echo "==> fetching $(basename "$f")"
  curl -sSLf -o "$out" "$BASE/$f"
done

echo "==> samples in $DEST:"
ls -1sh "$DEST" | grep -i evtx || true
