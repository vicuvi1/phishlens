#!/usr/bin/env bash
# Capture README / CV screenshots with headless Chrome. Needs: node tools/serve.js 5180
set -euo pipefail
CHROME="${CHROME:-/c/Program Files/Google/Chrome/Application/chrome.exe}"
BASE="${BASE:-http://127.0.0.1:5180/}"
OUT="$(cd "$(dirname "$0")/.." && pwd -W 2>/dev/null || pwd)/docs"
PROFILE="$(mktemp -d)"
shot() { # name url height
  "$CHROME" --headless=new --disable-gpu --use-angle=swiftshader --hide-scrollbars --no-first-run \
    --user-data-dir="$PROFILE" --window-size=1440,"$3" --force-device-scale-factor=1 \
    --virtual-time-budget=7000 --screenshot="$OUT/$1.png" "$BASE?static&${2#?}" >/dev/null 2>&1
  echo "docs/$1.png"
}
shot landing "" 1180
shot overview "?s=1#sample=01" 1250
shot sender "?s=2#sample=01&tab=sender" 1050
shot preview "?s=3#sample=01&tab=content" 1000
shot links "?s=4#sample=06&tab=links" 1100
shot quishing "?s=5#sample=05&tab=attachments" 960
shot attachments "?s=6#sample=03&tab=attachments" 1250
shot mitre "?s=7#sample=03&tab=mitre" 1000
shot bec "?s=8#sample=02" 1050
shot batch "?s=9#batch=samples" 760
shot light "?theme=light&s=10#sample=04" 1100
# social preview card (1200x630)
"$CHROME" --headless=new --disable-gpu --use-angle=swiftshader --hide-scrollbars --no-first-run --user-data-dir="$PROFILE" \
  --window-size=1200,630 --force-device-scale-factor=1 --virtual-time-budget=7000 --screenshot="$OUT/og.png" "${BASE}?static&og=1#sample=01" >/dev/null 2>&1
echo docs/og.png
