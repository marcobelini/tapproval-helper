#!/bin/bash
# Tapproval helper — one-line install, nothing to keep running.
#
#   curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash
#
# Installs onto the computer where Claude Code runs (laptop is fine).
# Registers the risk-triage hook, wires the relay to start itself with
# every Claude Code session, and adds a login wake-up so a reboot never
# needs a hand — after this, close the terminal and forget it.
# Standard library Python only; Bonjour + a secure tunnel handle the rest.
set -euo pipefail

DIR="$HOME/.tapproval"
REPO="https://github.com/marcobelini/tapproval-helper.git"

if [ -d "$DIR/.git" ]; then
  # A fast-forward can fail for good reasons (a rewritten history, a local
  # edit, a half-finished clone). Swallowing that with `|| true` left the
  # install frozen on old code forever, with nothing said — so fall back to
  # a fresh clone, keeping the old one aside rather than deleting it.
  if ! git -C "$DIR" pull -q --ff-only 2>/dev/null; then
    echo "update: fetching a fresh copy (the existing one could not fast-forward)"
    # Cloned beside it first, and swapped in only once the clone is whole.
    # Moving the old one aside before cloning left no install at all when
    # the clone failed for the same reason the pull did — a network blip —
    # while every hook still pointed here (2026-10-19 review).
    fresh="$DIR.fresh-$$"
    rm -rf "$fresh"
    if git clone -q --depth 1 "$REPO" "$fresh"; then
      # The installed Mac bridge, the helper's data (the paired watches'
      # keys among it) and its logs live in the checkout but are not part
      # of it (gitignored): they move with the install, not with the old copy.
      for kept in bridge-app data logs; do
        if [ -d "$DIR/$kept" ]; then mv "$DIR/$kept" "$fresh/$kept"; fi
      done
      mv "$DIR" "$DIR.superseded-$(date +%Y%m%d-%H%M%S)"
      mv "$fresh" "$DIR"
    else
      rm -rf "$fresh"
      echo "update: could not fetch a fresh copy either; keeping the one installed" >&2
    fi
  fi
elif [ -d "$DIR" ]; then
  # A folder that is not a checkout. Where the helper came as a Claude Code
  # plugin, the Mac bridge (bridge-app/), its data and its logs already live
  # here, and git clone refuses a folder that is not empty: make it a
  # checkout in place, keeping what is there. The repository's .gitignore
  # names all three.
  git -C "$DIR" init -q
  git -C "$DIR" remote add origin "$REPO" 2>/dev/null \
    || git -C "$DIR" remote set-url origin "$REPO"
  git -C "$DIR" fetch -q --depth 1 origin main
  git -C "$DIR" checkout -q -f -B main --track origin/main
else
  git clone -q --depth 1 "$REPO" "$DIR"
fi

# One call: --watch wires enforce mode and the relay address so the first
# card reaches the wrist. As two calls the transcript promised "shadow
# mode, work a week" and, three lines later, "wrist approvals are ON".
python3 "$DIR/ClaudeRiskClassifier.py" --install --watch
python3 "$DIR/watch_relay.py" --ensure

echo ""
echo "TAPPROVAL_BASE_READY"
echo "OK: Tapproval Base is ready. Start a new Claude Code session,"
echo "    then open Tapproval on your watch - it connects by itself."
echo "    No watch app yet? https://apps.apple.com/app/tapproval/id6805869018"
echo "    or the beta, where the unlock is free: https://testflight.apple.com/join/dW1tYBQG"
