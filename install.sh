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
    mv "$DIR" "$DIR.superseded-$(date +%Y%m%d-%H%M%S)"
    git clone -q --depth 1 "$REPO" "$DIR"
  fi
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
