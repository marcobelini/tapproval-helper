#!/bin/bash
# Tapproval helper — one-line install, nothing to keep running.
#
#   curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash
#
# Installs onto the computer where Claude Code runs (laptop is fine).
# Registers the risk-triage hook and wires the relay to start itself with
# every Claude Code session — after this, close the terminal and forget it.
# Standard library Python only; Bonjour + a secure tunnel handle the rest.
set -euo pipefail

echo "Tapproval Base installer — here is everything it will do:"
echo "  1. Clone github.com/marcobelini/tapproval-helper to ~/.tapproval"
echo "  2. Back up ~/.claude/settings.json, then register the hooks"
echo "  3. Start the local relay (it restarts itself with every session)"
echo "  No sudo. No dependencies. Undo anytime:"
echo "  python3 ~/.tapproval/ClaudeRiskClassifier.py --uninstall"
echo ""

command -v python3 >/dev/null || {
  echo "python3 is required and was not found on PATH." >&2; exit 1; }
command -v git >/dev/null || {
  echo "git is required and was not found on PATH." >&2; exit 1; }

DIR="$HOME/.tapproval"
REPO="https://github.com/marcobelini/tapproval-helper.git"

if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull -q --ff-only || true
else
  git clone -q --depth 1 "$REPO" "$DIR"
fi

python3 "$DIR/ClaudeRiskClassifier.py" --install
# --watch wires enforce mode and the relay address, so the first card
# reaches the wrist without a second command — same behaviour as the
# plugin path.
python3 "$DIR/ClaudeRiskClassifier.py" --watch
python3 "$DIR/watch_relay.py" --ensure

echo ""
echo "Done. Install Tapproval on your Apple Watch — it finds this"
echo "computer by itself on the same Wi-Fi, and learns how to reach it"
echo "from anywhere. You never need to run anything again."
