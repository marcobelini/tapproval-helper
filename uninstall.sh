#!/bin/bash
# Tapproval Base uninstaller — a clean exit, announced first.
#
#   curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.sh | bash
#
set -euo pipefail

echo "Tapproval Base uninstaller — here is everything it will do:"
echo "  1. Remove Base's hooks, settings entries and login wake-up"
echo "     (a settings backup is kept)"
echo "  2. Stop the local relay"
echo "  3. Delete ~/.tapproval, the relay's log and its update stamp"
echo "  4. Forget the paired watch (~/.tapproval-token, ~/.tapproval-auth.json)"
echo "     — after a reinstall, pair it again from Settings"
echo "  Your audit log stays, so your own history remains yours."
echo ""

if [ -f "$HOME/.tapproval/ClaudeRiskClassifier.py" ]; then
  python3 "$HOME/.tapproval/ClaudeRiskClassifier.py" --uninstall
else
  echo "(~/.tapproval not found — nothing registered to remove)"
fi
pkill -f "watch_relay.py" 2>/dev/null || true
rm -rf "$HOME/.tapproval"
# Everything else the relay writes beside its directory. Left behind, the
# pairing outlived the install it belonged to — a "clean exit" that kept
# the key to the door.
rm -f "$HOME/.tapproval-token" "$HOME/.tapproval-auth.json" \
      "$HOME/.tapproval-relay.log" "$HOME/.tapproval-say.log" "$HOME/.tapproval-last-update"

echo ""
echo "TAPPROVAL_BASE_REMOVED"
echo "OK: Tapproval Base is gone. The audit log (~/.claude/risk-audit.jsonl)"
echo "    was left for you to keep or delete."
