#!/bin/bash
# Tapproval Base uninstaller — a clean exit, announced first.
#
#   curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.sh | bash
#
set -euo pipefail

echo "Tapproval Base uninstaller — here is everything it will do:"
echo "  1. Remove Base's hooks and settings entries (a backup is kept)"
echo "  2. Stop the local relay"
echo "  3. Delete ~/.tapproval"
echo "  Your audit log stays, so your own history remains yours."
echo ""

if [ -f "$HOME/.tapproval/ClaudeRiskClassifier.py" ]; then
  python3 "$HOME/.tapproval/ClaudeRiskClassifier.py" --uninstall
else
  echo "(~/.tapproval not found — nothing registered to remove)"
fi
pkill -f "watch_relay.py" 2>/dev/null || true
rm -rf "$HOME/.tapproval"

echo ""
echo "TAPPROVAL_BASE_REMOVED"
echo "OK: Tapproval Base is gone. The audit log (~/.claude/risk-audit.jsonl)"
echo "    was left for you to keep or delete."
