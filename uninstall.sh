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
echo "  5. On a Mac, stop the iCloud bridge and remove its login job (the"
echo "     bridge itself lives in ~/.tapproval and goes with it)"
echo "  Your audit log stays, so your own history remains yours."
echo ""

if [ -f "$HOME/.tapproval/ClaudeRiskClassifier.py" ]; then
  # Not fatal: "installed as a plugin" is an answer, and stopping here left
  # the relay running and the pairing key on disk (2026-09-30 review).
  python3 "$HOME/.tapproval/ClaudeRiskClassifier.py" --uninstall \
    || echo "(continuing: the rest is removed either way)"
else
  echo "(~/.tapproval not found — nothing registered to remove)"
fi
pkill -f "watch_relay.py" 2>/dev/null || true
# The travel tunnel outlives a relay on purpose, so a restart keeps its
# address; an uninstall must stop it, or a public URL would outlive Tapproval.
pkill -f "cloudflared tunnel.*127.0.0.1:8978" 2>/dev/null || true
# The Mac bridge (route B, #378), here as well as in --uninstall: a plugin
# install answers --uninstall with "use /plugin uninstall" and removes
# nothing, and the bridge must not outlive the helper that installed it.
# Its job is stopped first: the app itself lives in ~/.tapproval/bridge-app,
# removed just below, and ~/.tapproval-bridge is where it lived before.
if [ "$(uname -s)" = "Darwin" ]; then
  launchctl bootout "gui/$(id -u)/com.tapproval.bridge" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/com.tapproval.bridge.plist"
fi
rm -rf "$HOME/.tapproval-bridge"
rm -rf "$HOME/.tapproval"
# Everything else the relay writes beside its directory. Left behind, the
# pairing outlived the install it belonged to — a "clean exit" that kept
# the key to the door.
rm -f "$HOME/.tapproval-token" "$HOME/.tapproval-auth.json" \
      "$HOME/.tapproval-relay.log" "$HOME/.tapproval-say.log" "$HOME/.tapproval-last-update" \
      "$HOME/.tapproval-relay.pid" "$HOME/.tapproval-tunnel.json" \
      "$HOME/.tapproval-tunnel.log" "$HOME/.tapproval-crashes.jsonl"
# The copies install.sh set aside when it replaced an older checkout.
rm -rf "$HOME"/.tapproval.superseded-*

echo ""
echo "TAPPROVAL_BASE_REMOVED"
echo "OK: Tapproval Base is gone. The audit log (~/.claude/risk-audit.jsonl)"
echo "    was left for you to keep or delete."
