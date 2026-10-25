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
echo "  3. Delete ~/.tapproval (the helper, its data and its logs), and the"
echo "     ~/.tapproval-* files older versions kept beside it"
echo "  4. Forget the paired watch (its key is in ~/.tapproval/data)"
echo "     — after a reinstall, pair it again from Settings"
echo "  5. On a Mac, stop the iCloud bridge and remove its login item (the"
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
# Stop this install's relay by the pid it wrote, never every relay this
# user runs: `pkill -f watch_relay.py` took CI's isolated relay and an e2e
# run's with it (2026-10-25 review). The old loose pid file too, for a relay
# that never restarted since 1.1.60.
for PIDFILE in "$HOME/.tapproval/data/relay.pid" "$HOME/.tapproval-relay.pid"; do
  [ -f "$PIDFILE" ] || continue
  RELAY_PID=$(tr -cd '0-9' < "$PIDFILE")
  [ -n "$RELAY_PID" ] || continue
  if ps -p "$RELAY_PID" -o command= 2>/dev/null | grep -q "watch_relay.py"; then
    kill "$RELAY_PID" 2>/dev/null || true
  fi
done
# The travel tunnel outlives a relay on purpose, so a restart keeps its
# address; an uninstall must stop it, or a public URL would outlive Tapproval.
pkill -f "cloudflared tunnel.*127.0.0.1:8978" 2>/dev/null || true
# The Mac bridge (route B, #378), here as well as in --uninstall: a plugin
# install answers --uninstall with "use /plugin uninstall" and removes
# nothing, and the bridge must not outlive the helper that installed it.
# Its job is stopped first: the app itself lives in ~/.tapproval/bridge-app,
# removed just below, and ~/.tapproval-bridge is where it lived before.
if [ "$(uname -s)" = "Darwin" ]; then
  # From 1.1.0 the bridge registered its own login item; only it can take
  # it out again, or Login Items keeps a "Tapproval" row for a deleted app.
  BRIDGE_APP="$HOME/.tapproval/bridge-app/Tapproval.app"
  if [ -x "$BRIDGE_APP/Contents/MacOS/Tapproval" ]; then
    "$BRIDGE_APP/Contents/MacOS/Tapproval" --unregister >/dev/null 2>&1 || true
  fi
  launchctl bootout "gui/$(id -u)/com.tapproval.bridge" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/com.tapproval.bridge.plist"
  # The relay's login wake-up too: only --uninstall removed it, and that
  # removes nothing on a plugin install or when it fails, leaving a job
  # that points at a deleted file (2026-10-24 review).
  launchctl bootout "gui/$(id -u)/com.tapproval.relay" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/com.tapproval.relay.plist"
fi
rm -rf "$HOME/.tapproval-bridge"
rm -rf "$HOME/.tapproval"
# What the relay wrote beside its directory until 1.1.60, when it moved
# into ~/.tapproval/data and logs (a relay that never restarted since, or a
# key kept back for an old bridge, can still be here). Left behind, the
# pairing outlived the install it belonged to — a "clean exit" that kept
# the key to the door.
rm -f "$HOME/.tapproval-token" "$HOME/.tapproval-auth.json" \
      "$HOME/.tapproval-relay.log" "$HOME/.tapproval-say.log" "$HOME/.tapproval-last-update" \
      "$HOME/.tapproval-relay.pid" "$HOME/.tapproval-tunnel.json" \
      "$HOME/.tapproval-tunnel.log" "$HOME/.tapproval-crashes.jsonl"
# The copies install.sh set aside when it replaced an older checkout.
rm -rf "$HOME"/.tapproval.superseded-* "$HOME"/.tapproval.fresh-*

echo ""
echo "TAPPROVAL_BASE_REMOVED"
echo "OK: Tapproval Base is gone. The audit log (~/.claude/risk-audit.jsonl)"
echo "    was left for you to keep or delete."
