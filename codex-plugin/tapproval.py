#!/usr/bin/env python3
"""Tapproval Base, as a Codex plugin: the plugin's only script.

Codex asks the person to trust a plugin's hooks once, and asks again
whenever a file in this folder changes. So this folder stays small and
still: the work is done by the helper this script puts in ~/.tapproval,
which updates itself like a terminal install, and which Codex's trust
does not cover. A change here makes every Codex user trust Tapproval
again; the version in .codex-plugin/plugin.json moves with it.

    tapproval.py session-start   SessionStart: fetch the helper if it is
                                 missing, then start the relay
    tapproval.py permission      PermissionRequest: the helper's Codex hook

Every failure leaves Codex as it was: it asks its questions as usual.
Standard library only, Python 3.9.
"""
import os
import subprocess
import sys

REPO = "https://github.com/marcobelini/tapproval-helper.git"
HOME = os.path.join(os.path.expanduser("~"), ".tapproval")
HELPER = os.path.join(HOME, "ClaudeRiskClassifier.py")
# As the Claude Code plugin's hook carries them on its command line: the
# watch is on and the relay is this computer's own.
WRIST = {"CLAUDE_RISK_MODE": "enforce",
         "CLAUDE_RISK_RELAY": "http://127.0.0.1:8977",
         "CLAUDE_RISK_RELAY_WAIT": "86400"}


def _git(*args):
    return subprocess.run(("git",) + args, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                          timeout=150).returncode == 0


def fetch():
    """Put the helper in ~/.tapproval, as install.sh does. True when it is there."""
    if os.path.isfile(HELPER):
        return True
    try:
        if os.path.isdir(HOME):
            # A Claude Code plugin install keeps its data and logs here, and
            # git clone refuses a folder that is not empty: a checkout in place.
            _git("-C", HOME, "init", "-q")
            if not _git("-C", HOME, "remote", "add", "origin", REPO):
                _git("-C", HOME, "remote", "set-url", "origin", REPO)
            _git("-C", HOME, "fetch", "-q", "--depth", "1", "origin", "main")
            _git("-C", HOME, "checkout", "-q", "-f", "-B", "main", "--track", "origin/main")
        else:
            _git("clone", "-q", "--depth", "1", REPO, HOME)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return os.path.isfile(HELPER)


def knows_the_plugin():
    """An older helper already in ~/.tapproval may predate this plugin; it
    is brought up to date by the relay's own update, so until then the
    commands every version has are used."""
    try:
        with open(HELPER, encoding="utf-8") as handle:
            return "--codex-plugin-start" in handle.read()
    except OSError:
        return False


def main(argv):
    what = argv[1] if len(argv) > 1 else ""
    if what == "permission":
        if not os.path.isfile(HELPER):
            return 0                     # no helper yet: Codex asks as usual
        tail = ["--from-codex-plugin"] if knows_the_plugin() else []
        return subprocess.call([sys.executable, HELPER, "--agent", "codex"] + tail,
                               env=dict(os.environ, **WRIST))
    if what == "session-start":
        if not fetch():
            print("Tapproval: could not download the helper (is git installed, and "
                  "is this computer online?). Codex works as usual; the next Codex "
                  "session tries again.", file=sys.stderr)
            sys.stdout.write("{}\n")
            return 0
        if knows_the_plugin():
            return subprocess.call([sys.executable, HELPER, "--codex-plugin-start"])
        subprocess.call([sys.executable, os.path.join(HOME, "watch_relay.py"), "--ensure"],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        sys.stdout.write("{}\n")
        return 0
    print("usage: tapproval.py session-start | permission", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
