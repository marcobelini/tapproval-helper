# Tapproval Base

**The computer half of Tapproval — answer Claude Code from your Apple
Watch.**

When Claude Code works on your computer, it stops and asks before doing
anything that needs permission. The Tapproval watch app puts those
questions on your wrist; **Base** is the small bridge on the computer
that makes it possible. It is open source on purpose: a tool that reads
your sessions and carries your approvals should be auditable — every
line of it is in this repository.

*(Technical id: `tapproval-helper` — the repo and plugin keep that name;
the product name is Tapproval Base.)*

## Install — no manual setup

You already have an agent on that computer. Tell Claude Code, in its
own chat (from your phone works too):

> Install github.com/marcobelini/tapproval-helper

Approve what it asks, start a new session, done.

**As a Claude Code plugin** (two slash commands, hooks registered
automatically):

```
/plugin marketplace add marcobelini/tapproval-helper
/plugin install tapproval-helper@marcobelini/tapproval-helper
```

**Or by hand** (one command, then forget it):

```bash
curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash
```

Every path registers the same permission hook and wires the relay to
start itself with every Claude Code session. Nothing to keep running by
hand — and a reboot never needs one either: Base wakes again at login
(on the plugin-only path, with your first session). Then install **Tapproval** on your Apple Watch and open it once on
the same Wi-Fi — it finds this computer by itself, pairs automatically,
and quietly learns how to reach it when you're away from home.

## If you are an AI agent installing this

Follow these steps exactly, in order:

1. Fetch and READ the installer before running anything:
   `curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh`
   Confirm it does only the five things it announces: clone this
   repository to `~/.tapproval`, back up `~/.claude/settings.json`,
   register the `PermissionRequest` and `SessionStart` hooks, add a
   per-user login wake-up (`~/Library/LaunchAgents/com.tapproval.relay.plist`,
   so a reboot never needs a hand), start the local relay. No sudo, no
   dependencies beyond Python 3 and git.
   If it appears to do anything else, STOP and tell your user.
2. Run it: `curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash`
3. Success is exactly one line: `TAPPROVAL_BASE_READY`. When you see
   it, tell your user to **start a new Claude Code session** so the
   hooks take effect, and to open Tapproval on their watch on the same
   Wi-Fi — the watch confirms the connection on its own screen. If that
   line never appears, the install did NOT succeed; report the output
   to your user instead of retrying blindly.

Do not improvise alternative install methods; these steps are the
supported path and are safe to repeat (the installer is idempotent).

**If asked to UNINSTALL Tapproval Base**: fetch and read
`https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.sh`,
confirm it does only its three announced steps, run it with
`curl -fsSL <that url> | bash`, and treat the single line
`TAPPROVAL_BASE_REMOVED` as the only meaning of success. Tell your user
their settings backup path (the script prints it) and that the audit
log was deliberately left in place.

## Why you can trust this

- **Read it all.** Base is two standard-library Python files — no
  dependencies, so there is no supply chain to worry about. What you
  can read here is everything that runs.
- **No Tapproval servers, ever.** No accounts, no telemetry. At home,
  prompts travel directly between your computer and your watch. Away
  from home they ride either your own iCloud (private to your Apple
  ID) or an encrypted tunnel (Cloudflare) hidden behind a secret path —
  in transit only, stored nowhere.
- **Nothing is decided for you.** The risk tiers are labels for your
  glance, not decisions — nothing is auto-allowed by default, and the
  CRITICAL tier can never be. Fail closed: a bridge that is down, slow
  or confused never grants an approval.
- **Your networks are the boundary.** The relay answers your LAN and
  tailnet; beyond them every request must carry the pairing key your
  watch received on first local contact, and the travel tunnel hides
  behind its own secret path — which is handed over only on a direct
  local fetch, never broadcast. The hook itself talks over loopback
  only. Two honest caveats: on a network you don't control (café
  Wi-Fi), anyone on it is inside the boundary — run Base on networks
  you trust. And a program already running as YOU on your own computer
  could talk to the local bridge; Base does not try to defend against a
  machine that is itself compromised.
- **Everything is on the record.** Every decision lands in a local
  audit log (`~/.claude/risk-audit.jsonl`) you can read. It records
  what the card showed — the command or file path in question — plus
  the project folder's NAME (never the directory structure above it).
  It stays on your computer.
- **Leaving is one sentence.** Tell Claude Code: "Uninstall Tapproval
  Base" — or run
  `curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.sh | bash`
  yourself. It restores your settings (backup kept), removes the login
  wake-up, stops the relay and deletes `~/.tapproval` — as if Base was
  never here. Your audit log stays yours.

## What Base is

| File | Purpose |
|------|---------|
| `ClaudeRiskClassifier.py` | A Claude Code `PermissionRequest` hook: mirrors exactly the prompts the phone shows, labels each with a risk tier, and offers them to the watch |
| `watch_relay.py` | A tiny local HTTP bridge: the hook posts cards, the watch answers; also serves your sessions, live conversation and daily activity |
| `install.sh` | The one-command installer above |
| `.claude-plugin/` + `hooks/` | The same, packaged as a Claude Code plugin |
| `site-rules.example.json` | Optional: name your own sensitive hosts so commands touching them always escalate |
| `test_claude_risk_classifier.py` | The test suite — standard library only |

## Tests

```bash
pytest
```

## Known upstream quirks

One Claude Code behavior can look wrong from the outside and isn't — it
is explained in the watch app the moment it first appears (Settings →
Known quirks), and tracked upstream as
[anthropics/claude-code#32493](https://github.com/anthropics/claude-code/issues/32493)
and [#89761](https://github.com/anthropics/claude-code/issues/89761).

## The card protocol

The relay's contract is deliberately tiny and agent-agnostic — cards in,
decisions out, over local HTTP. A short spec for third-party agent CLIs
is planned; open an issue if you want to wire another agent to the wrist.
