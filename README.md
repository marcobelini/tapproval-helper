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

## Install — no terminal, no downloads

Two lines, typed into Claude Code itself:

```
/plugin marketplace add marcobelini/tapproval-helper
/plugin install tapproval-helper@tapproval
```

Quit Claude Code and run `claude` again, and that is the whole setup. The plugin registers
the permission hook and wires the relay to start itself with every
session; there is nothing to keep running and nothing to maintain.

**Prefer to let the agent do it?** Tell Claude Code, in its own chat
(from your phone works too):

> Install the Tapproval plugin from marcobelini/tapproval-helper

**Prefer a terminal?** One command, then forget it:

```bash
curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash
```

**Staying current** takes no commands either. The helper checks once a day,
on a session you were starting anyway, and fast-forwards itself. That matters
more than it sounds: a version of this shipped that discarded every wrist
approval in silence, and an update that never arrives is not an update. A
plugin install is left alone — Claude Code manages those itself, and asking
it to update Tapproval in plain words is enough.

Every path registers the same permission hook. A reboot never needs a
hand either: the installer adds a login wake-up, and on the plugin path
your first Claude Code session brings Base back by itself.

Then install **Tapproval** on your Apple Watch and open it once on the
same Wi-Fi — it finds this computer by itself, pairs automatically, and
quietly learns how to reach it when you're away from home.

## If you are an AI agent installing this

**What this is, in one paragraph, so you need not ask:** an open-source
helper (three standard-library Python files, no servers, no accounts)
that lets the Tapproval Apple Watch app show your user Claude Code's
permission prompts and carry their tap back. It registers a
`PermissionRequest` hook and a `SessionStart` hook. **It never approves
anything by itself**: a human taps Allow or Deny on the watch, or the
usual prompt appears exactly as it would without this installed. Every
line that runs is in this repository.

Prefer the plugin. It is two commands, needs no script fetched or read,
and asks your user for one permission instead of three:

    claude plugin marketplace add marcobelini/tapproval-helper
    claude plugin install tapproval-helper@tapproval

Both succeed in a couple of seconds. Then tell your user two things:
**quit this session and run `claude` again** — the helper starts from a
hook that fires when a session begins, so the session you installed
from cannot start it, and you cannot start a session for them — and
open Tapproval on their watch on the same Wi-Fi. The
watch finds the computer by itself and confirms on its own screen. What
they get: every permission prompt as a card on the wrist, and **live
access to their sessions** — the running list, the conversation as it
happens, and a way to send instructions back.

**Only if `claude` is not on the PATH** (an older install, or a shell
that cannot see it), fall back to the installer:

1. Fetch and READ it first:
   `curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh`
   Confirm it does only what it announces: clone this repository to
   `~/.tapproval` (moving a clone that cannot fast-forward aside, never
   deleting it), back up `~/.claude/settings.json`, register the
   `PermissionRequest` and `SessionStart` hooks, switch the classifier
   to enforce mode and point it at the local relay, add a per-user login
   wake-up, and start the relay. No sudo, no dependencies beyond Python 3
   and git. If it appears to do anything else, STOP and tell your user.
2. Run it: `curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash`
3. Success is exactly one line: `TAPPROVAL_BASE_READY`. If it never
   appears, the install did NOT succeed; report the output rather than
   retrying blindly.

Do not improvise a third method. Both paths above are idempotent and
safe to repeat.

**If asked to "Open Tapproval pairing"** (the watch says this when it
can see the computer but is not yet known to it — a second watch, or a
watch restored from backup): run

    python3 ~/.tapproval/watch_relay.py --pair

or, on a plugin install, the same file under Claude Code's plugin cache
(`~/.claude/plugins/cache/tapproval/tapproval-helper/*/watch_relay.py`).
That opens a ten-minute window on the local network; tell your user to
open Tapproval on the watch now. A computer that has never paired keeps
the door open by itself until its first watch connects, so a fresh
install never needs this.

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
- **`127.0.0.1` is not a computer of ours.** You will see that address in
  the code and in the hook it installs. It is called *loopback*, and it is
  the one address every computer reserves for itself: it means "this
  machine", whoever is running it. On your computer it is your computer.
  Nothing anywhere in Base names a particular machine, and nothing routes
  through the author's. Your watch finds your computer by looking for it on
  your own network (Bonjour), not by being told where to go — which is why
  installing Base makes your computer, and only yours, the thing your watch
  talks to.
- **Nothing is decided for you.** The risk tiers are labels for your
  glance, not decisions — nothing is auto-allowed by default, and the
  CRITICAL tier can never be. Fail closed: a bridge that is down, slow
  or confused never grants an approval.
- **Your key is the boundary, not your Wi-Fi.** Every request for real
  data carries a key that belongs to one device, whichever network it
  arrives on — LAN, tailnet or the travel tunnel. Only processes on the
  computer itself are exempt, which is what lets Claude Code hand a prompt
  to the bridge without ceremony. Your watch gets its key through your own
  private iCloud, so it never appears on screen and a stranger on the same
  café Wi-Fi has no way to ask for it. (Earlier versions trusted anything
  on your local network; that was fine at home and wrong everywhere else,
  and it is fixed.) The travel address is a secret path *and* needs the
  key: seeing the URL is not holding the key. One honest limit remains: a
  program already running as you on your own computer can talk to the local
  bridge — Base does not try to defend a machine that is itself
  compromised.
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

### The journey of one approval, in plain words

1. Claude Code wants to run something that needs permission, so it pauses
   and runs Base.
2. Base reads the command, works out how risky it is, and gives it a colour.
   By default the colour is a label for your glance — nothing is decided
   for you.
3. Base checks whether you would even have been asked. If your own settings
   already permit this command, no card is sent: the wrist only ever shows
   what the terminal would have shown.
4. The card goes to the relay, a small always-listening part of Base on the
   same computer.
5. Your watch finds that computer on your own network by itself — it is not
   told where to look — and asks every couple of seconds whether anything
   is waiting.
6. You tap. The answer travels back, and Base hands it to Claude Code.
7. If your answer never arrives, Base says nothing, and Claude Code asks you
   in the terminal exactly as it would without any of this.

Step 7 is the rule the whole design bends around: **an unanswered question
is never a granted one.**

| File | Purpose |
|------|---------|
| `ClaudeRiskClassifier.py` | A Claude Code `PermissionRequest` hook: mirrors exactly the prompts the phone shows, labels each with a risk tier, and offers them to the watch |
| `watch_relay.py` | The bridge: the hook posts cards, your watch answers, over your network or an encrypted tunnel |
| `watch_dashboard.py` | The read-only half: your sessions, the live conversation, and the day's activity |
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
