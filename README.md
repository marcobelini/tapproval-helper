# Tapproval Base

**Approve Claude Code permission prompts from your Apple Watch, each one
marked with its risk.** This is the computer half of Tapproval.

[![Get it on the App Store](https://img.shields.io/badge/App%20Store-Get%20Tapproval-d97757?logo=apple&logoColor=white&style=for-the-badge)](https://apps.apple.com/app/tapproval/id6805869018)
[![Or try the beta on TestFlight](https://img.shields.io/badge/TestFlight-Beta-555555?logo=apple&logoColor=white&style=for-the-badge)](https://testflight.apple.com/join/dW1tYBQG)
[![Website](https://img.shields.io/badge/Website-tapproval.thoughtfulsteward.org-2f7f56?style=for-the-badge)](https://tapproval.thoughtfulsteward.org)

In the TestFlight beta the unlock is free.

Privacy policy: https://tapproval.thoughtfulsteward.org/privacy.html · Support: tapproval@thoughtfulsteward.org

When Claude Code works on your computer, it stops and asks before doing
anything that needs permission. The Tapproval watch app puts those
questions on your wrist; **Base** is the small helper on the computer
that makes it possible. It is open source on purpose: a tool that reads
your sessions and carries your approvals should be auditable — every
line of it is in this repository.

**One conversation, everywhere.** A message you send from the watch to a
session open on your computer goes into that session, so its terminal and
the Claude app on your phone show it, and Claude's answer opens with
"*⌚ …*" and your words. What you type in the terminal or on the phone shows
on the watch. If what you asked for needs your yes first, Claude asks it
back as a question card on your wrist. You can end a session from the
watch too (Reply › More › End session): Claude Code stops on the computer,
and the conversation stays there to pick up later.
That small watch is the only mark Base leaves: it says the words came
from your wrist. Base writes nothing into your commits, and no name or
link anywhere in the conversation.

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

**Staying current** matters more than it sounds: a version of this shipped
that discarded every wrist approval in silence, and an update that never
arrives is not an update. A plugin install is Claude Code's to update, and
Claude Code leaves auto-update off for every marketplace but Anthropic's
own, so turn it on once: type `/plugin`, open **Marketplaces**, choose
**tapproval** and pick **Enable auto-update**. From watch app 2.1 you can
do the same from the wrist instead: **Settings → Auto-update → Helper**
writes that very setting, and only when you turn the switch. Until it is
on, the watch's Connection screen mentions it, quietly, once a newer
helper has been out a week. A terminal install
needs nothing: it checks at most once an hour when either Claude Code or
Codex starts, and fast-forwards itself. Simultaneous starts share one updater;
a helper with a waiting approval is replaced only after that card is answered.
From watch app 2.2,
**Settings → Auto-update** says so.

If Codex was already wired before its session-start hook was added, rerun
the installer once and review the new hook in Codex. Hook trust remains
your decision; the helper never grants it for you. After that, whichever
agent starts first can trigger the next due update.

Every path registers the same permission hook. A reboot never needs a
hand either: the installer adds a login wake-up, and on the plugin path
your first Claude Code session brings Base back by itself.

Then install **Tapproval** on your Apple Watch and open it once on the
same Wi-Fi — it finds this computer by itself, pairs automatically, and
quietly learns how to reach it when you're away from home. Downloaded it
on your iPhone and it isn't on the watch? Open the Watch app on the
iPhone and tap **Install** next to Tapproval under **Available Apps**.

**A buzz while Tapproval is closed needs a Mac.** watchOS pauses apps in
the background, and a closed app wakes only for a notification from Apple.
Tapproval gets one by putting each card in your own iCloud: the bridge the
helper installs on a Mac (macOS 13 or later, signed in to iCloud with the
same Apple Account as the watch) writes the card there, and Apple then
buzzes your watch. Only an app signed by Apple and running on a Mac can
write to your iCloud, so this is Mac only. When the bridge is added, macOS
shows an "App Background Activity" notice saying "Tapproval" can run in the
background: that is the bridge. It is listed as Tapproval, with the app's
icon, under System Settings → General → Login Items & Extensions, where it
can be switched off; it also wakes the relay after a restart.
`--install --no-bridge` leaves it out altogether. (Bridges before 1.1.0 were
listed under the developer's name instead.)

| | Mac | Linux or another computer |
|---|---|---|
| Cards and answers while Tapproval is open on the watch | yes | yes |
| A tap on weak Wi-Fi falls back to the away address | yes | yes |
| A buzz while Tapproval is closed | yes, through the bridge and iCloud | no: cards wait until you open the app, and nothing is lost |

The other ways to wake a closed watch were weighed and set aside for now.
A push server of our own would carry every card through a computer that
isn't yours, which breaks the promise that cards stay between your computer,
your iCloud and your watch. Writing to iCloud straight from the helper,
through Apple's web sign-in, would work on any computer, and remains the way
to bring the buzz to Linux; Apple's sign-in did not complete in our tests.

## If you are an AI agent installing this

**What this is, in one paragraph, so you need not ask:** an open-source
helper (standard-library Python files, plus a signed Mac bridge for
iCloud on a Mac; no servers, no accounts)
that lets the Tapproval Apple Watch app show your user Claude Code's
permission prompts and carry their tap back. It registers a
`PermissionRequest` hook and a `SessionStart` hook. **It never approves
anything by itself**: a human taps Allow or Deny on the watch, or the
usual prompt appears exactly as it would without this installed. Every
line of Python that runs is in this repository, and so is the source of
the Mac bridge.

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
   wake-up, start the relay, and, on a Mac, install the signed iCloud
   bridge that ships in this repository (`bridge/`, checked against
   `bridge.json`), which registers its own per-user login item, listed as
   Tapproval (`com.tapproval.bridge`). No
   sudo, no dependencies beyond Python 3 and git. If it appears to do
   anything else, STOP and tell your user.
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
That opens a ten-minute window on the local network. Tell your user to
open Tapproval on the watch now. (A computer that has never paired opens
the window by itself for half an hour after every Claude Code session
starts, so a first install needs no command — but then the computer shows
"Allow a watch to pair?" when the watch knocks, and your user clicks
**Allow** on it. Where no such dialog can be shown, as on Linux, use
`--pair`.)

**If asked to UNINSTALL Tapproval Base**: fetch and read
`https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.sh`,
confirm it does only its five announced steps, run it with
`curl -fsSL <that url> | bash`, and treat the single line
`TAPPROVAL_BASE_REMOVED` as the only meaning of success. Tell your user
their settings backup path (the script prints it) and that the audit
log was deliberately left in place.

## Why you can trust this

- **Read it all.** Base is seven standard-library Python files — no
  dependencies, so there is no supply chain to worry about. On a Mac it
  also installs a small bridge app for the iCloud route, signed with a
  Developer ID and notarized by Apple; its source is in `bridge/`, though
  the signed build cannot be reproduced bit for bit (see `SECURITY.md`).
- **No Tapproval servers, ever.** No accounts, no telemetry. At home,
  prompts travel directly between your computer and your watch. Away
  from home they ride your tailnet or a tunnel (Cloudflare) hidden behind
  a secret path — in transit only, stored nowhere. On a Mac, a card can
  also wait in your own private iCloud database until it is answered.
- **Encrypted end to end, from watch app 2.1.** On your Wi-Fi and over
  Tailscale the watch talks to this computer over an encrypted
  connection, using a certificate the computer made for itself that the
  watch accepts only after the computer has proven it holds your pairing
  key. On the travel address every message is sealed with a key only your
  watch and your computer hold, so Cloudflare carries scrambled data it
  cannot read. In iCloud, a card's details and the pairing key sit in
  encrypted fields locked with your own iCloud Keychain, so Apple cannot
  read them; only the headline and the risk mark stay readable, because
  Apple builds the buzz from them. A watch before 2.1 keeps working,
  unencrypted, until it updates, and the readable iCloud copies it needs
  stop on each Mac once that Mac's watch runs 2.1.
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
  CRITICAL tier can never be. Fail closed: a relay that is down, slow
  or confused never grants an approval.
- **Your key is the boundary, not your Wi-Fi.** Every request for real
  data carries a key that belongs to one device, whichever network it
  arrives on — LAN, tailnet or the travel tunnel. Only processes on the
  computer itself are exempt, and even they cannot post a prompt without
  the key file only your own user account can read: the hook signs each
  card with it and believes an answer only if it proves the key back. On
  a Mac, your watch gets its key through
  your own private iCloud, so it never appears on screen; elsewhere, through
  the first pairing window, which asks at the computer before any key
  leaves. Either way, a stranger on the same café Wi-Fi has no way to get
  it. (Earlier versions trusted anything
  on your local network; that was fine at home and wrong everywhere else,
  and it is fixed.) The travel address is a secret path *and* needs the
  key: seeing the URL is not holding the key. One honest limit remains: a
  program already running as you on your own computer can talk to the local
  relay — Base does not try to defend a machine that is itself
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
  wake-up, stops the relay, forgets the paired watch, removes the Mac
  bridge and its login job, and deletes `~/.tapproval` — as if Base was
  never here. Your audit log stays yours.

## What Base runs, sends, fetches and reads

Anthropic's plugin directory asks every plugin to say this plainly, and
you should not have to read the code to learn it. Nothing on this list
reaches a server of ours; there is none.

**Runs on your computer**

- The hook, `ClaudeRiskClassifier.py`, each time Claude Code asks
  permission. It labels the prompt and offers it to the watch. With no
  watch paired it changes nothing.
- The relay, `watch_relay.py`, started with each session. It listens on
  this computer (ports 8977–8979: loopback, your own network, and the
  travel address's local end) and carries cards out and answers back. The
  dashboard reader, `watch_dashboard.py`, gives the watch your session
  list and the live thread.
- Bonjour (`dns-sd`), so your watch finds this computer on your own Wi-Fi
  without being told an address. Tailscale is used only if you already run
  it.
- On a Mac, the signed and notarized bridge (`TapprovalBridge`, a login
  item), which puts a waiting card into your own private iCloud database so
  a closed watch still buzzes. It ships inside this repository; Base
  downloads no other program.
- `cloudflared`, only if you installed it yourself: it opens the travel
  address for the days your iPhone is off.

**Sends**

- Cards to your watch: the command or file path in question, its risk
  mark, the project folder's name and the question text. Over your Wi-Fi
  or Tailscale, encrypted, to a watch that has proven your pairing key; or
  sealed with that key through the Cloudflare travel address, which carries
  data it cannot read.
- On a Mac, the same card into your own iCloud through the bridge, with
  the details in encrypted fields; only the headline and the risk mark stay
  readable, because Apple builds the buzz from them.
- Nothing else. No telemetry and no analytics. `crash_report.py` sends
  nothing without a mail key, and an installed copy has none.

**Fetches**

- The helper's release list from `api.github.com`, once a day, so the
  watch can say quietly when your copy is a week or more behind. Nothing of
  yours goes with the request. An empty `TAPPROVAL_RELEASES_URL` turns it
  off.
- A terminal install (`install.sh`) fast-forwards its own git checkout
  once an hour. A plugin install is updated by Claude Code, not by Base.

**Reads and writes**

- Reads `~/.claude/settings.json`, to know your own permission rules so the
  wrist shows only what the terminal would have asked; Claude Code's
  transcripts under `~/.claude/projects` and `~/.claude/sessions`, for the
  session list and the live thread; and `~/.codex`, if Codex is in use.
- Writes the audit log `~/.claude/risk-audit.jsonl`, its own files under
  `~/.tapproval`, the hook entry in your Claude Code settings, and on a Mac
  a login job in `~/Library/LaunchAgents` and the bridge's login item.
  "Uninstall Tapproval Base" removes all of it except the audit log, which
  stays yours.

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
| `watch_relay.py` | The relay: the hook posts cards, your watch answers, over your network or an encrypted tunnel; a message from the wrist goes into an open session's own inbox |
| `watch_dashboard.py` | The read-only half: your sessions, the live conversation, and the day's activity |
| `watch_permission_tool.py` | The second way to ask: when work from the watch runs as a separate background run (the session isn't open on your computer, is in bypass or plan mode, or the message is a command), no hook fires, so Claude Code asks this tool, which raises the same card and denies — in words — if nobody answers |
| `crash_report.py` | Records Base's own crashes on your computer and shows them on the watch. Sends nothing without a mail key, and a copy you install has none |
| `bridge_install.py` | On a Mac, installs the bridge below and keeps it current. Trusts only the checksum in `bridge.json`, the Developer ID signature and Apple's notarization |
| `tapproval_wire.py` | The few rules the files above share: how a request is signed and an answer proved, how a plan's formatting reads on the watch, where the helper keeps its files |
| `bridge/` | The Mac bridge's Swift source, and the signed, notarized build of it that the helper installs |
| `bridge.json` | Pins that build: its version, its place in `bridge/` and its SHA-256 |
| `install.sh` / `uninstall.sh` | The one-command installer above, and its way out |
| `.claude-plugin/` + `hooks/` | The same, packaged as a Claude Code plugin |
| `site-rules.example.json` | Optional: name your own sensitive hosts so commands touching them always escalate |
| `test_claude_risk_classifier.py` | The test suite — standard library only |

## Troubleshooting

### Codex approval synchronization — 3.0 preview

The extension in
[#993](https://github.com/marcobelini/tapproval/pull/993) is implemented and
verified locally, with helper publication pending. It lets Codex's native
iPhone approval and the watch card appear together; answering either
clears the other. Command, file-change and terminal-input approvals are
covered. Claude Code keeps its existing approval path.

If cards appear only on the watch, the existing blocking hook may still be
in use: it waits for the watch before Codex can present the iPhone prompt.
The new path needs the updated helper and access to the same running local
Codex app-server as the iPhone session. If it cannot attach, the hook keeps
the existing watch flow. It does not silently approve the request.

An automatic Codex reviewer can approve a call without a human prompt, so
neither device shows a card. To check synchronization, use a separate
manual-review session, open that same session on iPhone, and answer once
on each device while observing the other. Answer any older pending cards
before replacing the helper; a new helper does not answer them for you.

### Connection and helper status

One command says what the helper sees and the one next step:

```bash
python3 ~/.tapproval/ClaudeRiskClassifier.py --status
```

Its *Connection* block names the relay, the iCloud route, whether the away
address answers from the internet, Tailscale, when the watch was last seen,
any problem the helper has noticed (the same sentences the watch's
**Settings → Connection** shows), and the log: `~/.tapproval/logs/relay.log`.
cloudflared's own log, for the away address, is `~/.tapproval/logs/tunnel.log`.
What each row on the watch means, and what to do about it:
https://tapproval.thoughtfulsteward.org/apple-watch-claude-code.html

## Tests

```bash
pytest
```

## Known upstream quirks

One Claude Code behavior can look wrong from the outside and isn't — it
is explained in the watch app the moment it first appears (Settings →
How it works), and tracked upstream as
[anthropics/claude-code#32493](https://github.com/anthropics/claude-code/issues/32493)
and [#89761](https://github.com/anthropics/claude-code/issues/89761).

## The card protocol

The relay's contract is deliberately tiny and agent-agnostic — cards in,
decisions out, over local HTTP. A short spec for third-party agent CLIs
is planned; open an issue if you want to wire another agent to the wrist.

## If it saves you steps

Tapproval Base is one person's side project, no company behind it. There
is nothing to sign up for and nothing to buy here — the whole computer
half is in this repository.

If it earns its place in your setup, the useful thing is to tell one
other person who leaves Claude running unattended:
https://tapproval.thoughtfulsteward.org
