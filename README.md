# Tapproval helper

**The computer half of [Tapproval](https://github.com/marcobelini/tapproval-helper)
— answer Claude Code from your Apple Watch.**

When Claude Code works on your computer, it stops and asks before doing
anything that needs permission. The Tapproval watch app puts those
questions on your wrist; this helper is the small bridge on the computer
that makes it possible. It is open source on purpose: a tool that reads
your sessions and carries your approvals should be auditable.

## Install (one command, then forget it)

On the computer where Claude Code runs — any Mac or Linux machine, a
laptop counts:

```bash
curl -fsSL https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.sh | bash
```

That registers the permission hook and wires the relay to start itself
with every Claude Code session. There is nothing to keep running by
hand. Then install **Tapproval** on your Apple Watch and open it once on
the same Wi-Fi — it finds this computer by itself, pairs automatically,
and quietly learns how to reach it when you're away from home.

## What the helper is

| File | Purpose |
|------|---------|
| `ClaudeRiskClassifier.py` | A Claude Code `PermissionRequest` hook: mirrors exactly the prompts the phone shows, labels each with a risk tier, and offers them to the watch |
| `watch_relay.py` | A tiny local HTTP bridge: the hook posts cards, the watch answers; also serves your sessions, live conversation and daily activity |
| `install.sh` | The one-command installer above |
| `site-rules.example.json` | Optional: name your own sensitive hosts so commands touching them always escalate |
| `test_claude_risk_classifier.py` | The test suite — standard library only |

Standard-library Python throughout: no dependencies, nothing to update,
no accounts, no servers. Your prompts and conversations never leave your
own machines — the away-from-home path runs through your own iCloud,
private to your Apple ID.

## Security model, briefly

- Your own networks are the trust boundary: the relay answers your LAN
  and tailnet. Beyond them every request must carry the pairing key the
  watch received on first local contact, and the optional travel tunnel
  hides behind its own secret path.
- The hook talks to the relay over loopback only, and nothing is ever
  auto-allowed by default — the risk tiers are labels for your glance,
  not decisions made for you. Every decision lands in a local audit log
  you can read.
- Fail closed: a relay that is down, slow or confused never grants an
  approval.

## Tests

```bash
pytest
```

## Known upstream quirks

Two Claude Code behaviors can look wrong from the outside and aren't —
they are explained in the watch app the moment they first appear
(Settings → Known quirks), and tracked upstream as
[anthropics/claude-code#32493](https://github.com/anthropics/claude-code/issues/32493)
and [#89761](https://github.com/anthropics/claude-code/issues/89761).

## The card protocol

The relay's contract is deliberately tiny and agent-agnostic — cards in,
decisions out, over local HTTP. A short spec for third-party agent CLIs
is planned; open an issue if you want to wire another agent to the wrist.
