# Security

Tapproval Base decides whether a tool call reaches you or runs, so a bug
here is a bug in someone's permission boundary. Reports are welcome and
will be taken seriously.

## Reporting

Open a [private security advisory](https://github.com/marcobelini/tapproval-helper/security/advisories/new),
or e-mail **security@thoughtfulsteward.org** if you would rather not use
GitHub. Please include what you did, what happened, and what you expected.

You will get an acknowledgement within a few days. This is a small project
with one maintainer, so there is no bounty — only credit, if you want it,
and a fix.

## What counts

- Anything that makes the classifier auto-allow a call it should escalate.
  `CRITICAL` must never be auto-allowed, whatever the configuration says.
- Anything that lets a party who is not the owner read session data, answer
  a prompt, forge a card, or send text into a live session.
- Anything that leaks a key, a transcript, or command text off the machine
  by a route the README does not describe.

## What is known and accepted

- **A process running as you, on your machine, can talk to the local
  bridge.** Base does not defend against a compromised machine; the loopback
  exemption is what lets Claude Code hand it a prompt in the first place.
- **The audit log records command text** (with credential-shaped fragments
  redacted) and stays on your computer.
- **Cards travel through your own private iCloud or an encrypted tunnel**
  when you are away from home, in transit only.

## Design rules we will not trade away

- Loopback is the only exemption; every other caller presents a device key.
- The travel tunnel's secret path is an address, never a credential.
- Failure is closed: anything unparsed, unreachable or ambiguous ends in the
  prompt appearing where it always would.
