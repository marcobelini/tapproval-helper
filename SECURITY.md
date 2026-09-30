# Security

Tapproval Base decides whether a tool call reaches you or runs, so a bug
here is a bug in someone's permission boundary. Reports are welcome and
will be taken seriously.

## Reporting

Open a [private security advisory](https://github.com/marcobelini/tapproval-helper/security/advisories/new),
or e-mail **tapproval@thoughtfulsteward.org** if you would rather not use
GitHub. Please include what you did, what happened, and what you expected.

You will get an acknowledgement within a few days. This is a small project
with one maintainer, so there is no bounty — only credit, if you want it,
and a fix.

## Disclosure

A fix comes first, then the account of it. Once a fixed release is out,
what was wrong, since when, who could have used it and the fix are written
up on the [security page](https://tapproval.thoughtfulsteward.org/security.html)
and in the release notes. If you reported it, we agree the date with you,
and it is no later than 90 days after your report unless you ask for
longer. A problem that is not yet fixed is not described in public.

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
- **On the iCloud route, your Apple ID is the key.** With the optional Mac
  bridge, the watch learns its first key from your private iCloud, and
  answers can travel back the same way. Anyone who controls your Apple ID
  could therefore answer a prompt. Protect it with two-factor
  authentication. A second key stored beside the first would add nothing,
  and a key kept anywhere else would end automatic pairing.

## Design rules we will not trade away

- Loopback is the only exemption; every other caller presents a device key.
- The travel tunnel's secret path is an address, never a credential.
- Failure is closed: anything unparsed, unreachable or ambiguous ends in the
  prompt appearing where it always would.
