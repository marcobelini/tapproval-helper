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
  relay.** Base does not defend against a compromised machine: such a
  process can read the key file too. Another account on the same Mac
  cannot, and neither can a port-forward into it: loopback alone opens only
  `/health`, and everything else takes the key file, which only your own
  user account can read. A prompt needs it as well: the hook signs each card with it and believes an answer only
  if it proves the key back.
- **The audit log records command text** (with credential-shaped fragments
  redacted) and stays on your computer.
- **A message from the wrist can become a turn of a session you have
  open.** It is written to that session's inbox socket only if the socket
  sits in Claude Code's own socket folder, is a real socket rather than a
  link, is owned by you, and is held by that session's own process. It
  then runs under that session's permission mode and hook. It is never
  posted to a session in bypass or plan mode, and a command is never
  posted there.
- **Cards travel through your own private iCloud or a tunnel** when you
  are away from home. The tunnel carries them in transit only; in iCloud a
  card waits in your own private database until it is answered.
- **Encryption needs watch app 2.1.** From 2.1, with a helper of 1.1.74 or
  later: on the local network and the tailnet the watch uses TLS to the
  helper's own certificate, which it learns only from an answer carrying
  the relay's proof and then pins per host; on the travel tunnel, where
  Cloudflare ends TLS, each body is sealed end to end (ChaCha20-Poly1305,
  key derived from the device key, bound to method and path), so
  Cloudflare sees only ciphertext. Request signing stays on every direct
  road. In iCloud, with Mac bridge 1.0.2, a card's details, the device key
  and the certificate fingerprint are in CloudKit's encrypted fields; the
  headline and risk tier stay readable, because Apple builds the
  notification from them. **What is accepted, for now:** the helper keeps
  its plain listener and plain tunnel bodies for watches before 2.1, and
  writes readable iCloud copies on a Mac until that Mac's own watch has
  shown it runs 2.1 (bridge 1.0.3). On those paths a watch before 2.1 is
  protected by the signing alone: someone who can see the traffic, such
  as Cloudflare on the tunnel or Apple in iCloud without Advanced Data
  Protection, could read what it carries. Closing the plain paths is a
  later release's decision.
- **On the iCloud route, your Apple ID is the key.** With the Mac bridge
  the helper installs on a Mac, the watch learns its first key from your
  private iCloud, and
  answers can travel back the same way. Anyone who controls your Apple ID
  could therefore answer a prompt. Protect it with two-factor
  authentication. A second key stored beside the first would add nothing,
  and a key kept anywhere else would end automatic pairing.
- **Once the watch shows the terminal's row (the helper is ready since
  1.1.57), "don't ask again" on the watch writes what the terminal's
  would.** The terminal's words appear only where Claude Code itself
  offers the row, and the tap writes only what that row applies: a rule
  for the exact command (or the web host) in the project's
  `.claude/settings.local.json`, or a switch to accept edits for this
  session. Never to your user or shared project settings, never on a
  CRITICAL card, and never anything Base cannot read word for word. Until
  then the watch offers "Always allow for this session", which the relay
  remembers until it restarts and which writes nothing.

## The Mac bridge

On a Mac, the helper installs a small app, the bridge, which copies each
waiting card into your own private iCloud and carries your answers back.
It holds the helper's key file and mirrors the device key into that same
private database, which only your Apple Account can read.

- **What is trusted, in order.** The SHA-256 in `bridge.json`, for the
  zip that ships inside the helper in `bridge/` (nothing is downloaded from
  anywhere else);
  a code requirement that `codesign` checks: Apple's chain, a Developer ID
  Application certificate, team `K2RX2Y5896` and bundle id
  `app.tapproval.bridge`; and Gatekeeper's "Notarized Developer ID". A
  copy that fails any of these is thrown away, and the bridge already
  there keeps running.
- **Not reproducible.** The bridge is built, signed and notarized on the
  developer's Mac, so a copy cannot be rebuilt bit for bit from the source
  in `bridge/`. The source is published so it can be read; the signature
  and Apple's notarization are what tie a download to that developer.
- **Check a copy by hand:**

  ```bash
  shasum -a 256 ~/.tapproval/bridge/TapprovalBridge-*.zip   # compare with bridge.json
  # on a plugin install the zip is under
  # ~/.claude/plugins/cache/tapproval/tapproval-helper/*/bridge/
  codesign -dv ~/.tapproval/bridge-app/TapprovalBridge.app   # TeamIdentifier=K2RX2Y5896
  spctl -a -t exec -vv ~/.tapproval/bridge-app/TapprovalBridge.app  # Notarized Developer ID
  ```

- **Turning it off.**
  `python3 ~/.tapproval/ClaudeRiskClassifier.py --install --no-bridge`
  removes it and keeps it out; `uninstall.sh` removes it with everything
  else.

## Design rules we will not trade away

- Loopback alone opens only `/health`; a local caller shows the key file, and every other caller presents a device key.
- The travel tunnel's secret path is an address, never a credential.
- A watch learns the helper's certificate only from an answer the relay
  has proven, never from the network alone.
- Failure is closed: anything unparsed, unreachable or ambiguous ends in the
  prompt appearing where it always would.
