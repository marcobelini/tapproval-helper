"""When the helper breaks, say so — on the wrist, on disk, and by e-mail.

Tapproval has no server and no account, so it cannot copy the shape every
other app here uses (a phone POSTs a crash to a gateway, which mails the
owner). What it has is a long-running process on the owner's own Mac, and
that is enough for the half that matters: the helper's own crashes.

Three things happen, in this order, and the order is the design:

1. **The crash is written to disk**, always, before anything else is
   tried. Pantri shipped to TestFlight with only the push half and the
   owner sent crash reports for weeks that reached nobody — the absence
   of reports looks exactly like the absence of crashes. The file is the
   record; e-mail is only the push.
2. **The wrist is told**, through the conditions registry, so "the helper
   crashed at 12:03" appears on Check connection rather than being
   something you find out by noticing nothing works.
3. **An e-mail is sent**, if and only if this machine has been given a
   key. It never can be on anyone else's: the key is read from a file
   outside the repository, so a public helper clone records and shows
   crashes but silently sends nothing — which is correct, not a bug.

The dedupe, the limits, the fingerprint and the subject line are the same
as the crash routes in the owner's other apps, deliberately: one shape to
remember. Standard library only, like everything else here.

**It never raises.** A reporter that throws inside the crash path destroys
the evidence it exists to preserve.
"""
import getpass
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

# The same limits every other crash route here uses.
MAX_MESSAGE = 500
MAX_STACK = 8000
MAX_SHORT = 120
DEDUPE_WINDOW = 60 * 60          # seconds; one report per fingerprint per hour
MAX_SENDS_PER_WINDOW = 12        # a crash loop tells you nothing the first one did not
SEND_TIMEOUT = 5.0               # the process is usually dying; do not hang it

CRASH_LOG = os.path.expanduser("~/.tapproval-crashes.jsonl")
CRASH_LOG_MAX = 512 * 1024

# The key is never in the repository and never in an argument: a file on
# the owner's own machine, readable only by them. Absent everywhere else,
# which is why a public clone sends nothing.
KEY_FILE = os.path.expanduser("~/.appstoreconnect/resend-key")

# One contact address for the whole project (CLAUDE.md), and the shared
# sending subdomain, with the app in the local part so a report in the
# inbox can be told from another app's.
DEFAULT_TO = "tapproval@thoughtfulsteward.org"
DEFAULT_FROM = "tapproval@send.thoughtfulsteward.org"

# These names carry the app's own prefix, and that is the whole point.
# `RESEND_API_KEY`, `CRASH_REPORT_TO` and `CRASH_REPORT_FROM` are the
# names every app that uses Resend reaches for, so an environment that
# has them set for something else was silently configuring this. Two ways
# that went wrong, both found on 2026-09-10 on a machine that had them
# exported for a sibling project:
#
#   * On a stranger's computer: a `RESEND_API_KEY` they exported for
#     their own work, with no recipient set, meant this helper posted
#     their crash — traceback and all — to Resend under their account,
#     addressed to the author. Resend refuses the send, their account
#     having verified no such domain, but the POST has already left the
#     machine. The privacy policy says nothing reaches us. It has to be
#     true of a machine we did not configure.
#   * On the owner's own: the sibling project's key and inbox were
#     picked up, so `--test` would have reported success while sending
#     through another app's account to another app's mailbox.
#
# A generic name is a shared namespace. This is a config file, not a
# namespace, so it gets its own.
KEY_ENV = "TAPPROVAL_RESEND_API_KEY"
TO_ENV = "TAPPROVAL_CRASH_REPORT_TO"
FROM_ENV = "TAPPROVAL_CRASH_REPORT_FROM"

_seen = {}                       # fingerprint -> {count, first, notified}
_window_start = 0.0
_sent_in_window = 0


def _clip(value, limit):
    text = value if isinstance(value, str) else str(value or "")
    return text[:limit]


def fingerprint(message, stack):
    """One crash's identity: the message and the innermost frame.

    The same two facts every other app here hashes — so the same crash
    from the same place is one report with a count, not forty."""
    frames = [line for line in (stack or "").splitlines()
              if line.strip().startswith('File "')]
    top = frames[-1].strip() if frames else ""
    digest = hashlib.sha256(("%s\n%s" % (message, top)).encode("utf-8"))
    return digest.hexdigest()[:16]


def key_and_source(path=None, env=None):
    """``(key, where_it_came_from)``, or ``(None, None)``.

    The file wins over the environment, which is the opposite of the
    order this had first. `--install-key` writes the file, so the old
    order meant a paste could appear to work and then be ignored by a
    variable the person had forgotten was exported. The thing you just
    did should beat the thing you did months ago.

    The source travels with the key so `--test` can say which one it
    used. It is the key's *origin* that is returned, never the key.
    """
    env = os.environ if env is None else env
    try:
        with open(path or KEY_FILE, "r", encoding="utf-8") as handle:
            from_file = handle.read().strip()
        if from_file:
            return from_file, "the key file"
    except OSError:
        pass
    from_env = (env.get(KEY_ENV) or "").strip()
    if from_env:
        return from_env, "$" + KEY_ENV
    return None, None


def api_key(path=None, env=None):
    """The Resend key, or None. Never logged, never returned in a status."""
    return key_and_source(path, env)[0]


def mail_settings(env=None, key_path=None):
    """``(key, to, from)`` — each None when unset. Honest about absence:
    the reason a report was not sent must be sayable."""
    env = os.environ if env is None else env
    return (api_key(key_path, env),
            (env.get(TO_ENV) or DEFAULT_TO).strip() or None,
            (env.get(FROM_ENV) or DEFAULT_FROM).strip() or None)


def _rotate(path, limit=CRASH_LOG_MAX):
    try:
        if os.path.getsize(path) > limit:
            os.replace(path, path + ".1")
    except OSError:
        pass


def record(entry, path=None):
    """Write the crash down. This is the record; e-mail is the push."""
    path = path or CRASH_LOG
    try:
        _rotate(path)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        os.chmod(path, 0o600)
        return True
    except OSError as error:
        print("crash_report: could not write %s (%s)" % (path, error),
              file=sys.stderr)
        return False


def subject_for(entry, repeats):
    repeat = " (x%d)" % repeats if repeats > 1 else ""
    return ("Tapproval helper %s — crash%s: %s"
            % (entry.get("helper") or "?", repeat,
               _clip(entry.get("message"), 80))).replace("\n", " ")


def body_for(entry, count, first):
    where = {"thread": "in a background thread — the relay kept running",
             "process": "on the main path — the process stopped",
             "hook": "inside the Claude Code hook"}.get(
                 entry.get("source"), entry.get("source") or "unknown")
    lines = [
        "Helper:   Tapproval %s" % (entry.get("helper") or "unknown version"),
        "Where:    %s" % where,
        "Machine:  %s" % (entry.get("platform") or "unknown"),
        "Python:   %s" % (entry.get("python") or "unknown"),
        "Time:     %s" % (entry.get("at") or ""),
    ]
    if count > 1:
        lines.append("Repeats:  %d within the last hour" % count)
    lines += ["", entry.get("message") or "",
              "", entry.get("stack") or "(no traceback — not much to go on)"]
    return "\n".join(lines)


def send(entry, count, first, settings=None, opener=None):
    """POST one report to Resend. Returns a reason string, never raises."""
    key, to, sender = settings or mail_settings()
    if not (key and to and sender):
        return "mail_not_configured"
    payload = json.dumps({
        "from": sender, "to": [to],
        "subject": subject_for(entry, count),
        "text": body_for(entry, count, first),
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://api.resend.com/emails", data=payload,
        headers={"Authorization": "Bearer " + key,
                 "Content-Type": "application/json"})
    try:
        with (opener or urllib.request.urlopen)(
                request, timeout=SEND_TIMEOUT) as reply:
            return "sent" if 200 <= reply.status < 300 else "send_failed"
    except Exception as error:                       # never from a crash path
        # Resend refuses a from-address on a domain it has not verified, and
        # the refusal must be visible: a silent failure here is precisely the
        # state that looked like "no crashes" for weeks.
        print("crash_report: send failed (%s)" % error, file=sys.stderr)
        return "send_failed"


def report(message, stack, source="process", helper=None, now=None,
           settings=None, opener=None, path=None, note=None):
    """Record one crash, tell the wrist, and e-mail it if this machine can.

    Returns ``(reason, entry)``. Never raises: every failure inside is
    caught and named, because the caller is already handling a crash.
    """
    try:
        global _window_start, _sent_in_window
        stamp = time.time() if now is None else now
        entry = {
            "at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(stamp)),
            "source": _clip(source, MAX_SHORT),
            "message": _clip(message, MAX_MESSAGE),
            "stack": _clip(stack, MAX_STACK),
            "helper": _clip(helper or "unknown", MAX_SHORT),
            "platform": _clip(sys.platform, MAX_SHORT),
            "python": _clip(sys.version.split()[0], MAX_SHORT),
        }
        record(entry, path=path)
        if note:
            try:
                note(entry)
            except Exception:
                pass

        if stamp - _window_start > DEDUPE_WINDOW:
            _window_start, _sent_in_window = stamp, 0
            _seen.clear()
        key = fingerprint(entry["message"], entry["stack"])
        seen = _seen.setdefault(key, {"count": 0, "first": stamp,
                                      "notified": False})
        seen["count"] += 1
        if seen["notified"]:
            return "duplicate", entry
        if _sent_in_window >= MAX_SENDS_PER_WINDOW:
            return "rate_limited", entry

        reason = send(entry, seen["count"], seen["first"],
                      settings=settings, opener=opener)
        if reason == "sent":
            seen["notified"] = True
            _sent_in_window += 1
        return reason, entry
    except Exception as error:                       # the last line of defence
        print("crash_report: reporter itself failed (%s)" % error,
              file=sys.stderr)
        return "reporter_failed", {}


def install_key(text, path=None):
    """Store a Resend key, readable by nobody else. Never echoes it.

    The key is the one thing in this whole path that a person has to
    provide, so the step is one command and the value never passes through
    a shell argument (where it would land in the history) or a log.
    """
    path = path or KEY_FILE
    key = (text or "").strip()
    # Take what a person's clipboard actually holds. Copying a key out of
    # a dashboard, a .env line or a shell export brings decoration with
    # it, and none of it is the person making a mistake.
    if "=" in key.split("\n")[0][:40]:
        key = key.split("=", 1)[1].strip()      # RESEND_API_KEY=re_…
    key = key.strip("\"'").strip()             # "re_…" or 're_…'
    if not key:
        return "nothing on the clipboard — copy the key first"
    # Case-insensitively, because on 2026-09-10 a real key of the owner's
    # began "Re_" and this refused it — a validator that rejects the very
    # thing it exists to accept, with a message insisting on the form it
    # had just been handed. The prefix is here to catch a URL or a command
    # pasted by accident, not to police capitalisation.
    if not key.lower().startswith("re_"):
        # Say what arrived without printing it: a length and a shape are
        # enough to tell "I copied the wrong thing" from "it is right and
        # this is broken", and neither leaks the key if it was one.
        return ("that does not look like a Resend key: %d characters, "
                "starting %r. They begin with re_." % (len(key), key[:3]))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "w") as out:
            out.write(key + "\n")
        os.chmod(path, 0o600)
    except OSError as error:
        return "could not write %s (%s)" % (path, error)
    return "stored in %s, readable only by you" % path


def selftest(settings=None, opener=None, path=None):
    """Send one real report and say exactly what happened.

    Resend refuses a from-address on a domain it has not verified, and a
    crash path must swallow that refusal — which is why the failure of
    this whole idea looks like silence. This is the one place that asks
    out loud.
    """
    key, to, sender = settings or mail_settings()
    _key, source = key_and_source(path=None) if settings is None else (key, "the settings given")
    # Say the route before saying the result. A report that arrives is not
    # proof it went where you meant: on 2026-09-10 this machine had a
    # sibling project's key and inbox in its environment, and a "sent"
    # naming neither would have been believed.
    route = "using %s, addressed to %s from %s" % (source or "no key", to, sender)

    reason, _entry = report(
        "Test report from the Tapproval helper",
        "No traceback: this is the check that the path works, run by hand.",
        source="selftest", helper=os.environ.get("TAPPROVAL_VERSION", "helper"),
        settings=settings, opener=opener, path=path)
    if reason == "sent":
        return 0, "sent %s — look in that inbox" % route
    if reason == "mail_not_configured":
        missing = [name for name, value in (("a key", key), (TO_ENV, to),
                                            (FROM_ENV, sender)) if not value]
        return 1, ("not sent: %s missing. The crash is on disk either way."
                   % ", ".join(missing))
    return 1, ("not sent (%s), %s. The message above from Resend says why — an "
               "unverified sending domain is the usual answer." % (reason, route))


def key_from_stdin(stream=None, ask=None):
    """The key, from a pipe or from a person, whichever is there.

    `pbpaste | … --install-key` stays the one-liner. But somebody who
    runs the command on its own — because the key is in a password
    manager, or because the clipboard held the wrong thing a moment ago —
    used to get sys.stdin.read() against a terminal: no prompt, no
    cursor, waiting for a Ctrl-D nobody was told about. That is
    indistinguishable from a hang, and it is why this grew a second way
    in.

    On a terminal the key is asked for and not echoed. A pasted key still
    arrives in full; it simply does not appear on screen, and does not
    reach the scrollback of a shared terminal or a screen recording.
    """
    stream = sys.stdin if stream is None else stream
    if getattr(stream, "isatty", lambda: False)():
        ask = ask or getpass.getpass
        return ask("Paste the Resend key and press return "
                   "(it will not be shown): ")
    return stream.read()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--install-key"]:
        print(install_key(key_from_stdin()))
        return 0
    if argv[:1] == ["--test"]:
        code, said = selftest()
        print(said)
        return code
    print(__doc__.strip().splitlines()[0])
    print("\n  python3 crash_report.py --install-key      "
          "# asks for the key, does not echo it"
          "\n  pbpaste | python3 crash_report.py --install-key"
          "\n  python3 crash_report.py --test")
    return 0


def _reset_for_tests():
    global _window_start, _sent_in_window
    _seen.clear()
    _window_start, _sent_in_window = 0.0, 0


if __name__ == "__main__":
    sys.exit(main())
