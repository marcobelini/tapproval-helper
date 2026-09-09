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


def api_key(path=None):
    """The Resend key, or None. Never logged, never returned in a status."""
    from_env = os.environ.get("RESEND_API_KEY")
    if from_env:
        return from_env.strip() or None
    try:
        with open(path or KEY_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def mail_settings(env=None, key_path=None):
    """``(key, to, from)`` — each None when unset. Honest about absence:
    the reason a report was not sent must be sayable."""
    env = os.environ if env is None else env
    return (api_key(key_path),
            (env.get("CRASH_REPORT_TO") or DEFAULT_TO).strip() or None,
            (env.get("CRASH_REPORT_FROM") or DEFAULT_FROM).strip() or None)


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


def _reset_for_tests():
    global _window_start, _sent_in_window
    _seen.clear()
    _window_start, _sent_in_window = 0.0, 0
