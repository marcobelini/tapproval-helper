#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch_relay — the local go-between for the risk classifier and Tapproval.

The classifier hook decides *what* deserves a human; this relay carries the
question to whatever screen the human is wearing. It is a standard-library
HTTP server:

    hook  ── POST /card ────►  relay  ◄──── GET  /pending ──  watch app
          ◄─ blocks for the       │   ◄──── POST /decision ─
             decision ────────────┘

The core of it:

    POST /card      {"card": {...}, "wait": seconds}
                    Queues a wrist card and blocks until the watch answers
                    or the wait expires. Responds {"id", "decision"} where
                    decision is "allow", "deny" or "none" (timed out), with
                    an "answer" for a question and a "dont_ask" flag for the
                    terminal's "don't ask again" row. Loopback only, and
                    signed with the 0600 key file; the hook believes only an
                    answer that proves that key back.
    GET  /pending   {"cards": [{...}, ...]} — what the watch should show.
    POST /decision  {"id": "...", "decision": one of VALID_DECISIONS}
    GET  /health    {"ok": true, "pending": n, ...}

Around it are the session list, threads, usage and activity the watch reads,
sending from the wrist (/say, /new), pairing and enrolment, and admin routes
for the key-file holder. ROUTES is the full table, with each route's rules.

Run it::

    python3 watch_relay.py                # serve on 127.0.0.1:8977
    python3 watch_relay.py --demo         # serve + inject sample cards
    python3 watch_relay.py --card "rm -rf build"   # inject one real card

The login job and --ensure serve on every interface (--host 0.0.0.0) with
the travel tunnel, so a watch can reach it over the LAN, a tailnet or the
tunnel. Only loopback is exempt from the device key, and only for what a
local process needs; every other caller must present a paired device's
key, whatever its address.

Design rules follow the classifier's: standard library only, and fail
closed — a relay that is down, slow or confused must never grant an
approval. "none" is the only answer it gives on any doubt.
"""

from __future__ import annotations

import argparse
import errno
import hmac
import glob
import json
import shlex
import functools
import os
import re
import select
import signal
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict, deque
from contextlib import contextmanager, nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import tapproval_host as _host
import tapproval_wire as wire

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8977          # also referenced by the classifier's --watch/--status
TUNNEL_PORT = 8978
# The encrypted listener for the watch on the home network and the tailnet
# (#645 S4, the owner's decision of 2026-10-23). The plain one on
# DEFAULT_PORT stays for loopback, and for watches from before 2.1 until
# the owner closes that door.
TLS_PORT = 8979
# The helper's own files live in ~/.tapproval/data and ~/.tapproval/logs,
# beside its code. Until 1.1.60 they lay loose in the home folder as
# ~/.tapproval-*; the relay moves each one once (move_loose_files), and
# until it has, every reader and writer uses the file where it is.
# ClaudeRiskClassifier.py and crash_report.py spell the same rule out
# again, because each must stand alone.
TAPPROVAL_DIR = os.path.expanduser("~/.tapproval")
LEGACY_HOME = os.path.expanduser("~")


def home_file(folder, name, legacy):
    """Where one of the helper's files is: ~/.tapproval/<folder>/<name>,
    unless only the old loose file ~/<legacy> exists yet."""
    return wire.home_file(folder, name, legacy, TAPPROVAL_DIR, LEGACY_HOME)


# Every file the helper once left loose in the home folder: (folder, name,
# the old loose name). The key, the away address and the logs are the ones
# that matter; the pid file and the update stamp only tidy up.
LOOSE_FILES = (
    ("data", "auth.json", ".tapproval-auth.json"),
    ("data", "tunnel.json", ".tapproval-tunnel.json"),
    ("data", "relay.pid", ".tapproval-relay.pid"),
    ("data", "last-update", ".tapproval-last-update"),
    ("data", "crashes.jsonl", ".tapproval-crashes.jsonl"),
    ("logs", "relay.log", ".tapproval-relay.log"),
    ("logs", "tunnel.log", ".tapproval-tunnel.log"),
    ("logs", "say.log", ".tapproval-say.log"),
)

# The paths this module holds, by global name: (its file in LOOSE_FILES,
# the environment variable that may choose it instead). Read at import and
# again by _use_moved_files once the files have moved, so the two can
# never disagree about where a file is.
_HOME_PATHS = {
    "AUTH_FILE": ("auth.json", None),
    "PID_FILE": ("relay.pid", "TAPPROVAL_PID_FILE"),
    "RELAY_LOG": ("relay.log", None),
    "SAY_LOG": ("say.log", None),
    "_UPDATE_STAMP": ("last-update", "TAPPROVAL_UPDATE_STAMP"),
    "TUNNEL_STATE": ("tunnel.json", "TAPPROVAL_TUNNEL_STATE"),
    "TUNNEL_LOG": ("tunnel.log", None),
}


def _loose_file(name):
    """home_file() for one of LOOSE_FILES, by its name."""
    for folder, file_name, legacy in LOOSE_FILES:
        if file_name == name:
            return home_file(folder, file_name, legacy)
    raise KeyError(name)


def _home_path(global_name):
    """Where the file a global names is now. A variable's choice wins."""
    name, variable = _HOME_PATHS[global_name]
    return (variable and os.environ.get(variable)) or _loose_file(name)


# The key file: every paired device's key, mode 0600. The Mac bridge
# reads it too, which is why it moves only once the bridge can find it
# (_bridge_reads_data_dir).
AUTH_FILE = _home_path("AUTH_FILE")
# Bumped whenever the wire contract or the auth rules change, so a running
# relay from before an update can be recognised — and replaced — instead of
# quietly serving the old rules forever (see ensure_running).
RELAY_VERSION = 5
PAIR_WINDOW_SECONDS = 600   # a deliberately opened window, not a standing door
PAIR_WINDOW_CLAIMS = 2      # one watch, plus one retry
PAIR_FIRST_WINDOW_SECONDS = 1800   # never paired: half an hour, re-lit by every session start
PAIR_ASK_SECONDS = 120      # how long the Mac's "Allow a watch?" question waits for a click
PAIR_CONSENT_SECONDS = 120  # how long an Allow lets that address claim its key
DEFAULT_WAIT = 6.0     # how long POST /card blocks by default
try:
    # One number, one owner: the hook's wait, its timeout and this clamp
    # must move together, or cards expire on the wrist while the terminal
    # keeps waiting. Same directory, stdlib-only either way.
    from ClaudeRiskClassifier import RELAY_WAIT_SECONDS as MAX_WAIT
    from ClaudeRiskClassifier import __version__ as HELPER_VERSION
    MAX_WAIT = float(MAX_WAIT)
except Exception:                                  # standalone deployment
    # The hook's own number, written once more: 3600 here let a relay that
    # could not import the hook drop a card after an hour while the hook
    # still waited a day (2026-10-17 tech-debt review, item 3). A test
    # holds the two equal; `helper` says the import failed.
    MAX_WAIT = 86400.0
    HELPER_VERSION = "unknown"


_PROVENANCE = None


def install_crash_reporting():
    """Make the helper's own crashes visible instead of silent.

    A thread that dies takes its job with it — the advertiser stops
    announcing, the resolver stops resolving — and the relay carries on
    answering, so nothing looks wrong until something you needed did not
    happen. That is the crash worth catching here, which is why
    ``threading.excepthook`` matters more than the process one: after it,
    there is still a wrist to tell.

    Chains rather than replaces. Swallowing a fatal error turns a visible
    crash into a frozen process, which is harder to report, not easier.
    """
    try:
        import crash_report
    except Exception as error:                       # never blocks a start
        print("relay: crash reporting unavailable (%s)" % error, file=sys.stderr)
        return False

    def _wrist(entry):
        note_condition("crash", "Tapproval's helper hit a problem it did not "
                       "expect (%s). It is written down on the computer; "
                       "restarting Claude Code clears this."
                       % entry.get("message", "")[:80])

    previous_thread = threading.excepthook
    previous_process = sys.excepthook

    def on_thread(args):
        stack = "".join(traceback.format_exception(
            args.exc_type, args.exc_value, args.exc_traceback))
        crash_report.report("%s: %s" % (args.exc_type.__name__, args.exc_value),
                            stack, source="thread", helper=HELPER_VERSION,
                            note=_wrist)
        previous_thread(args)

    def on_process(kind, value, tb):
        stack = "".join(traceback.format_exception(kind, value, tb))
        crash_report.report("%s: %s" % (kind.__name__, value), stack,
                            source="process", helper=HELPER_VERSION)
        previous_process(kind, value, tb)

    def on_request(kind, value, tb):
        stack = "".join(traceback.format_exception(kind, value, tb))
        crash_report.report("%s: %s" % (kind.__name__, value), stack,
                            source="request", helper=HELPER_VERSION, note=_wrist)

    global _ON_HANDLER_ERROR
    threading.excepthook = on_thread
    sys.excepthook = on_process
    _ON_HANDLER_ERROR = on_request
    return True


def _head_commit(root):
    """The full commit id a checkout's HEAD names, read from the files.

    No git, no subprocess: HEAD, then the ref it points at, then
    packed-refs. This is the half of the receipt that must not fail — the
    relay compares it against the checkout's to decide whether the code
    moved underneath it (`_serving_older_code`). None when it cannot be
    read. Never raises.
    """
    git = os.path.join(root, ".git")
    try:
        with open(os.path.join(git, "HEAD"), encoding="utf-8") as handle:
            head = handle.read().strip()
        if not head.startswith("ref: "):
            return head if re.fullmatch(r"[0-9a-f]{40}", head) else None
        ref = head[len("ref: "):]
        loose = os.path.join(git, *ref.split("/"))
        if os.path.exists(loose):
            with open(loose, encoding="utf-8") as handle:
                sha = handle.read().strip()
                return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None
        with open(os.path.join(git, "packed-refs"), encoding="utf-8") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except (OSError, ValueError):
        return None
    return None


def helper_provenance(here=None):
    """``(commit, date)`` of a git-installed helper, or ``(None, None)``.

    The version number is a claim; this is the receipt. On 2026-09-08 the
    wrist ran a helper four days behind the repository while /health said
    v1.1.1 — the same v1.1.1 the app expected — because two thousand
    changed lines had not moved the number. The watch shows this date on
    the Connection screen, so "the helper is old" is something a person can
    see rather than something the number would have to admit.

    The commit is read from `.git` itself, not asked of git. On 2026-09-23
    a relay started at login answered `helper_commit: null` although git
    worked in that very environment when tried later — a subprocess with a
    five-second timeout at the busiest moment of a boot is the likeliest
    culprit, and it failed in silence. That null did more than blank a
    line on the wrist: it switched off the retry of a deferred update,
    which needs the commit to compare. So the commit never depends on git,
    the date (which only git can give without parsing packfiles) gets a
    longer wait, and when git does fail the log says how.

    Read once, by main() before serving: the checkout does not move
    underneath a running relay (an update replaces the process), and a
    request handler must not be the thing that runs git. A plugin install
    has no ``.git`` and answers nothing, honestly. Never raises.
    """
    global _PROVENANCE
    root = here or os.path.dirname(os.path.abspath(__file__))
    found = (None, None)
    if os.path.exists(os.path.join(root, ".git")):
        full = _head_commit(root)
        short, date = (full[:7] if full else None), None
        try:
            done = subprocess.run(
                ["git", "-C", root, "log", "-1", "--format=%h %cI"],
                capture_output=True, text=True, timeout=20)
            parts = done.stdout.split()
            if done.returncode == 0 and len(parts) == 2:
                short, date = (short or parts[0]), parts[1]
            else:
                print("relay: could not read this checkout's date from git "
                      "(exit %s): %s" % (done.returncode,
                                         (done.stderr or "").strip()[:200]),
                      file=sys.stderr)
        except Exception as error:                         # never blocks a start
            print("relay: could not read this checkout's date from git: %s"
                  % error, file=sys.stderr)
        found = (short, date)
    if here is None:
        _PROVENANCE = found
    return found
MAX_BODY = 256 * 1024   # a wrist message of SEND_CHARS in any script, with room
ANSWER_CHARS = 2000   # a wrist answer's words; ClaudeRiskClassifier.ANSWER_CHARS
# The most of one message sent from the wrist (/say, /new). Longer is
# refused with the count, never cut: until 2026-10-16 the cap was 500 and
# silent, and a dictated brief lost its second half. The watch carries the
# same number (RelayModel.sendChars) and refuses before sending; the thread
# view keeps a user turn of this length whole (watch_dashboard.TURN_CHARS),
# so the echo of a long message still finds its turn. The ceiling behind
# this one is the transcript reader's bound on one line (32768), and the
# suite holds the chain.
SEND_CHARS = 30000

VALID_DECISIONS = ("allow", "deny", "answer", "always", "dont_ask")
# What a card id looks like: twelve lowercase hex digits, the relay's own
# or the hook's (#795).
CARD_ID = re.compile(r"^[0-9a-f]{12}$")

# The Bonjour service type the watch app browses for.
BONJOUR_TYPE = "_wristtriage._tcp"


# --------------------------------------------------------------------------
# Conditions: what is quietly wrong right now
# --------------------------------------------------------------------------
#
# Several things degrade this relay without breaking it — Bonjour not
# advertising, the off-Wi-Fi tunnel missing, the helper not importable. Each
# was reported by one line on stderr, which lands in a log file on a Mac
# nobody is looking at. That is the same as not reporting it, and it is what
# issue #38 is about: the whole presentation of the failure is nothing
# happening.
#
# A condition recorded here rides /health to the watch, which is the only
# screen the user actually looks at. The relay sends the sentence and not
# only a key, so a condition invented by a newer relay still reads correctly
# on a watch app that has never heard of it.
#
# Each also carries a tone, so the watch can draw it as what it is:
#   "needs_you" — only the person can fix it, and the sentence says how.
#                 The default, and where anything unrecognised lands.
#   "in_hand"   — news: the relay is already dealing with it and nothing is
#                 asked of the person. Used sparingly, and only at the sites
#                 TestConditionsCarryATone lists, so a condition that needs
#                 somebody is never drawn as one that does not.

CONDITION_TONES = ("needs_you", "in_hand")

_CONDITIONS = {}
_CONDITIONS_LOCK = threading.Lock()


def note_condition(key, detail, tone="needs_you"):
    """Record something degraded, and say it on stderr the first time.

    Re-noting the same detail is silent: a warning that repeats on every
    retry teaches the reader to skip warnings. A tone nobody defined is
    read as needs_you: fail toward the person's attention.
    """
    if tone not in CONDITION_TONES:
        tone = "needs_you"
    with _CONDITIONS_LOCK:
        repeated = _CONDITIONS.get(key, (None, None))[0] == detail
        _CONDITIONS[key] = (detail, tone)
    if not repeated:
        print("relay: %s" % detail, file=sys.stderr)


def clear_condition(key):
    """Withdraw a condition that has since resolved. Never raises."""
    with _CONDITIONS_LOCK:
        _CONDITIONS.pop(key, None)


def conditions():
    """Everything currently wrong, key order, for /health and the tests."""
    with _CONDITIONS_LOCK:
        return [{"key": key, "detail": detail, "tone": tone}
                for key, (detail, tone) in sorted(_CONDITIONS.items())]


# The admin routes that only say something about this relay, or take it
# back: a process here tells the relay, and /health carries it to the
# wrist. Each entry stays a literal call, so the tests that read every
# condition this file can note (its key, its tone) still see these.
ADMIN_CONDITIONS = {
    # The launcher found a newer helper but a card is pending, so it left
    # this relay in place. That used to be one line on stderr, in a log on
    # a Mac nobody is looking at, while the machine ran yesterday's rules.
    # It clears itself: the only resolution is being replaced, and the
    # replacement starts with nothing recorded. Worded to stay true after
    # the card is answered: the deferral ends only at the next session
    # start, and a sentence that said "a card is pending" would sit on the
    # wrist, false, for the rest of a long session.
    "/admin/update-deferred": lambda: note_condition(
        "update",
        "A newer helper is waiting to take over. It will replace this one "
        "the next time Claude Code or Codex starts with no card waiting.",
        tone="in_hand"),
    # The hourly pull failed in a way the next one will repeat (a diverged
    # clone, local edits in the way). Fixed wording, no body: what git said
    # goes to the log, not to the wrist.
    "/admin/update-stuck": lambda: note_condition(
        "stuck",
        "The helper on this computer can no longer update itself, so it "
        "will miss fixes. Ask Claude Code to reinstall Tapproval's helper."),
    "/admin/update-unstuck": lambda: clear_condition("stuck"),
    # The detached --bridge-update could not install the pinned bridge.
    # Fixed wording, no body, like update-stuck: why goes to the bridge's
    # install.log, not to the wrist.
    "/admin/bridge-failed": lambda: note_condition(
        "bridge_install",
        "Tapproval could not set up its iCloud bridge on this computer, so "
        "your watch may not buzz while Tapproval is closed. It tries again "
        "within the hour while Claude Code runs."),
    "/admin/bridge-ok": lambda: clear_condition("bridge_install"),
}


def check_helper_is_visible():
    """Record whether the classifier could be imported beside this relay.

    Three lines inside main() to begin with, which left it the one
    condition no test could fire — and a reporting path nobody has seen
    fire is exactly what issue #38 says is not a check.
    """
    if HELPER_VERSION == "unknown":
        note_condition(
            "helper",
            "This relay cannot see the Tapproval helper on this computer, "
            "so it cannot tell you which version is running.")
        return False
    clear_condition("helper")
    return True


def lan_ips():
    """This machine's LAN addresses (never the tailnet). Never raises."""
    import socket
    # `ipconfig getifaddr` is the Mac's: Windows has an ipconfig too, which
    # prints its usage, and that text was published as the address.
    for iface in ("en0", "en1", "en2", "en3") if _host.is_mac() else ():
        try:
            out = subprocess.run(["ipconfig", "getifaddr", iface],
                                 capture_output=True, text=True, timeout=2)
            ip = (out.stdout or "").strip() if getattr(out, "returncode", 0) == 0 else ""
            if ip and not ip.startswith("100."):
                return [ip]
        except (OSError, subprocess.SubprocessError):
            pass
    # No named interface answered: the address the default route uses.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        probe.close()
        if ip and not ip.startswith("100."):
            return [ip]
    except OSError:
        pass
    return []


def advertise_txt(port):
    """The addresses to publish in the Bonjour TXT record.

    The watch reads these straight from the browse result, so it never has
    to resolve the service — resolution is exactly the step that fails on
    real hardware, and the tailnet address here also sidesteps local-network
    permission entirely.
    """
    txt = {}
    ips = lan_ips()
    if ips:
        txt["ip"] = ips[0]
    ts = tailscale_url(port)
    if ts:
        txt["ts"] = ts
    # The tunnel URL is deliberately NOT broadcast: its path carries the
    # travel secret, and a TXT record hands it to every device on the
    # network — hostile café Wi-Fi included. The watch learns it over an
    # authenticated LAN fetch (/tunnel) or through the owner's own
    # iCloud instead.
    txt["port"] = str(port)
    if TLS_INFO:
        # The port only. The fingerprint is never taken from a broadcast:
        # anyone on the network can answer Bonjour.
        txt["tls"] = str(TLS_INFO["port"])
    return txt


def _computer_name():
    """This computer's own short name, as the watch says it ("Office Mac
    mini"): the host name's first label, dashes as spaces. Empty when the
    host has none."""
    import socket
    return socket.gethostname().split(".")[0].replace("-", " ")


def _machine_name():
    host = _computer_name()
    return ("Tapproval on %s" % host) if host else "Tapproval"


def advertise(port, txt=None):
    """Advertise the relay over Bonjour so the watch app finds it by itself.

    macOS ships ``dns-sd``; most Linux distributions ship Avahi. Either
    way it's the system's own tool — no dependencies, per this repo's
    rules. Returns the child process, or None when neither is available;
    the relay still works then via the tunnel or a manual address.
    Never raises.
    """
    name = _machine_name()
    # ``txt`` lets the caller reuse a record it already built; each build
    # probes the interfaces with a subprocess per candidate address.
    pairs = ["%s=%s" % (key, value)
             for key, value in (txt or advertise_txt(port)).items()]
    if shutil.which("dns-sd"):
        command = ["dns-sd", "-R", name, BONJOUR_TYPE, ".", str(port)] + pairs
    elif shutil.which("avahi-publish"):
        command = ["avahi-publish", "-s", name, BONJOUR_TYPE, str(port)] + pairs
    else:
        # This returned None in complete silence: no log line here, and the
        # caller prints only on success. "Your watch cannot find this
        # computer by itself" was reported nowhere at all.
        note_condition(
            "bonjour",
            "Nothing is announcing this computer on the network, so the "
            "watch cannot find it by itself. Enter its address by hand, or "
            "install Bonjour (dns-sd) or Avahi.")
        return None
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as error:
        note_condition(
            "bonjour",
            "This computer could not announce itself on the network (%s), "
            "so the watch cannot find it by itself. Enter its address by "
            "hand." % error)
        return None
    # No clear_condition here: a process that exec'd is not an announcer
    # that works. Whoever started it decides when the condition is
    # withdrawn — at startup, immediately; on a restart, once the
    # replacement has lived a tick (see _Advertiser.check_once).
    return process


def _spawn_detached(command, log_path, cwd=None):
    """Start a child that outlives this process, appending output to a log.

    The relay keeps no handle on the log — the child inherits its own copy —
    so a long-lived relay does not leak one file descriptor per spawn.
    Returns "" on success or a short error string. Never raises.
    """
    # Every detached log is kept to size here, where it is opened: only the
    # relay's own log was rotated, and the /say log grew by every reply.
    _rotate_log(log_path)
    try:
        # The first spawn on a new install may come before the relay ever
        # made ~/.tapproval/logs.
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as log:
            _host.popen_detached(command, cwd=cwd, stdout=log, stderr=log)
    except OSError as error:
        return str(error)
    return ""


def _loopback_json(path, data=None, timeout=5, port=None, headers=None):
    """One request to the relay on this machine: the parsed JSON reply, or
    None for any failure at all — no relay, a slow one, a bad body. GET
    without ``data``, POST with it."""
    request = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (port or DEFAULT_PORT, path), data=data,
        method="POST" if data is not None else "GET",
        headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            return json.loads(reply.read().decode("utf-8"))
    except Exception:
        return None


def _probe_relay(timeout=2):
    """What the running relay says about itself, or None if none is up.

    Signed with the key file when it can be read: loopback alone opens
    liveness and the version, nothing more (S2; 2026-10-25 review), and
    --ensure needs the pending count and the pairing state to decide. With
    no key file yet, the unsigned answer still carries the version.
    """
    return _loopback_json("/health", timeout=timeout,
                          headers=_admin_signature("/health", b"", method="GET"))


PID_FILE = _home_path("PID_FILE")
# How long --ensure gives a freshly spawned relay to answer /health before
# it stops claiming the relay "started". A seam for tests.
RELAY_START_WAIT = 6.0


def _relay_pid(port=None):
    """The pid of the relay on the port, or None. The pidfile first — the
    relay writes its own — then whoever is listening, asked of lsof."""
    try:
        with open(PID_FILE, encoding="utf-8") as handle:
            pid = int(handle.read().strip())
        if _pid_alive(pid):
            return pid
    except (OSError, ValueError):
        pass
    return _host.listener_pid(port or DEFAULT_PORT)


def _stop_relay(deadline=8.0):
    """Stop the running relay and wait for the port to come free. True
    only when it is free — the caller must not start a second relay on
    the strength of a stop that did not happen.

    This used to be one `pkill -f "watch_relay.py --host"`, its exit code
    unread. On 2026-09-09 pkill returned 1 — it could not see a relay
    that `ps` and `lsof` both could — so nothing was stopped, the new
    relay died on "Address already in use", and --ensure printed
    "started in the background" over the corpse. The machine kept
    running yesterday's helper while /health, asked by the watch, said
    so to nobody. The relay is now found by the pid it wrote, or by who
    holds the port, and asked to stop by pid: TERM, then KILL.
    """
    pid = _relay_pid()
    if pid is None:                                     # last resort, as before
        for stray in _host.pids_running("watch_relay.py --host"):
            _host.stop(stray)
    for hard, wait in ((False, deadline), (True, 3.0)):
        if pid is not None:
            _host.stop(pid, hard=hard)
        end = time.time() + wait
        while time.time() < end:
            if _relay_is_down():
                return True
            time.sleep(0.4)
    return _relay_is_down()


def _port_in_use(port, host="127.0.0.1", timeout=1.0):
    """True while something is listening. Unknown counts as in use: this
    answers "may I bind?", and a maybe is a no."""
    return _host.something_listens(port, host, timeout)


def _relay_is_down():
    """Both listeners gone, not just the one that answers /health.

    The old check asked the main port only, and on 2026-09-11 that was
    enough to report a stop that had not finished: the main port came
    free, --ensure started a replacement, and the replacement died
    binding the TUNNEL port the dying relay still held. A stop proved on
    one of two sockets is the same class of mistake as the pkill whose
    exit code nobody read.
    """
    return _probe_relay(timeout=1) is None and not _port_in_use(TUNNEL_PORT)


def _admin_signature(path, body, auth_file=None, method="POST"):
    """The headers proving this user holds the key file, signed with the
    bootstrap so the key itself never travels; {} if it cannot be read,
    and the relay decides what an unproven caller may do."""
    bootstrap = wire.read_bootstrap(auth_file or AUTH_FILE)
    if not bootstrap:
        return {}
    return {"X-Tapproval-Signature": wire.signed_header(bootstrap, method, path, body)[0]}


def _admin_call(path, timeout=5):
    """Loopback-only administration: the relay owns the state, this just
    asks it, signed with the key file. Returns the parsed reply or None."""
    body = b"{}"
    return _loopback_json(path, data=body, timeout=timeout,
                          headers=_admin_signature(path, body))


def run_admin(args):
    """The `--pair` / `--pair-reset` / `--rotate-token` commands.

    Each is one sentence of recovery, meant to be run *by the user's agent*
    on their behalf ("tell Claude Code: open Tapproval pairing") rather than
    typed. The relay must be running: it owns the state, and asking it means
    a live change with no restart and no dropped card.
    """
    if _probe_relay() is None:
        print("Tapproval Base is not running. Start a Claude Code session "
              "(or run --ensure) and try again.", file=sys.stderr)
        return 1
    if args.rotate_token:
        if _admin_call("/admin/rotate") is None:
            print("Could not rotate the keys.", file=sys.stderr)
            return 1
        print("New keys in place. Your watch re-pairs by itself — over "
              "Wi-Fi at once, or within a couple of minutes when away.")
        return 0
    path = "/admin/pair-reset" if args.pair_reset else "/admin/pair-open"
    reply = _admin_call(path)
    if reply is None:
        print("Could not open pairing.", file=sys.stderr)
        return 1
    if args.pair_reset:
        print("Forgot every paired device.")
    print("Pairing is open for %d minutes — open Tapproval on your watch."
          % (int(reply.get("seconds", PAIR_WINDOW_SECONDS)) // 60))
    return 0


RELAY_LOG = _home_path("RELAY_LOG")
SAY_LOG = _home_path("SAY_LOG")
RELAY_LOG_MAX = 2 * 1024 * 1024      # keep the tail worth reading


def _rotate_log(path=None, limit=RELAY_LOG_MAX):
    """Keep the last ``limit`` bytes and drop the rest.

    A relay that runs for weeks appends to this file forever. Rotating at
    start rather than on a timer keeps it to one moment when nothing else is
    happening, and keeps the recent history a support question needs.
    """
    path = path or RELAY_LOG
    try:
        if os.path.getsize(path) <= limit:
            return False
        with open(path, "rb") as handle:
            handle.seek(-limit, os.SEEK_END)
            handle.readline()            # never start mid-line
            tail = handle.read()
        with open(path, "wb") as handle:
            handle.write(b"[earlier entries trimmed]\n" + tail)
        return True
    except OSError:
        return False


# At most once an hour, and never in the way. A stale helper is not a
# cosmetic problem: the version before 1.1.1 discarded every wrist
# approval in silence, so "an update that never arrives" is the failure
# mode this guards against.
# Overridable like CLAUDE_SETTINGS_PATH and CLAUDE_LAUNCH_AGENT_PATH, so a
# test — including one that runs the hook in a subprocess, where a
# monkeypatch cannot reach — never pulls the working tree it is testing.
_UPDATE_STAMP = _home_path("_UPDATE_STAMP")
# An hour, not a day: a helper published in the afternoon sat unread until
# the next morning (2026-10-01) while the watch said "start Claude Code
# once to update it". A fetch is cheap, and it never blocks a session.
_UPDATE_EVERY = 3600.0


# A plugin install is Claude Code's to update, and Claude Code leaves
# auto-update off for every marketplace but Anthropic's own: a user sat on
# 1.1.52 for weeks, without the bridge that makes a closed watch buzz,
# until they ran `claude plugin update` by hand (2026-10-23). So the relay
# asks GitHub for the releases once a day and says how to get them.
# Quietly, because releases come often (the owner, 2026-10-23): never
# when Claude Code's auto-update is on for this marketplace, only for a
# release out a week or more, and drawn as news, not as a problem.
# Empty turns the look off.
RELEASES_URL = os.environ.get(
    "TAPPROVAL_RELEASES_URL",
    "https://api.github.com/repos/marcobelini/tapproval-helper/releases?per_page=30")
_RELEASE_LOOK_EVERY = 24 * 3600.0
RELEASE_GRACE_SECONDS = 7 * 24 * 3600.0
MARKETPLACE = "tapproval"       # helper/.claude-plugin/marketplace.json


def _version_tuple(text):
    """"v1.1.10" → (1, 1, 10); anything else → None."""
    match = re.match(r"^v?(\d+(?:\.\d+)*)$", str(text or "").strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def _helper_releases():
    """[(tag, published at, epoch seconds)] of the published releases."""
    import datetime

    request = urllib.request.Request(RELEASES_URL, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "tapproval-helper"})
    with urllib.request.urlopen(request, timeout=10) as reply:
        listed = json.loads(reply.read().decode("utf-8"))
    return [(release.get("tag_name"), datetime.datetime.strptime(
                release["published_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc).timestamp())
            for release in listed
            if not release.get("draft") and not release.get("prerelease")
            and release.get("published_at")]


def _known_marketplaces_path():
    claude = os.path.expanduser("~/.claude")
    plugins = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR") or os.path.join(claude, "plugins")
    return os.path.join(plugins, "known_marketplaces.json")


def _auto_update_on():
    """Whether Claude Code auto-updates this marketplace, read in its own
    order: the settings file's extraKnownMarketplaces entry, then the
    /plugin toggle's record. Written only by set_auto_update, when the
    wearer turns the watch's switch."""
    import ClaudeRiskClassifier as classifier

    # The path set_auto_update writes, from the same helper: this read had
    # its own rule, which skipped expanduser (2026-10-24 review).
    for path, entries in (
            (classifier._settings_path(),
             lambda data: data.get("extraKnownMarketplaces")),
            (_known_marketplaces_path(), lambda data: data)):
        try:
            with open(path, encoding="utf-8") as handle:
                entry = (entries(json.load(handle)) or {}).get(MARKETPLACE) or {}
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(entry, dict) and isinstance(entry.get("autoUpdate"), bool):
            return entry["autoUpdate"]
    return False


def _plugin_install(here=None):
    """No checkout beside this file: Claude Code installed it, and only
    Claude Code updates it. A terminal install pulls its own (_self_update)."""
    here = here or os.path.dirname(os.path.abspath(__file__))
    return not os.path.exists(os.path.join(here, ".git"))


# Where the helper's marketplace lives, as users add it
# (`/plugin marketplace add marcobelini/tapproval-helper`), in the shape
# Claude Code's settings document for extraKnownMarketplaces.
MARKETPLACE_SOURCE = {"source": "github", "repo": "marcobelini/tapproval-helper"}


def set_auto_update(on):
    """The watch's "Keep the helper up to date" switch (2026-10-23): set
    `extraKnownMarketplaces.tapproval.autoUpdate` in Claude Code's settings,
    the documented place, which its /plugin toggle also writes. Only the
    wearer's tap gets here; nothing else in the file moves, the file is
    copied aside first, and one it cannot read is left alone.

    Returns (state read back, None) or (None, a sentence for the wrist)."""
    import ClaudeRiskClassifier as classifier

    path = classifier._settings_path()
    try:
        data = classifier._read_settings(path)
    except (OSError, ValueError):
        return None, ("Claude Code's settings file could not be read, so it was left as it is. "
                      "Turn on auto-update in Claude Code: /plugin → Marketplaces → tapproval.")
    markets = data.setdefault("extraKnownMarketplaces", {})
    entry = markets.setdefault(MARKETPLACE, {}) if isinstance(markets, dict) else None
    if not isinstance(entry, dict):
        return None, ("Claude Code's settings list marketplaces in a form this helper does not know, "
                      "so they were left as they are.")
    if not isinstance(entry.get("source"), dict):
        # The source Claude Code recorded when the marketplace was added,
        # so declaring it here never sends it to fetch from somewhere new.
        try:
            with open(_known_marketplaces_path(), encoding="utf-8") as handle:
                recorded = (json.load(handle).get(MARKETPLACE) or {}).get("source")
        except (OSError, ValueError, AttributeError):
            recorded = None
        entry["source"] = recorded if isinstance(recorded, dict) else dict(MARKETPLACE_SOURCE)
    if entry.get("autoUpdate") is not bool(on):
        entry["autoUpdate"] = bool(on)
        try:
            classifier._backup(path)
            classifier._write_settings(path, data)
        except OSError as error:
            print("relay: could not save auto-update (%s)" % error.__class__.__name__,
                  file=sys.stderr)
            return None, "Claude Code's settings could not be saved. Try again in a moment."
    print("relay: auto-update for the helper turned %s from the watch" % ("on" if on else "off"),
          file=sys.stderr)
    return _auto_update_on(), None


def check_for_newer_helper(releases=_helper_releases, auto_update=_auto_update_on,
                           now=time.time):
    """Note "outdated" when a release newer than this helper has been out
    a week and Claude Code will not fetch it by itself; clear it otherwise.
    A look that fails leaves things as they were and says so in the log.
    Never raises."""
    ours = _version_tuple(HELPER_VERSION)
    try:
        listed = [] if auto_update() else releases()
        why = None
    except Exception as error:
        listed, why = [], error
    missed = [_version_tuple(tag) for tag, published in listed
              if _version_tuple(tag) and now() - published >= RELEASE_GRACE_SECONDS]
    if why is not None or ours is None:
        print("relay: could not tell whether a newer helper is out (%s; "
              "this one is %s)" % (why, HELPER_VERSION), file=sys.stderr)
    elif any(version > ours for version in missed):
        note_condition(
            "outdated",
            "A newer helper is out. Claude Code can install updates by "
            "itself: type /plugin, open Marketplaces, choose tapproval and "
            "pick Enable auto-update.", tone="in_hand")
    else:
        clear_condition("outdated")


def watch_for_newer_helper(here=None):
    """The daily look, for plugin installs only: a git install pulls its
    own updates (_self_update)."""
    here = here or os.path.dirname(os.path.abspath(__file__))
    if not RELEASES_URL or os.path.exists(os.path.join(here, ".git")):
        return
    while True:
        check_for_newer_helper()
        time.sleep(_RELEASE_LOOK_EVERY)


@contextmanager
def _process_lock(path, wait=0):
    """One local process at a time; a crash releases the lock automatically.

    Session hooks never wait for another starter. Only the detached updater
    may wait briefly for a relay startup that is already in progress.
    Never unlink the file: contenders must keep locking the same inode.
    """
    descriptor = None
    acquired = False
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + wait
        while True:
            try:
                if _host.try_lock(descriptor):
                    acquired = True
                    break
            except OSError:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    except OSError:
        pass
    try:
        yield acquired
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _self_update():
    """Kick off a fast-forward of a git-installed helper, once an hour.

    Runs on the blocking path of the SessionStart hook, so it never pulls
    here: it spawns ``--update`` detached and returns at once. The
    background process pulls, and if the checkout moved it replaces the
    running relay itself, under the same "not while a card is waiting"
    rule. Nothing is returned: the caller never waits for the network.

    Only ever touches an install that is a git checkout — the one made by
    install.sh. A plugin install belongs to Claude Code, which manages its
    own updates, and must not be rewritten underneath it. A failure never
    stops anything — the relay simply starts what is already there — but
    one that will not pass by itself is said: see ``_pull_update``. Never
    raises, never blocks a session.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(os.path.join(here, ".git")):
        return
    # Claude Code and Codex share the stamp and this atomic claim. Checking
    # its age before taking the lock lets simultaneous starts both pull.
    with _process_lock(_UPDATE_STAMP + ".claim.lock") as claimed:
        if not claimed:
            return
        try:
            if time.time() - os.path.getmtime(_UPDATE_STAMP) < _UPDATE_EVERY:
                return
        except OSError:
            pass
        try:
            with open(_UPDATE_STAMP, "w") as handle:
                handle.write(str(int(time.time())))
        except OSError:
            return
        failed = _spawn_detached(
            [sys.executable, os.path.abspath(__file__), "--update"], RELAY_LOG)
        if failed:
            # A child that never started must not suppress the next retry.
            try:
                os.remove(_UPDATE_STAMP)
            except OSError:
                pass


# The Mac bridge is pinned by bridge.json, which a pull may move. Checking
# costs a file read; the download it may start never blocks a session, and
# a failing one is retried at most this often.
_BRIDGE_RETRY_EVERY = 3600.0


def _maybe_update_bridge():
    """Start a detached ``--bridge-update`` when this helper pins a bridge
    version this Mac does not have (route B, #378). Never raises, never
    blocks a session: the download and the checks happen in the child."""
    try:
        import bridge_install
        if bridge_install.state(bridge_install.read_pin()) != "install":
            return False
        stamp = os.path.join(bridge_install.bridge_dir(), ".last-attempt")
        try:
            if time.time() - os.path.getmtime(stamp) < _BRIDGE_RETRY_EVERY:
                return False
        except OSError:
            pass
        os.makedirs(bridge_install.bridge_dir(), exist_ok=True)
        with open(stamp, "w") as handle:
            handle.write(str(int(time.time())))
        log = os.path.join(bridge_install.bridge_dir(), "install.log")
    except Exception:
        return False
    return not _spawn_detached(
        [sys.executable, os.path.abspath(__file__), "--bridge-update"], log)


def _bridge_heard_from(wait=None, sleep=time.sleep):
    """After a new bridge is loaded: did the relay hear from it?

    /health says "bridge" while the bridge polled in the last
    BRIDGE_ALIVE_SECONDS, which the bridge it replaced may still have done.
    So wait that long first, then give the new one until the relay's own
    silence limit."""
    sleep(CardQueue.BRIDGE_ALIVE_SECONDS + 5)
    end = time.time() + (wait if wait is not None else BRIDGE_SILENT_SECONDS)
    while True:
        health = _probe_relay(timeout=2) or {}
        if health.get("alert_route") == "bridge":
            return True
        if time.time() >= end:
            return False
        sleep(5)


def run_bridge_update():
    """The detached half of ``_maybe_update_bridge``: install the pinned
    bridge unless a card is waiting, and tell the relay how it went."""
    import bridge_install
    pin = bridge_install.read_pin()
    if bridge_install.state(pin) != "install":
        return 0
    running = _probe_relay()
    if running is not None and running.get("pending"):
        # A restart of the bridge while a card waits could cost that card
        # its buzz. The next session start tries again.
        print("bridge: update deferred — a card is waiting", file=sys.stderr)
        return 0
    wait = _bridge_heard_from if running is not None else None
    try:
        version = bridge_install.install(pin, wait_for_bridge=wait)
    except (bridge_install.InstallError, OSError) as error:
        print("bridge: not installed — %s" % error, file=sys.stderr)
        _admin_call("/admin/bridge-failed", timeout=2)
        return 1
    print("bridge: %s installed" % version, file=sys.stderr)
    _admin_call("/admin/bridge-ok", timeout=2)
    # A bridge from 1.1.0 wakes the relay at login itself; the relay's own
    # job, listed under the interpreter's name in Login Items, then goes.
    try:
        import ClaudeRiskClassifier as classifier
        classifier.wake_relay_at_login()
    except Exception as error:
        print("bridge: the relay's wake-up was not handed over — %s" % error,
              file=sys.stderr)
    return 0


# What a pull says when the network, not the checkout, is the problem.
# Those pass by themselves within the hour; everything else — a clone that
# has diverged, local edits in the way — fails the same way every hour,
# forever, and the machine runs old rules without a word.
_TRANSIENT_PULL_ERRORS = (
    "could not resolve host", "unable to access", "could not read from remote",
    "timed out", "failed to connect", "connection refused", "connection reset",
    "early eof", "network is unreachable", "returned error: 5")


def _pull_is_stuck(returncode, stderr):
    """True when a failed pull will keep failing until someone acts."""
    if returncode == 0:
        return False
    text = (stderr or "").lower()
    return not any(marker in text for marker in _TRANSIENT_PULL_ERRORS)


def _pull_update():
    """The pull itself, synchronous, for the detached ``--update`` process.
    Returns True if the checkout moved. Never raises.

    A pull that cannot succeed until someone acts is told to the running
    relay (``/admin/update-stuck``), which records a condition the watch
    shows; the first pull that succeeds withdraws it. It used to be
    ignored outright, and the stamp is written before the pull, so a stuck
    clone ran old code indefinitely and said nothing anywhere
    (2026-10-14 tech-debt audit)."""
    here = os.path.dirname(os.path.abspath(__file__))
    # One guard around everything, including reading the results: the
    # promise is "never raises", and narrow excepts made it false once.
    try:
        before = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10)
        pull = subprocess.run(["git", "-C", here, "pull", "--ff-only", "--quiet"],
                              capture_output=True, text=True, timeout=60)
        after = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=10)
        moved = (before.returncode == 0 and after.returncode == 0
                 and before.stdout.strip() != after.stdout.strip())
        stuck = _pull_is_stuck(pull.returncode, pull.stderr)
        why = (pull.stderr or "").strip().splitlines()[-1:] or [""]
    except Exception:
        return False
    if stuck:
        print("relay: the helper cannot update itself: %s" % why[0], file=sys.stderr)
        _admin_call("/admin/update-stuck", timeout=2)
    elif pull.returncode == 0:
        _admin_call("/admin/update-unstuck", timeout=2)
    if moved:
        print("relay: helper updated to the latest published version",
              file=sys.stderr)
    return moved


def _serving_older_code(running):
    """True when the relay that answered is not the code that is installed.

    Compares the commit the relay recorded about itself at start (``/health``
    carries it as ``helper_commit``) with the checkout's commit now. Says no
    whenever either side is unknown — a plugin install has no ``.git``, an
    older relay reports no commit, git may be missing — because replacing a
    working relay on a guess is worse than leaving it. Never raises.
    """
    try:
        serving = (running or {}).get("helper_commit")
        if not serving:
            # Nothing to compare against, so do not even ask git: this is
            # the blocking path of a session start, and a relay that says
            # nothing about itself is answered by leaving it alone.
            return False
        # Read from .git, with no subprocess on this blocking path; git is
        # asked only when the files cannot say (a worktree's .git is a file).
        here = os.path.dirname(os.path.abspath(__file__))
        installed = _head_commit(here) or helper_provenance(here)[0]
    except Exception:
        return False
    # By prefix: git may abbreviate to more than seven characters, and an
    # older relay reported git's abbreviation rather than this one.
    return bool(installed and not (serving.startswith(installed)
                                   or installed.startswith(serving)))


def ensure_running(updated=False):
    """Serialize starts from either agent without blocking a session hook."""
    wait = PORT_TAKEN_WAIT + RELAY_START_WAIT + 5 if updated else 0
    with _process_lock(_UPDATE_STAMP + ".start.lock", wait=wait) as claimed:
        if not claimed:
            print("relay: another session is starting the helper; leaving it to it",
                  file=sys.stderr)
            return 0
        return _ensure_running(updated=updated)


def _ensure_running(updated=False):
    """Start the relay in the background unless one is already up.

    Registered as a Claude Code SessionStart hook, so the relay's whole
    lifecycle is automatic: it exists whenever Claude Code does. Prints a
    line to stderr and exits immediately either way. Never raises.

    ``updated`` is True only when the background updater calls back after
    a pull moved the checkout; the hook itself passes nothing and only
    kicks the updater off when it is due.
    """
    if not updated:
        _self_update()
    _maybe_update_bridge()
    running = _probe_relay()
    if running is None and _port_in_use(DEFAULT_PORT):
        # Held but silent: a busy relay, most likely (its /health can wait
        # seconds on `claude auth status`). Ask again, patiently — without
        # this, a slow answer skipped the whole replace-if-older decision,
        # and on 2026-09-24 a kickstart left 1.1.16 serving beside 1.1.17
        # installed. The check before spawning still stands if it stays
        # silent.
        running = _probe_relay(timeout=PORT_TAKEN_WAIT)
    if running is not None:
        version = running.get("version") or 0
        # A deferred update has to be tried again, or it is not deferred —
        # it is cancelled. `updated` is true only in the one invocation
        # whose pull moved the checkout; if a card was waiting just then,
        # the replacement was put off, and every later start arrived with
        # `updated` false, matched the protocol version, and said "already
        # running". Found on the owner's Mac on 2026-09-21: the checkout at
        # 1.1.9, the relay serving 1.1.8 for three days, and its own
        # condition on the wrist promising to be replaced "the next time
        # Claude Code starts" through dozens of starts.
        #
        # So ask the question directly: is the relay that is serving the
        # code that is installed? Both sides say which commit they are;
        # when both are known and they differ, the code moved, whoever
        # moved it and whenever.
        if not updated and _serving_older_code(running):
            updated = True
        # A plugin install has no commit to compare: Claude Code updates it
        # in a new folder and starts sessions from there, while the relay
        # started earlier kept serving the old code until the computer
        # restarted (2026-10-23). Its version says so. Unreadable on either
        # side is no reason to replace a working relay.
        ours, theirs = _version_tuple(HELPER_VERSION), _version_tuple(running.get("helper"))
        if not updated and ours and theirs and theirs < ours:
            updated = True
        # A relay started before an update is running the old code even
        # when its protocol version matches, so a fresh pull must replace
        # it — subject to the same "not while a card is waiting" rule.
        if version >= RELAY_VERSION and not updated:
            if running.get("paired_ever") is False:
                _admin_call("/admin/pair-relight")   # another half hour
            print("relay: already running", file=sys.stderr)
            return 0
        # An older relay is serving. Without this the machine keeps running
        # yesterday's rules forever — an update that never arrives is not an
        # update. But a relay holding a card is holding someone's approval:
        # replace it only when nothing is waiting.
        if not running.get("pending"):
            # That look can be twenty seconds old (PORT_TAKEN_WAIT), and a
            # card posted since died with the relay. Look again just
            # before stopping it; the hook re-posts a card cut off in what
            # little window remains.
            running = _probe_relay() or running
        if running.get("pending"):
            print("relay: update deferred — a card is waiting", file=sys.stderr)
            # Say it where it can be seen: the running relay records the
            # condition and the watch shows it. A relay old enough not to
            # know the route answers 404 and nothing is recorded — which
            # is exactly the relay this is about, the first time. From the
            # next version on it is visible.
            if _admin_call("/admin/update-deferred", timeout=2) is None:
                print("relay: (the running relay could not record that — "
                      "it predates the route)", file=sys.stderr)
            return 0
        print("relay: replacing an older relay (v%s -> v%d)"
              % (version or "?", RELAY_VERSION), file=sys.stderr)
        if not _stop_relay():
            # Starting a second relay on a held port produces a corpse
            # and a log line nobody reads. Say the true thing instead.
            print("relay: could not stop the relay on port %d (pid %s); "
                  "not starting a second one. The old one keeps serving. "
                  "See %s" % (DEFAULT_PORT, _relay_pid() or "?", RELAY_LOG),
                  file=sys.stderr)
            return 1
    # /health is not the only witness. On 2026-09-23 a SessionStart asked
    # it, got no answer inside two seconds — the relay was busy asking
    # `claude auth status`, which takes seconds on a cold start — and
    # started a second relay beside the first. The second died binding
    # the held port, its crash e-mailed the owner, and --ensure printed
    # "started in the background" because the FIRST relay then answered.
    # A held port is a relay that is slow, or something that is not a
    # relay; either way a second one can only die on it.
    if _port_in_use(DEFAULT_PORT):
        print("relay: port %d is taken but did not answer /health in time — "
              "not starting a second relay. A busy relay answers slowly; "
              "anything else holding the port is named in %s"
              % (DEFAULT_PORT, RELAY_LOG), file=sys.stderr)
        return 0
    log_path = RELAY_LOG
    error = _spawn_detached(                     # which rotates the log
        [sys.executable, os.path.abspath(__file__),
         "--host", "0.0.0.0", "--tunnel"], log_path)
    if error:
        print("relay: could not start (%s)" % error, file=sys.stderr)
        return 1
    # "Started" is a claim about the child, not about the spawn. Wait for
    # it to answer, and say so only when it has.
    end = time.time() + RELAY_START_WAIT
    while time.time() < end:
        if _probe_relay(timeout=1) is not None:
            print("relay: started in the background (log: %s)" % log_path,
                  file=sys.stderr)
            return 0
        time.sleep(0.3)
    print("relay: did not come up within %.0fs — read %s"
          % (RELAY_START_WAIT, log_path), file=sys.stderr)
    return 1


def alert_bucket(card):
    """What a notification for this card may offer a closed watch.

    A double tap runs a notification's first action, so this is what
    stands between a reflex and an approval. Decided here, once: the
    bridge copies it into iCloud and the watch picks its buttons by it.

    - "go"      SAFE, LOW: Allow first; the headline is on the screen.
    - "careful" MEDIUM: Deny first, Allow second — never a reflex yes.
    - "stop"    HIGH, CRITICAL: Deny only; approving means opening it.
    - "ask"     a question or a plan: open only, the answer is a choice.
    Anything unrecognised is "stop": fail closed.
    """
    if card.get("kind") in ("question", "handoff"):
        return "ask"
    return {"SAFE": "go", "LOW": "go", "MEDIUM": "careful"}.get(
        card.get("tier") if isinstance(card.get("tier"), str) else None, "stop")


class CardQueue:
    """Pending wrist cards and the decisions made about them."""

    wall_clock = staticmethod(time.time)    # a test may move it on

    def __init__(self):
        self._lock = threading.Condition()
        self._pending = OrderedDict()   # id -> card dict
        # (session_id, tool, fingerprint) granted "always for this
        # session" — the phone's third button, reproduced faithfully. The
        # fingerprint names the actual command (hashed by the hook), never
        # the headline: headlines are Claude's own prose and two different
        # commands can share one. Session-scoped by construction: the
        # store lives and dies with the relay.
        self._session_allows = set()
        self._decisions = {}            # id -> "allow" | "deny"
        self._seen = set()              # every id queued here, for not_here_yet()
        self.started = time.monotonic()
        self.last_poll = None           # monotonic time of last /pending fetch
        self.last_bridge_poll = None    # the same, for the Mac bridge

    # A watch that has not polled within this many seconds is not on a
    # wrist right now. Diagnostics only — cards queue regardless, because
    # a wrist raised late must still find its card.
    WATCH_PRESENT_SECONDS = 90
    # The bridge polls every 2 s while it runs; three missed polls and
    # nothing will mirror a card into iCloud, so nothing will buzz.
    BRIDGE_ALIVE_SECONDS = 30
    # How often a waiting card asks "is the hook still there, and has the
    # transcript answered this prompt?". It was 5 s, and an answer given on
    # the phone could stand on the wrist that long before the watch's own
    # 2 s poll even had a chance to see it go. An idle probe is one
    # zero-timeout select and one file-size check per transcript, so a
    # second is still cheap.
    PROBE_SECONDS = 1.0

    def submit(self, card, wait, caller_alive=None, resolved_elsewhere=None, admission_lock=None):
        """Queue a card and block until it is decided or ``wait`` expires.

        The card is queued whether or not a watch polled recently: Claude
        Code shows its own prompt CONCURRENTLY with this wait (proven
        live — the phone prompts while the hook holds), so waiting costs
        the user nothing, and a wrist raised a minute after the prompt
        fired must still find the card. The old fast-return for an absent
        watch silently starved the wrist of every prompt that arrived
        while it was down.

        ``caller_alive`` is checked each slice: when the hook that posted the
        card dies, the card is retracted immediately instead of haunting
        the watch. ``resolved_elsewhere`` is the second retraction path:
        Claude Code does NOT reliably kill the hook when the prompt is
        answered on the phone or terminal (observed live), so the relay
        watches the session's own transcript — the moment a tool_result
        lands for the very call this card asks about, the question has
        been answered somewhere, and the card leaves the wrist.
        """
        # A replayed grant is an auto-allow, not a human answer, so
        # CRITICAL is excluded outright — the tap that records the grant
        # was human and may land on any tier, but its echo may not.
        rule = (card.get("session_id"), card.get("tool"),
                card.get("fingerprint"))
        # A grant may only exist where the phone offers one: the hook sets
        # can_always from Claude Code's own permission suggestions.
        replayable = (all(rule) and card.get("tier") != "CRITICAL"
                      and bool(card.get("can_always")))
        if replayable and rule in self._session_allows:
            # Granted "always" earlier this session — answered instantly.
            return "", "allow", None
        entry = dict(card)
        wanted = entry.pop("post_id", None)
        # Always recomputed: the bucket is the relay's to decide, never the
        # poster's, so a card cannot ask for a looser notification.
        entry["alert"] = alert_bucket(entry)
        deadline = time.monotonic() + wait
        # The monotonic clock stops while a Mac sleeps, so on its own a 24 h
        # wait could hold a card for days of calendar time (six, for one
        # answered question on 2026-10-05). The wall clock bounds it too.
        wall_deadline = self.wall_clock() + wait
        # A native adapter serializes publication with native resolution.
        # Only admission holds that lock; the blocking wait never does.
        with admission_lock or nullcontext(), self._lock:
            if admission_lock is not None and resolved_elsewhere is not None and resolved_elsewhere():
                return "", "none", None
            # The hook's own id, so a repost after a restart keeps it (#795);
            # anything else, or an id already in use, gets a fresh one.
            card_id = (wanted if isinstance(wanted, str) and CARD_ID.match(wanted)
                       and wanted not in self._pending and wanted not in self._decisions
                       else uuid.uuid4().hex[:12])
            entry["id"] = card_id
            self._pending[card_id] = entry
            if time.monotonic() - self.started < self.START_GRACE_SECONDS:
                self._seen.add(card_id)     # only not_here_yet() reads it
            self._lock.notify_all()
        # T0 of the buzz-when-closed latency measurement (with the bridge's
        # "mirrored" line and the watch's "alert delivered" line).
        print("relay: queued %s %s at %d" % (card_id, entry["alert"],
                                             int(time.time() * 1000)),
              file=sys.stderr)
        # Once a card is up it STAYS up — a lowered wrist pauses polling
        # for minutes at a time and must not cost the question. A card
        # leaves in exactly three ways: answered here, its prompt resolved
        # elsewhere (the probes), or the wait truly expires. The probes do
        # socket and file I/O, so they run with the lock RELEASED — the
        # watch's /pending poll must never queue behind a transcript read.
        # They fire immediately on entry (a prompt already answered when
        # the card is posted must not stand even a second) and then on a
        # PROBE_SECONDS CLOCK, not per wakeup: notify_all() for unrelated
        # cards wakes every waiter, and probe I/O must scale with time, not
        # with card traffic. The exit predicate lives in exactly one place,
        # and names why the card left.
        started = time.monotonic()
        next_probe = 0.0
        reason = None
        try:
            while reason is None:
                now = time.monotonic()
                if now >= next_probe:
                    next_probe = now + self.PROBE_SECONDS
                    if caller_alive is not None and not caller_alive():
                        reason = "hook-gone"
                        break
                    if resolved_elsewhere is not None and resolved_elsewhere():
                        reason = "answered-elsewhere"
                        break
                with self._lock:
                    remaining = deadline - time.monotonic()
                    if card_id in self._decisions:
                        reason = "answered-here"
                    elif card_id not in self._pending:
                        reason = "answered-elsewhere"
                    elif remaining <= 0 or self.wall_clock() >= wall_deadline:
                        reason = "expired"
                    else:
                        self._lock.wait(max(0.05, min(
                            remaining, next_probe - time.monotonic())))
        except BaseException:
            # A probe that raised: the hook gets no answer and falls back to
            # the terminal, so the wrist must not keep a card that takes
            # taps nothing will act on.
            with self._lock:
                if self._pending.get(card_id) is None or self._pending.get(card_id) is entry:
                    self._pending.pop(card_id, None)
                    self._decisions.pop(card_id, None)
            raise
        with self._lock:
            # Whatever happened, the card is no longer pending: either it
            # was decided, or it expired and the watch must not answer a
            # question the hook has already given up on.
            current = self._pending.get(card_id)
            if current is entry or current is None:
                self._pending.pop(card_id, None)
                decision, answer = self._decisions.pop(card_id, ("none", None))
            else:
                # A native reconnect may repost the same stable card ID.
                # A retired waiter must not retract or consume its replacement.
                decision, answer = "none", None
                reason = "answered-elsewhere"
            if decision == "always":
                if replayable:
                    self._session_allows.add(rule)
                decision = "allow"
            # "dont_ask" (the terminal's "don't ask again", from a watch that
            # showed its words) stays itself here: the hook writes the rule
            # into Claude Code, so the relay keeps no grant of its own.
        if decision != "none":
            reason = "answered-here"    # a tap that beat the probe to it
        # The other half of the "queued" line: how long a card stood on the
        # wrist and why it left. A prompt answered on the phone that is slow
        # to leave the watch is read off these two lines.
        print("relay: left %s %s after %dms" % (
            card_id, reason, int((time.monotonic() - started) * 1000)),
            file=sys.stderr)
        return card_id, decision, answer

    def withdraw(self, card_id):
        """Retract a native request synchronously, before another tap/poll."""
        with self._lock:
            self._pending.pop(card_id, None)
            self._decisions.pop(card_id, None)
            self._lock.notify_all()

    def pending(self, from_watch=False, from_bridge=False):
        with self._lock:
            if from_watch:
                self.last_poll = time.monotonic()
            if from_bridge:
                self.last_bridge_poll = time.monotonic()
            return list(self._pending.values())

    def alert_route(self):
        """What will make a closed watch buzz, or None.

        "bridge" while the Mac bridge is polling: it mirrors each card into
        iCloud, whose subscription alerts the watch. A watch's own poll is
        not a route — it only happens while the app is open.
        """
        with self._lock:
            if (self.last_bridge_poll is not None
                    and time.monotonic() - self.last_bridge_poll
                    <= self.BRIDGE_ALIVE_SECONDS):
                return "bridge"
            return None

    def note_watch_indirect(self, seconds_ago):
        """A watch seen through the cloud counts as present.

        The bridge reads the watch's CloudKit heartbeat and reports its
        age here; an away watch polling iCloud is just as seen as one
        polling this socket directly. Presence is diagnostics (the
        /health "watch seen" answer) — cards queue regardless.
        Stale reports never rewind a fresher direct poll.
        """
        try:
            seconds_ago = float(seconds_ago)
        except (TypeError, ValueError):
            return False
        # A negative age is clock skew or a buggy reporter — fail closed.
        if not 0 <= seconds_ago <= self.WATCH_PRESENT_SECONDS:
            return False
        with self._lock:
            seen = time.monotonic() - seconds_ago
            if self.last_poll is None or seen > self.last_poll:
                self.last_poll = seen
        return True

    def watch_seen_seconds_ago(self):
        with self._lock:
            if self.last_poll is None:
                return None
            return int(time.monotonic() - self.last_poll)

    # A relay that has just started may not hold, yet, a card its hook is
    # about to post again after the last relay died with it — while the
    # watch still shows that card's iCloud copy (#795). A tap on it in that
    # minute is answered 503, which the bridge keeps and retries, rather
    # than a final "no longer waiting".
    START_GRACE_SECONDS = 60.0

    def not_here_yet(self, card_id):
        """True for a card id this young relay has never held."""
        with self._lock:
            unknown = card_id not in self._pending and card_id not in self._seen
        return (unknown and isinstance(card_id, str) and bool(CARD_ID.match(card_id))
                and time.monotonic() - self.started < self.START_GRACE_SECONDS)

    def decide(self, card_id, decision, answer=None):
        """Record the watch's answer. Returns True if the card was live.

        A refusal is logged loudly: "the tap did nothing" is the hardest
        symptom to diagnose from the outside, and the reason is always
        here — the card is gone, or the answer is not one we accept.
        """
        if decision not in VALID_DECISIONS:
            print("relay: refused %r for %s — not a valid decision"
                  % (decision, card_id), file=sys.stderr)
            return False
        if decision == "answer" and not answer:
            # An answer with no words collapses to "none" in the hook —
            # accepting it would flash success on the watch while the
            # session stays blocked. Refuse loudly instead.
            print("relay: refused empty answer for %s" % card_id,
                  file=sys.stderr)
            return False
        with self._lock:
            if card_id not in self._pending:
                print("relay: refused %s for %s — that card is no longer "
                      "waiting (the computer already handed it back)"
                      % (decision, card_id), file=sys.stderr)
                return False
            if card_id in self._decisions:
                # The first answer is final: a second tap, or a second
                # watch, must not overwrite what the hook is about to read
                # (2026-10-16 review, S13).
                print("relay: refused %s for %s — that card is already "
                      "answered (%s)" % (decision, card_id,
                                         self._decisions[card_id][0]),
                      file=sys.stderr)
                return False
            card = self._pending[card_id]
            if card.get("kind") == "handoff":
                print("relay: refused answer for %s — answer on Mac or iPhone" % card_id,
                      file=sys.stderr)
                return False
            if decision in ("always", "dont_ask") and (
                    card.get("tier") == "CRITICAL" or not card.get("can_always")):
                # A lasting grant only where the wrist offered one: never
                # on CRITICAL, never where Claude Code made no suggestion
                # (2026-10-16 review, S5).
                print("relay: refused %s for %s — this card offers no "
                      "lasting grant" % (decision, card_id), file=sys.stderr)
                return False
            # "answer" carries the chosen option label for question cards
            # — several, one per line, on a multi-select card — or a plan's
            # edits. The hook keeps ANSWER_CHARS (ask_watch); this kept
            # 200, then 600, which four long labels can pass (2026-10-16).
            self._decisions[card_id] = (decision,
                                        str(answer)[:ANSWER_CHARS] if answer else None)
            self._lock.notify_all()
        print("relay: accepted %s for %s" % (decision, card_id),
              file=sys.stderr)
        return True


# The session/usage/activity layer lives in its own module: this file is
# the relay, and the relay's job is small and dangerous, while reading
# transcripts is large and harmless. Only what the relay itself calls is
# imported; tests reach the rest through watch_dashboard.
#
# Guarded, because the two are not equal: an error anywhere in the large,
# harmless module used to stop the small, dangerous one at import, and
# every wrist approval then fell back to the terminal (2026-10-17 tech-debt
# review). Now the relay starts without it: the card path gets the
# answers it gets for an unknown session (no title, nobody live), and the
# session and thread screens fail with DashboardUnavailable, which is an
# OSError, so the readers that already treat a missing file as "nothing
# to read" treat this the same way. check_dashboard_is_loaded() says so
# on the Connection screen.
class DashboardUnavailable(OSError):
    """watch_dashboard could not be imported; the reason is the message."""


_DASHBOARD_ERROR = None
try:
    from watch_dashboard import (  # noqa: E402
        activity_summary, card_session_title, recap_summary, _find_transcript, image_bytes,
        inbox_ready,
        _message_of, _parse_thread, _read_appended,
        project_root, prompts_at_the_mac, recent_sessions, active_sessions, registry_turn, resolve_session,
        session_registry, session_state, shape, thread_after, thread_tool_id,
        thread_wake_at, transcript_origin, transcripts_newest_first,
        THREAD_TURN_LIMIT, usage_summary)
except Exception as _error:  # noqa: BLE001 — any import-time failure, not only ImportError
    _DASHBOARD_ERROR = "%s: %s" % (type(_error).__name__, _error)

    def _dashboard_unavailable(*_args, **_kwargs):
        raise DashboardUnavailable(_DASHBOARD_ERROR)

    # A chain, not a tuple with a count typed beside it: a name added to
    # the import has one more place to go, not two.
    activity_summary = recap_summary = _find_transcript = image_bytes = \
        _message_of = _parse_thread = _read_appended = project_root = \
        prompts_at_the_mac = recent_sessions = active_sessions = resolve_session = session_state = \
        shape = thread_after = thread_tool_id = thread_wake_at = transcript_origin = \
        transcripts_newest_first = usage_summary = _dashboard_unavailable

    def card_session_title(_session_id):
        return None             # an unknown title: the card goes out as it came

    def session_registry(*_args, **_kwargs):
        return {}               # nobody live: the send guard can only ever ask

    def registry_turn(*_args, **_kwargs):
        return None             # no word from Claude Code: the old rule

    def inbox_ready(*_args, **_kwargs):
        return False            # the old route, which needs nothing from here

    THREAD_TURN_LIMIT = 14      # watch_dashboard's own value


# A transcript line as a dict: wire's, so the card watcher reads lines
# whether or not the dashboard imported.
_json_object = wire.json_object


def check_dashboard_is_loaded():
    """Record whether watch_dashboard was imported beside this relay.
    Approvals carry on either way; the sessions and threads do not."""
    if _DASHBOARD_ERROR:
        note_condition(
            "dashboard",
            "Part of the Tapproval helper failed to load, so sessions and "
            "threads cannot show here. Approvals still reach your wrist; "
            "reinstalling the helper should fix it.")
        return False
    clear_condition("dashboard")
    return True


def _codex_catalog_status(status):
    """Catalog visibility and native approvals have independent health."""
    if status == "unavailable":
        note_condition("codex_sessions", "Codex chats are unavailable. Reconnect Codex "
                       "on your computer; the last list will return when it reconnects.")
    elif status == "ready":
        clear_condition("codex_sessions")


def _codex_sync_status(error):
    if error:
        note_condition("codex_sync", "Codex approvals are unavailable on the watch. "
                       "Answer on your computer or iPhone while Base reconnects.")
    else:
        clear_condition("codex_sync")


def codex_approval_sync(queue):
    """The hook and background observer share one native request ledger."""
    from codex_approvals import ApprovalHub
    with queue._lock:
        sync = getattr(queue, "codex_sync", None)
        if sync is None:
            sync = ApprovalHub(queue, card_title=with_session_title, status=_codex_sync_status)
            queue.codex_sync = sync
    return sync


def with_session_title(card):
    """The card with the session's title beside its repository, for the
    wrist's place line ("familia-gateway · Show multi-day appointment…",
    the Wrist cards design, 2026-10-02). Added here rather than in the hook,
    which stays fast; a card without a session, or a title nobody knows,
    goes out as it came."""
    session_id = card.get("session_id")
    if not session_id or card.get("session_title"):
        return card
    title = card_session_title(session_id)
    return dict(card, session_title=title) if title else card


# What a wrist-sent message asks Claude to sound like. Each message spawns
# a fresh `claude` process, and a process reads its settings once, at
# start — so this flag shapes exactly one reply and nothing else. The
# desktop session it lands in never restarts, so its own style is
# untouched. Trying to change the user's settings file instead would
# quietly follow them back to the keyboard.
BRIEF_REPLY_SETTINGS = json.dumps({"outputStyle": "Concise"})

# The permission tool that lets a headless run ask the wrist. A `-p` run
# never fires the PermissionRequest hook — the hook belongs to the
# interactive terminal — so until this existed, a wrist instruction that
# needed a yes simply stopped at the first risky command and said nothing
# about why. Claude Code hands the question to this MCP tool instead, and
# it asks the same watch through the same relay.
PERMISSION_TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "watch_permission_tool.py")

# What a wrist-started run is told about itself. A `-p` run ends the
# moment its reply is written, and Claude Code then stops every process
# it started — which is how, on 2026-09-08, a message from the watch that
# said "create a TestFlight build" archived build 111, began the upload,
# wrote "uploading in the background, I'll report when it lands", and
# was killed mid-upload before anyone was told. The run believed it had a
# background; it did not. Telling it so is the honest fix: work that
# cannot finish inside one reply is refused in words, not started and
# abandoned. Refusing is a product rule, so it is stated once, here.
WRIST_RUN_RULES = (
    "This run was started from the user's watch and ends the moment you "
    "reply; every process you leave running is stopped then, and nothing "
    "tells the user. Do not start builds, deploys, uploads, long test "
    "runs, or anything you would report on later — say what you would "
    "have started and that it needs a session at the keyboard. Finish "
    "what fits inside one reply.")


def _permission_tool_flags(tool_path=None):
    """The flags that put the wrist in charge of a headless run's prompts,
    or nothing at all when the tool is not installed beside this file.

    Nothing, rather than a broken flag: an older install that updates the
    relay but not its neighbours must keep sending messages, not fail
    every send on a missing file.
    """
    path = tool_path or PERMISSION_TOOL
    if not os.path.isfile(path):
        return []
    # The tool finds the wrist through CLAUDE_RISK_RELAY. A plugin install
    # sets that on the PermissionRequest hook's own command line only, so
    # neither this relay nor the run it starts had it, and every prompt in
    # a wrist-sent run was denied "no relay address configured". The relay
    # knows the address; it hands it down, unless the user set their own.
    try:
        from ClaudeRiskClassifier import WATCH_ENV
    except Exception:
        WATCH_ENV = {"CLAUDE_RISK_MODE": "enforce",
                     "CLAUDE_RISK_RELAY": "http://127.0.0.1:%d" % DEFAULT_PORT}
    env = {key: os.environ.get(key) or value for key, value in WATCH_ENV.items()}
    config = json.dumps({"mcpServers": {"tapproval": {
        "command": sys.executable or "python3", "args": [path], "env": env}}})
    return ["--mcp-config", config,
            "--permission-prompt-tool", "mcp__tapproval__approve"]


# How long a "is Claude Code signed in?" answer is trusted. The question
# costs a subprocess, and the answer changes about twice a year.
SIGNIN_CACHE_SECONDS = 120.0
# An answer that could not be read is trusted for less, but trusted: left
# uncached, every /health started `claude auth status` again, up to 15 s
# each, several at once from the Connection screen (2026-09-25 review).
SIGNIN_UNKNOWN_CACHE_SECONDS = 30.0
# How long a caller waits for a fresh answer before going on with the last
# one. `claude auth status` may take 15 s; the watch gives up at 5 s, and a
# /health that waited for it answered nobody (2026-10-05 review).
SIGNIN_WAIT_SECONDS = 2.0
# /health uses the answer only to say so on the Connection screen.
HEALTH_SIGNIN_WAIT = 0.5
_SIGNIN = {"at": 0.0, "in": None, "asked": False}
_SIGNIN_LOCK = threading.Lock()


def signed_in(runner=None, now=None, wait=None):
    """True, False, or None when it cannot be told.

    `claude auth status` prints JSON with `loggedIn`. None — an old CLI
    without the subcommand, a timeout, anything unparseable — is NOT a
    refusal: this must never become a reason a send does not happen.

    Why it exists: on 2026-09-18 the CLI's OAuth session expired with no
    refresh token, so every wrist send died with "Failed to authenticate:
    OAuth session expired and could not be refreshed" — a sentence that
    reached the watch looking like Claude's own reply, in a thread, under
    a working pulse. The wrist should say the Mac needs signing in, and
    say it on the Connection screen where every other fault is reported.
    """
    stamp = time.time() if now is None else now
    # One question at a time, asked off the caller's thread and never under
    # the lock: callers that arrive meanwhile share it, and none waits
    # longer than SIGNIN_WAIT_SECONDS — after that, the last answer.
    with _SIGNIN_LOCK:
        if _SIGNIN.get("asked"):
            trusted = (SIGNIN_CACHE_SECONDS if _SIGNIN["in"] is not None
                       else SIGNIN_UNKNOWN_CACHE_SECONDS)
            if stamp - _SIGNIN["at"] < trusted:
                return _SIGNIN["in"]
        answered = _SIGNIN.get("asking")
        if answered is None:
            answered = _SIGNIN["asking"] = threading.Event()
            threading.Thread(target=_refresh_signed_in, args=(runner, stamp, answered),
                             daemon=True, name="signin").start()
        last = _SIGNIN["in"]
    if answered.wait(SIGNIN_WAIT_SECONDS if wait is None else wait):
        with _SIGNIN_LOCK:
            return _SIGNIN["in"]
    return last


def _refresh_signed_in(runner, stamp, answered):
    try:
        _ask_signed_in(runner, stamp)
    finally:
        with _SIGNIN_LOCK:
            _SIGNIN.pop("asking", None)
        answered.set()


def _ask_signed_in(runner, stamp):
    answer = None
    try:
        run = runner or (lambda: subprocess.run(
            ["claude", "auth", "status"], capture_output=True, text=True, timeout=15))
        done = run()
        # The JSON is the answer, whatever the exit code: signed out, the
        # CLI prints {"loggedIn": false, ...} and exits 1 (seen 2026-10-11,
        # Claude Code 2.1.288). Read only on exit 0, a plain "signed out"
        # became "cannot tell", the Connection screen said nothing, and
        # wrist sends died with "Failed to authenticate" in the thread.
        # Only a real boolean counts; anything else stays None.
        said = json.loads(done.stdout or "")
        if isinstance(said, dict) and isinstance(said.get("loggedIn"), bool):
            answer = said["loggedIn"]
    except Exception:
        answer = None
    with _SIGNIN_LOCK:
        _SIGNIN.update(at=stamp, asked=True, **{"in": answer})
    if answer is False:
        note_condition("signin", "Claude Code on your computer is signed out. "
                                 "Open a Terminal there and run: claude auth login")
    elif answer is True:
        clear_condition("signin")
    return answer


def say_guard(session_id, force=False, live=None):
    """Why a send should stop before it starts, or None to go ahead.

    A wrist send runs ``claude --resume -p`` — a second process on the
    session. When a process on this Mac already holds the session open,
    that second one appends turns the first never reads: a fork, and
    Claude Code calls it one (``--bg --resume`` "starts a copy" in exactly
    this case). Measured 2026-09-17 on a desktop session: of 27 desktop
    turns that followed wrist turns, 17 carried on as if the wrist had
    said nothing.

    The live ones are what Claude Code's own session registry says they
    are — the same reading the session list is built from, dead pids and
    unattended SDK runs already left out — so this costs a directory
    listing, not a process. "live" is the answer; the watch turns it into
    a question with two buttons, and ``force`` is the "yes". A failure to
    read the registry is an empty dict, which lets a send through: this
    guard can only ever ask, never block.
    """
    if force or not session_id:
        return None
    rows = session_registry() if live is None else live
    return "live" if session_id in rows else None


# Where Claude Code's own installers put the binary, most likely first. A
# relay started by launchd — the login agent, or a detached respawn with
# nothing but launchd's PATH (/usr/bin:/bin:/usr/sbin:/sbin) — sees none of
# these, and `claude` lives in ~/.local/bin for a native install.
CLAUDE_HOMES = ("~/.local/bin", "~/.claude/local", "/opt/homebrew/bin",
                "/usr/local/bin", "~/.npm-global/bin", "~/.bun/bin",
                "~/.volta/bin")

# What a Claude Code session sets in the environment of everything it
# runs — including this relay, when the SessionStart hook starts it, and
# Terminal.app, when the relay's `open` is what launches Terminal. Carried
# on into a session started from the wrist, CLAUDE_CODE_CHILD_SESSION tells
# that session it is some other session's child, and an interactive child
# saves no transcript: it ran, it answered, and the watch — which reads
# transcripts — never saw it exist. Seen 2026-09-24 on two wrist-started
# sessions in one day. CLAUDE_RISK_* is ours and stays; so does anything
# a user sets for themselves (CLAUDE_CODE_USE_BEDROCK and the like).
HOST_SESSION_MARKERS = (
    "CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT", "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_PREVIEW_CLASSIFIER_FLOOR",
    "CLAUDE_CODE_CHILD_SESSION", "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_HOST_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ATTENDED", "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_EXECPATH",
    "CLAUDE_CODE_OAUTH_SCOPES", "CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH",
    "CLAUDE_CODE_DESKTOP_APP_VERSION", "CLAUDE_CODE_EAGER_FLUSH",
    "CLAUDE_CODE_REPORT_FINDINGS", "CLAUDE_CODE_EMIT_TOOL_USE_SUMMARIES",
    "CLAUDE_CODE_ENABLE_ASK_USER_QUESTION_TOOL",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
    "CLAUDE_CODE_DISABLE_TERMINAL_TITLE", "CLAUDE_CODE_DISABLE_CRON",
)


def forget_host_session(environ=None):
    """Drop the markers of whichever Claude Code session started this
    process, so nothing the relay spawns mistakes itself for that
    session's child. Returns the names removed."""
    env = os.environ if environ is None else environ
    return [name for name in HOST_SESSION_MARKERS
            if env.pop(name, None) is not None]


def ensure_claude_on_path(environ=None, homes=None):
    """Make `claude` findable by name, whoever started this process.

    Found on the owner's Mac on 2026-09-23: after a reboot the relay ran
    with launchd's bare PATH, `shutil.which("claude")` came back empty, and
    every message sent from the watch answered "claude not on PATH" — which
    the watch can only show as "Could not send — try again", on a failure
    that no number of tries would fix. Fixing PATH here, once, covers every
    place that runs claude by name: a message, a new session, the sign-in
    check, and whatever those runs spawn in turn.

    Returns True when claude can be run. When it truly is not installed,
    says so on the Connection screen rather than behind a retry button.
    Never raises.
    """
    env = os.environ if environ is None else environ
    homes = CLAUDE_HOMES if homes is None else homes
    try:
        # which() with no path reads os.environ, the one this process and
        # everything it spawns will use.
        found = (shutil.which("claude") if environ is None
                 else shutil.which("claude", path=env.get("PATH")))
        if found:
            clear_condition("claude")
            return True
        for home in homes:
            folder = os.path.expanduser(home)
            # which(), not os.access: Windows' claude is claude.exe.
            if shutil.which("claude", path=folder):
                env["PATH"] = os.pathsep.join(
                    part for part in (env.get("PATH", ""), folder) if part)
                print("relay: found Claude Code in %s (not on this process's "
                      "PATH)" % folder, file=sys.stderr)
                clear_condition("claude")
                return True
    except Exception:
        pass
    note_condition("claude", "The helper cannot find Claude Code on your "
                             "computer, so messages from the watch cannot "
                             "be sent. Open Claude Code there once, then try "
                             "again.")
    return False


def _applescript_literal(text):
    """An AppleScript string literal. json.dumps escapes the quotes and
    backslashes AppleScript understands — with ensure_ascii=False, because
    AppleScript has no \\u escape and refuses to parse one (see
    start_session: every Danish message lost its route to that)."""
    return json.dumps(str(text), ensure_ascii=False)


def too_long(text):
    """The status for a wrist message over SEND_CHARS: the count and the
    limit, so the wearer knows how much to cut. The watch shows these
    words as they are (capitalised), so they read as a sentence."""
    return "too long: %d characters, the most is %d" % (len(text), SEND_CHARS)


def _run_osascript(script, timeout=4):
    """(ok, stdout or the reason it failed). Never raises."""
    try:
        done = subprocess.run(["osascript", "-e", script], capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)
    if done.returncode == 0:
        return True, done.stdout.strip()
    lines = (done.stderr or done.stdout or "").strip().splitlines()
    return False, lines[-1] if lines else "no reason given"


def ask_owner_to_pair(client_ip):
    """True only when the person at this computer clicked Allow.

    On a Mac, plain ``display dialog`` from osascript: it needs no
    automation consent, so it cannot hang on one the way scripting Terminal
    does. On Linux and Windows, the desktop's own dialog
    (tapproval_host.ask_person). Don't Allow, no click within
    PAIR_ASK_SECONDS, or no screen to show it on are all a no — fail
    closed; ``--pair`` is the way in there."""
    text = ("A watch at %s on your network wants to pair with this "
            "computer and answer its Claude Code prompts.\n\n"
            "Allow it only if it is your watch and you just opened "
            "Tapproval on it." % client_ip)
    if not _host.is_mac():
        allowed, said = _host.ask_person("Tapproval", text, "Allow", "Don't Allow",
                                         PAIR_ASK_SECONDS)
        print("relay: pairing from %s %s" % (
            client_ip, "allowed at this computer" if allowed else "not allowed: " + said),
            file=sys.stderr)
        return allowed
    script = ('display dialog %s with title "Tapproval" '
              'buttons {"Don\'t Allow", "Allow"} default button "Don\'t Allow" '
              'cancel button "Don\'t Allow" with icon caution '
              'giving up after %d' % (_applescript_literal(text), PAIR_ASK_SECONDS))
    ok, said = _run_osascript(script, timeout=PAIR_ASK_SECONDS + 10)
    if not ok:
        print("relay: pairing from %s not allowed: %s" % (client_ip, said),
              file=sys.stderr)
        return False
    allowed = "button returned:Allow" in said and "gave up:true" not in said
    print("relay: pairing from %s %s" % (
        client_ip, "allowed at this Mac" if allowed else "not answered"),
        file=sys.stderr)
    return allowed


def _settle_pair_request(auth, client_ip, ticket):
    """Ask, then record the answer — a no if the asking itself breaks."""
    allowed = False
    try:
        allowed = ask_owner_to_pair(client_ip)
    finally:
        auth.finish_asking(client_ip, allowed, ticket)


# How long a watch's question about its open thread may be held while
# nothing happens, and how often the transcript is looked at meanwhile.
# Holding the question is what makes the wrist quick: an answer leaves the
# moment its line is written, not at the watch's next 2.5 s look, and a
# quiet thread costs the watch three questions a minute instead of 24.
# Under cloudflared's 100 s, and well inside the watch's own timeout.
THREAD_WAIT_MAX = 20.0
THREAD_WAIT_STEP = 0.25
# Questions held at once, across every watch. One more is answered at
# once, as before, so no device can tie up the relay's threads.
_THREAD_WAITERS = threading.BoundedSemaphore(8)


def _query_number(query, name, kind):
    """``query[name]`` as ``kind``, or None when absent or not a number."""
    try:
        value = kind((query.get(name) or [""])[0])
    except (TypeError, ValueError):
        return None
    return value if value == value and value >= 0 else None   # no NaN, no negatives


def thread_news(path, mark, wait, still=lambda: True, reader=None):
    """``thread_after(path, mark)``, held up to ``wait`` seconds (at most
    THREAD_WAIT_MAX) while it has nothing to say and ``still()`` holds.
    The thread's lock is taken per look, never across the wait."""
    reader = reader or thread_after
    news = reader(path, mark)
    if news[0] or news[4] or news[3] != mark or wait <= 0:
        return news
    if not _THREAD_WAITERS.acquire(blocking=False):
        return news
    try:
        give_up = time.monotonic() + min(wait, THREAD_WAIT_MAX)
        while time.monotonic() < give_up and still():
            time.sleep(THREAD_WAIT_STEP)
            try:
                if os.path.getsize(path) == mark:
                    continue
            except OSError:
                break
            news = reader(path, mark)
            if news[0] or news[4] or news[3] != mark:
                break
        return news
    finally:
        _THREAD_WAITERS.release()


# How long `end_session` waits for a signalled session to be gone. A
# probe on 2026-10-22 (SIGTERM, SIGINT then SIGTERM, SIGHUP, idle and
# mid-answer) saw every one exit within 1.7 s, its transcript whole, its
# registry file removed, and `claude --resume` pick it up again after.
# Under the watch's own 5 s wait for an answer.
END_WAIT_SECONDS = 3.5


def _our_claude_processes():
    """(pid, command) of every process of this user's whose command runs
    Claude Code. Never raises; nothing found is an empty list."""
    me = _host.current_user()
    return [(pid, command) for pid, owner, command in _host.processes()
            if me is not None and owner == me and "claude" in command]


def _gone(pid):
    """True once ``pid`` no longer runs (reaped here if it was ours)."""
    _host.reap(pid)
    return not _host.pid_exists(pid)


def end_session(prefix, waiting=()):
    """End a session from the wrist: stop the Claude Code process the
    session registry names for it, and any copy a wrist message started
    (`claude --resume <id> -p`), which nothing else tracks. Returns
    "ended", or a word the watch turns into a sentence; never raises.

    Only a session in a terminal, and only a process this user owns whose
    command is Claude Code's: the registry is a file on disk, and its pid
    could by now name anything. Never while a card waits for the session —
    the wearer answers that first. A session from the Claude app is left
    to the app, which keeps its own sessions and would not expect one to
    vanish under it."""
    registry = session_registry()
    session_id, _ = resolve_session(prefix, registry=registry)
    if not session_id:
        return "unknown session"
    if any(str(card) and (session_id.startswith(str(card)) or str(card).startswith(session_id))
           for card in waiting):
        return "card waiting"
    entry = registry.get(session_id)
    if entry is not None and entry.get("status") != "Terminal":
        return "desktop"
    ours = _our_claude_processes()
    copies = [pid for pid, command in ours if "--resume " + session_id in command]
    pids = list(copies)
    if entry is not None:
        if entry["pid"] not in {pid for pid, _ in ours}:
            return "not ours"
        pids = [entry["pid"]] + [pid for pid in copies if pid != entry["pid"]]
    if not pids:
        return "not live"
    started = time.monotonic()
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            return "not ours"
    while time.monotonic() - started < END_WAIT_SECONDS:
        if all(_gone(pid) for pid in pids):
            print("relay: end %s (%d process%s, %d ms)" % (
                session_id[:8], len(pids), "" if len(pids) == 1 else "es",
                (time.monotonic() - started) * 1000), file=sys.stderr)
            return "ended"
        time.sleep(0.1)
    print("relay: end %s: still running after %.0f s" % (session_id[:8], END_WAIT_SECONDS),
          file=sys.stderr)
    return "still running"


# Where Claude Code puts a session's inbox socket: its own directory under
# the temp folder, or the per-user runtime folder on Linux. Anything else in
# a registry file is not posted to.
INBOX_PATH = re.compile(r"^(?:/private)?/tmp/cc-socks(?:-\d+)?/[^/]+\.sock$"
                        r"|^/run/user/\d+/cc-socks/[^/]+\.sock$")
INBOX_TIMEOUT = 3.0


def _peer_pid(sock):
    """The pid at the other end of a connected Unix socket, or None."""
    try:
        if _host.is_mac():
            # SOL_LOCAL (0), LOCAL_PEERPID (2): <sys/un.h>
            return struct.unpack("i", sock.getsockopt(0, 2, 4))[0]
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize("3i"))
        return struct.unpack("3i", creds)[0]
    except (OSError, AttributeError, struct.error):
        return None


def post_to_inbox(entry, text, brief=False, timeout=INBOX_TIMEOUT):
    """Post a wrist message into a live session's own inbox (Claude Code's
    cross-session messaging), where the open session reads it as its next
    turn: no keystrokes, no permission, and the terminal and the phone
    follow it (#246, tested 2026-10-22). True only when the line was
    written. Never raises.

    The socket is the one the session's registry file names, under Claude
    Code's own directory, a socket and not a link, ours, and held by that
    session's process: the same checks Claude Code makes before it sends."""
    entry = entry or {}
    path = str(entry.get("socket") or "")
    if not INBOX_PATH.match(path) or not _host.unix_sockets():
        return False
    try:
        found = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISSOCK(found.st_mode) or found.st_uid != os.getuid():
        return False
    line = json.dumps({"type": "user",
                       "message": {"role": "user",
                                   "content": wire.wrist_inbox_message(text, brief)}}) + "\n"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(path)
        if _peer_pid(sock) != entry.get("pid"):
            return False
        sock.sendall(line.encode("utf-8"))
        return True
    except OSError:
        return False
    finally:
        sock.close()


class _StampedStream:
    """The relay's stderr with the time at the head of every line.

    The relay log had no times at all, so a slow send could not be timed
    from tap to transcript, nor a failure placed next to anything else
    (2026-09-30). Wraps the stream; never raises past it."""

    def __init__(self, stream, clock=None):
        self._stream = stream
        self._clock = clock or (lambda: time.strftime("%H:%M:%S"))
        self._at_start = True
        self._lock = threading.Lock()

    def write(self, text):
        with self._lock:
            out = []
            for piece in str(text).splitlines(keepends=True):
                if self._at_start:
                    out.append(self._clock() + " ")
                out.append(piece)
                self._at_start = piece.endswith("\n")
            self._stream.write("".join(out))
        return len(text)

    def flush(self):
        self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def say_to_session(prefix, text, projects_dir=None, brief=True, force=False, agent=None):
    """Send an instruction to a session, the way the terminal would.

    A session open on this computer gets it in its own inbox (post_to_inbox,
    #246), as its next turn. Otherwise — a closed session, one in bypass or
    plan mode, a command, or a post that fails — this
    runs ``claude --resume <id> -p <text>`` in that session's directory so
    the reply lands in the same transcript the watch is reading — which is
    why the answer simply appears in the thread view. With ``brief`` (the
    default) the reply is asked for in Claude Code's Concise style, which
    is what a 14 pt thread on a wrist wants. Returns a short status
    string; never raises and never blocks the caller.
    """
    text = " ".join(str(text or "").split())
    if not text:
        return "empty"
    if len(text) > SEND_CHARS:
        return too_long(text)
    if agent not in (None, "claude", "codex"):
        return "unknown agent"
    import codex_sessions
    codex_path = codex_sessions.find_rollout(prefix)
    if agent == "codex" or codex_path:
        if agent == "claude":
            return "session belongs to Codex"
        from ClaudeRiskClassifier import ensure_codex_on_path
        from codex_talk import send
        binary = ensure_codex_on_path()
        if not binary:
            return "Codex is not installed on your computer"
        return send(prefix, text, binary, _spawn_detached, SAY_LOG, brief=brief)
    registry = session_registry()
    session_id, cwd = resolve_session(prefix, projects_dir, registry=registry)
    if not session_id:
        return "unknown session"
    started = time.monotonic()
    # Open on this computer: into the session's own inbox, so the open
    # session itself reads it — the terminal and the phone with it. Not in
    # a mode where Claude Code would hold it for a click; then, and when
    # the post fails, the old route.
    entry = registry.get(session_id)
    # A command (/recap, a skill from More) is not one: the inbox delivers
    # text, never a command, so it goes the old way, which runs it.
    if (entry and not text.startswith("/")
            and inbox_ready(entry, _find_transcript(session_id, projects_dir))
            and post_to_inbox(entry, text, brief=brief)):
        print("relay: say %s inbox (%d ms)" % (session_id[:8],
              (time.monotonic() - started) * 1000), file=sys.stderr)
        return "sent"
    stop = say_guard(session_id, force=force, live=registry)
    if stop:
        return stop
    if not ensure_claude_on_path():
        return "claude not on PATH"
    if signed_in() is False:
        # Spawning anyway would put Claude Code's own authentication error
        # into the transcript, where the watch reads it as a reply.
        return "signed out"
    command = ["claude", "--resume", session_id]
    if brief:
        command += ["--settings", BRIEF_REPLY_SETTINGS]
    command += _permission_tool_flags()
    command += ["--append-system-prompt", WRIST_RUN_RULES]
    # "--" ends the options: without it a message reading
    # "--dangerously-skip-permissions" is parsed as that flag, not sent.
    command += ["-p", "--", text]
    error = _spawn_detached(command, SAY_LOG, cwd=cwd)
    print("relay: say %s headless (%d ms)%s" % (
        session_id[:8], (time.monotonic() - started) * 1000,
        " — could not start: %s" % error if error else ""), file=sys.stderr)
    return "could not start: %s" % error if error else "sent"


# The built-ins the watch offers by name, as (description, hint). Built-ins
# live inside the CLI, not on disk, so they cannot be discovered. The two
# reviews read and do not write. /design and /slides (Claude Code 2.1.310,
# signed in to claude.ai) make a new artifact from a brief; its publish asks
# on the wrist like any other permission. Their CLI hint is in square
# brackets, which required_argument() reads as optional, and a bare /design
# only makes Claude ask back what to design: so the hint here has no
# brackets, and the watch holds the tap for the brief.
SKILL_BUILTINS = {
    "code-review": ("Reviews the diff for bugs and risks before it ships.", None),
    "security-review": ("Checks the changes for vulnerabilities.", None),
    "design": ("Makes a new design from your brief.", "what to design"),
    "slides": ("Makes a slide deck from your brief.", "what the deck is about"),
}
_SKILLS_CACHE = {}          # cwd -> (expires, rows)
# ThreadingHTTPServer answers two /skills at once; an eviction iterating
# the dict while another thread inserts raised "dictionary changed size
# during iteration" (2026-10-25 review, L11). The scan of the disk runs
# outside the lock; only the read, the insert and the eviction are inside.
_SKILLS_CACHE_LOCK = threading.Lock()
SKILLS_CACHE_MAX = 32
SKILLS_CACHE_SECONDS = 60.0


def _frontmatter(path):
    """The handful of frontmatter keys the wrist uses from a skill or
    command file — ``description`` (the sentence its author wrote for
    exactly this use, or the first line of prose when there is none),
    ``argument-hint`` (what to say after the name) and ``user-invocable``
    (``false`` keeps a skill out of the slash menu, so out of the More
    list too). Stdlib only: the frontmatter is ``key: value`` lines, not
    full YAML. Never raises; an unreadable file is an empty dict."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read(20000).split("\n")
    except OSError:
        return {}
    found = {}
    if lines and lines[0].strip() == "---":
        for line in lines[1:]:
            if line.strip() == "---":
                break
            key, sep, value = line.partition(":")
            if sep and key.strip() in ("description", "argument-hint", "user-invocable"):
                found[key.strip()] = " ".join(value.strip().strip("'\"").split())[:300]
    if not found.get("description"):
        for line in lines:
            text = line.strip()
            if text and not text.startswith(("---", "#", "name:")):
                found["description"] = text[:300]
                break
    return found


def required_argument(hint):
    """The argument-hint, when the command needs something said after its
    name; None when every part of it is optional.

    The watch puts a row with a hint into the Message field instead of
    sending it, so the person can add the words. For "[optional note]"
    there is nothing they must add, and the tap that only filled a field
    above the list, out of sight, read as /wrap-up not working
    (2026-10-16). A part in square brackets is optional, by the usual
    reading of a usage line; anything else — "<question>", a bare word —
    still asks for words."""
    hint = " ".join(str(hint or "").split())
    rest = hint
    while True:
        shorter = re.sub(r"\[[^\[\]]*\]", "", rest)
        if shorter == rest:
            break
        rest = shorter
    return hint if rest.strip() else None


def _skill_roots(cwd, home):
    """Where this machine keeps skills and commands, as (root, source,
    plugin) rows, nearest first for the project.

    The project's own `.claude` and every one between `cwd` and the
    repository root (a worktree lists the main checkout's skills, as
    Claude Code does from 2.1.277); the user's; and each plugin's. A
    plugin lives in one of two places: the install registry
    (`installed_plugins.json`), or the folder the desktop app syncs an
    organisation's plugins into (`plugins/synced/<org>_<user>/<plugin>/`),
    whose folder name may carry a `~g2`-style suffix the slash name
    does not. `plugins/marketplaces/` is a catalogue cache, not an
    install, and is never read: on 2026-10-15 it held 127 skill files
    nobody had enabled."""
    roots = []
    if cwd:
        seen = set()
        here = os.path.abspath(cwd)
        stop = os.path.abspath(project_root(here) or here)
        while True:
            if here in seen:
                break
            seen.add(here)
            roots.append((os.path.join(here, ".claude"), "project", None))
            if here == stop or os.path.dirname(here) == here:
                break
            here = os.path.dirname(here)
    roots.append((os.path.join(home, ".claude"), "user", None))
    plugins_dir = os.path.join(home, ".claude", "plugins")
    try:
        with open(os.path.join(plugins_dir, "installed_plugins.json"),
                  encoding="utf-8") as handle:
            registry = json.load(handle).get("plugins", {})
    except (OSError, ValueError):
        registry = {}
    for key, entries in registry.items():
        for entry in (entries if isinstance(entries, list) else [entries]):
            path = entry.get("installPath") if isinstance(entry, dict) else None
            if path:
                roots.append((path, "plugin", _plugin_name(str(key).split("@", 1)[0])))
    for synced in sorted(glob.glob(os.path.join(plugins_dir, "synced", "*", "*"))):
        bucket, plugin = os.path.basename(os.path.dirname(synced)), os.path.basename(synced)
        if bucket.startswith(".") or plugin.startswith(".") or not os.path.isdir(synced):
            continue
        roots.append((synced, "plugin", _plugin_name(plugin)))
    return roots


def _plugin_name(folder):
    """`engineering~g2` is invoked as `/engineering:…`."""
    return re.sub(r"~g\d+$", "", folder)


def known_skills(cwd=None, home=None, now=None):
    """Every slash command this machine can answer for a session in
    ``cwd``: the built-ins, the project's skills and commands
    (and its repository's, from a worktree), the user's own, and each
    installed plugin's under the name the CLI gives them,
    ``/<plugin>:<skill>``. One row per name, with the description its
    file carries, so the watch lists a skill only where it exists and
    describes it in its author's words rather than in ours. A skill
    marked ``user-invocable: false`` is not a slash command and is not
    listed. A minute's cache per directory: the More list opens far less
    often than the session list polls.

    Not every skill listed will do what a headless run can — one that
    writes gets a refusal — but a command the CLI does not know now
    arrives on the wrist as a red notice rather than as nothing, so an
    honest list beats a curated one that goes stale.
    """
    home = home or os.path.expanduser("~")
    now = now or time.time()
    key = (cwd or "", home)
    with _SKILLS_CACHE_LOCK:
        hit = _SKILLS_CACHE.get(key)
    if hit and hit[0] > now:
        return hit[1]
    found = {}
    for name, (description, hint) in SKILL_BUILTINS.items():
        found[name] = {"description": description, "source": "builtin", "plugin": None,
                       "argument_hint": hint}
    for root, source, plugin in _skill_roots(cwd, home):
        files = [(os.path.basename(os.path.dirname(f)), f)
                 for f in glob.glob(os.path.join(root, "skills", "*", "SKILL.md"))]
        commands_dir = os.path.join(root, "commands")
        for f in glob.glob(os.path.join(commands_dir, "**", "*.md"), recursive=True):
            # commands/a/b.md is /a:b — a folder is a namespace.
            relative = os.path.relpath(f, commands_dir)[:-3]
            files.append((":".join(relative.split(os.sep)), f))
        for name, path in files:
            if plugin:
                name = "%s:%s" % (plugin, name)
            if name in found:
                continue
            meta = _frontmatter(path)
            if meta.get("user-invocable", "").lower() == "false":
                continue
            found[name] = {"description": meta.get("description", ""), "source": source,
                           "plugin": plugin,
                           "argument_hint": required_argument(meta.get("argument-hint"))}
    rows = [dict(name="/" + name, **meta) for name, meta in sorted(found.items())]
    with _SKILLS_CACHE_LOCK:
        _SKILLS_CACHE[key] = (now + SKILLS_CACHE_SECONDS, rows)
        while len(_SKILLS_CACHE) > SKILLS_CACHE_MAX:     # one per folder, for weeks
            _SKILLS_CACHE.pop(next(iter(_SKILLS_CACHE)), None)
    return rows


# Folders that hold throwaway work — Claude Code's own scratchpads live
# under /tmp. A module constant so the tests, whose temporary projects live
# there too on Linux, can say so.
# Windows adds its temp folder, which is not under /tmp.
SCRATCH_ROOTS = _host.scratch_roots(("/tmp", "/private/tmp"))

# Where a person keeps code, by the names people give that folder, for the
# Mac that has never run Claude Code: the first session has to start
# somewhere, and the transcripts have nothing to offer yet.
CODE_ROOTS = ("Developer", "Projects", "Code", "code", "src", "repos",
              "dev", "work", "git", "Sites")
# The home folder those names sit under. None means the real one; the
# suite points it at a temporary folder so no test reads the owner's.
FIRST_SESSION_HOME = None


def _is_repository(path):
    """A `.git` folder, or a worktree's `.git` file: the test
    repository_root makes, without the walk. Never raises."""
    marker = os.path.join(path, ".git")
    return os.path.isdir(marker) or os.path.isfile(marker)


def first_projects(limit=25, home=None, repositories_only=False):
    """What *New session* offers on a Mac whose transcripts offer nothing:
    the repositories in the person's code folders (`CODE_ROOTS`), newest
    first; failing those, the code folders that exist; failing those, the
    home folder itself, named "Home". So the first session can always be
    started from the wrist (the owner, 2026-10-17) — before this, the
    picker said "No projects yet" and the feature could not begin.

    Each row carries ``first: True`` so a watch can one day say where the
    list came from. Nothing under a scratch root, and nothing a symlink
    carries outside the home folder. ``repositories_only`` returns the
    repositories alone, or nothing: what `known_projects` adds to a list
    the transcripts already gave. Never raises.
    """
    now = time.time()
    home = os.path.realpath(home or FIRST_SESSION_HOME or os.path.expanduser("~"))
    scratch = tuple(os.path.realpath(p) + os.sep for p in SCRATCH_ROOTS)

    def row(path):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = now
        return {"name": os.path.basename(path.rstrip("/")) or path, "path": path,
                "minutes_ago": max(0, int((now - mtime) / 60)), "first": True}

    def inside_home(path):
        real = os.path.realpath(path) + os.sep
        return real.startswith(home + os.sep) and not real.startswith(scratch)

    # One row per folder, whatever it is called: on a Mac's
    # case-insensitive disk "Code" and "code" are the same folder, and
    # realpath does not say so — the inode does.
    seen = set()

    def fresh(path):
        try:
            stat = os.stat(path)
        except OSError:
            return False
        key = (stat.st_dev, stat.st_ino)
        if key in seen:
            return False
        seen.add(key)
        return True

    roots = [os.path.join(home, name) for name in CODE_ROOTS]
    roots = [r for r in roots if os.path.isdir(r) and inside_home(r) and fresh(r)]
    repos = []
    for root in roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            if (not name.startswith(".") and os.path.isdir(path)
                    and inside_home(path) and _is_repository(path) and fresh(path)):
                repos.append(row(path))
    if repositories_only:
        repos.sort(key=lambda r: r["minutes_ago"])
        return repos[:limit]
    rows = repos or [row(r) for r in roots]
    if not rows:
        home_row = row(home)
        home_row["name"] = "Home"
        return [home_row]
    rows.sort(key=lambda r: r["minutes_ago"])
    return rows[:limit]


def known_projects(projects_dir=None, limit=25):
    """Known folders, choosing the most recently used agent per project."""
    import codex_sessions
    rows = _claude_projects(projects_dir, limit)
    by_path = {os.path.realpath(row["path"]): dict(row) for row in rows}
    modified = {}
    for mtime, path, _, _ in transcripts_newest_first(projects_dir):
        cwd, entry = transcript_origin(path)
        if cwd and entry != shape("entrypoint.sdk_cli"):
            real = os.path.realpath(project_root(cwd))
            modified[real] = max(mtime, modified.get(real, 0))
    for mtime, path in codex_sessions._rollouts(os.path.join(codex_sessions._home(), "sessions")):
        meta = codex_sessions._rollout_meta(path)
        if not meta or not meta["cwd"]:
            continue
        root = project_root(meta["cwd"])
        if not root or not os.path.isdir(root):
            continue
        real = os.path.realpath(root)
        home = os.path.realpath(os.path.expanduser("~"))
        if real == home or any((real + os.sep).startswith(os.path.realpath(p) + os.sep)
                               for p in SCRATCH_ROOTS):
            continue
        age = max(0, int((time.time() - mtime) / 60))
        old = by_path.get(real)
        if old is None or mtime > modified.get(real, 0):
            by_path[real] = {"name": os.path.basename(root.rstrip("/")) or root,
                             "path": root, "minutes_ago": age, "agent": "codex"}
            modified[real] = mtime
    return sorted(by_path.values(), key=lambda r: r["minutes_ago"])[:limit]


def _claude_projects(projects_dir=None, limit=25):
    """The projects a new session may be started in: one row per repository
    a person has recently worked in, most recent first. Derived from the
    same transcripts the session list reads, so the watch never has to
    type a path and the relay never opens a terminal somewhere it has not
    already seen Claude Code run — or, before the first session, outside
    the person's own code folders (`first_projects`), which stand in only
    while this list would otherwise be empty.

    Two kinds of folder are not projects, and on 2026-09-23 they were most
    of the list. A session's own worktree folds into its repository — the
    picker offered "app-store-version-update-b03a35", and chose it by
    default, where the desktop app offers "ClaudeWatch". And a folder only
    ever worked in by unattended runs (`claude -p`, a scheduled loop) is
    where a machine works, not where a person starts something: twenty of
    the first twenty-five rows were those. Nor is a scratch folder, or the
    home folder itself — Claude Code runs there, nobody means to start work
    there from a wrist.
    """
    now = time.time()
    seen, rows = set(), []
    home = os.path.realpath(os.path.expanduser("~"))
    scratch = tuple(os.path.realpath(p) + os.sep for p in SCRATCH_ROOTS)
    checked = set()
    for mtime, path, _, _ in transcripts_newest_first(projects_dir):
        cwd, entry_point = transcript_origin(path)
        if not cwd or entry_point == shape("entrypoint.sdk_cli"):
            continue
        # Thousands of transcripts share a handful of folders, and a folder
        # gets the same answer every time: work out its repository once.
        if cwd in checked:
            continue
        checked.add(cwd)
        root = project_root(cwd)
        if root in seen or not os.path.isdir(root):
            continue
        seen.add(root)
        real = os.path.realpath(root)
        if real == home or (real + os.sep).startswith(scratch):
            continue
        rows.append({"name": os.path.basename(root.rstrip("/")) or root,
                     "path": root,
                     "minutes_ago": max(0, int((now - mtime) / 60))})
        if len(rows) >= limit:
            break
    # A Mac that has never run Claude Code where a person sits (a fresh
    # install, or only unattended loops so far) has nothing to offer from
    # its transcripts — and the first session has to start somewhere.
    if not rows:
        return first_projects(limit)
    # Nor has a repository made since: the transcripts know only where
    # Claude Code already ran, and a new repository was missing from the
    # picker it was made to be started from (the owner, 2026-10-25). So
    # the code folders' repositories join the list — but not a worktree
    # (a `.git` file), which is its repository's, nor a second copy of a
    # repository already offered: on this Mac most of ~/Developer is
    # spare clones, and they would bury the list as worktrees once did.
    listed = {os.path.realpath(r["path"]) for r in rows}
    remotes = {_origin(r["path"]) for r in rows} - {None}
    for found in first_projects(limit, repositories_only=True):
        path = found["path"]
        if os.path.realpath(path) in listed or not os.path.isdir(os.path.join(path, ".git")):
            continue
        remote = _origin(path)
        if remote in remotes:
            continue
        if remote:
            remotes.add(remote)
        rows.append(found)
    rows.sort(key=lambda r: r["minutes_ago"])
    return rows[:limit]


def _origin(path):
    """A repository's `origin`, as "host/owner/name" in lower case, so two
    clones of one repository compare equal whichever way they were cloned
    (https or ssh, with `.git` or without). None when there is none, or
    the config cannot be read. Never raises."""
    try:
        with open(os.path.join(path, ".git", "config"), encoding="utf-8",
                  errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    section = re.search(r'^\s*\[remote "origin"\](.*?)(?=^\s*\[|\Z)', text, re.M | re.S)
    url = section and re.search(r"^\s*url\s*=\s*(\S+)", section.group(1), re.M)
    if not url:
        return None
    where = re.sub(r"^[a-z+]+://", "", url.group(1).lower())
    where = re.sub(r"^[^@/]*@", "", where).replace(":", "/", 1)
    return re.sub(r"(\.git)?/*$", "", where) or None


# Claude Code's own config, where it records which folders a person has
# trusted. Overridable, so no test — nor a relay a test starts — writes the
# real one.
CLAUDE_CONFIG = os.environ.get("TAPPROVAL_CLAUDE_CONFIG") or os.path.join(
    os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~"), ".claude.json")

# What the wrist reads when a session opened but waits on the Mac for its
# folder to be trusted. A whole sentence, because a watch shows any status
# it has no words of its own for as it stands.
AWAITS_TRUST = "On your Mac, Claude asks once whether to trust this folder."


def _trusts(projects, path):
    """True if Claude Code's ``projects`` table trusts ``path`` or a folder
    above it, as Claude Code itself decides."""
    for folder in {path, os.path.realpath(path)}:
        while True:
            entry = projects.get(folder)
            if isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is True:
                return True
            parent = os.path.dirname(folder)
            if parent == folder:
                break
            folder = parent
    return False


# What a folder can bring that runs once Claude Code trusts it: its own
# settings (hooks, an API-key helper, environment) and its tool servers.
TRUST_RUNS = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")


def trust_folder(path, config=None):
    """Make sure Claude Code will not stop a new session in ``path`` at its
    "Do you trust the files in this folder?" question. True when it will
    not; False when it will, and the wearer must answer it at the Mac.

    A folder Claude Code has never opened asks first, before it writes a
    transcript, so a session started there never reaches the watch's list:
    on 2026-10-25 a repository made that afternoon, offered by the picker
    since #942, spun on the wrist as "Check <name>'s Mac" while two Terminal
    windows sat on the question. The wearer chose the folder, from their
    own code folders, on purpose — so the relay records the trust Claude
    Code would have asked for (the owner, 2026-10-25), touching that one
    key and nothing else in the file.

    Unless the folder brings settings of its own: trusting it runs its
    hooks and tool servers, which a stranger's repository can carry, so
    that question stays with the person at the Mac (the owner, 2026-10-26
    review). And Claude Code rewrites the file while sessions run, so a
    write that lands meanwhile is read again, never replaced. Never raises.
    """
    config = config or CLAUDE_CONFIG
    try:
        for _attempt in range(2):
            before = os.stat(config)
            with open(config, encoding="utf-8") as handle:
                settings = json.load(handle)
            projects = settings.setdefault("projects", {}) if isinstance(settings, dict) else None
            if not isinstance(projects, dict):
                raise ValueError("not Claude Code's config")
            if _trusts(projects, path):
                return True
            brings = [name for name in TRUST_RUNS if os.path.lexists(os.path.join(path, name))]
            if brings:
                raise ValueError("it brings %s" % ", ".join(brings))
            entry = projects.setdefault(path, {})
            if not isinstance(entry, dict):
                raise ValueError("an entry that is not a table")
            entry["hasTrustDialogAccepted"] = True
            handle, temp = tempfile.mkstemp(prefix=".claude.json.", dir=os.path.dirname(config))
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as out:
                    json.dump(settings, out, indent=2, ensure_ascii=False)
                os.chmod(temp, before.st_mode & 0o777)
                now = os.stat(config)
                if (now.st_mtime_ns, now.st_size) != (before.st_mtime_ns, before.st_size):
                    os.unlink(temp)
                    continue            # rewritten meanwhile: read it again
                os.replace(temp, config)
                break
            except BaseException:
                try:
                    os.unlink(temp)
                except OSError:
                    pass
                raise
        else:
            raise ValueError("Claude Code kept rewriting its config")
    except (OSError, ValueError) as error:
        print("relay: new session: %s awaits trust (%s)"
              % (os.path.basename(path.rstrip("/")), error), file=sys.stderr)
        return False
    print("relay: new session: trusted %s" % os.path.basename(path.rstrip("/")),
          file=sys.stderr)
    return True


def start_session(path, text, projects_dir=None, platform=None):
    """Open a REAL Claude Code session on this computer, in ``path``, with ``text``
    as its first message. Returns a short status; "started" on success.

    Not ``claude -p``: that is headless, and a headless session never fires
    the PermissionRequest hook — it would be the one session that could not
    ask the watch anything, and would stop at its first risky command. So
    this opens a Terminal window running an ordinary interactive ``claude``,
    whose cards reach the wrist like any other's.

    Every failure comes back as words the watch can show: no Mac, no
    ``claude`` on the PATH, a directory the picker did not offer (one Claude
    Code has never worked in — or, before the first session, one outside
    the person's code folders), or a Terminal that will not open (no one logged in at the screen — the
    usual reason). Never raises, never blocks longer than a few seconds.
    """
    text = " ".join(str(text or "").split())
    if not text:
        return "empty"
    if len(text) > SEND_CHARS:
        return too_long(text)
    if text[:1] in ("!", "#"):
        # First in Claude Code's prompt, `!` runs the rest as a shell
        # command with no card, and `#` writes memory (2026-09-25 review).
        return "a first message cannot start with ! or #"
    # Which window to open: Terminal on a Mac, the desktop's own terminal
    # on Linux and Windows. ``platform`` lets a test stand in for a host.
    on_mac = _host.is_mac() if platform is None else platform == "darwin"
    path = os.path.expanduser(str(path or ""))
    project = next((row for row in known_projects(projects_dir) if row["path"] == path), None)
    if project is None:
        return "unknown project"
    codex = project.get("agent") == "codex"
    if codex:
        from ClaudeRiskClassifier import ensure_codex_on_path
        from codex_talk import flags
        binary = ensure_codex_on_path()
        if not binary:
            return "Codex is not installed on your computer"
        started = "started"
    else:
        if not ensure_claude_on_path():
            return "claude not on PATH"
        if signed_in() is False:
            return "signed out"
        started = "started" if trust_folder(path) else AWAITS_TRUST
    # shlex.quote stops the shell reading the text; "--" stops claude
    # reading it as a flag, which quoting alone does not.
    # The unset is for a Terminal that is already carrying some session's
    # markers (see HOST_SESSION_MARKERS): scrubbing this process cannot
    # reach a Terminal launched before it, and its windows inherit.
    # The session is born on the wrist, so it speaks the wrist's style from
    # its first answer, as a reply sent into a session already does. It
    # stays Concise if the person later sits down at it; `/output-style`
    # changes that there.
    script = 'unset %s; cd %s && claude --settings %s -- %s' % (
        " ".join(HOST_SESSION_MARKERS), shlex.quote(path),
        shlex.quote(BRIEF_REPLY_SETTINGS), shlex.quote(text))
    if codex:
        script = 'unset %s; cd %s && %s' % (
            " ".join(HOST_SESSION_MARKERS), shlex.quote(path),
            shlex.join([binary] + flags() + ["--", text]))
    if not on_mac:
        # The same session in PowerShell words for Windows; Linux runs the
        # bash script above. Every word is a literal, the binary's included.
        words = ([binary] + flags() if codex
                 else ["claude", "--settings", BRIEF_REPLY_SETTINGS]) + ["--", text]
        if _host.is_windows():
            # A program, never a .cmd or .ps1 wrapper (npm's): a batch file
            # reads its arguments again, so "a&calc" in the wearer's text
            # would run calc. Claude Code's and Codex's own installers give
            # an .exe; anything else is refused, in words.
            program = binary if codex else shutil.which("claude")
            if not program or not program.lower().endswith(".exe"):
                return "new sessions need %s's own installer on Windows" % (
                    "Codex" if codex else "Claude Code")
            words[0] = program
        windows = "%s; Set-Location -LiteralPath %s -ErrorAction Stop; & %s" % (
            "; ".join("Remove-Item -ErrorAction SilentlyContinue Env:%s" % name
                      for name in HOST_SESSION_MARKERS),
            _host.powershell_literal(path),
            " ".join(_host.powershell_literal(word) for word in words))
        ok, why = _host.open_terminal(script, windows)
        return started if ok else "could not open a terminal: %s" % why
    # json.dumps is the right escaper for the quotes and backslashes an
    # AppleScript string literal understands — but only with
    # ensure_ascii=False. Left at its default it writes \u00e5 for "å",
    # and AppleScript has no \u escape: it does not mangle the text, it
    # refuses to parse, "Expected \u201d\"\u201d but found unknown token".
    # So every session started from the wrist in Danish, or with an emoji
    # or a smart quote, lost this route and limped along on the .command
    # fallback — which uses the unescaped string and therefore
    # worked, which is exactly why nobody noticed for the life of the
    # feature. A fallback that hides a failure is a fallback that stops
    # you fixing it.
    # A .command file first. Launch Services hands it to Terminal, which
    # runs it in a new window, and it asks nothing of anyone; the file
    # removes itself as its first act. Scripting Terminal comes second
    # because it needs an automation consent a background relay cannot
    # ask for, and without it osascript does not fail — it hangs until
    # its timeout. That wait was spent first, on every tap: measured
    # 2026-09-24, the relay took 4.3 s to answer on loopback, and the
    # watch, whose requests give up at 5 s and travel through the phone,
    # said "Your computer didn't answer" about a session that had started.
    try:
        handle, command_file = tempfile.mkstemp(prefix="tapproval-", suffix=".command")
        with os.fdopen(handle, "w") as out:
            out.write('#!/bin/bash\nrm -f -- "$0"\n%s\n' % script)
        os.chmod(command_file, 0o700)
        opened = subprocess.run(["open", command_file], capture_output=True,
                                text=True, timeout=8)
        if opened.returncode == 0:
            return started
        also = (opened.stderr or opened.stdout or "").strip().splitlines()
        not_opened = also[-1] if also else "no reason given"
    except subprocess.TimeoutExpired:
        # Launch Services may already have accepted the .command file.
        # A second launch through AppleScript could create two sessions.
        return "unknown"
    except (OSError, subprocess.SubprocessError) as error:
        not_opened = str(error)
    apple = ('tell application "Terminal"\n'
             '  activate\n'
             '  do script %s\n'
             'end tell' % _applescript_literal(script))
    ok, why = _run_osascript(apple)
    if ok:
        return started
    return "could not open Terminal: %s (nor a .command file: %s)" % (
        why, not_opened)


# How often the resolver looks for subagent transcripts that did not exist
# when the card was posted. A seam so tests need not sleep through it.
RESOLVER_RESCAN_SECONDS = 5.0


class _PromptResolver:
    """Answers, on each call: was this card's prompt resolved elsewhere?

    The transcript already carries the truth — the assistant's tool_use
    for the very call the card asks about was written before the prompt,
    and a tool_result for that same id appears the moment ANY surface
    answers it. We match the tool_use by the card's fingerprint (the same
    hash the hook stamped), remember its id, and watch for the result.
    Each check reads only bytes appended since the last one; the first
    reads a bounded tail to find the originating tool_use. Never raises.

    One entry per transcript we watch: the session's own, plus every
    subagent's. A card raised inside a subagent has its tool_use written
    to `<session>/subagents/agent-*.jsonl`, NOT to the session file — so
    watching only the session file meant such a card could never be
    retracted, and hung on the wrist until the wait expired.
    """
    TAIL_BYTES = 262144
    RETRY_SECONDS = 30.0

    def __init__(self, session_id, tool, fingerprint, fingerprint_of,
                 projects_dir=None, digests=None, digests_of=None):
        self.session_id = session_id
        self.tool = tool
        self.fingerprint = fingerprint
        self.fingerprint_of = fingerprint_of
        self.digests = digests if isinstance(digests, dict) else {}
        self.digests_of = digests_of
        self.projects_dir = projects_dir
        self.path = None            # the session transcript, once found
        self.files = {}             # transcript path -> bytes already read
        self.use_ids = set()        # tool_use ids that match the card
        # Calls of this card's tool that have no result yet, in the order
        # they were written: the fallback when nothing matches by content.
        self.open_calls = {}
        self.first_read = True      # the fallback is decided once, here
        self.scan_at = 0.0          # next time to look for new subagents
        self.retry_at = 0.0         # next time to look for a missing transcript

    def __call__(self):
        try:
            if not self._located():
                return False
            self._notice_new_transcripts()
            resolved = False
            for path in list(self.files):
                lines, self.files[path], shrunk = _read_appended(
                    path, self.files[path])
                if self._scan(lines, shrunk, path):
                    resolved = True
            if self.first_read:
                self.first_read = False
                self._adopt_the_one_open_call()
            return resolved
        except (OSError, ValueError, TypeError):
            # TypeError: a line whose id is a list or an object, which no
            # set or dict here can hold. Not answered, as for a bad line.
            return False

    def _located(self):
        """Find the session transcript — once, and when it is missing not
        on every probe but every RETRY_SECONDS, since that walks every
        project directory."""
        if self.path is not None:
            return True
        if time.monotonic() < self.retry_at:
            return False
        self.path = _find_transcript(self.session_id, self.projects_dir)
        if self.path is None:
            self.retry_at = time.monotonic() + self.RETRY_SECONDS
            return False
        return True

    def _watch_list(self):
        """Every transcript this card's answer could appear in.

        Subagents start after the card does, so this is rescanned — cheaply,
        on the probe's clock — rather than fixed at the first look.
        """
        paths = [self.path]
        directory, name = os.path.split(self.path)
        sub = os.path.join(directory, name[:-len(".jsonl")], "subagents")
        try:
            paths.extend(os.path.join(sub, f) for f in sorted(os.listdir(sub))
                         if f.endswith(".jsonl"))
        except OSError:
            pass
        return paths

    def _notice_new_transcripts(self):
        now = time.monotonic()
        if now < self.scan_at:
            return
        self.scan_at = now + RESOLVER_RESCAN_SECONDS
        for path in self._watch_list():
            if path not in self.files:
                # A file we have only just noticed gets a bounded tail,
                # the same as the session file did: enough to find the
                # originating tool_use, not the whole history of an
                # earlier run.
                try:
                    self.files[path] = max(
                        0, os.path.getsize(path) - self.TAIL_BYTES)
                except OSError:
                    pass

    def _scan(self, lines, shrunk, path):
        # Through the dashboard's table of upstream shapes, so a rename in
        # Claude Code's transcript is one entry to update, and dated.
        call, answer = shape("type.tool_use"), shape("type.tool_result")
        try:
            if shrunk:
                # The transcript was rewritten (compaction). Its history
                # now contains earlier runs of possibly the SAME command
                # with their old results — matching those BY CONTENT would
                # retract a live card nobody answered, so nothing new is
                # matched in the rewritten history. But a tool_use id is
                # unique: a result carrying an id this card already
                # matched can only be that call's answer, wherever it
                # sits. Forgetting the ids here left a question answered
                # at the desk on the wrist for six days (2026-10-05).
                self.open_calls.clear()
                return any(
                    part.get("type") == answer
                    and part.get("tool_use_id") in self.use_ids
                    for part in self._parts(lines))
            for part in self._parts(lines):
                if (part.get("type") == call
                        and part.get("name") == self.tool):
                    self.open_calls[part.get("id")] = path
                    if self._same_call(part.get("input") or {}):
                        self.use_ids.add(part.get("id"))
                elif part.get("type") == answer:
                    self.open_calls.pop(part.get("tool_use_id"), None)
                    if part.get("tool_use_id") in self.use_ids:
                        return True
        except (OSError, ValueError):
            return False
        return False

    @staticmethod
    def _parts(lines):
        """Every content part of every transcript line, as dicts."""
        for line in lines:
            entry = _json_object(line)
            if entry is None:
                continue
            content = _message_of(entry).get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, dict):
                    yield part

    def _adopt_the_one_open_call(self):
        """When nothing in the transcript matches the card by content,
        watch the one call of its tool still waiting for an answer.

        Claude Code does not always hand the hook what it writes down: a
        plan reaches the hook as different text (or as {}) from the plan
        the transcript records, so no fingerprint or digest can ever
        match, and every plan answered at the desk stayed on the wrist
        (seven at once on 2026-10-11). A session waits on one prompt at a
        time, so a single unanswered call of the card's tool is the call
        being asked about. Two or more, or none, and nothing is adopted:
        the card stays, as it always did.
        """
        if self.use_ids or len(self.open_calls) != 1:
            return
        self.use_ids.update(self.open_calls)


    def _same_call(self, recorded):
        """Is this transcript tool_use the call the card asks about?

        Exact when the fingerprints agree. Otherwise every key the
        transcript recorded must hash the same as the hook's copy: Claude
        Code adds fields to what the hook receives (consent flags, seen
        live) and never writes them down, and a whole-input hash can then
        never match. Keys the transcript lacks are the harness's own and
        do not count; a recorded key that differs, or an empty record,
        is never the same call.
        """
        if self.fingerprint_of(self.tool, recorded) == self.fingerprint:
            return True
        if not self.digests or self.digests_of is None or not recorded:
            return False
        seen = self.digests_of(self.tool, recorded)
        return bool(seen) and len(seen) == len(recorded) and all(
            self.digests.get(key) == value for key, value in seen.items())


def _prompt_resolver(card, projects_dir=None):
    """A callable answering whether the card's prompt was resolved
    elsewhere, or None when the card carries too little to tell."""
    session_id = str(card.get("session_id") or "")
    fingerprint = card.get("fingerprint")
    tool = card.get("tool")
    if not session_id or not fingerprint or not tool:
        return None
    try:
        from ClaudeRiskClassifier import _card_fingerprint
    except Exception:
        return None
    try:
        from ClaudeRiskClassifier import _input_digests
    except Exception:
        _input_digests = None
    return _PromptResolver(session_id, tool, fingerprint, _card_fingerprint,
                           projects_dir, card.get("input_digests"),
                           _input_digests)




def _normal_ip(ip):
    """``ip`` as an address object, IPv4-mapped forms unwrapped and an
    IPv6 scope dropped; None for anything that is not an address."""
    import ipaddress
    try:
        address = ipaddress.ip_address(str(ip or "").split("%", 1)[0])
    except ValueError:
        return None
    return getattr(address, "ipv4_mapped", None) or address


def _local_addresses(run=None):
    """Every address on this machine's interfaces — Wi-Fi, Ethernet, the
    tailnet, IPv6 — as address objects. Never raises; empty when no lister
    answers. `ifconfig` on a Mac, `ip -o addr` where that is what there is.

    A process here can bind its socket to one of this Mac's addresses and
    dial another, so "the peer is the address it dialled" alone let it pair
    as a watch and answer its own CRITICAL card (2026-10-19 review)."""
    run = run or subprocess.run
    found = set()
    for argv in (["ifconfig"], ["ip", "-o", "addr"]):
        try:
            out = run(argv, capture_output=True, text=True, timeout=3).stdout or ""
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        for match in re.finditer(r"\binet6?\s+([0-9A-Fa-f:.%a-zA-Z0-9]+?)(?:/\d+)?(?=\s)", out):
            address = _normal_ip(match.group(1))
            if address is not None:
                found.add(address)
        if found:
            break
    return found


def _is_loopback(ip):
    """By address, never by prefix: "::1:2" is somebody else's machine,
    and a prefix match called it this one (2026-10-05 review)."""
    address = _normal_ip(ip)
    return address is not None and address.is_loopback


def _is_ip_literal(text):
    """True only for a real IPv4/IPv6 address, never a hostname.

    ``10.evil.com`` starts with ``10.`` but is not an address — the Host
    allowlist must not be fooled by a name that merely looks local.
    """
    import ipaddress
    try:
        ipaddress.ip_address(str(text))
        return True
    except ValueError:
        return False


def host_allowed(host_header):
    """Whether the request's Host header names THIS machine.

    The main listener is loopback+LAN only, so a legitimate Host is always
    a loopback name or a bare local IP. A DNS-rebinding page carries its
    OWN domain in Host (the browser derives it from the URL and forbids
    scripts from overriding it), and a domain is neither a loopback name
    nor an IP literal — so this rejects the rebinding read primitive while
    every real caller passes. Applied only where the tunnel token prefix
    is NOT the credential (see RelayHandler._host_ok).
    """
    host = str(host_header or "").strip()
    if not host:
        return False                     # HTTP/1.1 mandates Host; absence is suspect
    if host.startswith("["):             # bracketed IPv6 literal: [::1]:8977
        hostname = host[1:host.index("]")] if "]" in host else host[1:]
    elif host.count(":") == 1:           # host:port (a lone ':' can't be IPv6)
        hostname = host.rsplit(":", 1)[0]
    else:
        hostname = host                  # bare hostname, or an unbracketed IPv6
    hostname = hostname.lower()
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    # Only a bare IP literal may match — and only one of our own ranges.
    return _is_ip_literal(hostname) and _is_private_address(hostname)


def _is_private_address(ip):
    """True for a LAN, tailnet or link-local address.

    This is NOT an authorization rule and must never become one again: a
    café network is full of private addresses belonging to strangers. Its
    only job is the DNS-rebinding check in :func:`host_allowed`, where the
    question is "does this Host header name this machine".
    """
    import ipaddress
    address = _normal_ip(ip)         # ::ffff:192.168.1.1 is 192.168.1.1
    if address is None:
        return False
    if address.is_loopback:
        return True
    return any(address in ipaddress.ip_network(block)
               for block in _OWN_ADDRESS_BLOCKS[address.version])


# The ranges a Host header may name this machine by, by address family.
# Spelled out rather than taken from ipaddress's is_private, which also
# counts the documentation range 2001:db8::/32 and the test nets as
# "private". Until 2026-10-25 this was a string-prefix check that knew no
# IPv6 beyond loopback and link-local, so a watch naming the tailnet's
# own IPv6 address, or any ULA, was answered 403 "bad host" (review, L10).
_OWN_ADDRESS_BLOCKS = {
    4: ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",     # RFC 1918
        "169.254.0.0/16",                                    # link-local
        "100.64.0.0/10"),                                    # CGNAT: Tailscale's IPv4
    6: ("fc00::/7",                                          # ULA
        "fd7a:115c:a1e0::/48",                               # Tailscale's IPv6, inside ULA
        "fe80::/10"),                                        # link-local
}


def authorize_request(client_ip, path, header_token,
                      tunnel_authed, auth, via_tunnel=False, local_proof=False):
    """May this request touch real data? One rule for every listener.

    Loopback alone opens only /health. Any account on this Mac, and any
    raw port-forward into it, arrives as loopback, and transcripts, the
    session list and the travel address are this user's (2026-10-16
    review, S2). So a local caller proves itself too: ``local_proof`` is
    the bootstrap from the 0600 key file, or a device key, which the hook,
    the bridge and the command line all hold. Everything else — LAN,
    tailnet, or the travel tunnel — must present a device token, whatever
    its address.

    Being on the user's Wi-Fi used to be enough. On a home network that
    reads as "me"; on café Wi-Fi it reads as "everyone here", which is how
    a stranger could read a transcript, answer a CRITICAL prompt, or speak
    into a live session.

    On the tunnel listener loopback means cloudflared, not a local process,
    so the exemption is deliberately withheld there: the secret path proves
    where the request came from, and the token proves who sent it.
    """
    if via_tunnel:
        return bool(tunnel_authed) and _credential_ok(auth, header_token)
    if path == "/health":            # liveness only; the body is trimmed
        return True
    if local_proof:
        return True
    # Loopback without the local proof is a proxy's forward or another
    # account: a device key still opens it, as from anywhere else. A
    # forwarded watch with a real key read 403 here while /decision took
    # the same request (2026-10-24 review).
    return _credential_ok(auth, header_token)


# ---- signed requests -----------------------------------------------------
#
# A watch used to send its key itself, in an X-Tapproval-Token header, over
# plain HTTP, to whichever host answered Bonjour first: anyone reading the
# Wi-Fi saw it, and any device advertising the service could collect it
# (2026-09-25 review, issue #271). A watch that signs sends a MAC instead:
#
#   X-Tapproval-Signature: v1 <unix time> <nonce> <hex HMAC-SHA256>
#
# keyed by its token, over the method, the path (percent-decoded, no
# query), the time, the nonce and the SHA-256 of the body. The key never
# travels, a signature is good for one request within two minutes, and
# the relay answers with a proof over the same nonce, so the watch can
# tell its own computer from something that merely answered.

SIGNATURE_WINDOW_SECONDS = 120
_SEEN_NONCES = OrderedDict()
_NONCE_LOCK = threading.Lock()


# The message, the signature and both proofs are tapproval_wire's, the
# hook's too: one rule, not two copies held equal by a test.
sign_request = wire.sign_request
relay_proof = wire.relay_proof
relay_proof2 = wire.relay_proof2
seal_body = wire.seal_body
open_body = wire.open_body
ENVELOPE_PATH = wire.ENVELOPE_PATH


def seal(token, nonce, secret):
    """``secret`` (a 32-character hex key) encrypted for the holder of
    ``token``: XOR with an HMAC-derived pad unique to this nonce. How a key
    issued in answer to a signed request crossed plain HTTP until 2.3.

    Legacy: a watch from 2.3 asks for the shared ChaCha20 seal instead
    (`wire.enrol_seal`, "seal": 2 in the enrolment body), and this pad is
    kept only for watches that cannot open that — every App Store version
    up to 2.2. Dropping it strands those watches at their next pairing, so
    when is the owner's decision (CLAUDE.md, constraint 4)."""
    import hashlib
    pad = hmac.new(str(token).encode("utf-8"),
                   ("tapproval-seal\n%s" % nonce).encode("utf-8"),
                   hashlib.sha256).digest()
    raw = str(secret).encode("utf-8")[:32]
    # By index, not zip(): zip(strict=) is 3.10, and the hook runs on 3.9.
    return bytes(raw[i] ^ pad[i] for i in range(len(raw))).hex()


def verify_signature(header, method, path, body, candidates, now=None, query=""):
    """The token among ``candidates`` that signed this request, and its
    nonce — or (None, None). A stale time, a malformed header or a nonce
    already seen is (None, None): never an error, never a fallback."""
    try:
        version, stamp, nonce, mac = str(header or "").split()
        stamp = int(stamp)
    except ValueError:
        return None, None
    if version not in ("v1", "v2") or not (16 <= len(nonce) <= 64) or not mac:
        return None, None
    # The signed fields are joined by newlines, so a decoded path holding
    # one (`/x%0Aq`) could sign as another request's path and query: v1 of
    # `P\nQ` is v2 of P with query Q (2026-10-24 review). No route has one.
    if any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        return None, None
    signed_query = query if version == "v2" else None
    moment = time.time() if now is None else now
    if abs(moment - stamp) > SIGNATURE_WINDOW_SECONDS:
        return None, None
    # Bytes, never str: compare_digest raises on a str with non-ASCII in
    # it, and a header is whatever latin-1 a stranger sent.
    mac = mac.encode("utf-8", "replace")
    match = None
    try:
        for token in candidates:
            if token and hmac.compare_digest(sign_request(
                    token, method, path, stamp, nonce, body, signed_query).encode("ascii"), mac):
                match = token
                break
    except ValueError:
        # A line break in the query: the wire refuses to sign such a request
        # (2026-10-25), and a request nobody could have signed is one that
        # does not verify, never an error (a 403 at the door, not a 500).
        return None, None
    if match is None:
        return None, None
    with _NONCE_LOCK:
        for seen, at in list(_SEEN_NONCES.items()):
            if moment - at <= 2 * SIGNATURE_WINDOW_SECONDS:
                break
            del _SEEN_NONCES[seen]
        if nonce in _SEEN_NONCES:
            return None, None              # a replay
        _SEEN_NONCES[nonce] = moment
    return match, nonce


def _credential_ok(auth, token):
    """Does ``token`` match the credential store — an Auth, or the bare
    token string the older call sites still pass? False when there is no
    store at all: nothing to prove against is not proof."""
    if auth is None:
        return False
    if hasattr(auth, "matches"):
        return auth.matches(token)
    return _token_matches(token, auth)


class _Limits:
    """Sliding-window rate limits and concurrency caps, standard library only.

    The map is LRU-bounded so a spray of forged source addresses cannot grow
    it without limit — a rate limiter that can be exhausted by the traffic it
    is meant to limit is not one.
    """

    MAX_KEYS = 512

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = OrderedDict()
        self._gates = {}

    def allow(self, bucket, key, limit, window):
        """(ok, retry_after_seconds) for one more request in this bucket."""
        now = time.time()
        mapkey = (bucket, str(key))
        with self._lock:
            hits = self._hits.get(mapkey)
            if hits is None:
                hits = deque()
                self._hits[mapkey] = hits
            self._hits.move_to_end(mapkey)
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= limit:
                return False, max(1, int(window - (now - hits[0])))
            hits.append(now)
            while len(self._hits) > self.MAX_KEYS:
                self._hits.popitem(last=False)
            return True, 0

    def gate(self, name, size):
        """A named concurrency cap. Never queues: callers get a refusal
        immediately, because a queued approval is a stalled terminal."""
        with self._lock:
            gate = self._gates.get(name)
            if gate is None:
                gate = threading.BoundedSemaphore(size)
                self._gates[name] = gate
            return gate

    def reset(self):
        with self._lock:
            self._hits.clear()
            self._gates.clear()


LIMITS = _Limits()


def _socket_alive(sock):
    """False once the peer's socket is dead. A readable socket before we
    have responded is the peer hanging up — hooks never pipeline."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return not readable
    except (OSError, ValueError):
        return False


# Routes that exist only for this machine and must never appear on the
# public tunnel — not even as a refusal, which would confirm what lives here.
# /pair is on this list because on the tunnel listener the caller looks like
# loopback (it is cloudflared), which once made the pairing key reachable
# from the whole internet.
class SessionPages:
    """Short-lived immutable lists: scrolling never skips a newly reordered row."""

    def __init__(self):
        self.lock = threading.Lock()
        self.snapshots = OrderedDict()

    def page(self, rows=None, status="ready", waiting=(), cursor=None):
        with self.lock:
            now = time.monotonic()
            self.snapshots = OrderedDict((key, value) for key, value in self.snapshots.items()
                                         if now - value[0] < 60)
            if cursor is None:
                key, offset = uuid.uuid4().hex, 0
                first = rows[:12]
                held = [row for row in rows[12:] if any(str(sid).startswith(row["session_id"])
                                                      for sid in waiting)]
                # Waiting cards must be on the first page, even past the cap.
                ordered = first + held + [row for row in rows[12:] if row not in held]
                initial = len(first) + len(held)
                self.snapshots[key] = (now, ordered, status, initial)
                while len(self.snapshots) > 32:
                    self.snapshots.popitem(last=False)
            else:
                if not isinstance(cursor, str) or not re.fullmatch(r"[a-f0-9]{32}:[0-9]{1,5}", cursor):
                    raise ValueError("Invalid session page")
                key, offset = cursor.split(":")
                offset = int(offset)
                if key not in self.snapshots:
                    raise ValueError("Session page expired")
            _, ordered, status, initial = self.snapshots[key]
            end = min(len(ordered), offset + (initial if offset == 0 else 12))
            if offset > len(ordered):
                raise ValueError("Invalid session page")
            return {"sessions": ordered[offset:end], "codex_status": status,
                    "next_cursor": "%s:%d" % (key, end) if end < len(ordered) else None}


_SESSION_PAGES = SessionPages()


class RelayHandler(BaseHTTPRequestHandler):
    # A socket that sends nothing for this long is closed. Without it a
    # peer on the network could hold connections half-open, one thread
    # each, until the relay ran out — and the hook's /card waits with it.
    # It bounds reads and writes only: a /card waiting for a tap reads
    # nothing meanwhile, so the wait itself is unaffected.
    timeout = 30
    queue = None            # installed by serve()
    required_token = None   # when set, only /t/<token>/... paths are served
    auth = None             # the Auth object: device tokens and pairing
    allow_simulator = False # a test relay (--allow-simulator) hears a Simulator
    protocol_version = "HTTP/1.1"

    # What one request proved about itself. HTTP/1.1 keeps a connection
    # open and this handler object answers every request on it, so these
    # must be forgotten before each one: kept, the body of a poll was read
    # as the body of the answer after it (400, and the unread answer then
    # corrupted the next request), and a request with no key rode the key
    # the one before it proved — on the travel address, where Cloudflare
    # pools connections across callers, a way in (2026-09-27).
    _PER_REQUEST = ("_body_bytes", "_presented_key", "_signed_nonce", "_enveloped")

    def parse_request(self):
        for name in self._PER_REQUEST:
            self.__dict__.pop(name, None)
        if not super().parse_request():
            return False
        # Read the body now, whatever the route: a request answered without
        # reading its body leaves it in the connection, where it becomes the
        # start of the next request. One too large to read ends the
        # connection instead.
        self._raw_body()
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            length = 0
        if length > MAX_BODY or self.headers.get("Transfer-Encoding"):
            self.close_connection = True
        return True

    def _host_ok(self):
        """Reject a request whose Host header does not name this machine —
        the defence against DNS rebinding. Only the main listener needs it:
        the tunnel listener's credential is the secret path prefix, and it
        arrives from cloudflared bearing the public tunnel hostname.
        """
        if self.required_token is not None:
            return True
        return host_allowed(self.headers.get("Host", ""))

    def _from_a_browser(self):
        """Did a web page send this? The Host check stops DNS rebinding,
        but not a page that simply posts to 127.0.0.1: the browser runs on
        this Mac, so the request arrives as loopback — the one free pass.
        With a text/plain body it needs no CORS preflight, and although
        the page never reads the reply, the action has already happened:
        every device revoked, a forged card, a session started.

        No client of this relay is a browser. The watch, the bridge, the
        hook and the command line send neither header; every browser sends
        Origin on a cross-site POST and Sec-Fetch-Site on everything.
        """
        if self.headers.get("Origin") is not None:
            return True
        site = self.headers.get("Sec-Fetch-Site")
        return site is not None and site != "none"

    def _authorized(self, path):
        token = self._presented()
        # A test relay (--allow-simulator) keeps the old open loopback, so a
        # Simulator watch pointed at it can read without being paired: it
        # cannot pair from this machine (/pair refuses it).
        local_proof = self._is_local_process() and (
            self.allow_simulator or self._proves_bootstrap()
            or _credential_ok(self.auth, token))
        allowed = authorize_request(
            self.client_address[0], path, token,
            getattr(self, "tunnel_authed", False), self.auth,
            via_tunnel=self.required_token is not None,
            local_proof=local_proof)
        # A watch presenting a real key from off this machine means the
        # machine is paired, however the key reached it.
        if (allowed and not self._is_local_process()
                and _credential_ok(self.auth, token)):
            self._note_paired()
        return allowed

    def _note_paired(self):
        """This request proves a watch holds the key: the machine is paired,
        for the first-run door. The one place that says so."""
        if hasattr(self.auth, "note_device_seen"):
            self.auth.note_device_seen()

    def _credentialed(self):
        """Did this caller prove anything at all? Decides how much /health
        is willing to say — a pending count and "is a watch on the wrist
        right now" is a presence oracle, not liveness. Loopback is not a
        proof: another account on this Mac and a raw port-forward arrive
        as loopback too (S2), and until 2026-10-25 both read the whole
        body. The hook, the bridge and --ensure sign with the key file."""
        return _credential_ok(self.auth, self._presented()) or self._proves_bootstrap()

    def _proves_key(self):
        """A device token from anywhere; or, from a local process on the
        main listener, the bootstrap secret out of the 0600 auth file —
        the Mac bridge's credential. Loopback by itself proves nothing on
        the two routes that act: a command Claude runs is a local process
        too, and must not answer its own card. No store, no proof."""
        if _credential_ok(self.auth, self._presented()):
            if not self._is_local_process():
                self._note_paired()
            return True
        return self._proves_bootstrap()

    # Headers a forwarding proxy adds (Tailscale serve, cloudflared, an
    # nginx in front): the request came from somewhere else and was handed
    # on. A raw TCP forward adds nothing, which is why loopback alone
    # proves nothing beyond /health.
    _FORWARDED_HEADERS = ("Forwarded", "X-Forwarded-For", "X-Real-IP",
                          "CF-Connecting-IP")

    def _forwarded(self):
        return (any(self.headers.get(name) is not None
                    for name in self._FORWARDED_HEADERS)
                or any(name.lower().startswith("tailscale-user-")
                       for name in self.headers.keys()))

    def _is_local_process(self):
        """Loopback on the LAN listener — the hook and the bridge. False on
        the tunnel listener, where loopback is only cloudflared, and for a
        request a proxy forwarded here from elsewhere."""
        return (self.required_token is None
                and _is_loopback(self.client_address[0])
                and not self._forwarded())

    def _from_this_machine(self):
        """Loopback, or a process here that dialled this Mac's own network
        address — both ends of the connection then carry the same address.
        Used only to refuse, never to trust: loopback stays the only free
        pass. A stranger cannot fake it; the reply to a forged source
        address never leaves this Mac (2026-10-05 review)."""
        peer = _normal_ip(self.client_address[0])
        if peer is not None and peer.is_loopback:
            return True
        try:
            here = _normal_ip(self.connection.getsockname()[0])
        except (OSError, AttributeError, IndexError):
            here = None
        if peer is not None and peer == here:
            return True
        # Bound to one of this Mac's addresses and dialling another: still
        # this Mac (_local_addresses says how that paired a process).
        return peer is not None and peer in _local_addresses()

    def _proves_bootstrap(self):
        """A local process holding the bootstrap from the 0600 auth file:
        this user, not merely this machine."""
        return (self._is_local_process()
                and hasattr(self.auth, "is_bootstrap")
                and self.auth.is_bootstrap(self._presented()))

    def _route(self):
        """Return ``(path, query)``, enforcing the token prefix if set."""
        from urllib.parse import parse_qs, urlsplit
        split = urlsplit(self.path)
        path, query = split.path, parse_qs(split.query)
        self.tunnel_authed = False
        if self.required_token is None:
            return path, query
        prefix = "/t/%s" % self.required_token
        if path == prefix or path.startswith(prefix + "/"):
            # The prefix is the rendezvous address, never a credential:
            # record that it matched, and authorize_request() still asks
            # for the device token on top (via_tunnel), so a leaked tunnel
            # address alone opens nothing (CLAUDE.md, hard constraint 4).
            self.tunnel_authed = True
            return (path[len(prefix):] or "/"), query
        return None, query

    # -- plumbing ----------------------------------------------------------

    # The segment after /t/ is the tunnel's rendezvous secret: not a
    # credential, but no business in a log file. Redacted on the formatted
    # line, so an error message quoting a malformed request line is covered
    # too; the route after it stays readable (/t/…/health).
    _TUNNEL_SECRET_IN_LOG = re.compile(r"/t/[^/\s\"'?#]+")

    def log_request(self, code="-", size="-"):
        # The bridge asks every two seconds: answered, it is 40,000 lines a
        # day that say nothing and push the ones that do out of the log.
        from urllib.parse import urlsplit
        # parse_request can reject the request line before path exists.
        # Only successful GET polls can qualify for quiet bridge logging.
        if code == 200 and getattr(self, "command", None) == "GET":
            split = urlsplit(getattr(self, "path", ""))
            if split.path == "/pending" and "source=bridge" in split.query:
                return
        super().log_request(code, size)

    def log_message(self, fmt, *args):  # quiet: diagnostics only on stderr
        line = self._TUNNEL_SECRET_IN_LOG.sub("/t/…", fmt % args)
        print("relay: %s" % line, file=sys.stderr)

    def _raw_body(self):
        """The request body, read once. A signature covers it, so it is read
        before the route decides anything; handlers read it from here."""
        if not hasattr(self, "_body_bytes"):
            self._body_bytes = b""
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                length = 0
            if 0 < length <= MAX_BODY:
                self._body_bytes = self.rfile.read(length)
        return self._body_bytes

    def _presented(self):
        """The key this request proves: the one that signed it, or — from a
        watch that predates signing — the key it sent. A signature that does
        not verify proves nothing; it never falls back to a sent key."""
        if not hasattr(self, "_presented_key"):
            self._presented_key, self._signed_nonce = "", None
            header = self.headers.get("X-Tapproval-Signature")
            if header:
                if self.auth is not None and hasattr(self.auth, "credentials"):
                    from urllib.parse import unquote, urlsplit
                    split = urlsplit(self.path)
                    key, nonce = verify_signature(
                        header, self.command, unquote(split.path),
                        self._raw_body(), self.auth.credentials(), query=split.query)
                    self._presented_key, self._signed_nonce = key or "", nonce
                    # Only a 2.1 watch, which has pinned this computer's
                    # certificate, signs on the encrypted listener.
                    if key and nonce and isinstance(self.server, _TLSRelayServer):
                        _note_updated_watch()
            else:
                self._presented_key = self.headers.get("X-Tapproval-Token", "")
        return self._presented_key

    def _over_limit(self, bucket, key, count, seconds, error):
        """True, with the 429 already sent, once ``key`` is past ``count``
        requests in ``seconds``."""
        allowed, retry = LIMITS.allow(bucket, key, count, seconds)
        if not allowed:
            self._send_json({"error": error}, 429,
                            headers={"Retry-After": str(int(retry))})
        return not allowed

    def _send_json(self, payload, status=200, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_body(status, "application/json; charset=utf-8", body, headers)

    def _send_body(self, status, media, body, headers=None):
        """An answer, sealed when the request was: the proofs cover the
        plain body, so the watch checks them after opening it."""
        sent_status = status
        if getattr(self, "_enveloped", False):
            # The status travels inside, beside the body: Cloudflare sees
            # every enveloped answer as the same 200 (#645, phase 3).
            wire_body, media, sent_status = seal_body(
                self._presented(), wire.wrap_answer(status, body),
                wire.ENVELOPE_ANSWER_AAD), "application/octet-stream", 200
        else:
            wire_body, media = self._sealed_answer(body, media)
        self.send_response(sent_status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(wire_body)))
        # Proof that this answer comes from a holder of the key the request
        # was signed with: the watch trusts an address only after it.
        self._send_proofs(status, body)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(wire_body)

    # ---- sealed bodies (the travel road, end to end) ----------------------
    # A watch from 2.1 seals what it sends through the tunnel and asks for a
    # sealed answer (X-Tapproval-Sealed: 1): Cloudflare's edge, where the
    # tunnel's TLS ends, then carries bytes only this computer and that
    # watch can read. Bound to the method and path, so a sealed body cannot
    # be replayed onto another route. A watch before 2.1 is served plain.

    SEALED_HEADER = "X-Tapproval-Sealed"

    def _wants_sealed(self):
        sealed = self.headers.get(self.SEALED_HEADER) == "1" and bool(self._presented())
        # Only a key this relay issued is a watch that seals: every refusal
        # answers through here, so a made-up key would otherwise be one more
        # entry and one more log line each time.
        if sealed and _credential_ok(self.auth, self._presented()):
            _note_first_seal(self._presented())
            if self._signed_nonce:
                _note_updated_watch()
        return sealed

    def _seal_aad(self, answer=False):
        from urllib.parse import unquote, urlsplit
        words = "%s %s" % (self.command.upper(), unquote(urlsplit(self.path).path))
        return (("answer " if answer else "") + words).encode("utf-8")

    def _opened_body(self):
        """The request body as the route reads it: opened, when sealed. None
        when a sealed body does not open with the signer's key."""
        raw = self._raw_body()
        if not raw or not self._wants_sealed() or getattr(self, "_enveloped", False):
            return raw              # an envelope's inner body was opened with it
        return open_body(self._presented(), raw, self._seal_aad())

    def _sealed_answer(self, body, media):
        if not self._wants_sealed():
            return body, media
        return (seal_body(self._presented(), body, self._seal_aad(answer=True)),
                "application/octet-stream")

    def _send_proofs(self, status, body):
        """Both proofs, when the request was signed: the nonce-only one for
        watches that predate the second, and the one over this answer."""
        if getattr(self, "_signed_nonce", None):
            self.send_header("X-Tapproval-Proof",
                             relay_proof(self._presented_key, self._signed_nonce))
            self.send_header("X-Tapproval-Proof2",
                             relay_proof2(self._presented_key, self._signed_nonce,
                                          status, body))

    def _read_json(self):
        raw = self._opened_body()
        if not raw:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    # -- routes ------------------------------------------------------------

    def _handle_pair(self):
        """Hand over the bootstrap token — but only through a door the owner
        deliberately opened, and never from the travel tunnel.

        This endpoint used to answer any private address, which meant every
        stranger on a café network could simply ask for the key. Worse, on
        the tunnel listener the caller looks like loopback, so the whole
        internet could ask too. The normal path no longer comes through here
        at all: a watch reads the bootstrap from the owner's own iCloud and
        enrols. This is the fallback for when iCloud is not available.
        """
        if self.required_token is not None:
            self._send_json({"error": "pairing is not available here"}, 403)
            return
        auth = self.auth
        if auth is None or not hasattr(auth, "claim_window"):
            self._send_json({"error": "pairing closed"}, 403)
            return
        if not auth.window_open():
            # Before the checks below: telling this Mac's own addresses
            # apart runs ifconfig, and a shut door has nothing to protect.
            self._refuse_pairing(auth)
            return
        if self._from_this_machine():
            # No watch pairs from this Mac. A process here that could open
            # the window (`--pair`) and claim it from 127.0.0.1 held a key
            # of its own — enough for a prompt-injected session to answer
            # its own CRITICAL card (2026-09-30 review). Dialling the Mac's
            # own Wi-Fi address instead of 127.0.0.1 got round that until
            # 2026-10-05.
            self._send_json({"error": "pair from the watch, not from this computer"}, 403)
            return
        client = self.client_address[0]
        if auth.needs_consent(client):
            # The door the relay lit by itself: nobody at this Mac asked
            # for a watch to pair, so the Mac asks before a key leaves it.
            # Without this, anyone on the same café Wi-Fi could claim a key
            # for half an hour after every session start on a Mac that had
            # never paired (#271). The question is asked off this thread —
            # the watch gives up on a request after 5 s — and answered on
            # the watch's next poll. One question at a time, and a refusal
            # or no answer shuts the door, so a stranger cannot keep
            # putting it on screen.
            ticket = auth.begin_asking(client)
            if ticket:
                threading.Thread(target=_settle_pair_request,
                                 args=(auth, client, ticket), daemon=True,
                                 name="pair-ask").start()
            self._send_json({"error": "allow this watch on your computer",
                             "waiting": True}, 403)
            return
        if self._over_limit("pair", client, 5, 600, "too many attempts"):
            # A burst is an attack, not a retry: shut the door rather than
            # let it be ground down for the rest of the window.
            auth.close_window()
            return
        token = auth.claim_window(client)
        if token:
            self._send_json({"token": token})
            return
        self._refuse_pairing(auth)

    def _refuse_pairing(self, auth):
        if auth.paired_ever and not auth.window_open():
            self._send_json({"error": "already paired",
                             "devices": len(auth.devices)}, 403)
        else:
            self._send_json({"error": "pairing closed"}, 403)

    def _handle_enroll(self, body):
        """Trade a bootstrap token for this device's own token.

        Per-device tokens mean one watch can be revoked without disturbing
        another, and the relay can say how many devices are paired.
        """
        if self.required_token is not None:
            self._send_json({"error": "enrolment is not available here"}, 403)
            return
        auth = self.auth
        if auth is None or not hasattr(auth, "issue_device"):
            self._send_json({"error": "pairing closed"}, 403)
            return
        client = self.client_address[0]
        if self._over_limit("pair", client, 5, 600, "too many attempts"):
            return
        presented = self._presented()
        if not (auth.is_bootstrap(presented) or auth.matches(presented)):
            self._send_json({"error": "not paired"}, 403)
            return
        # The watch names itself, inside its own namespace: `icloud` and
        # `lan-*` are rows the relay keeps, and an enrolment claiming
        # `icloud` replaced the iCloud key's row for good (2026-09-30).
        raw = str(body.get("device_id") or uuid.uuid4().hex)[:56]
        token = auth.issue_device("watch-" + raw,
                                  body.get("label") or "Apple Watch",
                                  source=str(body.get("source") or "icloud")[:40],
                                  replaces=raw)
        if not auth.is_bootstrap(presented):
            # A key from the pairing window is traded in, not multiplied.
            auth.revoke_token(presented)
        if getattr(self, "_signed_nonce", None):
            # Signed: the new key crosses plain HTTP sealed for the signer —
            # with the shared ChaCha20 seal when the watch can open it
            # (2.3, "seal": 2), the XOR pad for the watches before.
            if body.get("seal") == 2:
                self._send_json({"sealed2": wire.enrol_seal(presented, self._signed_nonce, token)})
                return
            self._send_json({"sealed": seal(presented, self._signed_nonce, token)})
            return
        self._send_json({"token": token})

    # ---- routing -----------------------------------------------------------
    #
    # One table says what each route needs; one dispatcher checks it; one
    # method per route does the work. The two previous handlers had grown
    # to 74 and 137 lines of if/elif with the rules spelled out inline,
    # which is exactly where a rule gets forgotten on the next route added.
    #
    #   auth       the caller must hold a device token (loopback is exempt
    #              inside _authorized); /pair and /enroll are how a token is
    #              obtained, so they cannot require one.
    #   lan_only   never served through the tunnel listener; the address a
    #              stranger could reach is not where the travel secret,
    #              cards or presence may change hands — nor where a key is
    #              handed out (/pair, /enroll) or the relay is administered.
    #              Through the tunnel such a route is a 404, indistinguishable
    #              from a path that does not exist. This flag is the ONLY
    #              list of what the tunnel hides; there used to be a second
    #              tuple that had to agree with it, and no test that it did.
    #   local      only a process on this machine: the hook, the bridge,
    #              the --pair / --rotate-token commands. Never the network,
    #              because a forged card harvests a real tap.
    #   key_file   signed (v2) with the bootstrap from the 0600 key file:
    #              this user, not merely this machine — and only a signed
    #              request gets the proof the hook requires of its answer.

    # Every administration route: local, admin, never through the tunnel.
    # One rule, so a route copied from another cannot drop lan_only.
    _ADMIN_ROUTE = dict(local=True, admin=True, lan_only=True)
    ROUTES = {
        "GET": {
            "/pair": ("_get_pair", dict(auth=False, lan_only=True)),
            "/pending": ("_get_pending", {}),
            "/health": ("_get_health", {}),
            "/projects": ("_get_projects", {}),
            "/new-receipt": ("_get_new_receipt", dict(token=True, no_simulator=True)),
            "/skills": ("_get_skills", {}),
            "/sessions": ("_get_sessions", {}),
            "/activity": ("_get_activity", {}),
            "/recap": ("_get_recap", {}),
            "/usage": ("_get_usage", {}),
            "/thread": ("_get_thread", {}),
            # A picture out of a transcript. token, like /say: these are
            # the user's own screens, and loopback alone is not a person.
            "/image": ("_get_image", dict(token=True)),
            "/tunnel": ("_get_tunnel", dict(lan_only=True)),
        },
        "POST": {
            "/enroll": ("_post_enroll", dict(auth=False, lan_only=True)),
            # key_file: loopback is any process of any user here, and the
            # hook believes only an answer that proves the key back (S1).
            "/card": ("_post_card", dict(local=True, lan_only=True, key_file=True)),
            "/codex/attach": ("_post_codex_attach", dict(local=True, lan_only=True, key_file=True)),
            "/heartbeat": ("_post_heartbeat", dict(local=True, lan_only=True)),
            # The bridge saying whether this Mac's iCloud account can carry
            # cards at all. admin: the key file, which the bridge signs
            # with. Loopback alone is any process, and "noAccount" from
            # one would reopen the door at the next --rotate-token.
            "/bridge-status": ("_post_bridge_status",
                               dict(local=True, admin=True, lan_only=True)),
            # token, like /say: a command Claude runs is a local process,
            # and it must not open sessions of its own on this machine.
            "/new": ("_post_new", dict(token=True, no_simulator=True)),
            # token: a key from EVERY source. Loopback is a local process,
            # and a command Claude runs is a local process too — it must
            # not be able to answer its own card or speak into a session.
            "/say": ("_post_say", dict(token=True, no_simulator=True)),
            "/end": ("_post_end", dict(token=True, no_simulator=True)),
            "/auto-update": ("_post_auto_update", dict(token=True, no_simulator=True)),
            # The watch reporting its own trouble. A device token, like
            # /say: a local process must not be able to file a fault in
            # the watch's name.
            "/diagnostic": ("_post_diagnostic", dict(token=True)),
            # no_simulator, on /new and /say too: a Simulator's tap is never
            # an answer on a relay real cards reach (see _dispatch).
            "/decision": ("_post_decision", dict(token=True, no_simulator=True)),
            "/admin/pair-open": ("_post_admin", _ADMIN_ROUTE),
            "/admin/pair-relight": ("_post_admin", _ADMIN_ROUTE),
            "/admin/pair-reset": ("_post_admin", _ADMIN_ROUTE),
            "/admin/rotate": ("_post_admin", _ADMIN_ROUTE),
            "/admin/update-deferred": ("_post_admin", _ADMIN_ROUTE),
            "/admin/update-stuck": ("_post_admin", _ADMIN_ROUTE),
            "/admin/update-unstuck": ("_post_admin", _ADMIN_ROUTE),
            "/admin/bridge-failed": ("_post_admin", _ADMIN_ROUTE),
            "/admin/bridge-ok": ("_post_admin", _ADMIN_ROUTE),
        },
    }

    def _dispatch(self, method):
        if not self._host_ok():
            self._send_json({"error": "bad host"}, 403)
            return
        if self._from_a_browser():
            self._send_json({"error": "not from a web page"}, 403)
            return
        # A second, independent wall: a JSON content type is what a browser
        # cannot send cross-site without a preflight, and this relay answers
        # no preflight. Every real client already sends it.
        if method == "POST" and not self.headers.get(
                "Content-Type", "").lower().startswith("application/json"):
            self._send_json({"error": "expected application/json"}, 415)
            return
        path, query = self._route()
        on_tunnel = self.required_token is not None
        if (on_tunnel and path == ENVELOPE_PATH and method == "POST"
                and not getattr(self, "_enveloped", False)):
            self._open_envelope()
            return
        route = self.ROUTES[method].get(path) if path else None
        if route is not None and on_tunnel and route[1].get("lan_only"):
            # A LAN-only route on the tunnel listener: say nothing about
            # what lives here — the same 404 as a wrong secret prefix or a
            # path that does not exist. Decided before the auth check so a
            # stranger cannot tell "hidden" from "absent" by the status.
            route = None
        if route is None:
            self._send_json({"error": "not found"}, 404)
            return
        handler, rules = route
        # Read the signature first, whatever the route: the reply's proof
        # rides on it, and a local route below may never ask for it.
        self._presented()
        # A local route carries its own, stricter rules below (key_file,
        # admin); the device-or-key-file check is for the data routes.
        if (rules.get("auth", True) and not rules.get("local")
                and not self._authorized(path)):
            self._send_json({"error": "not paired"}, 403)
            return
        if rules.get("local") and (
                not self._is_local_process()
                or (rules.get("admin") and not hasattr(self.auth, "rotate"))):
            self._send_json({"error": "local processes only"}, 403)
            return
        if (rules.get("admin") and not self._proves_bootstrap()
                and path != "/admin/pair-open"):
            # Loopback is any process of any user on this Mac. Unpairing
            # the watch, or rotating its key, takes the key file too
            # (2026-10-05 review). /admin/pair-open answers without it,
            # but opens a window that asks at the Mac first.
            self._send_json({"error": "the key file is required"}, 403)
            return
        if rules.get("key_file") and not (self._proves_bootstrap()
                                          and getattr(self, "_signed_nonce", None)):
            # Signed, not merely sent: the reply's proof is what the hook
            # checks, and only a signed request gets one.
            self._send_json({"error": "the key file is required"}, 403)
            return
        if rules.get("token") and not self._proves_key():
            self._send_json({"error": "a device key is required, even from "
                                      "this machine"}, 403)
            return
        if (rules.get("no_simulator") and not self.allow_simulator
                and self.headers.get("X-Tapproval-Simulator", "").strip()):
            # 2026-09-27: a tap in the watch Simulator, pointed at this
            # relay, allowed a real HIGH card when the list re-flowed under
            # it. A Simulator build says what it is, and a relay real cards
            # reach takes no answer from one. The header is only ever a
            # reason to refuse: a real watch is trusted by its key, never
            # by the header's absence.
            self._send_json({
                "error": "simulator",
                "message": "This relay does not take answers from a "
                           "Simulator. Start a test relay with "
                           "--allow-simulator."}, 403)
            return
        getattr(self, handler)(path, query)

    def _open_envelope(self):
        """A whole travel request in one sealed body (#645, phase 3): opened
        with the key that signed it, then dispatched as if it had arrived
        plain, under every rule a plain one meets. Cloudflare's edge saw
        only "POST /t/…/e"; the route, the query and the answer's status
        stay between this computer and the watch."""
        key = self._presented()
        if (not key or not getattr(self, "_signed_nonce", None)
                or self.headers.get(self.SEALED_HEADER) != "1"
                or not _credential_ok(self.auth, key)):
            # Nothing sealed can be said to a caller that proved no key.
            self._send_json({"error": "not paired"}, 403)
            return
        inner = open_body(key, self._raw_body(), wire.ENVELOPE_AAD)
        unwrapped = wire.unwrap_request(inner) if inner is not None else None
        self._enveloped = True
        if unwrapped is None:
            self._send_json({"error": "the envelope did not open"}, 400)
            return
        _note_first_seal(key)
        _note_updated_watch()       # only a 2.1-or-newer watch seals (#820)
        method, path, query, body = unwrapped
        self.command = method
        self.path = "/t/%s%s%s" % (self.required_token, path, "?" + query if query else "")
        self._body_bytes = body
        # The local log keeps the route; the secret is still redacted there.
        self.requestline = "%s %s HTTP/1.1 (sealed)" % (method, self.path)
        self._dispatch(method)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # ---- GET ---------------------------------------------------------------

    def _get_pair(self, path, query):
        self._handle_pair()

    def _get_pending(self, path, query):
        # The bridge identifies itself so its polls never masquerade as
        # a watch in the "watch seen" diagnostics.
        from_bridge = query.get("source", [""])[0] == "bridge"
        self._send_json({"cards": self.queue.pending(
            from_watch=not from_bridge, from_bridge=from_bridge)})

    def _get_image(self, path, query):
        """One picture a transcript carried, by the reference /thread gave.

        Bytes, not JSON: the watch draws it. An unknown reference is a 404
        rather than an error — a thread scrolled past may have dropped out
        of the bounded cache, and a missing picture is not a fault.
        """
        got = image_bytes(query.get("ref", [""])[0])
        if got is None:
            self._send_json({"error": "no such image"}, 404)
            return
        media, data = got
        self._send_body(200, media, data, {"Cache-Control": "private, max-age=3600"})

    def _get_health(self, path, query):
        # Liveness is public; the details are not. A pending count plus
        # "is a watch on the wrist right now" tells a stranger when
        # nobody is looking.
        if self._credentialed():
            # Ask before answering: a watch that opens the Connection screen
            # should learn the Mac is signed out without having to send
            # something first and watch it fail. Cached, so this is a
            # subprocess about twice a minute at worst — and it waits half
            # a second at most: a slow answer lands on the next poll.
            signed_in(wait=HEALTH_SIGNIN_WAIT)
            check_login_item()
            # Only a plugin install has the switch to show. A terminal
            # install updates itself and says so, or Settings had no
            # Auto-update section at all and read as missing (2026-10-24).
            extra = ({"auto_update": _auto_update_on()} if _plugin_install()
                     else {"self_update": True})
            self._send_json({**extra, "ok": True,
                             "pending": len(self.queue.pending()),
                             "watch_seen_seconds_ago":
                                 self.queue.watch_seen_seconds_ago(),
                             "alert_route": self.queue.alert_route(),
                             "version": RELAY_VERSION,
                             "helper": HELPER_VERSION,
                             "helper_commit": (_PROVENANCE or (None, None))[0],
                             "helper_date": (_PROVENANCE or (None, None))[1],
                             "tls": dict(TLS_INFO) if TLS_INFO else None,
                             # Opens sealed bodies: an away watch learns it
                             # here, on any road, proven like the rest.
                             "seal": 1,
                             "envelope": 1,
                             "conditions": conditions(),
                             "agents": wired_agents(),
                             # The watch says this, not "Mac" (2026-10-15).
                             "name": _computer_name(),
                             "paired_ever": getattr(self.auth, "paired_ever", True)})
        elif self._is_local_process():
            # A local process that proved nothing: alive, and which code
            # answers, so a hook or an --ensure without the key file yet
            # can still tell an old relay from the installed one. Not the
            # pending count, the wrist, the conditions or the name.
            self._send_json({"ok": True, "version": RELAY_VERSION,
                             "helper": HELPER_VERSION})
        else:
            self._send_json({"ok": True})

    def _get_projects(self, path, query):
        self._send_json({"projects": known_projects()})

    def _get_skills(self, path, query):
        # The slash commands this machine can answer for one session:
        # what the watch's More list shows, and describes, in each
        # skill's own words. Without a session it is the user's set.
        prefix = (query.get("session_id") or [""])[0][:64]
        from codex_sessions import find_rollout
        if prefix and find_rollout(prefix):
            self._send_json({"skills": [], "project": None})
            return
        _, cwd = resolve_session(prefix) if prefix else (None, None)
        # The repository's name captions the "its own" group on the wrist.
        project = os.path.basename(project_root(cwd).rstrip("/")) if cwd else None
        self._send_json({"skills": known_skills(cwd), "project": project or None})

    def _get_sessions(self, path, query):
        if query.get("cursor"):
            try:
                reply = _SESSION_PAGES.page(cursor=query["cursor"][0])
            except ValueError:
                self._send_json({"error": "session_page_expired"}, 409)
                return
            self._send_json(reply)
            return
        from codex_sessions import catalog_snapshot
        catalog = catalog_snapshot()
        _codex_catalog_status(catalog["status"])
        waiting = {card["session_id"] for card in self.queue.pending() if card.get("session_id")}
        paged = query.get("paged") == ["1"]
        rows = active_sessions(limit=None if paged else 12, waiting=waiting,
                               codex_rows=catalog["sessions"])
        if paged:
            self._send_json(_SESSION_PAGES.page(rows, catalog["status"], waiting))
        else:
            # Old watches continue to receive exactly their existing wire shape.
            self._send_json({"sessions": rows})

    def _get_activity(self, path, query):
        self._send_json(activity_summary(background=True))

    def _get_recap(self, path, query):
        # A lifetime summary, not today's. Costs a full pass over the audit
        # log, which is why nothing polls it.
        self._send_json(recap_summary(background=True))

    def _get_usage(self, path, query):
        self._send_json(usage_summary(background=True))

    def _get_thread(self, path, query):
        session_id = (query.get("id", [""])[0] or "")[:64]
        turns, active, running, tool_now = [], None, 0, None
        path_on_disk = _find_transcript(session_id) if session_id else None
        # A watch from 2.0 on says how far it has read (`after`) and how
        # long it will wait for more (`wait`); one before it asks for the
        # newest 14 and is answered exactly as it always was.
        mark = _query_number(query, "after", int)
        news = None

        def card_is_waiting():
            return bool(session_id) and any(
                str(card.get("session_id") or "").startswith(session_id)
                for card in self.queue.pending())
        card_waiting = card_is_waiting()
        if not path_on_disk and session_id:
            import codex_sessions
            rollout = codex_sessions.find_rollout(session_id)
            if rollout:
                if mark is None:
                    info = codex_sessions.thread_info(rollout, card_waiting=card_waiting)
                else:
                    info = {}
                    def codex_after(path, after):
                        nonlocal info
                        info = codex_sessions.thread_info(
                            path, after, card_waiting=card_is_waiting())
                        return (info["turns"], 0, info["running_tool"],
                                info["mark"], info["reset"])
                    thread_news(rollout, mark,
                                _query_number(query, "wait", float) or 0.0,
                                lambda: card_is_waiting() == card_waiting,
                                reader=codex_after)
                    # A waiting card can arrive without a rollout append.
                    if card_is_waiting() != card_waiting:
                        fresh = codex_sessions.thread_info(
                            rollout, mark, card_waiting=card_is_waiting())
                        fresh["reset"] = fresh["reset"] or info["reset"]
                        info = fresh
                self._send_json(info)
                return
        if path_on_disk:
            if mark is None:
                turns, running, tool_now = _parse_thread(
                    path_on_disk, THREAD_TURN_LIMIT)
            else:
                wait = _query_number(query, "wait", float) or 0.0
                news = thread_news(path_on_disk, mark, wait,
                                   lambda: card_is_waiting() == card_waiting)
                turns, running, tool_now = news[:3]
                card_waiting = card_is_waiting()
            try:
                # Freshness after any wait — the watch shows a "working"
                # pulse while Claude is actually writing.
                active = max(0, int(time.time()
                                    - os.path.getmtime(path_on_disk)))
            except OSError:
                pass
        elif mark is not None:
            news = ([], 0, None, 0, True)
        # The same state the session list shows, for the thread's header.
        wake_at = thread_wake_at(path_on_disk)
        state, reason = session_state(
            active, tool_now, running, card_waiting,
            bool(path_on_disk) and thread_tool_id(path_on_disk) in prompts_at_the_mac(),
            wake_at=wake_at, turn=registry_turn(session_id))
        reply = {"turns": turns,
                 "running_tasks": running,
                 "running_tool": tool_now,
                 "modified_seconds_ago": active,
                 "state": state,
                 "state_reason": reason,
                 "wake_at": int(wake_at) if state == "scheduled" else None}
        if news is not None:
            reply["mark"], reply["reset"] = news[3], news[4]
        self._send_json(reply)

    def _get_tunnel(self, path, query):
        # LAN only: hand the watch its away-addresses while it's home.
        # Deliberately NOT in the Bonjour TXT record — this fetch is the
        # one place the travel secret changes hands.
        # The tailnet address is a plain URL, so it carries the main
        # listener's port: over TLS this listener's own port is the
        # encrypted one, and `http://100.x:<tls port>` was what the
        # watch kept, masked only by its pin (2026-10-25 review).
        plain_port = getattr(self.server, "plain_port", None) or self.server.server_address[1]
        answer = {"url": TUNNEL_URL,
                  "tailscale": tailscale_url(plain_port)}
        if TLS_INFO:
            # Inside a proven answer: the one way a watch learns which
            # certificate is this computer's (#645 S4).
            answer["tls"] = dict(TLS_INFO)
        # This helper opens sealed bodies: a 2.1 watch seals the travel
        # road only after hearing so, so an older helper is never sent one.
        answer["seal"] = 1
        answer["envelope"] = 1
        # The bridge's cue to stop writing readable iCloud copies (#820).
        if watch_has_updated():
            answer["updated_watch"] = 1
        self._send_json(answer)

    # ---- POST --------------------------------------------------------------

    def _post_enroll(self, path, query):
        self._handle_enroll(self._read_json() or {})

    def _post_codex_attach(self, path, query):
        body = self._read_json() or {}
        if not isinstance(body, dict):
            self._send_json({"error": "expected an object"}, 400)
            return
        try:
            sync = codex_approval_sync(self.queue)
            attached = sync.attach(body.get("session_id"), approval=body.get("approval"))
        except (ImportError, OSError, ValueError):
            attached = False
        self._send_json({"attached": attached})

    def _post_card(self, path, query):
        body = self._read_json()
        if body is None or not isinstance(body.get("card"), dict):
            self._send_json({"error": "expected {\"card\": {...}}"}, 400)
            return
        if body["card"].get("agent") == "codex":
            # Older installed hooks may still post during an update. They
            # must yield to Codex instead of creating a second approval.
            self._send_json({"id": "", "decision": "none"})
            return
        try:
            wait = float(body.get("wait", DEFAULT_WAIT))
        except (TypeError, ValueError):
            wait = DEFAULT_WAIT
        wait = max(0.0, min(wait, MAX_WAIT))

        gate = LIMITS.gate("card", 32)
        if not gate.acquire(blocking=False):
            # Fail closed, exactly as a dead relay does: the terminal
            # asks instead. Better a prompt than a stalled hook.
            self._send_json({"id": "", "decision": "none"})
            return
        try:
            card_id, decision, answer = self.queue.submit(
                with_session_title(body["card"]), wait,
                caller_alive=functools.partial(_socket_alive, self.connection),
                resolved_elsewhere=_prompt_resolver(body["card"]))
        finally:
            gate.release()
        payload = {"id": card_id, "decision": decision}
        if decision == "dont_ask":
            # An allow to any hook; the flag tells a hook that knows it to
            # apply the terminal's row. One from before 1.1.57 allows once.
            payload = {"id": card_id, "decision": "allow", "dont_ask": True}
        if answer:
            payload["answer"] = answer
        self._send_json(payload)

    def _serialised_send(self, act, path):
        """/new and /say both spawn a `claude` process on this Mac: the
        same per-caller budget and the same one-at-a-time gate, for the
        same reasons — serialising them is correctness, not politeness.
        `act(body)` returns the status word; the reply says whether it
        was the good one. ``path`` is the routed path: the raw one carries
        the tunnel's /t/<secret> prefix, so the same message retried over
        the other route was a new one and ran twice (2026-10-19 review)."""
        who = self._presented() or self.client_address[0]
        body = self._read_json() or {}
        key = _send_key(who, path, body)
        replay = _recent_send(key)
        if replay is not None:
            # The watch gave up waiting (5 s) and the person tapped again;
            # the first one had already run. Answer it, run nothing.
            self._send_json(dict(replay, repeat=True))
            return
        if self._over_limit("say", who, 6, 60, "too many messages"):
            return
        gate = LIMITS.gate("say", 1)
        if not gate.acquire(blocking=False):
            self._send_json({"error": "a message is already being sent"}, 429)
            return
        try:
            status, good = act(body)
        finally:
            gate.release()
        answer = {"ok": status == good, "status": status}
        if answer["ok"]:
            _remember_send(key, answer)
        self._send_json(answer)

    def _post_new(self, path, query):
        # Opens a Terminal on this Mac.
        body = self._read_json() or {}
        if isinstance(body, dict) and "request_id" in body:
            self._tracked_new(body)
            return
        self._serialised_send(lambda body: (
            start_session(str(body.get("path", ""))[:512], body.get("text", "")),
            "started"), path)

    def _new_receipt_store(self):
        return NewReceipts(self.auth.path + ".new.sqlite3")

    def _new_receipt_key(self, request_id):
        import uuid
        # Canonical UUIDs only; never a caller-controlled filename.
        value = uuid.UUID(str(request_id)).hex
        return _send_key(self._presented(), "/new-receipt", value)

    def _get_new_receipt(self, path, query):
        try:
            key = self._new_receipt_key(query.get("id", [""])[0])
            answer = self._new_receipt_store().read(key)
        except ValueError:
            self._send_json({"ok": False, "status": "invalid request id"}, 400)
            return
        except (OSError, NewReceipts.Error):
            self._send_json({"ok": False, "status": "unknown"}, 503)
            return
        self._send_json(answer or {"ok": False, "status": "unknown"}, 200 if answer else 404)

    def _tracked_new(self, body):
        try:
            key = self._new_receipt_key(body["request_id"])
        except ValueError:
            self._send_json({"ok": False, "status": "invalid request id"}, 400)
            return
        fingerprint = _send_key("", "/new", body)
        store = self._new_receipt_store()
        try:
            answer = store.read(key, fingerprint)
        except ValueError:
            self._send_json({"ok": False, "status": "request id already used"}, 409)
            return
        except (OSError, NewReceipts.Error):
            self._send_json({"ok": False, "status": "receipt unavailable"}, 503)
            return
        if answer is not None:
            self._send_json(answer)
            return
        who = self._presented() or self.client_address[0]
        if self._over_limit("say", who, 6, 60, "too many messages"):
            return
        gate = LIMITS.gate("say", 1)
        if not gate.acquire(blocking=False):
            self._send_json({"ok": False, "status": "a message is already being sent"}, 429)
            return
        try:
            # Commit the claim before any launch. A duplicate, even after
            # a relay restart or over the other route, can only read it.
            answer = store.claim(key, fingerprint)
            if answer is None:
                status = start_session(str(body.get("path", ""))[:512], body.get("text", ""))
                answer = {"ok": status == "started", "status": status}
                if not answer["ok"]:
                    # False alone is not proof that nothing launched:
                    # Claude's trust handoff and launcher errors may come
                    # after Terminal accepted the command. Keep new and
                    # unclassified outcomes conservative by default.
                    answer["retry_safe"] = status in {
                        "empty", "unknown project", "claude not on PATH", "signed out",
                        "Codex is not installed on your computer",
                        "a first message cannot start with ! or #",
                        "new sessions need Codex's own installer on Windows",
                        "new sessions need Claude Code's own installer on Windows",
                    }
                store.finish(key, answer)
        except ValueError:
            self._send_json({"ok": False, "status": "request id already used"}, 409)
            return
        except (OSError, NewReceipts.Error):
            # If completion could not be saved, the durable pending claim
            # remains. Never turn uncertainty into permission to relaunch.
            self._send_json({"ok": False, "status": "unknown"}, 503)
            return
        finally:
            gate.release()
        self._send_json(answer)

    def _post_say(self, path, query):
        # Only an explicit false turns brevity off: a watch that predates
        # the switch, or a missing key, still gets the short reply the
        # screen was built for.
        self._serialised_send(lambda body: (
            say_to_session(str(body.get("session_id", ""))[:64],
                           body.get("text", ""),
                           brief=body.get("brief") is not False,
                           force=body.get("force") is True,
                           agent=body.get("agent")),
            "sent"), path)

    def _post_end(self, path, query):
        # Ends a session on this Mac. Under the same budget and gate as a
        # send: it acts on a process, and a tap retried after the watch
        # gave up must not act twice.
        waiting = [card["session_id"] for card in self.queue.pending() if card.get("session_id")]
        self._serialised_send(lambda body: (
            end_session(str(body.get("session_id", ""))[:64], waiting), "ended"), path)

    def _post_auto_update(self, path, query):
        """The watch's "Keep the helper up to date" switch: {"on": bool}.
        Answers with what Claude Code's settings now say, not with what was
        asked, so the switch shows the truth."""
        on = (self._read_json() or {}).get("on")
        if not isinstance(on, bool):
            self._send_json({"error": "expected {\"on\": true or false}"}, 400)
        elif not _plugin_install():
            self._send_json({"error": "This helper updates itself when Claude Code or Codex starts."}, 409)
        else:
            state, why = set_auto_update(on)
            if why:
                self._send_json({"error": why}, 500)
            else:
                self._send_json({"ok": True, "on": state})

    def _post_diagnostic(self, path, query):
        """The watch telling this computer something went wrong on it.

        watchOS has no MetricKit, so the app cannot be handed Apple's own
        crash report on the next launch; and Tapproval has no server to
        POST one to. What it does have is this: an authenticated channel
        to the owner's own Mac, already open. So the app reports what it
        CAN see — an error it caught, or a launch that follows a run which
        never ended cleanly — and the computer writes it down, exactly
        where the helper's own crashes go.

        It goes no further than that machine unless its owner has given it
        a key. Somebody else's watch reports to somebody else's Mac.
        """
        body = self._read_json() or {}
        kind = str(body.get("kind") or "")[:40]
        message = str(body.get("message") or "").strip()[:500]
        if not message:
            self._send_json({"error": "expected {\"kind\", \"message\"}"}, 400)
            return
        import crash_report
        where = " / ".join(part for part in (
            str(body.get("app_version") or "")[:40],
            str(body.get("build") or "")[:20]) if part)
        reason, _entry = crash_report.report(
            message, str(body.get("detail") or "")[:8000],
            source="watch:%s" % (kind or "problem"),
            helper="watch %s" % (where or "unknown"))
        # The reason is the honest answer: "recorded, not e-mailed" is a
        # different fact from "e-mailed", and the watch may want to say so.
        self._send_json({"ok": True, "reported": reason})

    def _post_decision(self, path, query):
        body = self._read_json()
        card_id = (body or {}).get("id")
        decision = (body or {}).get("decision")
        # Card ids are short; one longer than any the relay issues is a bad
        # request, refused before it reaches a log line (2026-10-25 review).
        if (not isinstance(card_id, str) or len(card_id) > 64
                or decision not in VALID_DECISIONS):
            self._send_json({"error": "expected {\"id\", \"decision\"}"}, 400)
            return
        if self.queue.not_here_yet(card_id):
            print("relay: holding off %s for %s — not here yet; the bridge "
                  "tries again" % (decision, card_id), file=sys.stderr)
            self._send_json({"ok": False, "retry": True}, 503)
            return
        accepted = self.queue.decide(card_id, decision,
                                     answer=(body or {}).get("answer"))
        # The bridge, signing with the key file, hands on an answer a
        # watch wrote to iCloud: a watch on this Apple Account holds the
        # key, so the machine is paired. Without this an iCloud-only watch
        # never shut the first-run door (D2), and it reopened at every
        # session start.
        if accepted and self._proves_bootstrap():   # a local process, by its own test
            self._note_paired()
        self._send_json({"ok": accepted})

    def _post_admin(self, path, query):
        # Administration is for a process on this machine only — the
        # `--pair` / `--rotate-token` commands, never the network.
        if path == "/admin/pair-relight":
            self._send_json({"ok": True, "until": int(self.auth.relight())})
        elif path == "/admin/pair-open":
            # Without the key file, the person at the Mac is asked before
            # any watch gets a key: a command Claude runs can reach here.
            until = self.auth.open_window(ask=not self._proves_bootstrap())
            self._send_json({"ok": True, "seconds": PAIR_WINDOW_SECONDS,
                             "until": int(until)})
        elif path == "/admin/pair-reset":
            self.auth.revoke_all()
            if not icloud_carries_the_key():
                self.auth.open_window()
            self._send_json({"ok": True, "devices": 0,
                             "seconds": PAIR_WINDOW_SECONDS})
        elif path == "/admin/rotate":
            secret = self.auth.rotate()
            _rotate_tunnel_prefix(secret)
            # A rotation re-mirrors through iCloud; opening the network door
            # as well handed the new key to whoever was still on the Wi-Fi.
            if not icloud_carries_the_key():
                self.auth.open_window()
            self._send_json({"ok": True, "rotated": True})
        elif path in ADMIN_CONDITIONS:
            ADMIN_CONDITIONS[path]()
            self._send_json({"ok": True})
        else:
            # Fail closed by shape: an admin route added to ROUTES without
            # a branch here used to fall through to a key rotation.
            self._send_json({"error": "unknown admin route"}, 404)

    def _post_bridge_status(self, path, query):
        # What the bridge's CKContainer.accountStatus() said, at its start
        # and whenever it changes. Anything but "available" means iCloud
        # carries nothing for this Mac, so a closed watch cannot buzz.
        body = self._read_json() or {}
        took = False
        if "icloud" in body:
            took = note_bridge_icloud(body.get("icloud")) or took
        # And whether its CloudKit saves go through (2026-10-25 review).
        if "saves" in body:
            took = note_bridge_saves(body.get("saves")) or took
        self._send_json({"ok": took})

    def _post_heartbeat(self, path, query):
        # The bridge relays the watch's CloudKit heartbeat: how many
        # seconds ago the watch last checked iCloud. Main server only —
        # never through the public tunnel.
        body = self._read_json() or {}
        seen = self.queue.note_watch_indirect(body.get("watch_seen_seconds_ago"))
        # A watch checking this account's iCloud holds the key mirrored
        # there: paired, for the first-run door, as a direct poll would be.
        # Only from the key file's holder, the bridge: shutting the door is
        # the safe direction, but a stray local process is still no witness.
        if seen and self._proves_bootstrap():
            self._note_paired()
        self._send_json({"ok": True})


# The tunnel listener's handler class, so a rotation can change the secret
# path in place instead of restarting cloudflared (whose hostname is stable).
_TUNNEL_HANDLER = None


def _live_tunnel_secret(fallback):
    """The secret path the tunnel listener answers now. A rotation changes
    it in place, so a copy taken at start goes stale (2026-09-30 review)."""
    return getattr(_TUNNEL_HANDLER, "required_token", None) or fallback


# Held while the tunnel's secret and the address that carries it change
# together. The announce thread used to write the address with the secret
# it was started with: a rotation during its wait found no address yet to
# rewrite, and the address handed out afterwards carried a secret the
# listener no longer answered (2026-10-14 tech-debt audit).
_TUNNEL_URL_LOCK = threading.RLock()


def _publish_tunnel_url(base, fallback):
    """Set TUNNEL_URL to ``base`` plus the secret the listener answers now."""
    global TUNNEL_URL
    with _TUNNEL_URL_LOCK:
        TUNNEL_URL = "%s/t/%s" % (base, _live_tunnel_secret(fallback))


def _rotate_tunnel_prefix(secret):
    """Point the live tunnel listener at the new secret path."""
    global TUNNEL_URL
    with _TUNNEL_URL_LOCK:
        if _TUNNEL_HANDLER is not None:
            _TUNNEL_HANDLER.required_token = secret
        if TUNNEL_URL:
            base = TUNNEL_URL.split("/t/")[0]
            TUNNEL_URL = "%s/t/%s" % (base, secret)


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, queue=None, token=None,
          auth=None, allow_simulator=False):
    """Build a server (does not block). Caller runs serve_forever().

    With ``token`` set, the server answers only under ``/t/<token>/…`` — the
    shape exposed through a public tunnel, where that path is a rendezvous
    address rather than a credential. ``auth`` carries the device tokens
    every non-local caller must present. ``allow_simulator`` lets a watch
    Simulator answer cards and speak into sessions: a test relay only.
    """
    queue = queue if queue is not None else CardQueue()
    server = _RelayServer((host, port), _bound_handler(queue, token, auth, allow_simulator))
    return server, queue


def _bound_handler(queue, token, auth, allow_simulator):
    """A RelayHandler class carrying one listener's queue and credentials."""
    return type("BoundRelayHandler", (RelayHandler,),
                {"queue": queue, "required_token": token,
                 "auth": auth, "allow_simulator": bool(allow_simulator)})


# Set by install_crash_reporting: how a request handler's crash is reported.
_ON_HANDLER_ERROR = None


# A send the watch repeats within this long, word for word, is the same
# send: it timed out on the wrist after 5 s while the Mac went on and did
# it, and the retry opened a second Terminal or said it twice (2026-10-05
# review). Only a send that went through is remembered; a refusal is
# worth trying again.
SEND_REPEAT_SECONDS = 30.0
_RECENT_SENDS = {}
_RECENT_SENDS_LOCK = threading.Lock()
_send_clock = time.monotonic


def _send_key(who, path, body):
    import hashlib
    raw = json.dumps([who, path, body], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _recent_send(key):
    now = _send_clock()
    with _RECENT_SENDS_LOCK:
        for old, (at, _answer) in list(_RECENT_SENDS.items()):
            if now - at > SEND_REPEAT_SECONDS:
                del _RECENT_SENDS[old]
        found = _RECENT_SENDS.get(key)
    return found[1] if found else None


def _remember_send(key, answer):
    with _RECENT_SENDS_LOCK:
        _RECENT_SENDS[key] = (_send_clock(), dict(answer))


class NewReceipts:
    """Durable, device-scoped New claims. No prompts, paths or tokens on disk.

    A pending claim after a crash is deliberately not executed on restart.
    Receipt lookup is read-only with respect to launching a session.
    """
    import sqlite3
    Error = sqlite3.Error

    def __init__(self, path):
        self.path = path

    def _connect(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        _host.restrict_to_owner(self.path)
        connection = self.sqlite3.connect(self.path, timeout=1)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE IF NOT EXISTS receipts "
                               "(key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, answer TEXT NOT NULL)")
        except BaseException:
            connection.close()
            raise
        return connection

    def read(self, key, fingerprint=None):
        if not os.path.exists(self.path):
            return None
        connection = self._connect()
        try:
            row = connection.execute("SELECT fingerprint, answer FROM receipts WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            if fingerprint is not None and row[0] != fingerprint:
                raise ValueError("request id already used")
            return json.loads(row[1])
        finally:
            connection.close()

    def claim(self, key, fingerprint):
        connection = self._connect()
        try:
            with connection:
                inserted = connection.execute("INSERT OR IGNORE INTO receipts VALUES (?, ?, ?)",
                    (key, fingerprint, json.dumps({"ok": False, "status": "pending"}))).rowcount
                row = connection.execute("SELECT fingerprint, answer FROM receipts WHERE key=?", (key,)).fetchone()
                if row[0] != fingerprint:
                    raise ValueError("request id already used")
            return None if inserted else json.loads(row[1])
        finally:
            connection.close()

    def finish(self, key, answer):
        connection = self._connect()
        try:
            with connection:
                connection.execute("UPDATE receipts SET answer=? WHERE key=?", (json.dumps(answer), key))
        finally:
            connection.close()


# A caller, or the link to it, that went away mid-request: the watch
# sleeping, a phone leaving Wi-Fi, a tunnel dropping. The network, never the
# relay's own fault. ENOTCONN is a plain OSError, not a ConnectionError, and
# missing it sent the owner three crash e-mails in an hour and put a crash
# row on the wrist (helper 1.1.46, 2026-10-13). An errno not named here —
# EMFILE, ENOSPC, EADDRINUSE — is the relay's own trouble and is reported.
_HUNG_UP = frozenset(getattr(errno, name) for name in (
    "ENOTCONN", "ECONNRESET", "ECONNABORTED", "EPIPE", "ETIMEDOUT",
    "ENETRESET", "ESHUTDOWN", "EHOSTDOWN") if hasattr(errno, name))


def _caller_went_away(error):
    import socket
    if isinstance(error, (ConnectionError, TimeoutError, socket.timeout)):
        return True
    return isinstance(error, OSError) and error.errno in _HUNG_UP


# Hang-ups are counted, not reported, and summed up in the log at most once
# an hour: a reconnect storm stays visible without a traceback per socket.
HANG_UP_SUMMARY_SECONDS = 60 * 60
_HANG_UPS = {"count": 0, "last": None, "since": None}   # None: none noted yet
_HANG_UPS_LOCK = threading.Lock()


def _note_hang_up(error, now=None):
    now = time.time() if now is None else now
    code = getattr(error, "errno", None)
    name = errno.errorcode.get(code) if code else None
    with _HANG_UPS_LOCK:
        _HANG_UPS["count"] += 1
        _HANG_UPS["last"] = name or type(error).__name__
        since = _HANG_UPS["since"]
        if since is not None and now - since < HANG_UP_SUMMARY_SECONDS:
            return
        count, last = _HANG_UPS["count"], _HANG_UPS["last"]
        _HANG_UPS["count"], _HANG_UPS["since"] = 0, now
    print("relay: %d caller%s hung up mid-request since the last note "
          "(last: %s) — the network, not a fault"
          % (count, "" if count == 1 else "s", last), file=sys.stderr)


class _RelayServer(ThreadingHTTPServer):
    """ThreadingHTTPServer, with handler crashes reported like any other.

    The stock server catches whatever a handler raises and prints it to
    stderr, so threading.excepthook never sees it: every route could fail
    with no record, no wrist condition and no mail (2026-09-25 review).

    At most MAX_CONNECTIONS at once, each a thread: past that a connection
    is closed unanswered. One person's watch, bridge and hooks never come
    near it; a flood of held-open sockets no longer grows threads without
    end (2026-10-05 review)."""
    daemon_threads = True
    MAX_CONNECTIONS = 64

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def server_bind(self):
        # One relay per port on every host, Windows included.
        _host.claim_port_alone(self)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        kind, value, tb = sys.exc_info()
        # A caller that went away or stalled is the network, not a fault:
        # no traceback, no report, no crash row on the wrist — a count.
        if _caller_went_away(value):
            _note_hang_up(value)
            return
        super().handle_error(request, client_address)
        if _ON_HANDLER_ERROR is not None:
            _ON_HANDLER_ERROR(kind, value, tb)


# Which keys have sealed a request since this relay started: the first from
# each is one line in the log, so "is this watch sealing?" can be answered
# from the Mac (2026-10-23, the owner's wrist check). Never the key itself.
_SEALING_KEYS = set()
_SEALING_LOCK = threading.Lock()


def _note_first_seal(key):
    import hashlib
    mark = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
    with _SEALING_LOCK:
        if mark in _SEALING_KEYS:
            return False
        _SEALING_KEYS.add(mark)
    print("relay: a watch seals its messages (key %s…)" % mark, file=sys.stderr)
    return True


# Whether this computer's watch has shown it runs 2.1 or newer: it signed a
# request on the encrypted listener, or sealed one on the travel road. Kept
# on disk, once and for good: from then on the Mac bridge writes a card's
# details and the pairing key to iCloud encrypted only (#820), and a watch
# older than 2.1 would see an iCloud card's headline alone. Until then it
# writes the readable copies too, so nobody on an old watch loses anything.
def updated_watch_file():
    return os.path.join(TAPPROVAL_DIR, "data", "updated-watch.json")


def watch_has_updated():
    return os.path.isfile(updated_watch_file())


def _note_updated_watch():
    path = updated_watch_file()
    if os.path.isfile(path):
        return False
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "w", encoding="utf-8") as out:
            json.dump({"since": int(time.time())}, out)
    except OSError as error:
        print("relay: could not note an updated watch: %s" % error, file=sys.stderr)
        return False
    print("relay: this computer's watch runs 2.1 or newer; iCloud copies "
          "go encrypted only from now on", file=sys.stderr)
    return True


class _TLSRelayServer(_RelayServer):
    """The same relay, encrypted: each connection's TLS handshake runs on
    its own thread (never in the accept loop, where one slow caller would
    stall everyone), and a handshake that fails is a caller that went
    away, counted, never a crash report."""
    HANDSHAKE_SECONDS = 10

    def __init__(self, address, handler, context):
        self._tls = context
        super().__init__(address, handler)

    def process_request_thread(self, request, client_address):
        import ssl
        try:
            request.settimeout(self.HANDSHAKE_SECONDS)
            wrapped = self._tls.wrap_socket(request, server_side=True)
            wrapped.settimeout(None)
        except (ssl.SSLError, OSError) as error:
            _note_hang_up(error)
            try:
                request.close()
            finally:
                self._slots.release()
            return
        super().process_request_thread(wrapped, client_address)


def serve_tls(host, port, cert, key, queue=None, auth=None, allow_simulator=False,
              plain_port=None):
    """The encrypted listener: the main listener's routes and rules, over
    TLS 1.2 or newer, with this computer's own certificate. ``plain_port``
    is the main listener's, for the one plain address /tunnel names."""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS 1.2 (all the LibreSSL in Xcode's Python has): forward-secret,
    # authenticated ciphers only. TLS 1.3 chooses its own, all of them so.
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    context.load_cert_chain(cert, key)
    queue = queue if queue is not None else CardQueue()
    handler = _bound_handler(queue, None, auth, allow_simulator)
    server = _TLSRelayServer((host, port), handler, context)
    server.plain_port = plain_port
    return server, queue


# ---- the encrypted listener -------------------------------------------------

# Where the certificate and its key live: the data folder, beside the key
# file, mode 0600. A test points TAPPROVAL_TLS_DIR at a folder of its own.
def tls_dir():
    return os.environ.get("TAPPROVAL_TLS_DIR") or os.path.join(TAPPROVAL_DIR, "data")


OPENSSL = "/usr/bin/openssl"
TLS_DAYS = 3650


def ensure_tls_identity(folder=None, openssl=None, runner=None):
    """This computer's own certificate for the encrypted listener: made
    once, with openssl, then reused, so the fingerprint a watch has pinned
    stays the same across restarts and updates. Returns (cert, key) paths,
    or None when it cannot be made (no openssl: some Linux), which is said
    on the Connection screen. Never raises."""
    import shutil
    import subprocess
    folder = folder or tls_dir()
    cert = os.path.join(folder, "tls-cert.pem")
    key = os.path.join(folder, "tls-key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        clear_condition("no_tls")
        return cert, key
    tool = openssl or (OPENSSL if os.path.exists(OPENSSL) else shutil.which("openssl"))
    if not tool:
        note_condition("no_tls", "Messages on your Wi-Fi are not encrypted: this "
                       "computer has no openssl to make its certificate. Install "
                       "openssl, then start Claude Code once.")
        return None
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        old = os.umask(0o077)
        try:
            (runner or subprocess.run)(
                # RSA, not EC: macOS's LibreSSL writes an EC key with its
                # curve spelled out, which the LibreSSL 2.8 inside Xcode's
                # Python (what the login job runs) cannot handshake with.
                [tool, "req", "-x509", "-newkey", "rsa:2048", "-sha256",
                 "-nodes", "-days", str(TLS_DAYS),
                 "-subj", "/CN=Tapproval", "-keyout", key, "-out", cert],
                check=True, capture_output=True, timeout=30)
        finally:
            os.umask(old)
        os.chmod(key, 0o600)
        _host.restrict_to_owner(key)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        note_condition("no_tls", "Messages on your Wi-Fi are not encrypted: the "
                       "certificate could not be made (%s)." % type(error).__name__)
        return None
    if not (os.path.exists(cert) and os.path.exists(key)):
        note_condition("no_tls", "Messages on your Wi-Fi are not encrypted: the "
                       "certificate could not be made.")
        return None
    clear_condition("no_tls")
    return cert, key


def tls_fingerprint(cert_path):
    """SHA-256 of the certificate (DER), lowercase hex: what a watch pins.
    None when there is no readable certificate."""
    import hashlib
    import ssl
    try:
        with open(cert_path, encoding="ascii") as handle:
            der = ssl.PEM_cert_to_DER_cert(handle.read())
    except (OSError, ValueError, TypeError):
        return None
    return hashlib.sha256(der).hexdigest()


# Set once the encrypted listener is up: {"port", "sha256"}, served only
# inside answers the relay proves (/tunnel, a credentialed /health).
TLS_INFO = None


_TAILSCALE_CACHE = {}
# A miss expires: the relay runs for weeks, and Tailscale started an hour
# after it would otherwise never be discovered.
_TAILSCALE_MISS_TTL = 600


def tailscale_url(port):
    """This machine's Tailscale address, if Tailscale is up.

    Cached: the tailnet address is stable for the life of the process, and
    this used to spawn a subprocess on every request.

    A watch whose phone runs Tailscale reaches the Mac reliably here — often
    more reliably than the LAN, since the VPN can hide local addresses. The
    watch learns it automatically (served at /tunnel alongside the public
    URL). Never raises.
    """
    cached = _TAILSCALE_CACHE.get(port)
    if cached is not None:
        value, found_at = cached
        # A hit is stable for the life of the process; a miss expires, so
        # Tailscale brought up later is still found.
        if value or time.time() - found_at < _TAILSCALE_MISS_TTL:
            return value
    _TAILSCALE_CACHE[port] = (None, time.time())
    for candidate in ("tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"):
        if shutil.which(candidate) or os.path.exists(candidate):
            try:
                out = subprocess.run([candidate, "ip", "-4"],
                                     capture_output=True, text=True, timeout=3)
                ip = out.stdout.strip().splitlines()[0].strip() if out.stdout else ""
                if ip.startswith("100."):
                    url = "http://%s:%d" % (ip, port)
                    _TAILSCALE_CACHE[port] = (url, time.time())
                    return url
            except (OSError, subprocess.SubprocessError, IndexError):
                pass
    return None


class Auth:
    """The relay's credentials, and the only thing that may hand one out.

    Two secrets with two different jobs. The *tunnel secret* is the
    unguessable ``/t/<secret>`` path the travel URL rides on — a rendezvous
    address, never a credential. A *device token* is the credential, and it
    is demanded of every caller that is not a local process, whichever
    network it arrives from. They were one string until it became clear that
    anyone who had ever seen the travel URL therefore held the key to the
    LAN as well.

    The *bootstrap* token exists so a new watch can obtain its own device
    token without a human typing anything: the Mac bridge mirrors it into
    the owner's private iCloud, where only the owner can read it. A stranger
    on the same Wi-Fi has no path to it. The LAN pairing door is only for
    when iCloud is unavailable, and it stays shut unless deliberately opened.
    """

    def __init__(self, path=None):
        self.path = path or AUTH_FILE
        self._lock = threading.RLock()
        self.tunnel_secret = ""
        self.bootstrap = ""
        self.devices = []
        self.paired_ever = False
        self._window_until = 0.0
        self._window_claims = 0
        self._window_ips = set()
        # Whether the open window is one the relay lit by itself, and so
        # asks the person at the Mac before handing out a key (#271).
        self._window_asks = False
        self._consented = {}        # address -> until when its Allow holds
        self._asking = None         # (address, window) the Mac is asking about now
        self._window_gen = 1        # which window an answer belongs to
        self._load()
        # A machine that has never paired opens its door for a while at
        # every relay start (here) and every --ensure (relight), not
        # forever: long enough to install the watch app, short enough that
        # a laptop left on café Wi-Fi is not handing out keys all afternoon.
        # A bridge does not keep it shut any more (route B, D2): installed
        # on every Mac, it may sit on an Apple Account the watch does not
        # use, and then iCloud never brings the key. The door asks at the
        # Mac first, and shuts the moment a watch shows a key
        # (note_device_seen), whichever way it came.
        if not self.paired_ever:
            self._window_until = time.time() + PAIR_FIRST_WINDOW_SECONDS
            self._window_asks = True

    # ---- persistence -------------------------------------------------

    def _load(self):
        data = None
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = None
        readable = isinstance(data, dict) and data.get("version") == 1
        if readable:
            self.tunnel_secret = str(data.get("tunnel_secret") or "")
            self.bootstrap = str(data.get("bootstrap") or "")
            self.paired_ever = bool(data.get("paired_ever"))
            devices = data.get("devices")
            if isinstance(devices, list):
                self.devices = [d for d in devices
                                if isinstance(d, dict) and d.get("token")]
        kept = None
        if not readable and os.path.exists(self.path):
            # A file is there but is not one this relay can read: not JSON,
            # or a version it does not know. Seeding over it threw every
            # pairing away in silence (2026-10-25 review, L9). It is kept
            # beside the fresh file instead, and said: here and on the wrist.
            kept = self._keep_unreadable()
        if not self.tunnel_secret or not self.bootstrap:
            self._seed()
        self._ensure_icloud_device()
        if kept is not None:
            # After the saves above: a successful save withdraws "pairing",
            # and this must outlive the one that wrote the fresh identity.
            # The next save that follows a watch pairing again lifts it.
            note_condition(
                "pairing",
                "Your computer's pairing file could not be read, so every "
                "watch must pair again; the old file was kept beside it%s."
                % (" as %s" % os.path.basename(kept) if kept else
                   ", but could not be renamed and was replaced"))

    def _keep_unreadable(self):
        """Rename the unreadable file to ``auth.json.bad-<unix stamp>``
        beside itself. Returns the new path, or "" when even that failed
        (the caller still says so; nothing is swallowed)."""
        kept = "%s.bad-%d" % (self.path, int(time.time()))
        try:
            os.replace(self.path, kept)
        except OSError as error:
            print("relay: could not read %s and could not keep it either: %s"
                  % (self.path, error), file=sys.stderr)
            return ""
        print("relay: could not read %s; kept as %s and starting a fresh "
              "identity, so every watch must pair again"
              % (self.path, os.path.basename(kept)), file=sys.stderr)
        return kept

    def _seed(self):
        """First run — or a file we cannot read, which fails closed to a
        fresh identity rather than to an open door."""
        self.tunnel_secret = self.tunnel_secret or uuid.uuid4().hex
        self.bootstrap = self.bootstrap or uuid.uuid4().hex
        # The single-token file of 2026-08-22..27 is not migrated any more:
        # every install has long since converted it, and reading it on a
        # fresh identity re-admitted a key that rotate() and revoke_all()
        # never deleted (2026-09-25 review).
        self.save()

    def _ensure_icloud_device(self):
        """The key the bridge mirrors into iCloud must BE a key.

        A watch reads it from the owner's private database and presents it
        directly. Treating it only as a ticket to exchange for a key meant
        older builds — which have no idea how to make that exchange — were
        refused, fell back to iCloud permanently, and silently lost the
        session list. It is no weaker than it looks: only the owner's Apple
        ID can read that record, and a stranger on the Wi-Fi still has no
        way to ask for it.
        """
        if any(device.get("id") == "icloud" for device in self.devices):
            return
        self.devices.append({
            "id": "icloud", "token": self.bootstrap,
            "label": "Watch via iCloud", "issued": int(time.time()),
            "last_seen": 0, "source": "icloud-mirror"})
        self.save()

    def save(self):
        payload = {
            "version": 1,
            "tunnel_secret": self.tunnel_secret,
            "bootstrap": self.bootstrap,
            "devices": self.devices,
            "paired_ever": self.paired_ever,
        }
        body = json.dumps(payload, indent=2)
        # Written beside the file and renamed over it: the bridge reads this
        # file too, and a truncated read is read as no key at all — which
        # the bridge would mirror to iCloud (2026-09-30 review). 0600 from
        # the moment the new file exists, whatever the old one's mode was.
        temp = "%s.%d.tmp" % (self.path, os.getpid())
        try:
            fd = os.open(temp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        except OSError as error:
            return self._not_saved(error)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(body + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            _host.restrict_to_owner(temp)
            os.replace(temp, self.path)
        except OSError as error:
            try:
                os.unlink(temp)
            except OSError:
                pass
            return self._not_saved(error)
        clear_condition("pairing")
        return True

    def _not_saved(self, error):
        """A save that failed used to say so on stderr only, and the
        pairing it was saving then vanished at the next restart, with the
        watch none the wiser (2026-10-17 tech-debt review, item 2)."""
        print("relay: could not save %s: %s" % (self.path, error), file=sys.stderr)
        note_condition(
            "pairing",
            "This computer could not save its list of paired watches, so a "
            "watch paired now may need pairing again after a restart. Check "
            "that the home folder has free space.")
        return False

    # ---- credentials -------------------------------------------------

    def device_for(self, token):
        """The device row a presented token belongs to, or None.

        Compared in constant time: a plain ``==`` on a secret is a timing
        oracle, and fixing it costs one stdlib call.
        """
        token = str(token or "")
        if not token:
            return None
        with self._lock:
            for device in self.devices:
                if _token_matches(token, device.get("token")):
                    device["last_seen"] = int(time.time())
                    return device
        return None

    def matches(self, token):
        return self.device_for(token) is not None

    def credentials(self):
        """Every key a signature may be made with: the devices' and the
        bootstrap (the iCloud copy, and what /enroll is signed with)."""
        with self._lock:
            keys = [d.get("token") for d in self.devices if d.get("token")]
        return keys + ([self.bootstrap] if self.bootstrap else [])

    def is_bootstrap(self, token):
        return bool(self.bootstrap) and _token_matches(token, self.bootstrap)

    RESERVED_IDS = ("icloud",)

    def issue_device(self, device_id=None, label="Apple Watch", source="icloud",
                     replaces=None):
        """Mint a token for one device. Re-enrolling the same device id
        replaces its token rather than growing the list forever.
        ``replaces`` names a row from before device ids had a namespace,
        dropped too unless it is one the relay keeps."""
        token = uuid.uuid4().hex
        device_id = str(device_id or uuid.uuid4().hex)[:64]
        gone = {device_id}
        if replaces and replaces not in self.RESERVED_IDS \
                and not str(replaces).startswith("lan-"):
            gone.add(str(replaces))
        with self._lock:
            self.devices = [d for d in self.devices
                            if d.get("id") not in gone]
            self.devices.append({"id": device_id, "token": token,
                                 "label": str(label or "Apple Watch")[:40],
                                 "issued": int(time.time()), "last_seen": 0,
                                 "source": source})
            if not self.paired_ever:
                # The first watch is through: the first-run door shuts
                # behind it. From here only --pair opens one.
                self._window_until = 0.0
            self.paired_ever = True
            self.save()
        return token

    def revoke_token(self, token):
        """Drop the one device row holding ``token``; the iCloud row is the
        bootstrap's and is never dropped this way."""
        with self._lock:
            kept = [d for d in self.devices
                    if d.get("id") in self.RESERVED_IDS
                    or not _token_matches(token, d.get("token") or "")]
            if len(kept) != len(self.devices):
                self.devices = kept
                self.save()

    def revoke_all(self):
        """--pair-reset: every key goes, the machine's own included.

        Clearing the devices alone left the bootstrap valid, and a stranger
        who had claimed it could enrol again the minute after a reset
        (2026-09-25 review). The iCloud copy is re-mirrored by the bridge,
        so the owner's watch comes back by itself."""
        with self._lock:
            self.bootstrap = uuid.uuid4().hex
            self.devices = []
            self._ensure_icloud_device()
            self.save()

    def rotate(self):
        """New tunnel path, new bootstrap, every device token revoked."""
        with self._lock:
            self.tunnel_secret = uuid.uuid4().hex
            self.bootstrap = uuid.uuid4().hex
            # The iCloud-mirrored key rotates with everything else, and stays
            # a usable key: the bridge re-mirrors it within the minute and a
            # watch picks it up without anyone touching anything.
            self.devices = []
            self._ensure_icloud_device()   # builds the row, and saves
            return self.tunnel_secret

    # ---- the pairing window -----------------------------------------

    def open_window(self, seconds=PAIR_WINDOW_SECONDS, ask=False):
        """Open the LAN pairing door for ``seconds``; returns when it shuts.

        ``ask``: the relay lit it by itself, not the owner, so each address
        needs an Allow clicked at this Mac before it gets a key. ``--pair``
        is the owner asking already, and asks nothing more — which is also
        the way to pair where no dialog can be shown."""
        with self._lock:
            self._window_until = time.time() + float(seconds)
            self._window_claims = 0
            self._window_ips = set()
            self._window_asks = bool(ask)
            self._consented = {}
            # A new window: an answer to a question the old one asked must
            # not shut it — a late no from a dialog left on screen used to
            # close the --pair window opened to get round it.
            self._window_gen += 1
            self._asking = None
            return self._window_until

    def close_window(self):
        """Shut the door now — a burst on /pair is an attack, not a retry."""
        with self._lock:
            self._window_until = 0.0

    def relight(self):
        """--ensure on a machine that has never paired: another
        PAIR_FIRST_WINDOW_SECONDS. A no-op once anything has paired, so a
        session start can never reopen a paired machine's door."""
        with self._lock:
            if self.paired_ever:
                return self._window_until
            if self.window_open() and not self._window_asks:
                # The owner's own --pair window is open; a session start
                # must not turn it back into one that asks.
                return self._window_until
            if self.window_open():
                # The same self-lit window, kept open longer: a question on
                # screen still counts when the owner gets to it.
                self._window_until = time.time() + PAIR_FIRST_WINDOW_SECONDS
                return self._window_until
            return self.open_window(PAIR_FIRST_WINDOW_SECONDS, ask=True)

    # ---- asking the person at the Mac -------------------------------

    def needs_consent(self, client_ip):
        """Would a key for this address need an Allow clicked first?"""
        with self._lock:
            now = time.time()
            return (now < self._window_until and self._window_asks
                    and self._consented.get(client_ip, 0.0) <= now)

    def begin_asking(self, client_ip):
        """Claim the one question slot. Returns a ticket naming the window
        that asked, for finish_asking; 0 if a question is already up."""
        with self._lock:
            if self._asking is not None:
                return 0
            self._asking = (client_ip, self._window_gen)
            return self._window_gen

    def finish_asking(self, client_ip, allowed, ticket):
        """An Allow lets this address claim for PAIR_CONSENT_SECONDS.
        Anything else — Don't Allow, no answer, no way to ask — shuts the
        door until the next session start or ``--pair``. An answer for a
        window that has since been replaced changes nothing."""
        with self._lock:
            if self._asking != (client_ip, ticket):
                return
            self._asking = None
            if allowed:
                self._consented[client_ip] = time.time() + PAIR_CONSENT_SECONDS
            else:
                self._window_until = 0.0

    def window_open(self):
        """Is /pair handing out the bootstrap right now?

        One timer. A machine that has NEVER paired lights it for
        PAIR_FIRST_WINDOW_SECONDS at every relay start and every --ensure:
        a 10-minute fuse lit once at install time burnt out while the user
        was still installing the watch app, and a door that never shut
        handed the key to whoever found the Bonjour advert first on a café
        network. Half an hour, re-lit by every Claude Code session, is long
        enough to install and short enough to be a window. The first watch
        through shuts it; from then on only --pair lights it, for
        PAIR_WINDOW_SECONDS. A burst on /pair shuts either.
        """
        with self._lock:
            return time.time() < self._window_until

    def claim_window(self, client_ip):
        """Hand out a key of its own, once per address and twice at most.

        Returns the token, or None with the window left shut. A burst is an
        attack, not a retry, so the caller closes the window on a rate-limit
        rejection rather than letting it be ground down.

        A device key, not the bootstrap: the bootstrap is the machine's own
        secret — the one the bridge mirrors and --pair-reset could not take
        back — and whoever claimed it held every future key too (2026-09-25
        review). A device key can be seen, counted and revoked.
        """
        with self._lock:
            if time.time() >= self._window_until:
                return None
            if self.needs_consent(client_ip):
                return None
            if self._window_claims >= PAIR_WINDOW_CLAIMS:
                return None
            if client_ip in self._window_ips:
                return None
            self._window_ips.add(client_ip)
            self._window_claims += 1
            return self.issue_device("lan-" + str(client_ip),
                                     label="Watch paired on the network",
                                     source="lan-window")

    def note_device_seen(self):
        """A watch just proved it holds a key: the machine is paired.

        A watch that pairs through iCloud presents the mirrored key and
        never enrols, so until now the first-run door never learned it was
        no longer needed and reopened for half an hour at every Claude
        Code session (2026-09-25 review)."""
        with self._lock:
            if self.paired_ever:
                return
            self.paired_ever = True
            self._window_until = 0.0
            self.save()


# What the bridge last said of this Mac's iCloud account (/bridge-status):
# None until a bridge that reports it has spoken, which every bridge before
# route B never does.
_BRIDGE_ICLOUD = None
_ICLOUD_STATUSES = ("available", "noAccount", "restricted",
                    "couldNotDetermine", "temporarilyUnavailable")


def note_bridge_icloud(status):
    """Record the bridge's iCloud account status, and say so on the wrist
    when it cannot carry cards. False for a value that is not one of
    CloudKit's, which changes nothing."""
    global _BRIDGE_ICLOUD
    if status not in _ICLOUD_STATUSES:
        return False
    _BRIDGE_ICLOUD = status
    if status == "available":
        clear_condition("icloud_off")
    else:
        note_condition(
            "icloud_off",
            "iCloud is not available to Tapproval on this computer, so your "
            "watch cannot buzz while Tapproval is closed. Check that this "
            "Mac is signed in to iCloud with the Apple Account your watch "
            "uses.")
    return True


def note_bridge_saves(saves):
    """What the bridge says about its CloudKit saves: `{"failing": bool,
    "error": str}`. Failing, the wrist hears why no card arrives away from
    home; working again, the sentence goes. A bridge whose saves were all
    refused retried every card every 2 s for ever and told nobody
    (2026-10-25 review). False for anything not of that shape, which
    changes nothing."""
    if not isinstance(saves, dict):
        return False
    failing = saves.get("failing")
    if not isinstance(failing, (bool, int)):
        return False
    if failing:
        why = str(saves.get("error") or "no reason given")[:120]
        note_condition(
            "bridge_saves",
            "iCloud is refusing Tapproval's cards from this computer (%s), so "
            "away from home your watch gets no cards until it clears. The "
            "bridge keeps trying; if this stays, check this Mac's iCloud "
            "storage and sign-in." % why)
    else:
        clear_condition("bridge_saves")
    return True


# The bridge's login item (1.1.0), asked at most this often: the answer is a
# subprocess, and /health is polled.
LOGIN_ITEM_EVERY = 300.0
_LOGIN_ITEM = {"at": 0.0}


def check_login_item(now=None):
    """Say on the wrist when the user switched Tapproval off in Login Items:
    the bridge then never starts, so a closed watch stops buzzing, and
    nothing else would tell them why. Their switch is respected — the
    helper never turns it back on — so the sentence says where it is."""
    now = time.time() if now is None else now
    if now - _LOGIN_ITEM["at"] >= LOGIN_ITEM_EVERY:
        _LOGIN_ITEM["at"] = now
        try:
            import bridge_install
            app = bridge_install.app_path()
            word = None
            if os.path.isdir(app) and bridge_install.registers_itself(app):
                word = bridge_install.login_item("login-status", app)
                if word is None:
                    # Timed out: the same as a check that broke, so the
                    # word stays what the last one saw (2026-10-26 review).
                    raise OSError("the bridge did not answer")
            _LOGIN_ITEM["word"] = word
        except Exception as error:
            # A check that broke changes nothing: the word stays what the
            # last check saw, so a condition it noted stands. Resetting it
            # here read a bridge that could not be asked as "Login Items
            # is fine" (2026-10-25 review).
            print("relay: could not ask the bridge's login item: %s" % error,
                  file=sys.stderr)
    if _LOGIN_ITEM.get("word") == "requires-approval":
        note_condition(
            "login_item_off",
            "Tapproval is switched off in Login Items on this Mac, so your "
            "watch cannot buzz while Tapproval is closed. Turn it on in "
            "System Settings, General, Login Items.")
    else:
        clear_condition("login_item_off")


def _bridge_apps():
    """Where a Mac bridge may be installed: the installer's place (under its
    name from 1.1.0, then the older one), then the
    one it lived in until 2026-10-16, a bridge until the first install into
    the new place retires it. Asked of bridge_install, so the relay and the
    installer cannot disagree (and honour the same overrides).

    The bridge mirrors the key into the user's private iCloud database,
    where only that Apple Account can read it. Where it is installed a watch
    on the same account pairs through iCloud; the first-run door still
    opens, for a watch on another account (see Auth.__init__)."""
    import bridge_install
    return (bridge_install.app_path(), bridge_install.old_app_path(),
            os.path.join(bridge_install.legacy_dir(), bridge_install.OLD_APP_NAME))


def bridge_installed():
    """Is a Mac bridge installed on this computer, in either place?"""
    return any(os.path.isdir(app) for app in _bridge_apps())


# The first bridge that reads the key from ~/.tapproval/data (and still
# from the old place, for a helper that has not moved it).
BRIDGE_READS_DATA_DIR = (1, 0, 1)



def _tell(line):
    print(line, file=sys.stderr)


def make_home_dirs():
    """~/.tapproval/data (only this user may open it) and ~/.tapproval/logs.
    True when both are there. Never raises."""
    try:
        os.makedirs(os.path.join(TAPPROVAL_DIR, "data"), mode=0o700, exist_ok=True)
        os.chmod(os.path.join(TAPPROVAL_DIR, "data"), 0o700)
        _host.restrict_to_owner(os.path.join(TAPPROVAL_DIR, "data"), folder=True)
        os.makedirs(os.path.join(TAPPROVAL_DIR, "logs"), exist_ok=True)
        return True
    except OSError as error:
        _tell("relay: could not make %s/data and logs (%s); the files stay "
              "where they are" % (TAPPROVAL_DIR, error))
        return False


def _bridge_version(app):
    """An installed bridge's version as a tuple, or None if unreadable."""
    import bridge_install
    try:
        return tuple(int(part) for part in
                     (bridge_install.installed_version(app) or "").split("."))
    except ValueError:
        return None


def _bridge_reads_data_dir():
    """May the key move? Only if every bridge installed here reads the new
    place: bridge 1.0.0 reads ~/.tapproval-auth.json alone, and with the
    key gone from there a closed watch would stop buzzing."""
    for app in _bridge_apps():
        if os.path.isdir(app):
            version = _bridge_version(app)
            if version is None or version < BRIDGE_READS_DATA_DIR:
                return False
    return True


def move_loose_files():
    """Move each old ~/.tapproval-* file into ~/.tapproval once.

    Run by the relay only once it holds the port, so no older relay is left
    to write the old place again. A file already at the new place is never
    overwritten: the old one is left and said. Returns the names moved."""
    if not make_home_dirs():
        return []
    moved = []
    for folder, name, legacy in LOOSE_FILES:
        old = os.path.join(LEGACY_HOME, legacy)
        new = os.path.join(TAPPROVAL_DIR, folder, name)
        if not os.path.exists(old):
            continue
        if name == "auth.json" and not _bridge_reads_data_dir():
            _tell("relay: the pairing key stays at ~/%s until the Mac bridge "
                  "can read ~/.tapproval/data" % legacy)
            continue
        if os.path.exists(new):
            _tell("relay: ~/%s left where it is: %s already exists" % (legacy, new))
            continue
        try:
            shutil.move(old, new)
            if folder == "data":
                # A move keeps the old folder's grants on Windows.
                _host.restrict_to_owner(new)
            moved.append(name)
        except OSError as error:
            _tell("relay: could not move ~/%s (%s); it is used where it is" % (legacy, error))
    if moved:
        _tell("relay: moved %s into %s" % (", ".join(moved), TAPPROVAL_DIR))
    return moved


def _use_moved_files():
    """After move_loose_files: every path this process holds, where its file
    is now. A path an environment variable chose is kept."""
    for global_name in _HOME_PATHS:
        globals()[global_name] = _home_path(global_name)
    crash_report = sys.modules.get("crash_report")
    if crash_report is not None:
        crash_report.CRASH_LOG = _loose_file("crashes.jsonl")


def icloud_carries_the_key():
    """Does the Mac bridge carry the key through iCloud here?

    Installed, and not known to be without an iCloud account: a bridge
    that has never reported (one from before /bridge-status) counts, as it
    always did; one that reported anything but "available" does not."""
    return bridge_installed() and _BRIDGE_ICLOUD in (None, "available")


def _token_matches(given, expected):
    """Constant-time secret comparison. False on anything unusable."""
    try:
        if not given or not expected:
            return False
        return hmac.compare_digest(str(given).encode("utf-8"),
                                   str(expected).encode("utf-8"))
    except (UnicodeError, TypeError):
        return False


# The tunnel's public watch URL, once cloudflared reports it. The LAN
# listener serves it at /tunnel so the watch can learn its away-address
# automatically while at home — no typing, ever.
TUNNEL_URL = None


# The running tunnel, remembered so the next relay can adopt it: with the
# iPhone off, a watch reaches its computer only over the internet (Apple,
# TN3135), so the travel address is the one route it has — and a new random
# address at every relay restart stranded it until it next met the Mac.
TUNNEL_STATE = _home_path("TUNNEL_STATE")
# cloudflared's own log: where the new address is read from, and the first
# place to look when the away address will not open.
TUNNEL_LOG = _home_path("TUNNEL_LOG")
TUNNEL_ANNOUNCE_WAIT = 60      # seconds for cloudflared to name its address


def _tunnel_pids(port):
    """Every cloudflared process that forwards to our tunnel port."""
    if _host.is_windows():
        # pgrep's pattern is a regular expression; the process list is not.
        return [pid for pid in _host.pids_running("127.0.0.1:%d" % port)
                if "cloudflared" in _host.command_of(pid)]
    return _host.pids_running("cloudflared tunnel.*127.0.0.1:%d" % port)


def _reap_stale_tunnels(port, keep=None):
    """Kill cloudflared processes left over from earlier relay runs, except
    the one being adopted.

    cloudflared outlives the relay on purpose (so the next one can adopt
    it); every OTHER one forwarding to our port is an orphan holding a
    public URL, and goes. Anything targeting our tunnel port is ours by
    definition. Never raises.
    """
    for pid in _tunnel_pids(port):
        if pid == keep:
            continue
        _host.stop(pid)


def _pid_alive(pid):
    return _host.pid_alive(pid)


def _remember_tunnel(pid, url, port, path=None):
    """Write the running tunnel down (0600), for the next relay. Never raises."""
    path = path or TUNNEL_STATE
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"pid": int(pid), "url": url, "port": int(port)}, handle)
        os.chmod(path, 0o600)
        _host.restrict_to_owner(path)
    except (OSError, ValueError, TypeError):
        pass


def _adoptable_tunnel(port):
    """The remembered tunnel, if it is alive and still ours; else None.

    Ours means: the pid is alive and its command line is cloudflared
    forwarding to this port — a recycled pid belongs to something else.
    Whether it still reaches this relay is `_tunnel_answers`' question.
    """
    try:
        with open(TUNNEL_STATE, encoding="utf-8") as handle:
            saved = json.load(handle)
        pid, url, saved_port = int(saved["pid"]), str(saved["url"]), int(saved["port"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if saved_port != port or not url.startswith("https://") or not _pid_alive(pid):
        return None
    command = _host.command_of(pid)
    if "cloudflared" not in command or "127.0.0.1:%d" % port not in command:
        return None
    return {"pid": pid, "url": url, "port": port}


def _tunnel_answers(url, token):
    """True when a request through the public URL reaches THIS relay.

    Our tunnel listener answers any request under its secret path in JSON
    — 401 without a key is still an answer. Cloudflare answers a tunnel
    with nothing behind it (or no tunnel at all) in HTML: 502, 530. Never
    raises.
    """
    return wire.answers_as_relay("%s/t/%s/health" % (url, token), 10,
                                 "Tapproval-helper")


# The edge needs a moment after a relay handover: cloudflared has been
# pointing at a dead origin while one relay stopped and the next started, and
# its first reply can be a 502. One probe at that instant replaced a healthy
# tunnel on 2026-09-30 and stranded the watch. Give it a few tries.
TUNNEL_PROBE_GAP = 3            # seconds between tries
TUNNEL_ADOPT_TRIES = 5          # at relay start: about 15 s of grace
TUNNEL_WATCH_TRIES = 3          # the watchdog's five-minute check


def _tunnel_answers_soon(url, token, tries=1):
    """`_tunnel_answers`, allowing a few tries for the edge to catch up.
    True at the first real answer; False only when every try failed."""
    for attempt in range(max(1, tries)):
        if attempt:
            time.sleep(TUNNEL_PROBE_GAP)
        if _tunnel_answers(url, token):
            return True
    return False


class _AdoptedTunnel:
    """A cloudflared this relay did not start: known by its pid alone."""

    def __init__(self, pid):
        self.pid = pid


# launchd hands a process a bare PATH — no /opt/homebrew/bin, no
# /usr/local/bin. The relay is started by a login item after every reboot,
# so looking only on PATH found nothing, printed "cloudflared not
# installed" (which was false), and silently left the travel route off
# until someone restarted the relay from a shell. Look where Homebrew
# actually puts it as well.
_TUNNEL_PATHS = ("/opt/homebrew/bin/cloudflared",      # Apple silicon
                 "/usr/local/bin/cloudflared",         # Intel
                 "/opt/local/bin/cloudflared")         # MacPorts


def _cloudflared():
    """The cloudflared binary, or None when it genuinely is not installed."""
    found = shutil.which("cloudflared")
    if found:
        return found
    for candidate in _TUNNEL_PATHS:
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def start_tunnel(port, token):
    """Expose the token-only listener through a Cloudflare quick tunnel.

    Prints the exact URL to enter on the watch once the tunnel is up.
    Returns the cloudflared process, or None when cloudflared is missing.
    The process is registered for cleanup at exit so a relay restart never
    leaves an orphan tunnel running.
    """
    binary = _cloudflared()
    if not binary:
        note_condition(
            "tunnel",
            "Answering from away is off: cloudflared is not installed on "
            "this computer. Install it with: %s" % _host.cloudflared_install())
        return None
    adopted = _adoptable_tunnel(port)
    if adopted and _tunnel_answers_soon(adopted["url"], token,
                                        tries=TUNNEL_ADOPT_TRIES):
        _publish_tunnel_url(adopted["url"], token)
        clear_condition("tunnel")
        _reap_stale_tunnels(port, keep=adopted["pid"])
        print("relay: tunnel adopted %s — the travel address is unchanged"
              % adopted["url"], file=sys.stderr)
        return _AdoptedTunnel(adopted["pid"])
    reason = ("the last one no longer answered" if adopted
              else "none to adopt")
    _reap_stale_tunnels(port)
    # The files this tunnel uses, fixed now: the thread below outlives this
    # call, and reading the module's names later found whatever they were
    # by then. On 2026-10-01 that was a test's fake tunnel (pid 5151,
    # own-file.trycloudflare.com) written into the real record after the
    # test had put the names back — on every suite run on that Mac, CI's
    # included — so each relay restart found nothing to adopt.
    log_path, state_path = TUNNEL_LOG, TUNNEL_STATE
    # cloudflared writes to a file of its own, in a session of its own. Its
    # stderr used to be a pipe into this relay, so the moment the relay
    # exited — every update, every restart — cloudflared's next log line hit
    # a closed pipe and killed it (measured 2026-09-30: dead within a
    # second). No travel address had ever survived a relay restart.
    try:
        log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        _host.restrict_to_owner(log_path)       # it names the travel address
    except OSError:
        log_fd = subprocess.DEVNULL
    proc = _host.popen_detached(
        [binary, "tunnel", "--no-autoupdate",
         "--url", "http://127.0.0.1:%d" % port],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log_fd)
    if log_fd is not subprocess.DEVNULL:
        os.close(log_fd)                # the child has its own copy

    def announce():
        deadline = time.monotonic() + TUNNEL_ANNOUNCE_WAIT
        while time.monotonic() < deadline:
            try:
                with open(log_path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                text = ""
            match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", text)
            if match:
                # Remembered before announced: whoever reads the address
                # next (the next relay, a test) finds it already written.
                _remember_tunnel(proc.pid, match.group(0), port, state_path)
                if adopted:
                    # The address the watch knew is gone. Said until the
                    # watchdog's next healthy check: a watch away from home
                    # is out of reach until iCloud carries the new one.
                    note_condition(
                        "tunnel",
                        "The away address changed. Your watch learns the new "
                        "one through iCloud within a minute or two.",
                        tone="in_hand")
                else:
                    clear_condition("tunnel")
                _publish_tunnel_url(match.group(0), token)
                print("relay: tunnel new %s (%s)" % (match.group(0), reason),
                      file=sys.stderr)
                print("relay: off-Wi-Fi tunnel up — the watch learns this "
                      "address automatically while on the same Wi-Fi.\n"
                      "       (manual fallback: %s/t/…)" % match.group(0),
                      file=sys.stderr)
                return
            if proc.poll() is not None:
                break
            time.sleep(0.2)
        # cloudflared exited, or never named a URL: the tunnel died on the
        # way up. Nothing said so before: the away address never appeared.
        note_condition(
            "tunnel",
            "Answering from away is not working: the connection closed "
            "before it opened. Answers still work on your own Wi-Fi.")
        print("relay: tunnel did not open — see %s" % log_path, file=sys.stderr)

    threading.Thread(target=announce, daemon=True).start()
    return proc


# The Mac bridge polls /pending?source=bridge every two seconds; it is the
# iCloud route, the only one a watch away from home with its iPhone off has
# for cards. Silence longer than this is a stopped bridge, and is said.
BRIDGE_SILENT_SECONDS = 120


def check_bridge(queue, started, now=None):
    """One look at the bridge: note or clear the `bridge` condition.
    True when all is well (or no bridge is installed here)."""
    now = time.monotonic() if now is None else now
    last = queue.last_bridge_poll
    if not bridge_installed():
        clear_condition("bridge")
        return True
    if last is None and now - started < BRIDGE_SILENT_SECONDS:
        return True                     # just started: give it a moment
    if last is not None and now - last <= BRIDGE_SILENT_SECONDS:
        clear_condition("bridge")
        return True
    note_condition(
        "bridge",
        "The iCloud route is off: Tapproval's bridge on this computer is not "
        "running, so away from home cards cannot reach your watch. "
        "Restarting the computer starts it again.")
    return False


def wired_agents():
    """The agents whose hook is wired on this Mac, for /health: Claude Code
    always (this relay is its helper), and Codex once our hook is in its
    hooks.json, trusted or not. The watch marks each card with its agent
    only once both are in use (owner, 2026-10-14), and learns that here
    before the first Codex card arrives."""
    agents = ["claude"]
    try:
        from ClaudeRiskClassifier import codex_hook_trusted
        if codex_hook_trusted() is not None:
            agents.append("codex")
    except ImportError:                # no helper beside us: `helper` says so
        pass
    except Exception as error:         # noqa: BLE001 — check_codex_hook says it aloud
        print("relay: could not check Codex's hook: %s" % error, file=sys.stderr)
    return agents


def check_codex_hook():
    """Note or clear the `codex` condition: our hook is in Codex's
    hooks.json but Codex has not been told to trust it, so every Codex
    question stays at the computer. True when all is well, or when there
    is no Codex here. Paths are read on each call (#362)."""
    try:
        from ClaudeRiskClassifier import codex_hook_trusted
    except ImportError:                # no helper beside us: `helper` says so
        return True
    try:
        trusted = codex_hook_trusted()
    except Exception as error:         # noqa: BLE001 — a bug, not "no Codex"
        # Read as "no Codex" until 2026-10-17, which cleared the condition
        # in silence whenever the check itself broke.
        print("relay: could not check Codex's hook: %s" % error, file=sys.stderr)
        note_condition(
            "codex",
            "Tapproval could not check whether Codex trusts its hook, so "
            "Codex questions may stay on the computer. Reinstalling the "
            "helper should fix it.")
        return False
    if trusted is False:
        note_condition(
            "codex",
            "Codex asks its questions on the computer until you open codex "
            "in Terminal once and choose \"Trust all and continue\".")
        return False
    clear_condition("codex")
    return True


def watch_bridge(queue, sleep=time.sleep, checks=None):
    """Look at the bridge once a minute for as long as the relay runs."""
    started = time.monotonic()
    done = 0
    while checks is None or done < checks:
        sleep(60)
        done += 1
        check_bridge(queue, started)
        check_codex_hook()


# How often the relay looks at its own tunnel. start_tunnel() checked once,
# at start; on 2026-09-30 the adopted cloudflared exited some time later and
# the relay went on handing out a dead travel address — every row on the
# watch's Connection screen red, in a car, and nothing said why.
TUNNEL_CHECK_EVERY = 60                 # seconds: is the process alive?
TUNNEL_PROBE_EVERY = 5                  # every 5th check, ask through Cloudflare
TUNNEL_BACKOFF = (120, 300, 600)        # after failures, wait longer — no spin


def _tunnel_alive(handle):
    """Our own child by poll(); an adopted one only by its pid."""
    if handle is None:
        return False
    poll = getattr(handle, "poll", None)
    if poll is not None:
        return poll() is None
    return _pid_alive(handle.pid)


def _stop_tunnel(handle):
    """Stop a cloudflared that is running but useless. Never raises."""
    try:
        if hasattr(handle, "terminate"):
            handle.terminate()
        elif handle is not None and handle.pid:
            _host.stop(handle.pid)
    except (OSError, AttributeError):
        pass


def watch_tunnel(handle, port, token, sleep=time.sleep, checks=None):
    """Keep the travel address alive for as long as the relay runs.

    Every minute: is cloudflared still running? Every fifth minute: does
    the public address still reach this relay? When either answer is no,
    stop handing the dead address out, say so on the Connection screen,
    and open a new tunnel — the bridge mirrors the new address through
    iCloud, which is how a watch away from home learns it. `checks` bounds
    the loop for tests; the relay passes None.
    """
    global TUNNEL_URL
    failures = 0
    done = 0
    unannounced = 0                     # seconds alive with no address yet
    while checks is None or done < checks:
        pause = (TUNNEL_CHECK_EVERY if not failures
                 else TUNNEL_BACKOFF[min(failures, len(TUNNEL_BACKOFF)) - 1])
        sleep(pause)
        done += 1
        url = TUNNEL_URL
        if _tunnel_alive(handle):
            if not url:
                # Still announcing itself — for a while. One that never
                # printed its address was waited on for as long as it ran,
                # and the travel route stayed off (2026-10-05 review).
                unannounced += pause
                if unannounced <= TUNNEL_ANNOUNCE_WAIT + TUNNEL_CHECK_EVERY:
                    continue
                why = "never announced its address"
                _stop_tunnel(handle)
            elif done % TUNNEL_PROBE_EVERY:
                failures = 0
                unannounced = 0
                continue
            elif _tunnel_answers_soon(url.split("/t/")[0], _live_tunnel_secret(token),
                                      tries=TUNNEL_WATCH_TRIES):
                failures = 0
                unannounced = 0
                clear_condition("tunnel")   # a changed-address notice ends here
                continue
            else:
                why = "no longer answers"
        else:
            why = "has exited"
        failures += 1
        unannounced = 0
        TUNNEL_URL = None
        note_condition(
            "tunnel",
            "Answering from away stopped. Reopening it — your watch learns "
            "the new address through iCloud.", tone="in_hand")
        print("relay: tunnel %s — reopening" % why, file=sys.stderr)
        handle = start_tunnel(port, _live_tunnel_secret(token))


# --------------------------------------------------------------------------
# Demo / manual injection
# --------------------------------------------------------------------------

DEMO_CARDS = [
    {"tier": "CRITICAL", "headline": "git push --force origin main",
     "detail": "git push --force origin main", "project": "acme-platform"},
    {"tier": "HIGH", "headline": "Delete build -r",
     "detail": "rm -r build dist", "project": "acme-platform"},
    {"tier": "MEDIUM", "headline": "Edit handlers.py",
     "detail": "Edit src/api/handlers.py", "project": "acme-platform"},
    {"tier": "HIGH", "headline": "SUDO systemctl restart nginx",
     "detail": "sudo systemctl restart nginx", "project": "infra"},
]


def _classified_card(command):
    """Run a command through the real classifier to build its card."""
    try:
        import ClaudeRiskClassifier as classifier
    except ImportError:
        return {"tier": "MEDIUM", "headline": command[:40], "detail": command[:80]}
    result = classifier.classify({"tool_name": "Bash",
                                  "tool_input": {"command": command}})
    card = classifier.wrist_card(result["tool"], result["tool_input"],
                                 result["risk"])
    card["project"] = "manual"
    return card


def _inject(queue, card, wait):
    def worker():
        card_id, decision, _answer = queue.submit(card, wait)
        print("card %s [%s] %-40s -> %s"
              % (card_id, card.get("tier"), card.get("headline"), decision),
              file=sys.stderr)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Local relay between the risk classifier and a watch app.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--demo", action="store_true",
                        help="inject sample wrist cards to exercise the watch app")
    parser.add_argument("--card", metavar="COMMAND",
                        help="classify COMMAND and inject its card")
    parser.add_argument("--wait", type=float, default=300.0,
                        help="how long injected cards wait for an answer")
    parser.add_argument("--no-bonjour", action="store_true",
                        help="do not advertise the relay on the local network")
    parser.add_argument("--allow-simulator", action="store_true",
                        help="take answers from a watch Simulator: for a "
                             "test relay only, never one real cards reach")
    parser.add_argument("--tls-port", type=int, default=TLS_PORT,
                        help=argparse.SUPPRESS)
    # A test relay's own tunnel port: the live relay holds TUNNEL_PORT.
    parser.add_argument("--tunnel-port", type=int, default=TUNNEL_PORT,
                        help=argparse.SUPPRESS)
    parser.add_argument("--tunnel", action="store_true",
                        help="also expose the relay through a Cloudflare "
                             "tunnel so the watch works off Wi-Fi")
    parser.add_argument("--ensure", action="store_true",
                        help="start the relay in the background if it is "
                             "not already running, then exit")
    parser.add_argument("--update", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--bridge-update", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--pair", action="store_true",
                        help="open a short pairing window so a new watch can "
                             "connect, then exit")
    parser.add_argument("--pair-reset", action="store_true",
                        help="forget every paired device and open a fresh "
                             "pairing window")
    parser.add_argument("--rotate-token", action="store_true",
                        help="replace the travel address and every device "
                             "key; paired watches re-pair by themselves")
    return parser


def _start_tls(args, queue, auth):
    """The encrypted listener beside the main one, when the main one faces
    the network (production binds 0.0.0.0). A relay on loopback only (the
    tests, the isolated relays) has no one to encrypt for. A missing
    openssl or a taken port costs the encryption, never the relay, and is
    said on the Connection screen."""
    global TLS_INFO
    if args.host in ("127.0.0.1", "localhost", "::1"):
        return False                     # loopback only: nobody to encrypt for
    identity = ensure_tls_identity()
    if identity is None:
        return False                     # ensure_tls_identity said why
    cert, key = identity
    try:
        server, _ = serve_tls(args.host, args.tls_port, cert, key, queue=queue,
                              auth=auth, allow_simulator=args.allow_simulator,
                              plain_port=args.port)
    except (OSError, ValueError) as error:
        note_condition("no_tls", "Messages on your Wi-Fi are not encrypted: the "
                       "encrypted port %d is in use on this computer." % args.tls_port)
        print("relay: encrypted port %d unavailable (%s)" % (args.tls_port, error),
              file=sys.stderr)
        return None
    TLS_INFO = {"port": args.tls_port, "sha256": tls_fingerprint(cert)}
    threading.Thread(target=server.serve_forever, name="tls-listener",
                     daemon=True).start()
    print("relay: encrypted on https://%s:%d (%s…)" % (
        args.host, args.tls_port, (TLS_INFO["sha256"] or "")[:12]), file=sys.stderr)
    return server


def _start_tunnel(queue, auth, allow_simulator=False, port=TUNNEL_PORT):
    """The second listener and the cloudflared process behind it. Two
    independent secrets on the public path: the unguessable rendezvous
    prefix says where, the device token says who."""
    global _TUNNEL_HANDLER
    try:
        tunnel_server, _ = serve("127.0.0.1", port,
                                 queue=queue, token=auth.tunnel_secret,
                                 auth=auth, allow_simulator=allow_simulator)
    except OSError as error:
        # 2026-09-11, 23:58: this raised out of main() and killed a relay
        # whose MAIN listener had already bound. The away route is the
        # fallback, not the product — losing it must never cost the local
        # path, which is the one the wrist uses at the desk all day. Same
        # rule the missing-cloudflared branch below already follows: say
        # so on the Connection screen and carry on.
        note_condition(
            "tunnel",
            "Answering from away is off: the travel port is already in use "
            "on this computer, usually another Tapproval still shutting "
            "down. Approvals at home are unaffected.")
        print("relay: tunnel port %d unavailable (%s) — continuing without "
              "the away route" % (port, error), file=sys.stderr)
        return None
    _TUNNEL_HANDLER = tunnel_server.RequestHandlerClass
    threading.Thread(target=tunnel_server.serve_forever, daemon=True).start()
    handle = start_tunnel(port, auth.tunnel_secret)
    if handle is not None:
        threading.Thread(target=watch_tunnel, daemon=True,
                         args=(handle, port, auth.tunnel_secret)).start()
    return handle


class _Advertiser:
    """The Bonjour advertisement, re-published once the tunnel URL exists
    so the TXT record carries every address the watch might need — and
    watched afterwards, because a process nobody looks at can die.

    advertise() starts dns-sd with both pipes to DEVNULL and nothing ever
    polled it. If it exited — an mDNSResponder restart, a stray killall,
    a crash — the relay carried on believing it was announced, and the
    watch simply stopped finding the computer with no screen and no log
    line saying why. #92 made "never started" visible; this is "started
    and then died". A name conflict is NOT the exit case: measured, two
    registrations of the same name from one host both stay up.

    The swap in _republish is deliberate and must not read as a death, so
    the process is only ever replaced under the same lock the watchdog
    takes: by the time the watchdog looks, it sees the new process.
    """

    WATCH_SECONDS = 5.0          # how often the watchdog looks
    WATCH_BACKOFF_MAX = 60.0     # when restarts keep failing, look less often
    MAX_RESTARTS = 3             # after this many in a row, stop and say so

    def __init__(self, port):
        self.port = port
        self._lock = threading.Lock()
        # Consecutive restarts whose replacement has not yet lived a tick.
        # Non-zero means "unproven": the condition noted at the death
        # stands until the next look finds the replacement alive.
        self._restarts = 0
        txt = advertise_txt(port)
        self.txt = txt
        self.process = advertise(port, txt)
        if self.process is not None:
            clear_condition("bonjour")
            print("relay: advertising as \"Tapproval\" (%s) with %s"
                  % (BONJOUR_TYPE, txt), file=sys.stderr)

    def republish_when_tunnel_is_up(self):
        threading.Thread(target=self._republish, daemon=True).start()

    def _republish(self):
        for _ in range(60):
            time.sleep(1)
            if TUNNEL_URL:
                break
        if not TUNNEL_URL:
            return
        txt = advertise_txt(self.port)
        with self._lock:
            if self.process is None:
                return
            if txt == self.txt:
                # The record does not carry the away address any more, so
                # this usually changed nothing — and re-registering an
                # identical record can make the watch lose the computer
                # for a moment (2026-10-05 review).
                return
            self.process.terminate()
            self.txt = txt
            self.process = advertise(self.port, txt)
            # A deliberate fresh start: whatever run of unproven restarts
            # came before does not carry into the give-up count. But if a
            # condition is standing from one, this new process still has
            # to live a tick before it is withdrawn — so one, not zero.
            self._restarts = min(self._restarts, 1)
            # If advertise() returned None it said why; the watchdog then
            # finds nothing to watch and ends. No further restarts: the
            # tool that was there a minute ago is gone, not flapping.
        print("relay: re-advertised with %s" % txt, file=sys.stderr)

    def watch(self):
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        pause = self.WATCH_SECONDS
        while True:
            time.sleep(pause)
            outcome = self.check_once()
            if outcome in ("none", "down"):
                return                  # nothing left to watch, and it has been said
            # A relay that restarts a dying announcer every five seconds
            # forever is a fork bomb with good intentions; back off while
            # it keeps failing, and come straight back once it holds.
            pause = (min(pause * 2, self.WATCH_BACKOFF_MAX) if outcome == "restarted"
                     else self.WATCH_SECONDS)

    def check_once(self):
        """One look at the announcer. Returns what was found, for the
        watchdog's pacing and for the tests: "none" (nothing to watch —
        whoever stopped it said why), "fine", "restarted" (it had exited
        and a replacement is up) or "down" (it had exited and there will
        be no more restarts; the condition stands).

        A restart is not a recovery. The first cut withdrew the condition
        the moment advertise() returned a process — which says only that
        the exec succeeded. A dns-sd that dies fifty milliseconds later
        would have been noted, cleared and "restarted" every tick, and
        /health would almost never have caught the condition existing:
        the #94 failure reproduced one level up. Now the condition is
        withdrawn only once the replacement is still alive at the NEXT
        look, and after MAX_RESTARTS in a row the relay stops trying and
        leaves a sentence that says what is actually true.
        """
        with self._lock:
            if self.process is None:
                return "none"
            code = self.process.poll()
            if code is None:
                if self._restarts:
                    self._restarts = 0
                    clear_condition("bonjour")
                    print("relay: announcing again after the announcer exited",
                          file=sys.stderr)
                return "fine"
            self._restarts += 1
            if self._restarts > self.MAX_RESTARTS:
                note_condition(
                    "bonjour",
                    "The network announcement keeps stopping (dns-sd exited %d "
                    "times in a row, last with code %s), so the watch may not "
                    "find this computer by itself. Enter its address by hand."
                    % (self._restarts, code))
                self.process = None
                return "down"
            note_condition(
                "bonjour",
                "The network announcement stopped (dns-sd exited with code %s), "
                "so the watch may no longer find this computer by itself. "
                "Trying to announce again." % code, tone="in_hand")
            self.txt = advertise_txt(self.port)
            self.process = advertise(self.port, self.txt)
            if self.process is None:
                return "down"          # advertise() has said why, in its own words
        return "restarted"

    def terminate(self):
        with self._lock:
            if self.process is not None:
                self.process.terminate()


def _inject_startup_cards(args, queue):
    if args.demo:
        for index, card in enumerate(DEMO_CARDS):
            threading.Timer(1.0 + index * 2.0, _inject,
                            args=(queue, card, args.wait)).start()
        print("relay: demo cards arriving over the next few seconds",
              file=sys.stderr)
    if args.card:
        threading.Timer(1.0, _inject,
                        args=(queue, _classified_card(args.card), args.wait)).start()


# How long a relay that lost the race for its port waits for the winner
# to say what it is. Longer than the probe --ensure uses, because the
# winner is the relay that was too slow for that probe: /health may be
# waiting on `claude auth status`, whose own limit is fifteen seconds.
PORT_TAKEN_WAIT = 20.0


def _port_taken(port):
    """The relay could not bind: say who has the port, and do not crash.

    Two relays racing for one port is not a fault in either — the loser
    is simply not needed. Until 1.1.15 it died with a traceback, and the
    crash reporter mailed the owner about a relay that was running fine.
    Anything else on the port is a real problem, and one the user can act
    on: it becomes a condition, not a stack trace.
    """
    reply = _loopback_json("/health", timeout=PORT_TAKEN_WAIT, port=port)
    if isinstance(reply, dict) and reply.get("ok") and "version" in reply:
        print("relay: another relay already serves port %d (helper %s) — "
              "leaving it to it" % (port, reply.get("helper") or "?"),
              file=sys.stderr)
        return 0
    note_condition("port", "Another program on your computer is using the "
                           "connection Tapproval needs (port %d), so the "
                           "helper could not start. Restarting the computer "
                           "frees it." % port)
    return 1


def _start_slow_parts(args, queue, auth):
    """The travel tunnel and the Bonjour advertiser, each on its own thread.

    Both are slow to start: the tunnel probes Cloudflare (about a minute
    when an adopted tunnel no longer answers) and Bonjour asks ipconfig,
    tailscale and dns-sd. They used to run before the relay served at all,
    so the hook, the bridge and the watch at home all waited on the away
    route, and --ensure gave up after six seconds (2026-10-21). Returns
    ``stop()``, which ends the advertiser however far it got. Never raises.
    """
    lock, stopping, made = threading.Lock(), [False], []

    def tunnel():
        # Not kept: the tunnel outlives this relay on purpose (see main()).
        _start_tunnel(queue, auth, allow_simulator=args.allow_simulator,
                      port=getattr(args, "tunnel_port", TUNNEL_PORT))

    def bonjour():
        advertiser = _Advertiser(args.port)
        with lock:
            made.append(advertiser)
            if stopping[0]:
                advertiser.terminate()
                return
        advertiser.watch()
        if args.tunnel:
            advertiser.republish_when_tunnel_is_up()

    if args.tunnel:
        threading.Thread(target=tunnel, name="tunnel-start", daemon=True).start()
    if not args.no_bonjour:
        threading.Thread(target=bonjour, name="bonjour-start", daemon=True).start()

    def stop():
        with lock:
            stopping[0] = True
            for advertiser in made:
                advertiser.terminate()
    return stop


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if not isinstance(sys.stderr, _StampedStream):
        sys.stderr = _StampedStream(sys.stderr)
    forget_host_session()
    make_home_dirs()
    if args.ensure:
        return ensure_running()
    if args.update:
        # The detached half of --ensure: pull, then replace the relay if
        # the code moved and nothing is waiting. Hold the worker lock
        # through replacement, even if another hourly check becomes due.
        with _process_lock(_UPDATE_STAMP + ".worker.lock") as claimed:
            if claimed and _pull_update():
                ensure_running(updated=True)
        return 0
    if args.bridge_update:
        return run_bridge_update()
    if args.pair or args.pair_reset or args.rotate_token:
        return run_admin(args)

    # One machine-wide key gates every non-local caller, whichever
    # listener they arrive on. First contact from the user's own network
    # fetches it via /pair — pairing is automatic and never broadcast.
    auth = Auth()
    # A machine that has never paired lights the first-contact window
    # (see Auth.window_open); a paired one is left alone. This used to
    # call open_window() with its default — the ten-minute --pair fuse —
    # which quietly cut the half hour Auth() had just lit to a third, on
    # the only path that runs at startup. relight() uses the right
    # constant and is a no-op once anything has paired.
    if auth.relight() > time.time():
        print("relay: pairing open until the first watch connects",
              file=sys.stderr)

    check_helper_is_visible()
    check_dashboard_is_loaded()
    check_codex_hook()
    ensure_claude_on_path()
    helper_provenance()
    install_crash_reporting()

    try:
        server, queue = serve(args.host, args.port, auth=auth,
                              allow_simulator=args.allow_simulator)
    except OSError as error:
        if error.errno != errno.EADDRINUSE:
            raise
        return _port_taken(args.port)
    # Only now, holding the port: no older relay is left to write the old
    # loose files again once they have moved.
    if move_loose_files():
        _use_moved_files()
        auth.path = AUTH_FILE
    print("relay: listening on http://%s:%d" % (args.host, args.port),
          file=sys.stderr)
    _start_tls(args, queue, auth)
    stop_slow_parts = _start_slow_parts(args, queue, auth)
    threading.Thread(target=watch_bridge, args=(queue,), daemon=True).start()
    threading.Thread(target=watch_for_newer_helper, name="release-look",
                     daemon=True).start()
    _inject_startup_cards(args, queue)
    if not args.allow_simulator:
        codex_approval_sync(queue).start()

    # SIGTERM (pkill, launchd, a relay restart from --ensure) must run the
    # same cleanup as Ctrl-C — otherwise the Bonjour advertiser and the
    # tunnel outlive the relay and keep announcing a stale address.

    def _stop(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _stop)

    try:
        with open(PID_FILE, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
    except OSError:
        pass                                            # lsof still finds us
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("relay: stopped", file=sys.stderr)
    finally:
        stop_slow_parts()
        sync = getattr(queue, "codex_sync", None)
        if sync is not None:
            sync.stop()
        # The tunnel is left running on purpose: the next relay adopts it,
        # so the travel address — the one route a watch without its iPhone
        # has — survives restarts and updates. start_tunnel() reaps it if
        # it no longer answers; uninstall.sh stops it for good.
        server.server_close()
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
