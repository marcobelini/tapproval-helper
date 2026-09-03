#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch_relay — the local bridge between the risk classifier and Tapproval.

The classifier hook decides *what* deserves a human; this relay carries the
question to whatever screen the human is wearing. It is a deliberately tiny
HTTP server on loopback:

    hook  ── POST /card ────►  relay  ◄──── GET  /pending ──  watch app
          ◄─ blocks for the       │   ◄──── POST /decision ─
             decision ────────────┘

Endpoints:

    POST /card      {"card": {...}, "wait": seconds}
                    Queues a wrist card and blocks until the watch answers
                    or the wait expires. Responds {"id", "decision"} where
                    decision is "allow", "deny" or "none" (timed out).
    GET  /pending   {"cards": [{...}, ...]} — what the watch should show.
    POST /decision  {"id": "...", "decision": "allow"|"deny"}
    GET  /health    {"ok": true, "pending": n}

Run it::

    python3 watch_relay.py                # serve on 127.0.0.1:8977
    python3 watch_relay.py --demo         # serve + inject sample cards
    python3 watch_relay.py --card "rm -rf build"   # inject one real card

Design rules follow the classifier's: standard library only, loopback only,
and fail closed — a relay that is down, slow or confused must never grant an
approval. "none" is the only answer it gives on any doubt.
"""

from __future__ import annotations

import argparse
import hmac
import json
import shlex
import functools
import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8977          # also referenced by the classifier's --watch/--status
TUNNEL_PORT = 8978
# Read once, to migrate a pre-per-device install into the auth file; never
# written any more. The function that used to create it went with the
# single-token design, and was the last write-then-chmod left in the tree.
TOKEN_FILE = os.path.expanduser("~/.tapproval-token")
AUTH_FILE = os.path.expanduser("~/.tapproval-auth.json")
# Bumped whenever the wire contract or the auth rules change, so a running
# relay from before an update can be recognised — and replaced — instead of
# quietly serving the old rules forever (see ensure_running).
RELAY_VERSION = 2
PAIR_WINDOW_SECONDS = 600   # a deliberately opened window, not a standing door
PAIR_WINDOW_CLAIMS = 2      # one watch, plus one retry
DEFAULT_WAIT = 6.0     # how long POST /card blocks by default
try:
    # One number, one owner: the hook's wait, its timeout and this clamp
    # must move together, or cards expire on the wrist while the terminal
    # keeps waiting. Same directory, stdlib-only either way.
    from ClaudeRiskClassifier import RELAY_WAIT_SECONDS as MAX_WAIT
    from ClaudeRiskClassifier import __version__ as HELPER_VERSION
    MAX_WAIT = float(MAX_WAIT)
except Exception:                                  # standalone deployment
    MAX_WAIT = 3600.0
    HELPER_VERSION = "unknown"
MAX_BODY = 64 * 1024   # nobody's wrist card is 64KB

VALID_DECISIONS = ("allow", "deny", "answer", "always")

# The Bonjour service type the watch app browses for.
BONJOUR_TYPE = "_wristtriage._tcp"


def lan_ips():
    """This machine's LAN addresses (never the tailnet). Never raises."""
    import socket
    ips = []
    for iface in ("en0", "en1", "en2", "en3"):
        try:
            out = subprocess.run(["ipconfig", "getifaddr", iface],
                                 capture_output=True, text=True, timeout=2)
            ip = (out.stdout or "").strip()
            if ip and not ip.startswith("100."):
                return [ip]
        except (OSError, subprocess.SubprocessError):
            pass
    if not ips:
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            ip = probe.getsockname()[0]
            probe.close()
            if ip and not ip.startswith("100."):
                ips.append(ip)
        except OSError:
            pass
    return ips


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
    return txt


def _machine_name():
    import socket
    host = socket.gethostname().split(".")[0].replace("-", " ")
    return ("Tapproval on %s" % host) if host else "Tapproval"


def advertise(port):
    """Advertise the relay over Bonjour so the watch app finds it by itself.

    macOS ships ``dns-sd``; most Linux distributions ship Avahi. Either
    way it's the system's own tool — no dependencies, per this repo's
    rules. Returns the child process, or None when neither is available;
    the relay still works then via the tunnel or a manual address.
    Never raises.
    """
    name = _machine_name()
    pairs = ["%s=%s" % (key, value)
             for key, value in advertise_txt(port).items()]
    if shutil.which("dns-sd"):
        command = ["dns-sd", "-R", name, BONJOUR_TYPE, ".", str(port)] + pairs
    elif shutil.which("avahi-publish"):
        command = ["avahi-publish", "-s", name, BONJOUR_TYPE, str(port)] + pairs
    else:
        return None
    try:
        return subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as error:
        print("relay: bonjour advertising unavailable (%s)" % error,
              file=sys.stderr)
        return None


def _spawn_detached(command, log_path, cwd=None):
    """Start a child that outlives this process, appending output to a log.

    The relay keeps no handle on the log — the child inherits its own copy —
    so a long-lived relay does not leak one file descriptor per spawn.
    Returns "" on success or a short error string. Never raises.
    """
    try:
        with open(log_path, "a") as log:
            subprocess.Popen(command, cwd=cwd, stdout=log, stderr=log,
                             start_new_session=True)
    except OSError as error:
        return str(error)
    return ""


def _probe_relay(timeout=2):
    """What the running relay says about itself, or None if none is up.

    Asks over loopback, which the relay trusts, so the answer carries the
    version and the pending count rather than the anonymous liveness reply.
    """
    import urllib.request
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1:%d/health" % DEFAULT_PORT,
                timeout=timeout) as reply:
            return json.loads(reply.read().decode("utf-8"))
    except Exception:
        return None


def _stop_relay(deadline=8.0):
    """Ask the running relay to exit, then wait for the port to come free."""
    try:
        subprocess.run(["pkill", "-f", "watch_relay.py --host"],
                       capture_output=True, timeout=5)
    except Exception:
        return False
    end = time.time() + deadline
    while time.time() < end:
        if _probe_relay(timeout=1) is None:
            return True
        time.sleep(0.4)
    return False


def _admin_call(path):
    """Loopback-only administration: the relay owns the state, this just
    asks it. Returns the parsed reply or None."""
    import urllib.request
    request = urllib.request.Request(
        "http://127.0.0.1:%d%s" % (DEFAULT_PORT, path),
        data=b"{}", method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:
            return json.loads(reply.read().decode("utf-8"))
    except Exception:
        return None


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


RELAY_LOG = os.path.expanduser("~/.tapproval-relay.log")
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


# At most once a day, and never in the way. A stale helper is not a
# cosmetic problem: the version before 1.1.1 discarded every wrist
# approval in silence, so "an update that never arrives" is the failure
# mode this guards against.
# Overridable like CLAUDE_SETTINGS_PATH and CLAUDE_LAUNCH_AGENT_PATH, so a
# test — including one that runs the hook in a subprocess, where a
# monkeypatch cannot reach — never pulls the working tree it is testing.
_UPDATE_STAMP = os.environ.get("TAPPROVAL_UPDATE_STAMP") or os.path.expanduser(
    "~/.tapproval-last-update")
_UPDATE_EVERY = 86400.0


def _self_update():
    """Fast-forward a git-installed helper. Returns True if it moved.

    Only ever touches an install that is a git checkout — the one made by
    install.sh. A plugin install belongs to Claude Code, which manages its
    own updates, and must not be rewritten underneath it. Every failure is
    silent and harmless: a machine that cannot reach GitHub, a clone with
    local edits, no git at all — the relay simply starts what is already
    there. Never raises, never blocks a session.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(os.path.join(here, ".git")):
        return False
    try:
        age = time.time() - os.path.getmtime(_UPDATE_STAMP)
        if age < _UPDATE_EVERY:
            return False
    except OSError:
        pass
    try:
        with open(_UPDATE_STAMP, "w") as handle:
            handle.write(str(int(time.time())))
    except OSError:
        pass
    # Everything, including reading the results, sits inside one guard and
    # catches everything. The promise above is "never raises", and this runs
    # on the blocking path of a SessionStart hook: an exception here would
    # take down the session, which is a far worse outcome than a missed
    # update. Narrow excepts made that promise false.
    try:
        before = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=10)
        subprocess.run(["git", "-C", here, "pull", "--ff-only", "--quiet"],
                       capture_output=True, text=True, timeout=60)
        after = subprocess.run(["git", "-C", here, "rev-parse", "HEAD"],
                               capture_output=True, text=True, timeout=10)
        moved = (before.returncode == 0 and after.returncode == 0
                 and before.stdout.strip() != after.stdout.strip())
    except Exception:
        return False
    if moved:
        print("relay: helper updated to the latest published version",
              file=sys.stderr)
    return moved


def ensure_running():
    """Start the relay in the background unless one is already up.

    Registered as a Claude Code SessionStart hook, so the relay's whole
    lifecycle is automatic: it exists whenever Claude Code does. Prints a
    line to stderr and exits immediately either way. Never raises.
    """
    updated = _self_update()
    running = _probe_relay()
    if running is not None:
        version = running.get("version") or 0
        # A relay started before an update is running the old code even
        # when its protocol version matches, so a fresh pull must replace
        # it — subject to the same "not while a card is waiting" rule.
        if version >= RELAY_VERSION and not updated:
            print("relay: already running", file=sys.stderr)
            return 0
        # An older relay is serving. Without this the machine keeps running
        # yesterday's rules forever — an update that never arrives is not an
        # update. But a relay holding a card is holding someone's approval:
        # replace it only when nothing is waiting.
        if running.get("pending"):
            print("relay: update deferred — a card is waiting", file=sys.stderr)
            return 0
        print("relay: replacing an older relay (v%s -> v%d)"
              % (version or "?", RELAY_VERSION), file=sys.stderr)
        _stop_relay()
    log_path = RELAY_LOG
    _rotate_log(log_path)
    error = _spawn_detached(
        [sys.executable, os.path.abspath(__file__),
         "--host", "0.0.0.0", "--tunnel"], log_path)
    if error:
        print("relay: could not start (%s)" % error, file=sys.stderr)
    else:
        print("relay: started in the background (log: %s)" % log_path,
              file=sys.stderr)
    return 0


class CardQueue:
    """Pending wrist cards and the decisions made about them."""

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
        self.last_poll = None           # monotonic time of last /pending fetch

    # A watch that has not polled within this many seconds is not on a
    # wrist right now. Diagnostics only — cards queue regardless, because
    # a wrist raised late must still find its card.
    WATCH_PRESENT_SECONDS = 90

    def watch_present(self):
        with self._lock:
            return (self.last_poll is not None and
                    time.monotonic() - self.last_poll
                    <= self.WATCH_PRESENT_SECONDS)

    def submit(self, card, wait, caller_alive=None, resolved_elsewhere=None):
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
        card_id = uuid.uuid4().hex[:12]
        entry = dict(card)
        entry["id"] = card_id
        deadline = time.monotonic() + wait
        with self._lock:
            self._pending[card_id] = entry
            self._lock.notify_all()
        # Once a card is up it STAYS up — a lowered wrist pauses polling
        # for minutes at a time and must not cost the question. A card
        # leaves in exactly three ways: answered here, its prompt resolved
        # elsewhere (the probes), or the wait truly expires. The probes do
        # socket and file I/O, so they run with the lock RELEASED — the
        # watch's /pending poll must never queue behind a transcript read.
        # They fire immediately on entry (a prompt already answered when
        # the card is posted must not stand even five seconds) and then on
        # a ~5s CLOCK, not per wakeup: notify_all() for unrelated cards
        # wakes every waiter, and probe I/O must scale with time, not with
        # card traffic. The exit predicate lives in exactly one place.
        next_probe = 0.0
        while True:
            now = time.monotonic()
            if now >= next_probe:
                next_probe = now + 5.0
                if caller_alive is not None and not caller_alive():
                    break
                if resolved_elsewhere is not None and resolved_elsewhere():
                    break
            with self._lock:
                if card_id in self._decisions:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._lock.wait(max(0.05, min(
                    remaining, next_probe - time.monotonic())))
        with self._lock:
            # Whatever happened, the card is no longer pending: either it
            # was decided, or it expired and the watch must not answer a
            # question the hook has already given up on.
            self._pending.pop(card_id, None)
            decision, answer = self._decisions.pop(card_id, ("none", None))
            if decision == "always":
                if replayable:
                    self._session_allows.add(rule)
                decision = "allow"
        return card_id, decision, answer

    def pending(self, from_watch=False):
        with self._lock:
            if from_watch:
                self.last_poll = time.monotonic()
            return list(self._pending.values())

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
            return
        # A negative age is clock skew or a buggy reporter — fail closed.
        if not 0 <= seconds_ago <= self.WATCH_PRESENT_SECONDS:
            return
        with self._lock:
            seen = time.monotonic() - seconds_ago
            if self.last_poll is None or seen > self.last_poll:
                self.last_poll = seen

    def watch_seen_seconds_ago(self):
        with self._lock:
            if self.last_poll is None:
                return None
            return int(time.monotonic() - self.last_poll)

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
            # "answer" carries the chosen option label for question cards.
            self._decisions[card_id] = (decision,
                                        str(answer)[:200] if answer else None)
            self._lock.notify_all()
        print("relay: accepted %s for %s" % (decision, card_id),
              file=sys.stderr)
        return True


# The session/usage/activity layer lives in its own module now: this file
# is the relay, and the relay's job is small and dangerous, while reading
# transcripts is large and harmless. Re-exported here so `watch_relay.X`
# keeps working for everything that already calls it.
from watch_dashboard import (  # noqa: E402,F401  (re-exports, see above)
    CLAUDE_PROJECTS, CLAUDE_SESSIONS, ENTRYPOINTS,
    PREWARM_SESSIONS, THREAD_TURN_LIMIT, USAGE_WINDOW_HOURS,
    _ACTIVITY_LOCK, _ACTIVITY_STATE, _GH_FACT, _GH_VERB, _MD_BULLET,
    _MD_CODE, _MD_EM, _MD_ESCAPE, _MD_FENCE, _MD_HEADING, _MD_HR, _MD_HTML,
    _MD_IMAGE, _MD_LINK, _MD_QUOTE, _MD_STRIKE, _MD_STRONG, _MD_TABLE_SEP,
    _META_CACHE, _REPO_SLUG_CACHE, _REPO_SLUG_MAX, _TASK_DONE,
    _TASK_LAUNCH, _THREAD_LOCKS, _THREAD_LOCKS_GUARD, _THREAD_STATE,
    _TOOL_PHRASES, _TRANSCRIPT_PATHS, _USAGE_FILES,
    _activity_summary_locked, _audit_log_path, _find_transcript,
    _fresh_thread_state, _last_github_fact, _last_prewarm, _parse_stamp,
    _parse_thread, _parse_thread_locked, _read_appended,
    _remember_repo_slug, _session_meta, _stat_cached, _task_state,
    _thread_activity, _thread_line, _thread_lock, _tool_phrase,
    _usage_entries, _usage_entries_uncached, activity_summary,
    derive_title, live_sessions, session_registry, plain_text, prewarm_threads,
    recent_sessions, repo_slug, resolve_session,
    session_meta, session_thread, usage_summary)


# What a wrist-sent message asks Claude to sound like. Each message spawns
# a fresh `claude` process, and a process reads its settings once, at
# start — so this flag shapes exactly one reply and nothing else. The
# desktop session it lands in never restarts, so its own style is
# untouched. Trying to change the user's settings file instead would
# quietly follow them back to the keyboard.
BRIEF_REPLY_SETTINGS = json.dumps({"outputStyle": "Concise"})


def say_to_session(prefix, text, projects_dir=None, brief=True):
    """Send an instruction to a session, the way the terminal would.

    Runs ``claude --resume <id> -p <text>`` in that session's directory so
    the reply lands in the same transcript the watch is reading — which is
    why the answer simply appears in the thread view. With ``brief`` (the
    default) the reply is asked for in Claude Code's Concise style, which
    is what a 14 pt thread on a wrist wants. Returns a short status
    string; never raises and never blocks the caller.
    """
    text = " ".join(str(text or "").split())[:500]
    if not text:
        return "empty"
    session_id, cwd = resolve_session(prefix, projects_dir)
    if not session_id:
        return "unknown session"
    if not shutil.which("claude"):
        return "claude not on PATH"
    command = ["claude", "--resume", session_id]
    if brief:
        command += ["--settings", BRIEF_REPLY_SETTINGS]
    command += ["-p", text]
    error = _spawn_detached(
        command,
        os.path.expanduser("~/.tapproval-say.log"),
        cwd=cwd or os.path.expanduser("~"))
    return "could not start: %s" % error if error else "sent"


def known_projects(projects_dir=None, limit=50):
    """The projects a new session may be started in: one row per directory
    Claude Code has recently worked in, most recent first. Derived from the
    same transcripts the session list reads, so the watch never has to
    type a path and the relay never opens a terminal somewhere it has not
    already seen Claude Code run."""
    seen, rows = set(), []
    for session in recent_sessions(limit=limit, projects_dir=projects_dir,
                                   include_idle=True):
        path = session.get("path") or ""
        if not path or path in seen or not os.path.isdir(path):
            continue
        seen.add(path)
        rows.append({"name": session.get("project") or os.path.basename(path),
                     "path": path,
                     "minutes_ago": session.get("minutes_ago", 0)})
    return rows


def start_session(path, text, projects_dir=None, platform=None):
    """Open a REAL Claude Code session on this Mac, in ``path``, with ``text``
    as its first message. Returns a short status; "started" on success.

    Not ``claude -p``: that is headless, and a headless session never fires
    the PermissionRequest hook — it would be the one session that could not
    ask the watch anything, and would stop at its first risky command. So
    this opens a Terminal window running an ordinary interactive ``claude``,
    whose cards reach the wrist like any other's.

    Every failure comes back as words the watch can show: no Mac, no
    ``claude`` on the PATH, a directory Claude Code has never worked in, or
    a Terminal that will not open (no one logged in at the screen — the
    usual reason). Never raises, never blocks longer than a few seconds.
    """
    text = " ".join(str(text or "").split())[:500]
    if not text:
        return "empty"
    if (platform or sys.platform) != "darwin":
        return "new sessions need a Mac"
    path = os.path.expanduser(str(path or ""))
    if path not in {row["path"] for row in known_projects(projects_dir)}:
        return "unknown project"
    if not shutil.which("claude"):
        return "claude not on PATH"
    script = 'cd %s && claude %s' % (shlex.quote(path), shlex.quote(text))
    apple = ('tell application "Terminal"\n'
             '  activate\n'
             '  do script %s\n'
             'end tell' % json.dumps(script))
    try:
        done = subprocess.run(["osascript", "-e", apple], capture_output=True,
                              text=True, timeout=8)
    except (OSError, subprocess.SubprocessError) as error:
        return "could not open Terminal: %s" % error
    if done.returncode != 0:
        why = (done.stderr or done.stdout or "").strip().splitlines()
        return "could not open Terminal: %s" % (why[-1] if why else "no reason given")
    return "started"


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
                 projects_dir=None):
        self.session_id = session_id
        self.tool = tool
        self.fingerprint = fingerprint
        self.fingerprint_of = fingerprint_of
        self.projects_dir = projects_dir
        self.path = None            # the session transcript, once found
        self.files = {}             # transcript path -> bytes already read
        self.use_ids = set()        # tool_use ids that match the card
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
            return resolved
        except (OSError, ValueError):
            return False

    def _located(self):
        """Find the session transcript — once, and not on every 5s wake
        when it is missing, since that walks every project directory."""
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
        on the same 5s clock — rather than fixed at the first look.
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
        try:
            if shrunk:
                # The transcript was rewritten (compaction). Its history
                # now contains earlier runs of possibly the SAME command
                # with their old results — matching those would retract a
                # live card nobody answered. Go dormant past the rewrite:
                # only appends from here on can resolve this card.
                self.use_ids.clear()
                try:
                    self.files[path] = os.path.getsize(path)
                except OSError:
                    pass
                return False
            for line in lines:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                content = (entry.get("message") or {}).get("content")
                if not isinstance(content, list):
                    continue
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if (part.get("type") == "tool_use"
                            and part.get("name") == self.tool
                            and self.fingerprint_of(
                                self.tool, part.get("input") or {})
                            == self.fingerprint):
                        self.use_ids.add(part.get("id"))
                    elif (part.get("type") == "tool_result"
                          and part.get("tool_use_id") in self.use_ids):
                        return True
        except (OSError, ValueError):
            return False
        return False


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
    return _PromptResolver(session_id, tool, fingerprint, _card_fingerprint,
                           projects_dir)




def _is_loopback(ip):
    return str(ip or "").startswith(("127.", "::1", "::ffff:127."))


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
    ip = str(ip or "")
    if _is_loopback(ip):
        return True
    if ip.startswith(("10.", "192.168.", "169.254.", "fe80")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    if ip.startswith("100."):        # CGNAT block: Tailscale's range
        try:
            return 64 <= int(ip.split(".")[1]) <= 127
        except (ValueError, IndexError):
            return False
    return False


def authorize_request(client_ip, path, header_token,
                      tunnel_authed, auth, via_tunnel=False):
    """May this request touch real data? One rule for every listener.

    Loopback is the local-process boundary the project documents and
    accepts: the hook, the Mac bridge and the liveness probe all run as the
    same user on the same machine. Everything else — LAN, tailnet, or the
    travel tunnel — must present a device token, whatever its address.

    Being on the user's Wi-Fi used to be enough. On a home network that
    reads as "me"; on café Wi-Fi it reads as "everyone here", which is how
    a stranger could read a transcript, answer a CRITICAL prompt, or speak
    into a live session.

    On the tunnel listener loopback means cloudflared, not a local process,
    so the exemption is deliberately withheld there: the secret path proves
    where the request came from, and the token proves who sent it.
    """
    def _credential_ok():
        if auth is None:
            return False
        if hasattr(auth, "matches"):
            return auth.matches(header_token)
        return _token_matches(header_token, auth)

    if via_tunnel:
        return bool(tunnel_authed) and _credential_ok()
    if _is_loopback(client_ip):
        return True
    if path == "/health":            # liveness only; the body is trimmed
        return True
    return _credential_ok()


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
TUNNEL_HIDDEN = ("/card", "/heartbeat", "/pair", "/enroll", "/tunnel")


class RelayHandler(BaseHTTPRequestHandler):
    queue = None            # installed by serve()
    required_token = None   # when set, only /t/<token>/... paths are served
    auth = None             # the Auth object: device tokens and pairing
    protocol_version = "HTTP/1.1"

    def _host_ok(self):
        """Reject a request whose Host header does not name this machine —
        the defence against DNS rebinding. Only the main listener needs it:
        the tunnel listener's credential is the secret path prefix, and it
        arrives from cloudflared bearing the public tunnel hostname.
        """
        if self.required_token is not None:
            return True
        return host_allowed(self.headers.get("Host", ""))

    def _authorized(self, path):
        return authorize_request(
            self.client_address[0], path,
            self.headers.get("X-Tapproval-Token", ""),
            getattr(self, "tunnel_authed", False), self.auth,
            via_tunnel=self.required_token is not None)

    def _credentialed(self):
        """Did this caller prove anything at all? Decides how much /health
        is willing to say — a pending count and "is a watch on the wrist
        right now" is a presence oracle, not liveness."""
        if self.required_token is None and _is_loopback(self.client_address[0]):
            return True
        auth = self.auth
        token = self.headers.get("X-Tapproval-Token", "")
        if auth is None:
            return False
        if hasattr(auth, "matches"):
            return auth.matches(token)
        return _token_matches(token, auth)

    def _is_local_process(self):
        """Loopback on the LAN listener — the hook and the bridge. False on
        the tunnel listener, where loopback is only cloudflared."""
        return (self.required_token is None
                and _is_loopback(self.client_address[0]))

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
            # The prefix IS the credential — record that it matched, so
            # authorization rests on the check itself, not on which
            # listener the request happened to arrive at.
            self.tunnel_authed = True
            return (path[len(prefix):] or "/"), query
        return None, query

    # -- plumbing ----------------------------------------------------------

    def log_message(self, fmt, *args):  # quiet: diagnostics only on stderr
        print("relay: %s" % (fmt % args), file=sys.stderr)

    def _send_json(self, payload, status=200, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
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
        client = self.client_address[0]
        allowed, retry = LIMITS.allow("pair", client, 5, 600)
        if not allowed:
            # A burst is an attack, not a retry: shut the door rather than
            # let it be ground down for the rest of the window.
            auth.close_window()
            self._send_json({"error": "too many attempts"}, 429,
                            headers={"Retry-After": str(int(retry))})
            return
        token = auth.claim_window(client)
        if token:
            self._send_json({"token": token})
            return
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
        allowed, retry = LIMITS.allow("pair", client, 5, 600)
        if not allowed:
            self._send_json({"error": "too many attempts"}, 429,
                            headers={"Retry-After": str(int(retry))})
            return
        presented = self.headers.get("X-Tapproval-Token", "")
        if not (auth.is_bootstrap(presented) or auth.matches(presented)):
            self._send_json({"error": "not paired"}, 403)
            return
        token = auth.issue_device(body.get("device_id"),
                                  body.get("label") or "Apple Watch",
                                  source=str(body.get("source") or "icloud"))
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
    #              cards or presence may change hands.
    #   local      only a process on this machine: the hook, the bridge,
    #              the --pair / --rotate-token commands. Never the network,
    #              because a forged card harvests a real tap.

    ROUTES = {
        "GET": {
            "/pair": ("_get_pair", dict(auth=False)),
            "/pending": ("_get_pending", {}),
            "/health": ("_get_health", {}),
            "/projects": ("_get_projects", {}),
            "/sessions": ("_get_sessions", {}),
            "/activity": ("_get_activity", {}),
            "/usage": ("_get_usage", {}),
            "/thread": ("_get_thread", {}),
            "/tunnel": ("_get_tunnel", dict(lan_only=True)),
        },
        "POST": {
            "/enroll": ("_post_enroll", dict(auth=False)),
            "/card": ("_post_card", dict(local=True, lan_only=True)),
            "/heartbeat": ("_post_heartbeat", dict(local=True, lan_only=True)),
            "/new": ("_post_new", {}),
            "/say": ("_post_say", {}),
            "/decision": ("_post_decision", {}),
            "/admin/pair-open": ("_post_admin", dict(local=True, admin=True)),
            "/admin/pair-reset": ("_post_admin", dict(local=True, admin=True)),
            "/admin/rotate": ("_post_admin", dict(local=True, admin=True)),
        },
    }

    def _dispatch(self, method):
        if not self._host_ok():
            self._send_json({"error": "bad host"}, 403)
            return
        path, query = self._route()
        on_tunnel = self.required_token is not None
        if path is not None and on_tunnel and (
                path in TUNNEL_HIDDEN or path.startswith("/admin/")):
            # Wrong (or absent) secret prefix on the tunnel listener, or a
            # route that does not exist there: say nothing about what
            # lives here.
            path = None
        route = self.ROUTES[method].get(path) if path else None
        if route is None:
            self._send_json({"error": "not found"}, 404)
            return
        handler, rules = route
        if rules.get("auth", True) and not self._authorized(path):
            self._send_json({"error": "not paired"}, 403)
            return
        if rules.get("local") and (
                not self._is_local_process()
                or (rules.get("admin") and not hasattr(self.auth, "rotate"))):
            self._send_json({"error": "local processes only"}, 403)
            return
        if rules.get("lan_only") and on_tunnel:
            self._send_json({"error": "not found"}, 404)
            return
        getattr(self, handler)(path, query)

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
        from_watch = query.get("source", [""])[0] != "bridge"
        self._send_json({"cards": self.queue.pending(from_watch=from_watch)})

    def _get_health(self, path, query):
        # Liveness is public; the details are not. A pending count plus
        # "is a watch on the wrist right now" tells a stranger when
        # nobody is looking.
        if self._credentialed():
            self._send_json({"ok": True,
                             "pending": len(self.queue.pending()),
                             "watch_seen_seconds_ago":
                                 self.queue.watch_seen_seconds_ago(),
                             "version": RELAY_VERSION,
                             "helper": HELPER_VERSION})
        else:
            self._send_json({"ok": True})

    def _get_projects(self, path, query):
        self._send_json({"projects": known_projects()})

    def _get_sessions(self, path, query):
        rows = recent_sessions()
        prewarm_threads([row["session_id"] for row in rows])
        self._send_json({"sessions": rows})

    def _get_activity(self, path, query):
        self._send_json(activity_summary())

    def _get_usage(self, path, query):
        self._send_json(usage_summary())

    def _get_thread(self, path, query):
        session_id = (query.get("id", [""])[0] or "")[:64]
        turns, active, running, tool_now = [], None, 0, None
        path_on_disk = _find_transcript(session_id) if session_id else None
        if path_on_disk:
            try:
                # Freshness first — the watch shows a "working" pulse
                # while Claude is actually writing.
                active = max(0, int(time.time()
                                    - os.path.getmtime(path_on_disk)))
            except OSError:
                pass
            turns, running, tool_now = _parse_thread(
                path_on_disk, THREAD_TURN_LIMIT)
        self._send_json({"turns": turns,
                         "running_tasks": running,
                         "running_tool": tool_now,
                         "modified_seconds_ago": active})

    def _get_tunnel(self, path, query):
        # LAN only: hand the watch its away-addresses while it's home.
        # Deliberately NOT in the Bonjour TXT record — this fetch is the
        # one place the travel secret changes hands.
        self._send_json({"url": TUNNEL_URL,
                         "tailscale": tailscale_url(
                             self.server.server_address[1])})

    # ---- POST --------------------------------------------------------------

    def _post_enroll(self, path, query):
        self._handle_enroll(self._read_json() or {})

    def _post_card(self, path, query):
        body = self._read_json()
        if body is None or not isinstance(body.get("card"), dict):
            self._send_json({"error": "expected {\"card\": {...}}"}, 400)
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
                body["card"], wait,
                caller_alive=functools.partial(_socket_alive, self.connection),
                resolved_elsewhere=_prompt_resolver(body["card"]))
        finally:
            gate.release()
        payload = {"id": card_id, "decision": decision}
        if answer:
            payload["answer"] = answer
        self._send_json(payload)

    def _serialised_send(self, act):
        """/new and /say both spawn a `claude` process on this Mac: the
        same per-caller budget and the same one-at-a-time gate, for the
        same reasons — serialising them is correctness, not politeness.
        `act(body)` returns the status word; the reply says whether it
        was the good one."""
        who = self.headers.get("X-Tapproval-Token", "") or self.client_address[0]
        allowed, retry = LIMITS.allow("say", who, 6, 60)
        if not allowed:
            self._send_json({"error": "too many messages"}, 429,
                            headers={"Retry-After": str(int(retry))})
            return
        gate = LIMITS.gate("say", 1)
        if not gate.acquire(blocking=False):
            self._send_json({"error": "a message is already being sent"}, 429)
            return
        try:
            status, good = act(self._read_json() or {})
        finally:
            gate.release()
        self._send_json({"ok": status == good, "status": status})

    def _post_new(self, path, query):
        # Opens a Terminal on this Mac.
        self._serialised_send(lambda body: (
            start_session(str(body.get("path", ""))[:512], body.get("text", "")),
            "started"))

    def _post_say(self, path, query):
        # Only an explicit false turns brevity off: a watch that predates
        # the switch, or a missing key, still gets the short reply the
        # screen was built for.
        self._serialised_send(lambda body: (
            say_to_session(str(body.get("session_id", ""))[:64],
                           body.get("text", ""),
                           brief=body.get("brief") is not False),
            "sent"))

    def _post_decision(self, path, query):
        body = self._read_json()
        card_id = (body or {}).get("id")
        decision = (body or {}).get("decision")
        if not isinstance(card_id, str) or decision not in VALID_DECISIONS:
            self._send_json({"error": "expected {\"id\", \"decision\"}"}, 400)
            return
        accepted = self.queue.decide(card_id, decision,
                                     answer=(body or {}).get("answer"))
        self._send_json({"ok": accepted})

    def _post_admin(self, path, query):
        # Administration is for a process on this machine only — the
        # `--pair` / `--rotate-token` commands, never the network.
        if path == "/admin/pair-open":
            until = self.auth.open_window()
            self._send_json({"ok": True, "seconds": PAIR_WINDOW_SECONDS,
                             "until": int(until)})
        elif path == "/admin/pair-reset":
            self.auth.revoke_all()
            self.auth.open_window()
            self._send_json({"ok": True, "devices": 0,
                             "seconds": PAIR_WINDOW_SECONDS})
        else:
            secret = self.auth.rotate()
            type(self).required_token = None   # main listener unchanged
            _rotate_tunnel_prefix(secret)
            self.auth.open_window()
            self._send_json({"ok": True, "rotated": True})

    def _post_heartbeat(self, path, query):
        # The bridge relays the watch's CloudKit heartbeat: how many
        # seconds ago the watch last checked iCloud. Main server only —
        # never through the public tunnel.
        body = self._read_json() or {}
        self.queue.note_watch_indirect(body.get("watch_seen_seconds_ago"))
        self._send_json({"ok": True})


# The tunnel listener's handler class, so a rotation can change the secret
# path in place instead of restarting cloudflared (whose hostname is stable).
_TUNNEL_HANDLER = None


def _rotate_tunnel_prefix(secret):
    """Point the live tunnel listener at the new secret path."""
    global TUNNEL_URL
    if _TUNNEL_HANDLER is not None:
        _TUNNEL_HANDLER.required_token = secret
    if TUNNEL_URL:
        base = TUNNEL_URL.split("/t/")[0]
        TUNNEL_URL = "%s/t/%s" % (base, secret)


def serve(host=DEFAULT_HOST, port=DEFAULT_PORT, queue=None, token=None,
          auth=None, auth_token=None):
    """Build a server (does not block). Caller runs serve_forever().

    With ``token`` set, the server answers only under ``/t/<token>/…`` — the
    shape exposed through a public tunnel, where that path is a rendezvous
    address rather than a credential. ``auth`` carries the device tokens
    every non-local caller must present. (``auth_token`` accepts a bare
    string for callers that predate per-device tokens.)
    """
    queue = queue if queue is not None else CardQueue()
    if auth is None:
        auth = auth_token
    handler = type("BoundRelayHandler", (RelayHandler,),
                   {"queue": queue, "required_token": token,
                    "auth": auth})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server, queue


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
        self._slammed = False
        self._load()

    # ---- persistence -------------------------------------------------

    def _load(self):
        data = None
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict) and data.get("version") == 1:
            self.tunnel_secret = str(data.get("tunnel_secret") or "")
            self.bootstrap = str(data.get("bootstrap") or "")
            self.paired_ever = bool(data.get("paired_ever"))
            devices = data.get("devices")
            if isinstance(devices, list):
                self.devices = [d for d in devices
                                if isinstance(d, dict) and d.get("token")]
        if not self.tunnel_secret or not self.bootstrap:
            self._seed()
        self._ensure_icloud_device()

    def _seed(self):
        """First run — or a file we cannot read, which fails closed to a
        fresh identity rather than to an open door."""
        self.tunnel_secret = self.tunnel_secret or uuid.uuid4().hex
        self.bootstrap = self.bootstrap or uuid.uuid4().hex
        # An install from before per-device tokens keeps working: its one
        # token becomes a device entry, so the watch on the owner's wrist
        # never notices the upgrade.
        legacy = ""
        try:
            with open(TOKEN_FILE, encoding="utf-8") as handle:
                legacy = handle.read().strip()
        except OSError:
            legacy = ""
        if legacy and not self.devices:
            self.devices = [{"id": "legacy", "token": legacy,
                             "label": "Existing watch", "issued": int(time.time()),
                             "last_seen": 0, "source": "migrated"}]
            self.paired_ever = True
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
        # 0600 from the moment it exists: writing first and chmod-ing after
        # leaves a readable window, however brief.
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        except OSError:
            return
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(body + "\n")
        except OSError:
            pass

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

    def is_bootstrap(self, token):
        return bool(self.bootstrap) and _token_matches(token, self.bootstrap)

    def issue_device(self, device_id=None, label="Apple Watch", source="icloud"):
        """Mint a token for one device. Re-enrolling the same device id
        replaces its token rather than growing the list forever."""
        token = uuid.uuid4().hex
        device_id = str(device_id or uuid.uuid4().hex)[:64]
        with self._lock:
            self.devices = [d for d in self.devices
                            if d.get("id") != device_id]
            self.devices.append({"id": device_id, "token": token,
                                 "label": str(label or "Apple Watch")[:40],
                                 "issued": int(time.time()), "last_seen": 0,
                                 "source": source})
            self.paired_ever = True
            self.save()
        return token

    def revoke_all(self):
        with self._lock:
            self.devices = []
            self.save()

    def rotate(self):
        """New tunnel path, new bootstrap, every device token revoked."""
        with self._lock:
            self.tunnel_secret = uuid.uuid4().hex
            self.bootstrap = uuid.uuid4().hex
            # The iCloud-mirrored key rotates with everything else, and stays
            # a usable key: the bridge re-mirrors it within the minute and a
            # watch picks it up without anyone touching anything.
            self.devices = [{
                "id": "icloud", "token": self.bootstrap,
                "label": "Watch via iCloud", "issued": int(time.time()),
                "last_seen": 0, "source": "icloud-mirror"}]
            self.save()
            return self.tunnel_secret

    # ---- the pairing window -----------------------------------------

    def open_window(self, seconds=PAIR_WINDOW_SECONDS):
        with self._lock:
            self._window_until = time.time() + float(seconds)
            self._window_claims = 0
            self._window_ips = set()
            self._slammed = False
            return self._window_until

    def close_window(self):
        with self._lock:
            self._window_until = 0.0
            # A never-paired door has no timer to expire, so a burst needs
            # something explicit to shut. Cleared by open_window().
            self._slammed = True

    def window_open(self):
        """Is /pair handing out the bootstrap right now?

        Two doors, one question. A machine that has NEVER paired keeps the
        door open until its first device enrols: there is nothing behind
        it to protect yet, and a 10-minute fuse lit at install time was
        burning out while the user was still installing the watch app —
        they arrived to "Not paired yet" and a phrase no README explains.
        Once anything has paired, the door is the deliberate, short window
        that --pair opens, exactly as before. A burst still shuts either
        one (close_window); the next --ensure reopens the first kind.
        """
        with self._lock:
            if not self.paired_ever and not self._slammed:
                return True
            return time.time() < self._window_until

    def claim_window(self, client_ip):
        """Hand out the bootstrap, once per address and twice at most.

        Returns the token, or None with the window left shut. A burst is an
        attack, not a retry, so the caller closes the window on a rate-limit
        rejection rather than letting it be ground down.
        """
        with self._lock:
            never_paired = not self.paired_ever and not self._slammed
            if not never_paired and time.time() >= self._window_until:
                return None
            if self._window_claims >= PAIR_WINDOW_CLAIMS:
                return None
            if client_ip in self._window_ips:
                return None
            self._window_ips.add(client_ip)
            self._window_claims += 1
            return self.bootstrap


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


def _reap_stale_tunnels(port):
    """Kill cloudflared processes left over from earlier relay runs.

    cloudflared is spawned as our child but survives a killed relay; each
    orphan holds a public URL forwarding to whoever owns the port now.
    Anything targeting our tunnel port is ours by definition. Never raises.
    """
    try:
        subprocess.run(["pkill", "-f",
                        "cloudflared tunnel.*127.0.0.1:%d" % port],
                       capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


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
        print("relay: cloudflared not installed — off-Wi-Fi tunnel disabled.\n"
              "       install it with:  brew install cloudflared",
              file=sys.stderr)
        return None
    _reap_stale_tunnels(port)
    proc = subprocess.Popen(
        [binary, "tunnel", "--no-autoupdate",
         "--url", "http://127.0.0.1:%d" % port],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    def announce():
        global TUNNEL_URL
        for line in proc.stderr:
            match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if match:
                TUNNEL_URL = "%s/t/%s" % (match.group(0), token)
                print("relay: off-Wi-Fi tunnel up — the watch learns this "
                      "address automatically while on the same Wi-Fi.\n"
                      "       (manual fallback: %s)" % TUNNEL_URL,
                      file=sys.stderr)
                break
        for _ in proc.stderr:   # drain quietly
            pass

    threading.Thread(target=announce, daemon=True).start()
    return proc


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
    parser.add_argument("--tunnel", action="store_true",
                        help="also expose the relay through a Cloudflare "
                             "tunnel so the watch works off Wi-Fi")
    parser.add_argument("--ensure", action="store_true",
                        help="start the relay in the background if it is "
                             "not already running, then exit")
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


def _start_tunnel(queue, auth):
    """The second listener and the cloudflared process behind it. Two
    independent secrets on the public path: the unguessable rendezvous
    prefix says where, the device token says who."""
    global _TUNNEL_HANDLER
    tunnel_server, _ = serve("127.0.0.1", TUNNEL_PORT,
                             queue=queue, token=auth.tunnel_secret, auth=auth)
    _TUNNEL_HANDLER = tunnel_server.RequestHandlerClass
    threading.Thread(target=tunnel_server.serve_forever, daemon=True).start()
    return start_tunnel(TUNNEL_PORT, auth.tunnel_secret)


class _Advertiser:
    """The Bonjour advertisement, re-published once the tunnel URL exists
    so the TXT record carries every address the watch might need."""

    def __init__(self, port):
        self.port = port
        self.process = advertise(port)
        if self.process is not None:
            print("relay: advertising as \"Tapproval\" (%s) with %s"
                  % (BONJOUR_TYPE, advertise_txt(port)), file=sys.stderr)

    def republish_when_tunnel_is_up(self):
        threading.Thread(target=self._republish, daemon=True).start()

    def _republish(self):
        for _ in range(60):
            time.sleep(1)
            if TUNNEL_URL:
                break
        if not TUNNEL_URL or self.process is None:
            return
        self.process.terminate()
        self.process = advertise(self.port)
        print("relay: re-advertised with the away address included",
              file=sys.stderr)

    def terminate(self):
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


def main(argv=None):
    args = _build_parser().parse_args(argv)
    if args.ensure:
        return ensure_running()
    if args.pair or args.pair_reset or args.rotate_token:
        return run_admin(args)

    # One machine-wide key gates every non-local caller, whichever
    # listener they arrive on. First contact from the user's own network
    # fetches it via /pair — pairing is automatic and never broadcast.
    auth = Auth()
    if not auth.paired_ever:
        # Nothing has ever paired: the door stays open until the first
        # watch enrols (see Auth.window_open). open_window() here only
        # resets the claim budget and clears a slam from an earlier run.
        auth.open_window()
        print("relay: pairing open until the first watch connects",
              file=sys.stderr)

    server, queue = serve(args.host, args.port, auth=auth)
    print("relay: listening on http://%s:%d" % (args.host, args.port),
          file=sys.stderr)
    tunnel_proc = _start_tunnel(queue, auth) if args.tunnel else None
    advertiser = None
    if not args.no_bonjour:
        advertiser = _Advertiser(args.port)
        if args.tunnel:
            advertiser.republish_when_tunnel_is_up()
    _inject_startup_cards(args, queue)

    # SIGTERM (pkill, launchd, a relay restart from --ensure) must run the
    # same cleanup as Ctrl-C — otherwise the Bonjour advertiser and the
    # tunnel outlive the relay and keep announcing a stale address.
    import signal

    def _stop(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _stop)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("relay: stopped", file=sys.stderr)
    finally:
        if advertiser is not None:
            advertiser.terminate()
        if tunnel_proc is not None:
            tunnel_proc.terminate()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
