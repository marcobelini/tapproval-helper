"""Reading what Claude Code is doing: sessions, threads, usage, activity.

This is the half of the bridge that answers "what is happening on my
computer" — the session list, one session's live conversation, the day's
totals, and the Markdown flattener that makes a terminal's output legible
on a wrist. It is separate from the relay because the relay's job is small
and dangerous (carry a permission question, carry an answer back) while
this one is large and harmless (read files the user already owns).
Nothing here writes or spawns anything — say_to_session lives in the relay
precisely because it acts.

`watch_relay` imports these names and re-exports them, so it remains the
one module anything else needs to know about.

Standard library only, like everything else here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict

import tapproval_wire as wire

def _read_appended(path, offset, limit=None):
    """Lines appended since ``offset`` -> (lines, new_offset, shrunk).
    At most ``limit`` lines when given; the offset stops after the last.

    The one owner of the append-follow rules every transcript follower
    needs: only whole lines are consumed (a mid-append partial tail waits
    for the next call), and a shrunken file — rewrite, rotation — resets
    to byte zero and says so. ``shrunk`` is the caller's cue to reset its
    own accumulated state before folding in the returned lines: acting on
    a rewritten file's content while keeping state from the old one is
    how turns duplicate and counts double. Never raises; on error the
    offset stands still.
    """
    shrunk = False
    try:
        size = os.path.getsize(path)
        if size < offset:
            offset, shrunk = 0, True
        if size == offset:
            return [], offset, shrunk
        lines, read = [], 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            # Line by line: the first read after a start is the whole log,
            # and one read() of it sat in memory twice over (2026-10-05).
            for raw in handle:
                if not raw.endswith(b"\n"):
                    break                      # a line still being written
                read += len(raw)
                lines.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
                if limit is not None and len(lines) >= limit:
                    break
    except OSError:
        return [], offset, shrunk
    return lines, offset + read, shrunk



CLAUDE_PROJECTS = os.path.expanduser("~/.claude/projects")


CLAUDE_SESSIONS = os.path.expanduser("~/.claude/sessions")

# Claude Code's usage limits run on a rolling five-hour window, so that is
# the number worth putting on a wrist.
USAGE_WINDOW_HOURS = 5

# One lock for the small caches below. The relay serves each request on
# its own thread, and an OrderedDict moved and trimmed from two at once
# raises (2026-10-05 review). Held only around the dict, never around the
# work that fills it.
_CACHE_LOCK = threading.RLock()


def _bounded_put(cache, key, value, limit):
    """Store under the cache lock, then drop the oldest entries past
    ``limit``: the relay runs for weeks and must not grow with every
    transcript it ever saw."""
    with _CACHE_LOCK:
        cache[key] = value
        while len(cache) > limit:
            cache.pop(next(iter(cache)), None)


def _stat_cached(cache, path, compute, extra=None, limit=64):
    """Memoize ``compute()`` per path until the file's (mtime, size) changes.

    One helper serves every transcript cache in the relay, so the key rule
    and the eviction cannot drift apart between copies. ``extra`` joins the
    key for callers whose answer depends on more than the file (a parse
    limit). At most ``limit`` paths are kept, oldest first out — the relay
    runs for weeks and must not grow with every transcript it ever saw.
    """
    try:
        st = os.stat(path)
        key = (st.st_mtime, st.st_size, extra)
    except OSError:
        return compute()
    with _CACHE_LOCK:
        cached = cache.get(path)
    if cached and cached[0] == key:
        return cached[1]
    result = compute()
    _bounded_put(cache, path, (key, result), limit)
    return result


# Parsed usage entries per transcript — a transcript that has not changed
# is never read twice.
_USAGE_FILES = {}   # path -> {"offset": bytes read, "entries": [(stamp, inp, out, cache_read, model)]}


def _parse_stamp(text):
    """ISO-8601 from a transcript to epoch seconds. None when unparseable."""
    if not text:
        return None
    try:
        from datetime import datetime
        cleaned = str(text).replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).timestamp()
    except (ValueError, TypeError):
        return None


_USAGE_LOCK = threading.Lock()


def _usage_entries(path, horizon=None):
    """All usage records in one transcript, read once and then followed.

    An active transcript changes every few seconds, and a cache keyed on
    (mtime, size) re-read it from the first byte each time: 2.2 s per
    /usage over ten minutes' worth of files (2026-09-25 review). Only what
    was appended is read now, line by line so a big file never sits in
    memory whole; a file that shrank is read again from the start."""
    with _USAGE_LOCK:
        state = _USAGE_FILES.get(path) or {"offset": 0, "entries": []}
        try:
            size = os.path.getsize(path)
        except OSError:
            return state["entries"]
        if size < state["offset"]:
            state = {"offset": 0, "entries": []}
        if size > state["offset"]:
            try:
                with open(path, "rb") as handle:
                    handle.seek(state["offset"])
                    for raw in handle:
                        if not raw.endswith(b"\n"):
                            break              # a line still being written
                        state["offset"] += len(raw)
                        if b'"usage"' in raw:
                            entry = _usage_entry(raw.decode("utf-8", "replace"))
                            if entry is not None:
                                state["entries"].append(entry)
            except OSError:
                pass
        if horizon is not None:
            # Nothing reads past a day, and a transcript that stays active
            # for weeks kept every entry it ever had (2026-10-05 review).
            state["entries"] = [e for e in state["entries"] if e[0] >= horizon]
        _USAGE_FILES[path] = state
        return state["entries"]


def _json_object(line):
    """One transcript or audit line as a dict, or None.

    Every reader here parsed a line and then called .get on it; a line that
    is JSON but not an object ([], a string, a number) raised
    AttributeError inside functions documented never to raise (2026-09-25
    review). One parse, one rule, for all of them."""
    try:
        entry = json.loads(line)
    except (ValueError, TypeError):
        return None
    return entry if isinstance(entry, dict) else None


def _message_of(entry):
    """An entry's message, as a dict whatever the line held — and none at
    all for a copy of a request, whose `message` repeats a turn the
    transcript already holds (record.request_copy)."""
    if entry.get("type") == shape("record.request_copy"):
        return {}
    message = entry.get("message")
    return message if isinstance(message, dict) else {}


def _usage_entry(line):
    """One usage record, or None — for a line of any shape at all. A usage
    block that was not numbers raised here and broke /usage until the file
    aged out of the window (2026-09-30 review)."""
    try:
        return _usage_entry_of(line)
    except (AttributeError, TypeError, ValueError):
        return None


def _usage_entry_of(line):
    entry = _json_object(line)
    if entry is None:
        return None
    message = _message_of(entry)
    usage = message.get("usage") or {}
    if not usage:
        return None
    stamp = _parse_stamp(entry.get("timestamp"))
    if stamp is None:
        return None
    return (stamp,
            int(usage.get("input_tokens") or 0),
            int(usage.get("output_tokens") or 0),
            int(usage.get("cache_read_input_tokens") or 0),
            message.get("model") or "unknown")


def usage_summary(projects_dir=None, now=None):
    """Token consumption measured from the transcripts themselves.

    Every assistant message records its own ``usage`` block, so this is a
    true count of what this machine spent — not an estimate. It is NOT the
    subscription quota: Anthropic keeps that server-side, and Claude Code
    shows it with /usage. Never raises.
    """
    now = now or time.time()
    root = projects_dir or CLAUDE_PROJECTS
    window_start = now - USAGE_WINDOW_HOURS * 3600
    day_start = now - 24 * 3600
    totals = {
        "window_hours": USAGE_WINDOW_HOURS,
        "window_input": 0, "window_output": 0, "window_cache_read": 0,
        "day_input": 0, "day_output": 0,
        "window_messages": 0, "day_messages": 0,
        "models": {},
        "measured": True,
    }
    paths = [path for mtime, path, _, _ in transcripts_newest_first(root)
             if mtime >= day_start]

    with _USAGE_LOCK:
        for stale in set(_USAGE_FILES) - set(paths):
            _USAGE_FILES.pop(stale, None)   # fell out of the 24h window

    for path in paths:
        for stamp, inp, out, cached_read, model in _usage_entries(path, day_start):
            if stamp < day_start:
                continue
            totals["day_input"] += inp
            totals["day_output"] += out
            totals["day_messages"] += 1
            if stamp >= window_start:
                totals["window_input"] += inp
                totals["window_output"] += out
                totals["window_cache_read"] += cached_read
                totals["window_messages"] += 1
                totals["models"][model] = totals["models"].get(model, 0) + out

    totals["models"] = dict(sorted(totals["models"].items(),
                                   key=lambda kv: kv[1], reverse=True)[:4])
    return totals

# Where a session is being driven from, in the words the app uses.
ENTRYPOINTS = {
    "claude-vscode": "VS Code",
    "claude-desktop": "Desktop",
    "claude-code": "Terminal",
    "cli": "Terminal",
}


def session_registry(sessions_dir=None):
    """What Claude Code records about each live session, by id: where it
    runs, whether the phone can see it (Remote Control gave it a bridge
    id), and the name a person gave it with /rename, if any. Dead pids and
    unattended SDK runs are left out. Never raises."""
    registry = {}
    root = sessions_dir or CLAUDE_SESSIONS
    try:
        names = os.listdir(root)
    except OSError:
        return registry
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(root, name), encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        session_id, pid = data.get("sessionId"), data.get("pid")
        if not session_id or not pid:
            continue
        # Unattended SDK runs (claude agents, headless drivers) never
        # appear in the phone app's session list — and the wrist mirrors
        # the phone, so they don't belong on the watch either.
        if data.get("entrypoint") == shape("entrypoint.sdk_cli"):
            continue
        try:
            os.kill(int(pid), 0)          # signal 0: "are you there?"
        except (OSError, ValueError, TypeError):
            continue
        registry[session_id] = {
            "status": ENTRYPOINTS.get(data.get("entrypoint", ""), "Connected"),
            "bridged": bool(data.get(shape("registry.bridged"))),
            # The title the phone and the desktop app show. A name the CLI
            # derived from the folder ("acme-3f") is not a title, so that
            # one is left out; a /rename and the desktop app's own title
            # (which carries no nameSource at all) are what a person reads
            # everywhere else, and the wrist showed neither for desktop
            # sessions until 2026-09-23 — it showed "Base directory for this
            # skill…", the first line a skill injected.
            "name": (str(data.get("name") or "").strip()
                     if data.get(shape("registry.name_source"))
                     != shape("registry.name_derived") else ""),
            "cwd": str(data.get("cwd") or ""),
            "pid": int(pid),
            "started_at": _started_seconds(data.get(shape("registry.started_at"))),
            "socket": str(data.get(shape("registry.messaging_socket")) or ""),
        }
    return registry


def _started_seconds(value):
    """The registry's startedAt (ms) as seconds, or None when absent."""
    try:
        return float(value) / 1000.0 if value else None
    except (TypeError, ValueError):
        return None


def live_sessions(sessions_dir=None):
    """Sessions running right now: id -> where it is being driven from.
    The status-only view of :func:`session_registry`. Never raises.
    """
    return {sid: entry["status"]
            for sid, entry in session_registry(sessions_dir).items()}


_MODE_TAIL_BYTES = 262144


def permission_mode(path, tail=_MODE_TAIL_BYTES):
    """The permission mode of a session's latest turn, from the end of its
    transcript; "" when it cannot be told. Never raises."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - tail))
            text = handle.read().decode("utf-8", "replace")
    except (OSError, TypeError):
        return ""
    found = re.findall(r'"%s"\s*:\s*"([A-Za-z]+)"' % shape("key.permission_mode"), text)
    return found[-1] if found else ""


def inbox_ready(entry, transcript):
    """Whether a wrist message can go into this live session's own inbox:
    it has one, and its mode is not one in which Claude Code would hold a
    message from outside for a click (#246, 2026-10-22)."""
    if not (entry or {}).get("socket"):
        return False
    return permission_mode(transcript) not in (shape("mode.bypass"), shape("mode.plan"))


_REPO_SLUG_CACHE = OrderedDict()
_REPO_SLUG_MAX = 128


def _remember_repo_slug(cwd, slug):
    """Bounded cache: a project's remote rarely changes, but the map must
    not grow for the life of a process that runs for weeks."""
    with _CACHE_LOCK:
        _REPO_SLUG_CACHE[cwd] = slug
        _REPO_SLUG_CACHE.move_to_end(cwd)
        while len(_REPO_SLUG_CACHE) > _REPO_SLUG_MAX:
            _REPO_SLUG_CACHE.popitem(last=False)


def repo_slug(cwd):
    """``Owner/repo`` from the git remote — what the Claude app shows.

    Cached per directory: this shells out to git, and a project's remote
    does not change while the relay runs. Never raises.
    """
    if not cwd:
        return ""
    with _CACHE_LOCK:
        if cwd in _REPO_SLUG_CACHE:
            _REPO_SLUG_CACHE.move_to_end(cwd)
            return _REPO_SLUG_CACHE[cwd]
    slug = ""
    try:
        out = subprocess.run(["git", "-C", cwd, "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=3)
        url = (out.stdout or "").strip()
        match = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?/?$", url)
        if match:
            slug = match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    _remember_repo_slug(cwd, slug)
    return slug


def card_session_title(session_id, projects_dir=None, registry=None):
    """The title a wrist card shows after its repository: the name the app
    gave the session, else a title from its opening ask, at most 60
    characters; "" when neither is known. Never raises."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return ""
    try:
        registry = session_registry() if registry is None else registry
        name = str((registry.get(session_id) or {}).get("name") or "").strip()
        if not name:
            path = _find_transcript(session_id[:12], projects_dir)
            if path:
                _, opening, _ = session_meta(path, scan_lines=40)
                name = derive_title(opening)
        name = " ".join(name.split())
        return name if len(name) <= 60 else name[:59].rstrip() + "…"
    except Exception:
        return ""


def derive_title(text):
    """A short title from the opening ask, the way the app titles sessions."""
    if not text:
        return ""
    title = re.sub(r"^/\S+\s*", "", str(text).strip())   # drop /slash-commands
    title = re.split(r"[.!?\n]", title)[0].strip(" ,;:-")
    if len(title) > 44:
        title = title[:43].rstrip() + "…"
    return title[:1].upper() + title[1:] if title else ""


_META_CACHE = OrderedDict()   # (path, scan_lines) -> what session_meta has read so far
_ORIGIN_CACHE = {}  # path -> ((mtime, size), (cwd, entrypoint))


def project_root(cwd):
    """The repository a directory belongs to, when it is a session's own
    worktree; otherwise the directory itself. The desktop app and the phone
    name the repository ("ClaudeWatch"), never the worktree it made for one
    session ("app-store-version-update-b03a35")."""
    cwd = str(cwd or "")
    marker = shape("path.worktree")
    if marker in cwd:
        return cwd.split(marker, 1)[0]
    # Any other worktree or subfolder ("wt-push", "ios") belongs to the
    # repository git says it does — found, not rebuilt. "Parent of the
    # folder plus the repository's name" made /x/proj/ios into /x/proj/proj,
    # and a project New Session could not open dropped out of its list
    # without a word (2026-10-05 review).
    try:
        from ClaudeRiskClassifier import repository_root
        root = repository_root(cwd)
    except Exception:
        root = None
    return root or cwd


def transcript_origin(path, scan_lines=60):
    """Where a transcript was written and what started it: (cwd, entrypoint).
    Both sit on its first lines, so this reads a handful, and it is cached
    for many more paths than the list screen's parse — the projects picker
    walks every transcript on the machine. Never raises."""
    def read():
        cwd = entry_point = ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index >= scan_lines or (cwd and entry_point):
                        break
                    entry = _json_object(line)
                    if entry is None:
                        continue
                    cwd = cwd or str(entry.get("cwd") or "")
                    entry_point = entry_point or str(entry.get("entrypoint") or "")
        except OSError:
            pass
        return cwd, entry_point
    return _stat_cached(_ORIGIN_CACHE, path, read, extra=scan_lines, limit=4096)


def transcripts_newest_first(projects_dir=None, only=None):
    """Every transcript on the machine as (mtime, path, folder, session_id),
    newest first. Never raises.

    ``only``, a set of session ids, leaves the rest out before they are
    stat-ed: the session list polls every few seconds and shows a handful
    of live sessions out of some 900 transcripts on this Mac."""
    root = projects_dir or CLAUDE_PROJECTS
    found = []
    try:
        for project in os.listdir(root):
            pdir = os.path.join(root, project)
            if not os.path.isdir(pdir):
                continue
            for entry in os.listdir(pdir):
                if not entry.endswith(".jsonl"):
                    continue
                if only is not None and entry[:-6] not in only:
                    continue
                path = os.path.join(pdir, entry)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                found.append((mtime, path, project, entry[:-6]))
    except OSError:
        return []
    found.sort(reverse=True)
    return found



# --------------------------------------------------------------------------
# What we know about Claude Code's transcript
#
# Every line below is a shape this file reads out of a file another product
# writes, in a format with no version number and no promise. When one of
# them changes upstream, the thread on the wrist quietly loses something —
# that is how "No response requested." became a reply bubble and how a
# /recap once showed nothing at all. So each shape is named here with the
# date it was last seen with our own eyes, and the code below refers to
# this table rather than repeating the string. A test fails if any of them
# is spelled out a second time somewhere else in this file.
#
# Seen means seen: each date is a transcript on this machine that contained
# it, not a date from documentation.
UPSTREAM_SHAPES = {
    "record.request_copy":
        ("api-request-blob", "A copy of what was sent to the model, from "
         "Claude Code 2.1.301: its message repeats a turn already in the "
         "transcript, and read as one it doubled every thread.", "2026-10-16"),
    "review.summary":
        ("summary", "Each finding /code-review prints, from Claude Code "
         "2.1.301, as a JSON list in its output: summary, with file and "
         "line beside it.", "2026-10-16"),
    "tag.local_command_stderr":
        ("<local-command-stderr>", "A slash command that failed inside the "
         "CLI, written as a user line, not a system one: /security-review "
         "without an origin to compare against.", "2026-10-16"),
    "key.is_meta":
        ("isMeta", "Marks a user line the CLI wrote, not the person: a "
         "skill's whole SKILL.md after its slash command.", "2026-10-16"),
    "system.subtype.local_command":
        ("local_command", "A slash command the CLI answered itself; its "
         "output is a system line, not an assistant turn.", "2026-10-11"),
    "system.level.error":
        ("error", "A system line the CLI marks as a failure. The phone "
         "paints both of these red; the watch is told which is which, by "
         "a notice's tone.", "2026-09-08"),
    "tag.command_name":
        ("<command-name>", "The echo of a slash command a person sent, "
         "carried as a user turn.", "2026-09-08"),
    "tag.command_args":
        ("<command-args>", "Its arguments, in a second tag.", "2026-09-08"),
    "tag.local_command_out":
        ("<local-command-", "What the command printed: stdout and stderr are "
         "the same tag with a different word, which is why the reader below "
         "matches the stem.", "2026-10-11"),
    "text.auth_failed":
        ("Failed to authenticate", "What Claude Code writes when its own "
         "sign-in has expired. It is the CLI's fault line, not Claude "
         "speaking — the wrist showed it as a reply, in a thread, under a "
         "working pulse. It also opens a slash command's local_command "
         "output when the CLI is signed out (a wrist /recap, "
         "2026-10-11).", "2026-10-11"),
    "text.nothing_to_add":
        ("No response requested.", "What Claude says when the CLI already "
         "answered and its own turn has nothing to add. Not a reply.",
         "2026-09-08"),
    "text.continue_nudge":
        ("Continue from where you left off.", "What Claude Code itself writes "
         "as a user turn when a headless run resumes a session mid-answer. "
         "Nobody said it; the wrist showed it as the owner's own message, "
         "each time answered by the filler above.", "2026-09-24"),
    "registry.bridged":
        ("bridgeSessionId", "The session registry's mark of a session "
         "Remote Control carries to the phone.", "2026-09-03"),
    "registry.started_at":
        ("startedAt", "When the registry says a session's process started, "
         "in milliseconds: a task output file born after it belongs to the "
         "live process, which writes the exit marker itself.", "2026-10-14"),
    "registry.name_source":
        ("nameSource", "How the registry says a session's name came about.",
         "2026-09-03"),
    "registry.name_derived":
        ("derived", "The nameSource of a name the CLI made from the folder "
         "(\"acme-3f\"): not a title anybody chose.", "2026-09-03"),
    "text.caveat_opener":
        ("Caveat:", "How a slash command's local-command note opens, as a "
         "user turn nobody typed.", "2026-08-27"),
    "text.request_opener":
        ("[Request", "How an interruption notice opens (\"[Request "
         "interrupted by user]\"), as a user turn.", "2026-08-27"),
    "tag.system_reminder":
        ("system-reminder", "The tag of the notes Claude Code prepends to "
         "the very text a person typed.", "2026-09-24"),
    "task.exited":
        ("[exited", "The last words of a background task's output file "
         "when it has finished.", "2026-08-27"),
    "task.killed":
        ("[killed]", "…and when it was stopped.", "2026-08-27"),
    "task.launched":
        ("background with ID", "The tool result that says a background "
         "command started.", "2026-08-27"),
    "task.agent_id":
        ("agentId", "The same, for a background agent.", "2026-08-27"),
    "task.monitor_started":
        ("Monitor started (task", "The tool result that says a Monitor "
         "started; it is a background task like a command.", "2026-10-01"),
    "task.workflow_launched":
        ("Workflow launched in background. Task ID:", "The tool result that "
         "says a Workflow started; the phone counts it as a running task, "
         "like an agent.", "2026-10-22"),
    "wakeup.scheduled":
        ("Next wakeup scheduled for", "ScheduleWakeup's result when it took: "
         "\"Next wakeup scheduled for 07:42:00 (in 257s)\". The session "
         "comes back by itself then.", "2026-10-01"),
    "wakeup.stopped":
        ("Loop stopped", "ScheduleWakeup's result for stop: the pending "
         "wake-up is cancelled.", "2026-10-01"),
    "tag.task_id":
        ("<task-id>", "The id inside a task notification. A Monitor sends "
         "one with every event, so on its own it does not mean finished.",
         "2026-10-01"),
    "tag.task_status":
        ("<status>", "What makes a task notification an ending: completed, "
         "failed, killed. A Monitor's events carry none.", "2026-10-01"),
    "part.tool_result":
        ('"tool_result"', "A tool has answered, so nothing is running now.",
         "2026-09-04"),
    # The parsed forms of a content part's type, as the readers compare
    # them: the relay matches a card's call to its answer by these, and a
    # rename upstream would leave every answered-at-the-desk card on the
    # wrist (2026-10-17 tech-debt review, item 6).
    "type.tool_use":
        ("tool_use", "A content part calling a tool; the id it carries "
         "comes back on the answer.", "2026-10-17"),
    "type.tool_result":
        ("tool_result", "A content part answering a tool call, read as the "
         "parsed type rather than the raw text the line check above uses.",
         "2026-10-17"),
    # Read by the hook (ClaudeRiskClassifier.py), which cannot import this
    # module — it runs on every prompt, and this module imports it — so it
    # spells them out, and a test holds its spelling to these entries.
    "key.plan_file_path":
        ("planFilePath", "Where plan mode keeps the plan: attachment."
         "planFilePath on a transcript line, and in ExitPlanMode's input.",
         "2026-10-17"),
    "key.permission_mode":
        ("permissionMode", "The mode a turn ran in, on each transcript "
         "line; the hook watches for \"auto\".", "2026-10-17"),
    "mode.bypass":
        ("bypassPermissions", "The permission mode that skips every prompt. "
         "Claude Code holds a message from outside for a click in such a "
         "session, so a wrist message goes the old way there.", "2026-10-22"),
    "mode.plan":
        ("plan", "Plan mode, which Claude Code counts as bypassing when it "
         "decides whether to hold a message from outside.", "2026-10-17"),
    "registry.messaging_socket":
        ("messagingSocketPath", "The session's inbox socket, in its "
         "registry file: where a wrist message is posted so the open "
         "session itself reads it (Claude Code 2.1.303).", "2026-10-22"),
    "entrypoint.sdk_cli":
        ("sdk-cli", "What a transcript and the session registry call a run "
         "nobody is sitting at: `claude -p`, the Agent SDK, a scheduled "
         "loop. The phone never lists them, and nobody starts a session "
         "in the folder a loop works in.", "2026-09-23"),
    "path.worktree":
        ("/.claude/worktrees/", "Where Claude Code, and the desktop app, "
         "put a session's own worktree inside the repository it belongs "
         "to. The app names the repository, not the worktree.", "2026-09-23"),
}


def shape(name):
    """The upstream string named in UPSTREAM_SHAPES. Reading them through
    one door is what makes the table true rather than decorative."""
    return UPSTREAM_SHAPES[name][0]


# System subtypes we have no reading for. Not an error — Claude Code emits
# plenty this file has no business rendering — but a new one is the first
# sign that a transcript has grown a shape we do not know, so the relay log
# gets one line the first time each is seen rather than nothing at all.
_UNKNOWN_SUBTYPES = set()


def note_unknown_subtype(subtype):
    if not subtype or subtype in _UNKNOWN_SUBTYPES:
        return False
    _UNKNOWN_SUBTYPES.add(subtype)
    print("watch_dashboard: transcript has a system line this helper does "
          "not read: subtype %r" % subtype, file=sys.stderr)
    return True


# Prefixes the harness injects as a "user" turn that no human typed. Both
# the session list (its title) and the thread (its first turn) skip them;
# they used to each carry this tuple, and a prefix Claude Code adds
# tomorrow would have been skipped on one screen and shown on the other.
_SYSTEM_OPENERS = ("<", shape("text.caveat_opener"), shape("text.request_opener"))


# Claude Code rides its own notes INTO the person's message: memory recall,
# pending notifications, CLAUDE.md on a first turn arrive as a
# <system-reminder> block prepended to the very text the person typed.
# Seen 2026-09-24 in front of "proceed", "Merged #580", "Trigger a new
# TestFlight build": one string, reminder first, so the turn opened with
# "<" and both screens skipped it as harness noise — the person's own
# words, gone from their own thread, whenever the CLI had a note to attach.
_SYSTEM_REMINDER = re.compile(r"<{0}>.*?</{0}>\s*".format(
    re.escape(shape("tag.system_reminder"))), re.S)

def _tag_pattern(tag, inner, flags=0):
    """A reader for a tag out of UPSTREAM_SHAPES, so a tag that changes
    upstream is changed in one place: ``<x>`` opens, ``</x>`` closes,
    ``inner`` between."""
    return re.compile(re.escape(tag) + inner + re.escape("</" + tag[1:]), flags)


_COMMAND_NAME = _tag_pattern(shape("tag.command_name"), r"\s*(/?[\w:-]+)\s*")
_COMMAND_ARGS = _tag_pattern(shape("tag.command_args"), r"(.*?)", re.S)
# A stem, not a whole tag: stdout and stderr share it, so the word and the
# closing ">" follow it on both ends.
_STEM = re.escape(shape("tag.local_command_out"))
_CLOSE_STEM = re.escape("</" + shape("tag.local_command_out")[1:])
_TAGGED_OUT = re.compile(_STEM + r"(?:stdout|stderr)>(.*?)" + _CLOSE_STEM + r"(?:stdout|stderr)>",
                         re.S)


def _command_sent(lead):
    """"/recap" — or "/loop 5m /x" — from the tagged echo of a slash
    command, or None when this is not one."""
    m = _COMMAND_NAME.search(lead)
    if not m:
        return None
    args = _COMMAND_ARGS.search(lead)
    tail = " ".join(args.group(1).split()) if args else ""
    return (m.group(1) + " " + tail).strip()


def _system_text(entry):
    """What a system line says, with the CLI's own tags peeled off.

    This is the whole output of a slash command — a /recap is several
    paragraphs — and it used to be flattened to one line and cut at 200
    characters with no marker, before it ever left the Mac. The cap was
    written for the one-line notices ("Unknown command: /verify") that
    share this shape, and the test fixture for a recap was 58 characters
    long, which is why nobody saw it. On the wrist the tap that opens a
    collapsed bubble then revealed the same 200 characters, so the
    truncation looked like the command's own answer.

    Same rule as an assistant reply now: keep the lines, bound the work
    rather than the sentence, and if something truly enormous is ever
    cut, cut at a word and say so.
    """
    for key in ("content", "message", "text"):
        value = entry.get(key)
        if isinstance(value, dict):
            value = value.get("content")
        if isinstance(value, str) and value.strip():
            inner = "\n".join(m.group(1) for m in _TAGGED_OUT.finditer(value))
            text = plain_text(_findings_as_lines((inner or value)[:32768]))
            if len(text) > TURN_CHARS:
                text = text[:TURN_CHARS].rsplit(" ", 1)[0] + " …"
            return text
    return ""


_JSON_FENCE = re.compile(r"```json[ \t]*\n(.*?)\n```", re.S)


def _findings_as_lines(text):
    """A review's JSON findings as one line each — "calc.py:2 — what is
    wrong" — in place of the block. Any other code is left for
    plain_text to box: only a list whose every item carries a summary
    is a review's findings."""
    def lines(match):
        try:
            found = json.loads(match.group(1))
        except ValueError:
            return match.group(0)
        key = shape("review.summary")
        if not (isinstance(found, list) and found
                and all(isinstance(f, dict) and f.get(key) for f in found)):
            return match.group(0)
        out = []
        for f in found:
            where = ":".join(str(p) for p in (f.get("file"), f.get("line")) if p not in (None, ""))
            summary = " ".join(str(f[key]).split())
            out.append("- %s — %s" % (where, summary) if where else "- " + summary)
        return "\n".join(out)
    return _JSON_FENCE.sub(lines, text)


SIGNED_OUT_NOTICE = ("Claude Code on this computer is signed out — run: "
                     "claude auth login")


def _notice(text, tone, entry):
    """A system notice turn, carrying the tone the watch draws it in:
    "signin" (Claude Code on this Mac is signed out; the person has to act
    there, and the notice says how), "error" (a line the CLI itself marks as
    a failure) or "output" (what a slash command printed, /recap or /cost:
    ordinary output, not a fault). Claude Code's own fault lines are
    notices, never drawn as replies."""
    return {"role": "system", "kind": "notice", "tone": tone, "text": text,
            "desc": "", "at": entry.get("timestamp", "")}


# Pictures a transcript carries, kept in memory so the watch can ask for
# one by name. A screenshot pasted into Claude Code arrives as a base64
# image part, and until 2026-09-18 every screen here dropped it: a turn
# that was only a picture showed as nothing at all, which reads as the
# watch having lost the message.
#
# In memory, not on disk: these are the user's own screens, and the
# relay's promise is that nothing about a session is written anywhere new.
# Bounded twice — a count and a total size — because a long session of
# screenshots must not grow the helper until the Mac notices.
_IMAGES = OrderedDict()      # ref -> (media_type, base64 str)
IMAGE_CACHE_MAX = 24
IMAGE_CACHE_BYTES = 24 * 1024 * 1024
IMAGE_MAX_BYTES = 6 * 1024 * 1024        # one picture; a watch shows less
# The most of one turn the thread view carries, cut at a word and marked.
# A wrist-sent message (watch_relay.SEND_CHARS) must fit in it whole, or
# the watch's echo of a long message would never find its own turn.
TURN_CHARS = 32000


def remember_image(part):
    """Keep one transcript image part and return its reference, or None if
    it is not a picture we can serve. Never raises."""
    try:
        source = part.get("source") or {}
        data = source.get("data")
        media = str(source.get("media_type") or "")
        if (source.get("type") != "base64" or not isinstance(data, str)
                or not media.startswith("image/")
                or len(data) > IMAGE_MAX_BYTES):
            return None
        ref = hashlib.sha256(data.encode("ascii", "ignore")).hexdigest()[:16]
        with _CACHE_LOCK:
            if ref in _IMAGES:
                _IMAGES.move_to_end(ref)
            else:
                _IMAGES[ref] = (media, data)
            while (len(_IMAGES) > IMAGE_CACHE_MAX
                   or sum(len(v[1]) for v in _IMAGES.values()) > IMAGE_CACHE_BYTES):
                _IMAGES.popitem(last=False)
        return ref
    except Exception:
        return None


def image_bytes(ref):
    """``(media_type, bytes)`` for a reference the watch asks for, or None.
    Never raises — an unreadable picture is a missing one."""
    got = _IMAGES.get(str(ref or ""))
    if not got:
        return None
    try:
        return got[0], base64.b64decode(got[1])
    except Exception:
        return None


def _message_parts(content):
    """``(text, tool_use part, image refs)`` of a transcript message, in one
    pass: the first NON-EMPTY text part — Claude Code does emit empty
    leading text blocks, and taking the first one would drop the real reply
    — the first tool_use part, and a reference per picture. Both screens
    that read messages go through here, so an added part type is handled
    once."""
    if isinstance(content, str):
        return _SYSTEM_REMINDER.sub("", content), None, []
    text, tool, images = "", None, []
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                continue
            kind = part.get("type")
            if kind == "text" and not text:
                # Without the harness's own note, so a part that is ONLY a
                # reminder counts as empty and the person's text after it
                # — same part or the next — is what both screens read.
                text = _SYSTEM_REMINDER.sub("", part.get("text", ""))
            elif kind == shape("type.tool_use") and tool is None:
                tool = part
            elif kind == "image":
                ref = remember_image(part)
                if ref:
                    images.append(ref)
    return text, tool, images

def _meta_start():
    return {"offset": 0, "lines": 0, "cwd": None, "opening": None, "turns": 0}


def _fold_meta(state, line, scan_lines):
    """One transcript line into what session_meta knows. Lines past
    ``scan_lines`` change nothing: a session of slash commands never has an
    opening, and waiting for one read the whole transcript (2026-09-30)."""
    if state["lines"] >= scan_lines:
        return
    state["lines"] += 1
    entry = _json_object(line)
    if entry is None:
        return
    if state["cwd"] is None and entry.get("cwd"):
        state["cwd"] = entry["cwd"]
    message = _message_of(entry)
    if message.get("role") != "user" or entry.get(shape("key.is_meta")):
        return
    state["turns"] += 1
    if state["opening"] is not None:
        return
    text, _, _ = _message_parts(message.get("content"))
    lead = str(text).lstrip()
    # Skip system-injected openers; we want what the human asked.
    if lead and not lead.startswith(_SYSTEM_OPENERS):
        state["opening"] = " ".join(plain_text(text).split())[:120]


def session_meta(path, scan_lines=600):
    """``(cwd, opening ask, user turns)`` from a transcript's first
    ``scan_lines`` lines — what :func:`_session_meta` reads, followed
    instead of re-read. Each call folds in only the whole lines appended
    since the last, and once ``scan_lines`` lines are in nothing more is
    read. An active session's size changes on every poll, and a stat-keyed
    cache re-parsed its first 600 lines each time: about 80 ms a session,
    a /sessions, on a live 7.7 MB transcript (2026-10-21). Never raises."""
    key = (path, scan_lines)
    with _CACHE_LOCK:
        cached = _META_CACHE.get(key)
    # A copy: two requests following the same transcript at once each fold
    # from where the cache stood, and neither counts a turn twice.
    state = dict(cached) if cached else _meta_start()
    if state["lines"] >= scan_lines:
        try:
            if os.path.getsize(path) >= state["offset"]:
                return state["cwd"], state["opening"], state["turns"]
        except OSError:
            return state["cwd"], state["opening"], state["turns"]
        state = _meta_start()                       # shrank: a rewrite
    lines, offset, shrunk = _read_appended(path, state["offset"],
                                           limit=scan_lines - state["lines"])
    if shrunk:
        state = _meta_start()
    for line in lines:
        _fold_meta(state, line, scan_lines)
    state["offset"] = offset
    _bounded_put(_META_CACHE, key, state, 256)
    return state["cwd"], state["opening"], state["turns"]


def _session_meta(path, scan_lines=600):
    """Read what a transcript says about itself: real cwd, opening ask, size.

    Claude Code's directory names are the working directory with every
    non-alphanumeric character replaced by "-", which is lossy: a project
    called familia-gateway is indistinguishable from a folder "gateway"
    inside "familia". The transcript carries the true ``cwd``, so read it.
    Never raises.
    """
    state = _meta_start()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if state["lines"] >= scan_lines:
                    break
                _fold_meta(state, line, scan_lines)
    except OSError:
        pass
    return state["cwd"], state["opening"], state["turns"]


_AUDIT_PATH_MEMO = (None, None)   # (what it was read from, the path)


def _audit_log_path():
    """Where the audit log lives — the hook's answer, not a second one.

    The environment variable was honoured but a path set in the policy file
    was not, so a user who moved their log saw a permanently empty Today
    screen with nothing to explain it. Ask the classifier when it is
    importable (the normal deployment) and fall back to the same default.

    Polled every few seconds, so the answer is kept until what it was read
    from changes — the config file named, that file's age, and the home
    folder — rather than reloading the whole policy on every poll.
    """
    global _AUDIT_PATH_MEMO
    explicit = os.environ.get("CLAUDE_RISK_AUDIT_LOG")
    if explicit:
        return os.path.expanduser(explicit)
    config = os.environ.get("CLAUDE_RISK_CONFIG")
    try:
        age = os.stat(os.path.expanduser(config)).st_mtime_ns if config else None
    except OSError:
        age = None
    key = (config, age, os.path.expanduser("~"))
    if _AUDIT_PATH_MEMO[0] == key:
        return _AUDIT_PATH_MEMO[1]
    try:
        from ClaudeRiskClassifier import _audit_path, load_policy
        path = _audit_path(load_policy())
    except Exception:
        return os.path.expanduser("~/.claude/risk-audit.jsonl")
    _AUDIT_PATH_MEMO = (key, path)
    return path


# What one silenced prompt is worth in seconds of somebody's attention.
#
# Deliberately mean. The real cost of a permission prompt is the context
# switch back to the laptop, which is a good deal more than five seconds —
# but a number that flatters the tool is worse than no number at all, and
# every screen that shows this must call it an estimate. Five seconds is
# the figure that survives an argument.
SECONDS_PER_SILENCED_PROMPT = 5


def _count_decision(stats, entry):
    """Fold one audit entry into the four counts the Today screen and the
    recap share. Returns whether the wrist answered it.

    Both screens used to keep this arithmetic by hand, beside a comment
    promising they could never disagree. A promise kept by a comment is
    kept until the next edit; one function keeps it structurally.
    The classifier's verdict is counted, not the mode: in shadow mode
    nothing is acted on, but "would not have bothered you" is still the
    honest measure of the triage.
    """
    stats["total"] += 1
    if entry.get("decision") == "allow":
        stats["silenced"] += 1
    else:
        stats["asked"] += 1
    answered = entry.get("watch") in ("allow", "deny", "answer")
    if answered:
        stats["answered_on_watch"] += 1
    return answered


def _finish_counts(stats):
    """The two derived numbers, from the same constant on both screens."""
    stats["silenced_percent"] = (int(round(100.0 * stats["silenced"]
                                           / stats["total"]))
                                 if stats["total"] else 0)
    stats["seconds_saved"] = stats["silenced"] * SECONDS_PER_SILENCED_PROMPT
    return stats

# Running per-day totals per audit log, so each request reads only the
# bytes appended since the last one — the audit log grows for the
# product's whole lifetime and must never be rescanned from byte zero.
_ACTIVITY_STATE = {}    # path -> {"day", "offset", ...running stats}
_ACTIVITY_LOCK = threading.Lock()


def _local_time(stamp):
    """("YYYY-MM-DD", "HH:MM") of an ISO timestamp in this machine's zone,
    or None when it does not parse."""
    from datetime import datetime
    try:
        moment = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    local = moment.astimezone()
    return local.strftime("%Y-%m-%d"), local.strftime("%H:%M")


def activity_summary(audit_log=None, now=None):
    """What the triage actually did today, and the last few decisions.

    This is the product's own thesis made visible: how many prompts were
    handled without a human, and how few needed one. Never raises.
    """
    now = now or time.time()
    # The wearer's day, not UTC's: the log is written in UTC, and Today
    # turned over at 02:00 in Copenhagen and clocked 09:30 as 07:30.
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    path = audit_log or _audit_log_path()
    # Requests run on their own threads, and this reads a file offset,
    # advances it, and adds to counters. Two overlapping calls — the watch
    # and the bridge poll independently — would each fold the same appended
    # lines into the same totals, and the day's numbers would be wrong for
    # the rest of the day with nothing to show why.
    with _ACTIVITY_LOCK:
        return _activity_summary_locked(path, today)


def _activity_summary_locked(path, today):
    """The body of :func:`activity_summary`, holding ``_ACTIVITY_LOCK``."""

    def fresh_state():
        return {"day": today, "offset": 0, "total": 0, "silenced": 0,
                "asked": 0, "answered_on_watch": 0, "tiers": {}, "recent": []}

    state = _ACTIVITY_STATE.get(path)
    if state is None or state["day"] != today:
        # A new day starts where the old one stopped reading: everything
        # before that offset was read before midnight, so none of it is
        # today's. Starting from byte zero read the lifetime log each night.
        carried = state["offset"] if state is not None else 0
        state = fresh_state()
        state["offset"] = carried
        _ACTIVITY_STATE[path] = state

    lines, state["offset"], shrunk = _read_appended(path, state["offset"])
    if shrunk:
        # Rewritten log: the returned lines ARE the whole new file, so the
        # counts start over — folding them into yesterday's totals would
        # double-count everything that survived the rewrite.
        offset = state["offset"]
        state = fresh_state()
        state["offset"] = offset
        _ACTIVITY_STATE[path] = state
    for line in lines:
        entry = _json_object(line)
        if entry is None:
            continue
        local = _local_time(entry.get("ts"))
        if local is None or local[0] != today:
            continue
        tier = entry.get("tier", "?")
        state["tiers"][tier] = state["tiers"].get(tier, 0) + 1
        if _count_decision(state, entry):
            state["recent"].append({
                "verdict": entry.get("watch"),
                "tier": tier,
                "headline": entry.get("headline", ""),
                "project": entry.get("project") or "",
                "at": local[1],
            })
            state["recent"] = state["recent"][-12:]

    stats = {key: state[key] for key in
             ("total", "silenced", "asked", "answered_on_watch")}
    stats["tiers"] = dict(state["tiers"])
    stats["recent"] = list(reversed(state["recent"]))
    return _finish_counts(stats)


# The recap is a lifetime figure, but its counts only ever add up: the
# total, the four buckets, CRITICAL and the first day. So it follows the
# audit log the way the Today screen does, reading only what was appended
# since the last ask; a rotation (the file shrank) starts it over. It used
# to re-read the whole log, at most once a minute (2026-10-21).
_RECAP_CACHE = OrderedDict()   # path -> {"offset", the running counts}


def _recap_start():
    return {"offset": 0, "total": 0, "silenced": 0, "asked": 0,
            "answered_on_watch": 0, "critical": 0, "first_day": ""}


def recap_summary(audit_log=None, now=None):
    """Everything the triage has done since the log began. Never raises."""
    path = audit_log or _audit_log_path()
    with _CACHE_LOCK:
        cached = _RECAP_CACHE.get(path)
    # A copy, so two requests at once never fold the same lines twice.
    running = dict(cached) if cached else _recap_start()
    lines, offset, shrunk = _read_appended(path, running["offset"])
    if shrunk:
        running = _recap_start()
    for line in lines:
        entry = _json_object(line)
        if entry is None:
            continue              # a torn line is not a reason to fail
        _count_decision(running, entry)
        day = str(entry.get("ts", ""))[:10]
        if day and (not running["first_day"] or day < running["first_day"]):
            running["first_day"] = day
        if entry.get("tier") == "CRITICAL":
            running["critical"] += 1
    running["offset"] = offset
    _bounded_put(_RECAP_CACHE, path, running, 8)
    return _recap_facts(running, now)


def _recap_facts(running, now=None):
    """The answer from the running counts: the derived numbers, and how
    many days the log covers up to today."""
    stats = {key: value for key, value in running.items() if key != "offset"}
    stats.update(days=0, silenced_percent=0, seconds_saved=0)
    _finish_counts(stats)
    if stats["first_day"]:
        from datetime import datetime, timezone
        try:
            start = datetime.strptime(stats["first_day"], "%Y-%m-%d")
            today = datetime.fromtimestamp(now or time.time(), timezone.utc)
            stats["days"] = max(1, (today.date() - start.date()).days + 1)
        except ValueError:
            pass
    return stats


_TRANSCRIPT_PATHS = {}   # full session id -> path, validated with exists()
_TRANSCRIPT_PATHS_MAX = 4096


def _remember_transcript(path):
    """Memoise where a session's transcript is, for _find_transcript, under
    its full id: a card's 12-character prefix and the resolver's full id
    then find the same entry, where each used to walk every project
    folder for itself (2026-10-21)."""
    session_id = os.path.basename(path)[:-len(".jsonl")]
    _bounded_put(_TRANSCRIPT_PATHS, session_id, path, _TRANSCRIPT_PATHS_MAX)


def _find_transcript(prefix, projects_dir=None):
    """Path of the transcript whose session id starts with ``prefix``.
    None when there is no match. Memoised — the watch resolves the same
    session every couple of seconds while a thread view is open. Never
    raises."""
    with _CACHE_LOCK:
        cached = _TRANSCRIPT_PATHS.get(prefix) or next(
            (path for session_id, path in _TRANSCRIPT_PATHS.items()
             if session_id.startswith(prefix)), None)
    if cached and os.path.exists(cached):
        return cached
    root = projects_dir or CLAUDE_PROJECTS
    try:
        for project in os.listdir(root):
            pdir = os.path.join(root, project)
            if not os.path.isdir(pdir):
                continue
            for entry in os.listdir(pdir):
                if entry.endswith(".jsonl") and entry.startswith(prefix):
                    path = os.path.join(pdir, entry)
                    if projects_dir is None:
                        _remember_transcript(path)
                    return path
    except OSError:
        pass
    return None


# Markdown is noise at watch size. These turn Claude's replies into the
# plain lines a 40mm screen can show: structure kept (one line per list
# item or paragraph), markers gone.
# The patterns are tapproval_wire's, the hook's too.
_MD_FENCE = wire.MD_FENCE
_MD_HEADING = wire.MD_HEADING
_MD_QUOTE = wire.MD_QUOTE
_MD_BULLET = wire.MD_BULLET
_MD_NUMBER = wire.MD_NUMBER
_MD_HR = wire.MD_HR
_MD_TABLE_SEP = wire.MD_TABLE_SEP
_MD_IMAGE = wire.MD_IMAGE
_MD_LINK = wire.MD_LINK
_MD_CODE = wire.MD_CODE
_MD_STRONG = wire.MD_STRONG
_MD_EM = wire.MD_EM
_MD_STRIKE = wire.MD_STRIKE
_MD_HTML = wire.MD_HTML
_MD_ESCAPE = wire.MD_ESCAPE


def blocks(markdown, always=False):
    """The same reply as ``plain_text`` gives, but with its code kept.

    A list of ``{"kind": "text", "text"}`` and ``{"kind": "code", "text",
    "lang"}`` in reading order. Text blocks are flattened exactly as
    ``plain_text`` flattens them except that inline marks — ``**bold**``,
    ``*em*``, ```` `code` ```` — survive, because a watch that renders
    them natively is better than one that strips them; a watch that does
    not simply shows the marks. Code blocks are verbatim, one per fence,
    with the language the fence named. A ``markdown`` fence is prose in
    disguise and lands in a text block, as in ``plain_text``.

    Text blocks keep the reply's shape as the phone shows it (2026-10-12):
    bold, emphasis and code marks, a heading as a bold line, and nested
    points indented two spaces a level — the rules of the hook's
    ``_plan_marked``, so a thread and a plan card read alike.

    Returns ``[]`` when there is no fence, unless ``always``: a reply with
    nothing but prose still has a shape worth sending. Never raises.
    """
    lines = str(markdown or "").splitlines()
    if not always and not any(_MD_FENCE.match(line) for line in lines):
        return []
    out, prose, code, lang = [], [], [], ""
    fence_len, fence_is_prose = 0, False

    def flush_prose():
        text = _marked_lines(prose)
        if text:
            out.append({"kind": "text", "text": text})
        prose.clear()

    for raw in lines:
        line = raw.rstrip()
        fence = _MD_FENCE.match(line)
        if fence:
            marker = len(fence.group(1))
            if fence_len == 0:
                fence_len = marker
                fence_is_prose = fence.group(2).lower() in ("markdown", "md")
                lang = "" if fence_is_prose else fence.group(2).lower()
                if not fence_is_prose:
                    flush_prose()
                continue
            if marker >= fence_len:
                if not fence_is_prose:
                    out.append({"kind": "code", "lang": lang,
                                "text": "\n".join(code).strip("\n")})
                    code.clear()
                fence_len, fence_is_prose = 0, False
                continue
            if fence_is_prose:
                # A shorter fence inside a prose fence is a bare marker
                # line; plain_text loses it to the inline-code strip.
                continue
        if fence_len and not fence_is_prose:
            code.append(raw)
            continue
        prose.append(raw)   # trailing spaces can be a hard break
    if code:
        # An unclosed fence at the end of a reply is still code.
        out.append({"kind": "code", "lang": lang, "text": "\n".join(code).strip("\n")})
    flush_prose()
    return out


# One line read, and wrapped lines joined: tapproval_wire's rules, which the
# hook's plan card applies too.
_flatten_line = wire.flatten_line
_unwrap = wire.unwrap


def _marked_lines(lines):
    """Prose lines as the phone shows them, in what a watch can draw: the
    inline marks kept, a heading as a bold line with air above it, a
    nested point indented two spaces a level, block markup read, and a
    wrapped paragraph one line (``_unwrap``). The hook's ``_plan_marked``
    applies the same rules to a plan."""
    out = []
    for raw in _unwrap(lines):
        raw = raw.expandtabs(4)
        if not raw.strip() or _MD_HR.match(raw) or _MD_TABLE_SEP.match(raw):
            if not raw.strip() and out and out[-1]:
                out.append("")
            continue
        text = _flatten_line(raw, keep_inline=True).strip()
        if not text:
            continue
        if _MD_HEADING.match(raw):
            text = "**%s**" % text.replace("**", "")
            if out and out[-1]:
                out.append("")
        elif _MD_BULLET.match(raw) or _MD_NUMBER.match(raw):
            depth = (len(raw) - len(raw.lstrip(" "))) // 2
            text = "  " * min(depth, 3) + text
        out.append(text)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


def plain_text(markdown):
    """Flatten Markdown to the plain, line-structured text a watch can show.

    Headings, quotes, bullets, rules, tables, links, images, code fences,
    emphasis and HTML tags all reduce to their readable content; list
    items and paragraphs keep their own lines so structure survives
    without markers. Never raises; returns "" for empty input.
    """
    if not markdown:
        return ""
    out, fence_len, fence_is_prose = [], 0, False
    for raw in str(markdown).splitlines():
        line = raw.rstrip()
        fence = _MD_FENCE.match(line)
        if fence:
            marker = len(fence.group(1))
            if fence_len == 0:
                # Opening fence. Remember its length: four-backtick fences
                # exist precisely to CONTAIN ``` lines, so only a marker at
                # least as long as the opener closes the block. A
                # ```markdown block is prose in disguise and flattens.
                fence_len = marker
                fence_is_prose = fence.group(2).lower() in ("markdown", "md")
                continue
            if marker >= fence_len:
                fence_len, fence_is_prose = 0, False
                continue
            # A shorter fence inside a longer one is content, not a fence.
        if fence_len and not fence_is_prose:
            # A code block is unreadable at watch size — mark it instead,
            # once per block (the phone shows a box; this is our box).
            if not out or out[-1] != "[code]":
                out.append("[code]")
            continue
        if not line.strip() or _MD_HR.match(line) or _MD_TABLE_SEP.match(line):
            # A blank line is a paragraph break — the phone shows the gap,
            # so the wrist must too. One is enough.
            if not line.strip() and out and out[-1]:
                out.append("")
            continue
        line = " ".join(_flatten_line(line).split())
        if line:
            out.append(line)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


# How many turns the watch's thread view shows — the ONE number the
# /thread handler, session_thread and the session list all share, so a
# state warmed by the list can never hold a different depth than what is
# served.
THREAD_TURN_LIMIT = 14


def session_thread(session_id, limit=THREAD_TURN_LIMIT, projects_dir=None):
    """The tail of a session's conversation, small enough for a watch.

    Reads the transcript backwards-ish: the whole file is scanned but only
    the last ``limit`` human/assistant turns are kept, each trimmed to a
    glanceable length. Never raises.
    """
    path = _find_transcript(session_id, projects_dir)
    if not path:
        return []
    return _parse_thread(path, limit)[0]


# The phone's wording, in both the shapes it uses: one run named on its own,
# and several of a kind counted. It writes "Ran 4 commands", never
# "Ran a command, ran a command, ran a command".
_TOOL_PHRASES = (
    (("Bash", "BashOutput"), "ran a command", "ran %d commands"),
    (("Edit", "Write", "NotebookEdit", "MultiEdit"), "edited a file",
     "edited %d files"),
    (("Read",), "read a file", "read %d files"),
    (("Grep", "Glob"), "searched the code", "ran %d searches"),
    (("WebFetch", "WebSearch"), "searched the web", "ran %d web searches"),
    (("Task", "Agent"), "launched a task", "launched %d tasks"),
)


def _tool_phrase(name, count=1):
    """The phone app's wording for one tool run, or for several of a kind."""
    for names, one, many in _TOOL_PHRASES:
        if name in names:
            return one if count < 2 else many % count
    return "used a tool" if count < 2 else "used tools %d times" % count


# Background tasks announce themselves when launched and are receipted by
# a task-notification when they end; the difference is what is running.
_TASK_LAUNCH = re.compile(
    r"running in background with ID: ([\w-]+)|agentId: ([a-f0-9]+)"
    r"|Monitor started \(task ([\w-]+)"
    r"|Workflow launched in background\. Task ID: ([\w-]+)")
_TASK_DONE = re.compile(r"<task-id>([\w-]+)</task-id>")
_WAKEUP_IN = re.compile(r"Next wakeup scheduled for [^(]*\(in (\d+)s\)")
# How many tool descriptions to remember, to name a task by what it is for.
_DESCRIPTIONS_KEPT = 64


def _tasks_ended(line):
    """The task ids a line says have ENDED: those whose notification carries
    a <status>. A Monitor sends a notification per event with the same
    <task-id> and no status, and reading every <task-id> as an ending
    retired a live monitor at its first event (2026-10-01)."""
    ended = set()
    for block in line.split("<task-notification>")[1:]:
        block = block.split("</task-notification>")[0]
        if shape("tag.task_status") in block:
            ended.update(_TASK_DONE.findall(block))
    return ended


def _task_state(session_id, task_id):
    """Ground-truth a transcript-counted task against its output file.

    Launch-minus-receipt overcounts forever for a task that dies without
    a terminal notification; the phone knows better. Each task writes
    .../<session>/tasks/<id>.output. Returns one of three verdicts:
    "done" (an exit marker — terminal, safe to remember forever),
    "running" (a fresh file with no marker), or "unknown" (no file at
    all, or a stale or unreadable one — see _judge_task_files for why a
    missing file is not "running"). "unknown" is deliberately NOT terminal: a long-quiet task that
    resumes writing, or a transient read error, must be able to come
    back — only an exit marker is forever.
    """
    return _judge_task_files(_task_output_files(session_id).get(task_id, ()),
                             _owner_started(session_id))


def _owner_started(session_id):
    """When the live process that owns this session started, in seconds,
    or None when no live process owns it."""
    return session_registry().get(session_id, {}).get("started_at")


def _born(path):
    """When a file was created: its birth time where the platform keeps
    one (macOS), else its mtime — later than birth, so never a reason to
    believe a file is newer than it is."""
    info = os.stat(path)
    return getattr(info, "st_birthtime", None) or info.st_mtime


def _task_output_files(session_id):
    """``{task_id: [paths]}`` for every task output a session has written.

    One walk of the tmp tree per session. Judging each task with its own
    glob walked the same two wildcard levels once per outstanding task,
    and the tree only grows — stale claude-* directories are never swept.
    """
    import glob as _glob
    patterns = ["/private/tmp/claude-*/*/%s/tasks/*.output" % session_id]
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        patterns.append(os.path.join(
            tmpdir, "claude-*", "*", session_id, "tasks", "*.output"))
    by_task = {}
    for pattern in patterns:
        for path in _glob.glob(pattern):
            by_task.setdefault(os.path.basename(path)[:-7], []).append(path)
    return by_task


def _judge_task_files(found, owner_started=None):
    """The verdict for one task, from its output files (see _task_state).

    A file quiet for half an hour is still "running" when the process that
    owns the session is alive and started before the file was born: that
    process writes the exit marker itself when its task ends, so no marker
    from a live owner means not ended. A wait that sends its output to
    /dev/null ("gh run watch … >/dev/null") writes nothing until it ends,
    and the wrist called a session idle 36 minutes into one (2026-10-14).
    A dead owner, or a file older than the live one, stays "unknown"."""
    # No file at all is no evidence, and no evidence is not "running".
    #
    # This used to let the transcript's word stand, which sounds humble and
    # is actually how a phantom becomes immortal: a test fixture containing
    # the words "agentId: deadbeef99" travelled through the conversation,
    # got read as a launch, and — having never existed — could never produce
    # the file that would retire it. The wrist reported a running task for
    # the rest of the day while the phone, which tracks real tasks, showed
    # none.
    for path in found:
        try:
            with open(path, "rb") as handle:
                size = os.path.getsize(path)
                handle.seek(max(0, size - 300))
                tail = handle.read().decode("utf-8", "replace")
            if shape("task.exited") in tail or shape("task.killed") in tail:
                return "done"
            if time.time() - os.path.getmtime(path) <= 1800:
                return "running"
            if owner_started is not None and _born(path) >= owner_started:
                return "running"
        except OSError:
            continue
    return "unknown"

# Incremental per-transcript thread state: a byte offset plus the running
# accumulations, so a live session's every-2.5s poll parses only the lines
# appended since last time — the _ACTIVITY_STATE pattern applied to
# threads. A transcript rewrite (size shrink) resets the state.
_THREAD_STATE = {}   # path -> {"offset", "turns", "launched", ...}

# One lock per transcript: the pre-warmer below and the watch's own
# /thread poll may parse the same file from two handler threads, and two
# concurrent incremental reads of one offset would double-append turns.
_THREAD_LOCKS = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock(path):
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(path, threading.Lock())


def _fresh_thread_state():
    return {"offset": 0, "turns": [], "launched": set(),
            "finished": set(), "running_tool": None, "running_tool_id": None,
            "descriptions": OrderedDict(), "task_labels": {}, "running_label": None,
            "wake_at": None,
            "github": None,
            "last_said": None,
            "result": None, "result_at": 0.0, "limit": None}


def _parse_thread(path, limit):
    """The turns of one transcript — (turns, running_tasks, running_tool).

    The watch polls this every 2.5 seconds; only appended complete lines
    are ever read and parsed."""
    with _thread_lock(path):
        return _parse_thread_locked(path, limit)


def _thread_state_for(path):
    """This transcript's accumulated state, created on first sight.

    Evicting under the map guard, and dropping each transcript's lock
    with its state. A thread mid-parse holds its OWN path lock, not this
    one, so evicting its dict left it accumulating into an orphan — and
    the next poll cold-parsed from byte zero, which is the "Loading…" a
    warm state exists to prevent. The lock map also grew one entry per
    transcript, forever, in a process that runs for weeks.
    """
    state = _THREAD_STATE.get(path)
    if state is not None:
        return state
    state = _fresh_thread_state()
    with _THREAD_LOCKS_GUARD:
        _THREAD_STATE[path] = state
        if len(_THREAD_STATE) > 32:
            for stale in list(_THREAD_STATE):
                if len(_THREAD_STATE) <= 32:
                    break
                if stale == path:
                    continue
                lock = _THREAD_LOCKS.get(stale)
                # Only retire a transcript nobody is reading right now.
                if lock is not None and lock.locked():
                    continue
                _THREAD_STATE.pop(stale, None)
                _THREAD_LOCKS.pop(stale, None)
    return state


def _merge_tool_runs(turns):
    """Phone-style aggregation: consecutive tool turns collapse into one
    phrase — "Ran a command, edited a file" — deduped, order kept. One
    call is named by what it was for, several are counted. Pure."""
    merged = []
    runs = []                 # (name, desc, at) of the current consecutive run

    def flush():
        if not runs:
            return
        if len(runs) == 1 and runs[0][1]:
            phrase = "ran %s" % runs[0][1]
        else:
            counts = OrderedDict()
            for name, _desc, _at in runs:
                counts[name] = counts.get(name, 0) + 1
            phrase = ", ".join(_tool_phrase(name, n)
                               for name, n in counts.items())
        merged.append({"role": "assistant", "kind": "tool", "at": runs[-1][2],
                       "text": phrase[:1].upper() + phrase[1:]})
        del runs[:]

    for turn in turns:
        if turn["kind"] == "tool":
            runs.append((turn["text"], turn.get("desc") or "",
                         turn.get("at", "")))
            continue
        flush()
        merged.append(dict(turn))
    flush()
    return merged


def _running_task_count(state, session_id):
    """How many launched tasks are still running, judged from files
    OUTSIDE this transcript. "done" is terminal and never re-judged;
    "unknown" counts as not running now but is asked again next time —
    quiet tasks may wake, read errors pass."""
    running = 0
    outstanding = state["launched"] - state["finished"]
    files = _task_output_files(session_id) if outstanding else {}
    owner_started = _owner_started(session_id) if outstanding else None
    labels = state.setdefault("task_labels", {})
    label = None
    # Launch order, so the label is the newest running task's.
    for tid in [t for t in labels if t in outstanding] + sorted(outstanding - set(labels)):
        verdict = _judge_task_files(files.get(tid, ()), owner_started)
        if verdict == "done":
            state["finished"].add(tid)
        elif verdict == "running":
            running += 1
            label = labels.get(tid) or label
    # What the wrist can say instead of "1 task": the description Claude
    # gave the command, monitor or agent ("Wait for build 95 to finish").
    state["running_label"] = label if running else None
    return running


# How much of a transcript's end is read the first time the watch asks
# for its thread. The thread is its last turns; reading the whole file to
# find them took 17-27 s and 1.26 GB for one 238 MB transcript on the
# first /sessions after a relay start (2026-09-25 review). What a tail
# cannot know: a background task launched before it (the running count
# may miss it until it finishes) and a message of yours older than it
# (the head of the thread then starts inside the tail).
THREAD_TAIL_BYTES = 4 * 1024 * 1024


def _tail_start(path, tail=None):
    """The offset of the first whole line in the file's last ``tail``
    bytes, or 0 when the file is no longer than that. Never raises."""
    tail = THREAD_TAIL_BYTES if tail is None else tail
    try:
        size = os.path.getsize(path)
        if size <= tail:
            return 0
        with open(path, "rb") as handle:
            handle.seek(size - tail)
            handle.readline()               # never start mid-line
            return handle.tell()
    except OSError:
        return 0


def _parse_thread_locked(path, limit):
    state = _thread_state_for(path)
    if state["offset"] == 0 and not state["turns"]:
        state["offset"] = _tail_start(path)
    lines, state["offset"], shrunk = _read_appended(path, state["offset"])
    if shrunk:
        # Rewritten transcript: the returned lines are the whole new file;
        # keeping the old accumulations would duplicate every surviving turn.
        offset = state["offset"]
        state = _fresh_thread_state()
        state["offset"] = offset
        _THREAD_STATE[path] = state
    if lines:
        for line in lines:
            try:
                _thread_line(state, line, limit)
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as error:
                # One line of a shape nobody expected used to end the batch
                # — and the offset had moved past it, so the rest was lost
                # for good (2026-09-30 review). Skip it, and say so once.
                if not state.get("skipped"):
                    print("dashboard: skipped a transcript line in %s (%s)"
                          % (os.path.basename(path), error), file=sys.stderr)
                state["skipped"] = state.get("skipped", 0) + 1
        state["result"] = None
    # Recompute on new lines, a new limit, or a 30s clock: the task
    # verdicts depend on files OUTSIDE this transcript, so a cached
    # result must not outlive their truth just because the session went
    # quiet.
    if (state["result"] is None or state["limit"] != limit
            or time.monotonic() - state["result_at"] > 30.0):
        merged = _merge_tool_runs(state["turns"])
        session_id = os.path.splitext(os.path.basename(path))[0]
        running = _running_task_count(state, session_id)
        state["result"] = (_keep_what_was_said(merged, state["last_said"], limit),
                           running, state["running_tool"])
        state["result_at"] = time.monotonic()
        state["limit"] = limit
    return state["result"]


def _keep_what_was_said(turns, said, limit):
    """The last `limit` turns — and the person's latest message, always.

    A run answering a message from the wrist writes a turn per step, and
    within minutes the message it is answering had scrolled out of the
    window: "messages disappear in sessions" (2026-09-24). The words are
    what the thread is about, so they stay at its head however long the
    work beneath them runs. Pure."""
    window = turns[-limit:]
    if said is None or limit < 2 or any(t is said or (t.get("at") == said.get("at") and t.get("text") == said.get("text"))
                                         for t in window):
        return window
    return [said] + turns[-(limit - 1):]


def _thread_line(state, line, limit):
    """Fold one appended transcript line into the running thread state."""
    entry = _json_object(line)
    if entry is None:
        return
    message = _message_of(entry)
    role = message.get("role")
    # Task launches and receipts arrive as user-role tool results and
    # notifications — never in Claude's own prose. An assistant message
    # QUOTING an id (writing tests, discussing a task) must not count.
    if role != "assistant":
        if (shape("task.launched") in line or shape("task.agent_id") in line
                or shape("task.monitor_started") in line
                or shape("task.workflow_launched") in line):
            asked = [part.get("tool_use_id") for part in
                     (message.get("content") if isinstance(message.get("content"), list) else [])
                     if isinstance(part, dict) and part.get("type") == shape("type.tool_result")]
            description = next((state.get("descriptions", {}).get(i) for i in asked
                                if state.get("descriptions", {}).get(i)), None)
            for groups in _TASK_LAUNCH.findall(line):
                tid = next(g for g in groups if g)
                state["launched"].add(tid)
                if description:
                    state.setdefault("task_labels", {})[tid] = description
        if shape("tag.task_id") in line:
            state["finished"].update(_tasks_ended(line))
        # A wake-up the session set for itself: when it comes back.
        if shape("wakeup.scheduled") in line:
            found = _WAKEUP_IN.search(line)
            if found:
                said = _parse_stamp(entry.get("timestamp")) or time.time()
                state["wake_at"] = said + int(found.group(1))
        elif shape("wakeup.stopped") in line:
            state["wake_at"] = None
    if shape("part.tool_result") in line:
        state["running_tool"] = None
        state["running_tool_id"] = None
    if entry.get("type") == "system":
        # A slash command the CLI answered itself — /recap, /cost, an
        # unknown command — writes its output here, not as an assistant
        # turn. The watch shows it as a notice; it used to drop the line,
        # and a send that bounced showed nothing, which read as the watch
        # being broken. Each notice carries a tone (see _notice): a
        # /recap is ordinary "output", a line the CLI marks as failed is an
        # "error", and Claude Code's own sign-in failure is "signin" — on
        # 2026-10-11 that arrived here, as a local_command, and reached the
        # wrist raw, because the rewrite below only looked at prose.
        subtype = entry.get("subtype")
        if subtype not in (shape("system.subtype.local_command"), None):
            note_unknown_subtype(subtype)
        if (subtype == shape("system.subtype.local_command")
                or entry.get("level") == shape("system.level.error")):
            text = _system_text(entry)
            if text.startswith(shape("text.auth_failed")):
                state["turns"].append(_notice(SIGNED_OUT_NOTICE, "signin", entry))
            elif text:
                failed = entry.get("level") == shape("system.level.error")
                state["turns"].append(_notice(text, "error" if failed else "output", entry))
        return
    if role not in ("user", "assistant"):
        return
    inbox = False
    if role == "user" and entry.get(shape("key.is_meta")):
        # A wrist message delivered into the session's inbox is filed as a
        # hidden line from "another session"; its words are the wearer's.
        content = message.get("content")
        if isinstance(content, list):
            content = "\n".join(str(block.get("text", "")) for block in content
                                 if isinstance(block, dict))
        words = wire.wrist_words(content)
        if words is None:
            return
        message, inbox = {"content": words}, True
    text, part, pictures = _message_parts(message.get("content"))
    tool, tool_description = "", ""
    if part is not None:
        tool = part.get("name", "")
        inp = part.get("input") or {}
        tool_description = inp.get("description")
        phrase = _tool_phrase(tool)
        # Which call: a prompt for it at the terminal is "needs you".
        state["running_tool_id"] = part.get("id")
        if part.get("id") and tool_description:
            kept = state.setdefault("descriptions", OrderedDict())
            kept[part["id"]] = " ".join(str(tool_description).split())[:80]
            while len(kept) > _DESCRIPTIONS_KEPT:
                kept.popitem(last=False)
        state["running_tool"] = (
            " ".join(str(tool_description or "").split())
            or phrase[:1].upper() + phrase[1:])
    kind = "text"
    lead = str(text).lstrip()
    description = ""
    if not lead and tool:
        lead, kind = tool, "tool"
        description = " ".join(str(tool_description or "").split())[:60]
    # The echo of a slash command the user sent — "/recap" — arrives
    # wrapped in <command-name> tags, which used to be dropped with every
    # other "<"-prefixed line. It is the user's own bubble, like any send;
    # the command's OUTPUT follows as a system line, handled above.
    command = _command_sent(lead)
    if command:
        state["turns"].append({"role": "user", "kind": "text", "text": command,
                               "desc": "", "at": entry.get("timestamp", "")})
        return
    # A command that failed inside the CLI says so as a user line in a
    # tag, which the "<" rule below would drop: the wrist then showed the
    # command and nothing after it. It is the CLI's fault line — a notice.
    if role == "user" and lead.startswith(shape("tag.local_command_stderr")):
        said = _system_text({"content": lead})
        if said:
            state["turns"].append(_notice(said, "error", entry))
        return
    if not lead and pictures:
        # A turn that is only a picture: give it words, so a watch that
        # cannot show the picture still says one arrived.
        lead, text, kind = "[image]", "[image]", "text"
    if not lead or lead.startswith(_SYSTEM_OPENERS):
        return
    # After the CLI has answered a slash command itself, the headless run
    # still gives Claude a turn, and Claude — having nothing to add —
    # says exactly this. It is not a reply; on the wrist it read as one,
    # right under a Recap that had already been answered in red.
    if (role == "assistant" and kind == "text"
            and lead.strip() == shape("text.nothing_to_add")):
        return
    # Its twin on the other side: the CLI's own nudge, not the person's.
    if role == "user" and kind == "text" and lead.strip() == shape("text.continue_nudge"):
        return
    # Claude Code's own authentication failure. It arrives as prose, so it
    # reads as a reply; it is the CLI's fault, not Claude speaking, and the
    # fix is on the Mac — a "signin" notice, never a reply bubble.
    if kind == "text" and lead.startswith(shape("text.auth_failed")):
        state["turns"].append(_notice(SIGNED_OUT_NOTICE, "signin", entry))
        return
    # The watch shows the FULL text of a message, like the phone — a 2KB
    # cap here once cut a real reply mid-sentence on the wrist. Bound the
    # WORK, not the sentence: flatten up to 32KB of raw input and keep up
    # to TURN_CHARS flattened (far beyond any real reply, and the whole of
    # the longest message the wrist may send); if something truly
    # enormous is ever cut, cut at a word and say so.
    raw_text = text
    text = (plain_text(str(text)[:32768]) if kind == "text" else lead)
    if len(text) > TURN_CHARS:
        text = text[:TURN_CHARS].rsplit(" ", 1)[0] + " …"
    if role == "assistant" and kind == "text":
        fact = _last_github_fact(text)
        if fact:
            state["github"] = fact
    turn = {
        "role": role,
        "kind": kind,
        "text": text,
        "desc": description,
        "at": entry.get("timestamp", ""),
    }
    # The phone shows code in a box; "[code]" in ``text`` is the wrist's
    # box for a watch that cannot do better. One that can gets the code
    # itself, alongside — never instead — so an older watch keeps reading.
    # And a reply without code carries its shape the same way — bold,
    # nesting, air between points — but only when it has one: a plain
    # sentence would only be sent twice (2026-10-12).
    if kind == "text" and role == "assistant":
        parts = blocks(str(raw_text)[:32768], always=True)
        if parts and ("[code]" in text or parts != [{"kind": "text", "text": text}]):
            turn["blocks"] = parts
    if pictures:
        turn["images"] = pictures
    # A turn the wrist sent — appended by a headless run, which the live
    # process has not seen, or posted into the session's inbox (#246) —
    # is named, so the thread shows where it came from.
    if role == "user" and kind == "text" and (
            inbox or entry.get("entrypoint") == shape("entrypoint.sdk_cli")):
        turn["origin"] = "headless"
    state["turns"].append(turn)
    if role == "user" and kind == "text":
        state["last_said"] = turn
    if len(state["turns"]) > limit * 4:
        state["turns"] = state["turns"][-limit * 2:]


# A GitHub fact is a LAST-MENTIONED claim parsed from what Claude wrote —
# never API truth. Only verb+number shapes count, so a bare "PR #14"
# reference in prose cannot masquerade as an event.
_GH_FACT = re.compile(
    r"(?:(opened|merged|created|closed)\s+PR\s+#(\d+)"
    r"|PR\s+#(\d+)\s+(?:is\s+|was\s+|er\s+|blev\s+)?"
    r"(opened|merged|created|closed|\u00e5ben|\u00e5bnet|merget|lukket))",
    re.I)
_GH_VERB = {"\u00e5ben": "opened", "\u00e5bnet": "opened",
            "merget": "merged", "lukket": "closed"}


def _last_github_fact(text):
    """"PR #142 opened" from the last event-shaped mention, or None."""
    fact = None
    if "#" not in text:
        return None
    for match in _GH_FACT.finditer(text):
        verb = (match.group(1) or match.group(4) or "").lower()
        number = match.group(2) or match.group(3)
        fact = "PR #%s %s" % (number, _GH_VERB.get(verb, verb))
    return fact


def _thread_activity(path):
    """The list row's share of the thread state: (running_tasks,
    running_tool, github). Same limit as /thread, so the list and the
    detail screen share one incremental parse per transcript. (A topic
    from your latest message was computed here too, and dropped by the
    only caller since titles come from the opening ask.)"""
    _, running, running_tool = _parse_thread(path, THREAD_TURN_LIMIT)
    state = _THREAD_STATE.get(path) or {}
    return running, running_tool, state.get("github")


def resolve_session(prefix, projects_dir=None, registry=None):
    """Full session id and working directory from a truncated id.

    The watch carries short ids; resuming a session needs the whole one.
    Returns (session_id, cwd) or (None, None). Never raises.

    An empty prefix names nobody: `""` matched every transcript, and the
    first the directory listed was resumed (2026-09-25 review).
    """
    if not str(prefix or "").strip():
        return None, None
    path = _find_transcript(prefix, projects_dir)
    if not path:
        return None, None
    session_id = os.path.basename(path)[:-6]
    began, _, _ = session_meta(path, scan_lines=40)
    # Where the session is now wins: a desktop session can move, and a
    # wrist run started in the folder it began in edits the wrong tree
    # (found 2026-09-24: "HOV Testflight timeline" had moved from a
    # worktree to the repository). `--resume` finds the transcript from
    # any folder, so only the working directory is at stake. A worktree
    # deleted after its merge falls back to the repository it was in.
    now = (session_registry() if registry is None else registry).get(session_id, {}).get("cwd", "")
    for cwd in (now, began, project_root(now), project_root(began)):
        if cwd and os.path.isdir(cwd):
            return session_id, cwd
    return session_id, now or began


# A transcript written this recently means Claude is writing now.
STATE_WRITING_SECONDS = 20
# A tool call unanswered this long after the transcript last moved is a
# leftover of an interrupted turn, not work in flight.
STATE_TOOL_SECONDS = 1800


def session_state(active_seconds_ago, running_tool, running_tasks,
                  card_waiting, waiting_at_mac, wake_at=None):
    """The one state a session is in, and why: ``(state, reason)``.

    ``running`` — Claude writing (``writing``), a tool call in flight
    (``tool``), or tasks still running behind a quiet transcript
    (``tasks``). ``asking`` — a card on the wrist (``card``) or a prompt
    waiting at the Mac (``terminal``). ``scheduled`` — nothing running,
    but the session set a wake-up that is still ahead (``wakeup``), so it
    comes back by itself. ``idle`` otherwise.

    Decided here, once, by the side that can see the transcript, the task
    files and the audit log. The watch used to decide "working" alone from
    20 seconds of transcript silence: a session with background tasks
    still running read as idle, and so did a prompt that went to the
    terminal (2026-10-01).
    """
    if card_waiting:
        return "asking", "card"
    quiet = active_seconds_ago if active_seconds_ago is not None else float("inf")
    tool_live = bool(running_tool) and quiet <= STATE_TOOL_SECONDS
    if tool_live and waiting_at_mac:
        return "asking", "terminal"
    if quiet < STATE_WRITING_SECONDS:
        return "running", "writing"
    if tool_live:
        return "running", "tool"
    if running_tasks:
        return "running", "tasks"
    if wake_at and wake_at > time.time():
        return "scheduled", "wakeup"
    return "idle", ""


_AT_MAC_CACHE = {}


def prompts_at_the_mac(audit_log=None, tail=128 * 1024):
    """The tool calls the hook left with the person at the terminal.

    The audit log records every PermissionRequest with its tool_use_id and
    what was done with it; "escalate" means the prompt is on the screen at
    the Mac (a SAFE call Claude Code answers itself is "skipped-parity",
    not a prompt). Whether it is still waiting is the transcript's to say:
    its tool_result has not arrived. Reads the log's tail, cached on its
    size and time. Never raises."""
    path = audit_log or _audit_log_path()

    def read():
        found = set()
        try:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - tail))
                for raw in handle.read().decode("utf-8", "replace").splitlines():
                    entry = _json_object(raw)
                    if (entry and entry.get("effective") == "escalate"
                            and entry.get("watch") != "skipped-parity"
                            and entry.get("tool_use_id")):
                        found.add(str(entry["tool_use_id"]))
        except OSError:
            return set()
        return found
    return _stat_cached(_AT_MAC_CACHE, path, read, limit=1)


def thread_wake_at(path):
    """When this transcript's session comes back by itself (a wake-up it
    set), epoch seconds, or None. Read from the parse state, never raises."""
    return (_THREAD_STATE.get(path) or {}).get("wake_at") if path else None


def thread_tool_id(path):
    """The id of the tool call this transcript is waiting on, or None —
    after _parse_thread or _thread_activity has read it."""
    return (_THREAD_STATE.get(path) or {}).get("running_tool_id")


def recent_sessions(limit=12, projects_dir=None, include_idle=False,
                    waiting=()):
    """The user's ACTIVE Claude Code sessions, straight from local storage.

    ``include_idle`` lifts the liveness filter. The session LIST never wants
    that — it mirrors the phone, which shows active sessions — but the
    "start a new session where?" list does: a project you worked in
    yesterday is exactly where you might start one today.

    Claude Code keeps transcripts at ~/.claude/projects/<munged-path>/<id>.jsonl
    — the only sanctioned way to enumerate sessions today (no remote API).
    Only sessions with a live Claude process are returned: the phone app's
    list shows the active sessions, and the wrist mirrors the phone —
    never a graveyard of every transcript on disk. Newest first.
    Never raises.
    """
    # Two reads of the same directory, on purpose: live_sessions() is the
    # seam the tests patch to stage a live set, and a registry read costs
    # about 2 ms — not worth taking that seam away.
    live = live_sessions()
    registry = session_registry()
    # Only what the filter below could keep is stat-ed; the filter still
    # runs, so the answer is the same.
    found = transcripts_newest_first(
        projects_dir, only=None if include_idle else set(live) | set(waiting))
    if not include_idle:
        # A card waiting on the wrist keeps its session listed even when
        # the liveness check missed its process: cards live only inside
        # sessions on the watch, so a card with no row has nowhere to be.
        found = [f for f in found if f[3] in live or f[3] in waiting]
        # Mirror the phone: when Remote Control has any session, the phone
        # lists exactly those, so the wrist does too. A watch whose owner
        # never turned Remote Control on still sees every live session.
        if any(entry["bridged"] for entry in registry.values()):
            # ...except a session with a card waiting on the wrist: the
            # card came from it, so the list must have somewhere to go.
            # A terminal session without Remote Control otherwise sent
            # cards to a watch that could not show where they came from.
            found = [f for f in found
                     if f[3] not in registry or registry[f[3]]["bridged"]
                     or f[3] in waiting]
    # One row per session. A session that left its worktree writes on in
    # the repository's folder, and the worktree's copy of its transcript
    # stays: the list sent both under one id, the watch drew one row per id
    # and left a row-sized hole (2026-10-21). Newest first, so the copy kept
    # is the one still being written.
    seen = set()
    found = [f for f in found if not (f[3] in seen or seen.add(f[3]))]
    # The cap keeps the list short, never a card's session out of it.
    found = found[:limit] + [f for f in found[limit:] if f[3] in waiting]
    at_mac = prompts_at_the_mac()
    sessions = []
    for mtime, path, project, session_id in found:
        # Only the ones we actually return are worth opening.
        cwd, opening, turns = session_meta(path)
        # The repository, as the app names it: the registry knows where the
        # session is now (a desktop session can move), the transcript where
        # it began, and a worktree folds into the repository it is part of.
        where = project_root(registry.get(session_id, {}).get("cwd") or cwd)
        name = os.path.basename(where.rstrip("/")) if where else ""
        if not name:
            name = project.rstrip("-").rsplit("-", 1)[-1] or project
        running_tasks, running_tool, github = _thread_activity(path)
        if projects_dir is None:
            # The row's short id is what the watch opens the thread by, so
            # that first open finds the transcript without walking every
            # project folder — and the thread state is already warm, parsed
            # just now for this row.
            _remember_transcript(path)
        wake_at = (_THREAD_STATE.get(path) or {}).get("wake_at")
        state, reason = session_state(
            max(0, int(time.time() - mtime)), running_tool, running_tasks,
            card_waiting=session_id in waiting,
            waiting_at_mac=thread_tool_id(path) in at_mac,
            wake_at=wake_at)
        repo = repo_slug(cwd)
        # The app's own title wins outright — a /rename, or the title the
        # desktop app gave it, which is what the phone shows too. Otherwise
        # the opening ask: the phone titles a session once, from how it
        # began, and a wrist that re-titled by the newest message showed a
        # different name for the same session — which read as a different
        # session.
        named = registry.get(session_id, {}).get("name", "")
        sessions.append({
            "title": named or derive_title(opening) or name,
            "project": name,
            "repo": repo,
            "status": live.get(session_id, ""),
            "live": session_id in live,
            # A process on this computer holds the session open, so a
            # message from the wrist runs beside it — a side thread the
            # open session does not read. Said per row, by the side that
            # knows, so a route that does reach a live session can turn it
            # off without a new watch build.
            "side_thread": (session_id in live
                            and not inbox_ready(registry.get(session_id), path)),
            "path": cwd or "",
            "session_id": session_id[:12],
            "opening": opening or "",
            "turns": turns,
            "modified": int(mtime),
            "minutes_ago": max(0, int((time.time() - mtime) / 60)),
            # The ring's truth, same sources as the detail screen: the
            # list must tell "working now" from "connected but quiet".
            "active_seconds_ago": max(0, int(time.time() - mtime)),
            "running_tool": running_tool,
            "running_tasks": running_tasks,
            # What is running, in Claude's own words, when anything is.
            "running_label": ((_THREAD_STATE.get(path) or {}).get("running_label")
                              if running_tasks else None),
            "github": github,
            # The state itself, decided here (session_state). A watch
            # older than this field keeps its own 20-second rule.
            "state": state,
            "state_reason": reason,
            # When a scheduled session comes back, epoch seconds.
            "wake_at": int(wake_at) if state == "scheduled" else None,
        })
    return sessions
