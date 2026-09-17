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

import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict

def _read_appended(path, offset):
    """Lines appended since ``offset`` -> (lines, new_offset, shrunk).

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
        with open(path, "rb") as handle:
            handle.seek(offset)
            chunk = handle.read()
    except OSError:
        return [], offset, shrunk
    if chunk and not chunk.endswith(b"\n"):
        chunk = chunk[:chunk.rfind(b"\n") + 1]
    return (chunk.decode("utf-8", "replace").splitlines(),
            offset + len(chunk), shrunk)



CLAUDE_PROJECTS = os.path.expanduser("~/.claude/projects")


CLAUDE_SESSIONS = os.path.expanduser("~/.claude/sessions")

# Claude Code's usage limits run on a rolling five-hour window, so that is
# the number worth putting on a wrist.
USAGE_WINDOW_HOURS = 5

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
    cached = cache.get(path)
    if cached and cached[0] == key:
        return cached[1]
    result = compute()
    cache[path] = (key, result)
    while len(cache) > limit:
        cache.pop(next(iter(cache)), None)
    return result


# Parsed usage entries per transcript — a transcript that has not changed
# is never read twice.
_USAGE_FILES = {}   # path -> (stat_key, [(stamp, inp, out, cache_read, model)])


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


def _usage_entries(path):
    """All usage records in one transcript, cached until the file changes."""
    return _stat_cached(_USAGE_FILES, path,
                        lambda: _usage_entries_uncached(path))


def _usage_entries_uncached(path):
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if '"usage"' not in line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                message = entry.get("message") or {}
                usage = message.get("usage") or {}
                if not usage:
                    continue
                stamp = _parse_stamp(entry.get("timestamp"))
                if stamp is None:
                    continue
                entries.append((stamp,
                                int(usage.get("input_tokens") or 0),
                                int(usage.get("output_tokens") or 0),
                                int(usage.get("cache_read_input_tokens") or 0),
                                message.get("model") or "unknown"))
    except OSError:
        return []
    return entries


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
    paths = []
    try:
        for project in os.listdir(root):
            pdir = os.path.join(root, project)
            if not os.path.isdir(pdir):
                continue
            for entry in os.listdir(pdir):
                if not entry.endswith(".jsonl"):
                    continue
                path = os.path.join(pdir, entry)
                try:
                    if os.path.getmtime(path) >= day_start:
                        paths.append(path)
                except OSError:
                    continue
    except OSError:
        return totals

    for stale in set(_USAGE_FILES) - set(paths):
        _USAGE_FILES.pop(stale, None)   # fell out of the 24h window

    for path in paths:
        for stamp, inp, out, cached_read, model in _usage_entries(path):
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
        if data.get("entrypoint") == "sdk-cli":
            continue
        try:
            os.kill(int(pid), 0)          # signal 0: "are you there?"
        except (OSError, ValueError, TypeError):
            continue
        registry[session_id] = {
            "status": ENTRYPOINTS.get(data.get("entrypoint", ""), "Connected"),
            "bridged": bool(data.get("bridgeSessionId")),
            "name": (str(data.get("name") or "").strip()
                     if data.get("nameSource") == "user" else ""),
        }
    return registry


def live_sessions(sessions_dir=None):
    """Sessions running right now: id -> where it is being driven from.
    The status-only view of :func:`session_registry`. Never raises.
    """
    return {sid: entry["status"]
            for sid, entry in session_registry(sessions_dir).items()}


_REPO_SLUG_CACHE = OrderedDict()
_REPO_SLUG_MAX = 128


def _remember_repo_slug(cwd, slug):
    """Bounded cache: a project's remote rarely changes, but the map must
    not grow for the life of a process that runs for weeks."""
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


def derive_title(text):
    """A short title from the opening ask, the way the app titles sessions."""
    if not text:
        return ""
    title = re.sub(r"^/\S+\s*", "", str(text).strip())   # drop /slash-commands
    title = re.split(r"[.!?\n]", title)[0].strip(" ,;:-")
    if len(title) > 44:
        title = title[:43].rstrip() + "…"
    return title[:1].upper() + title[1:] if title else ""


_META_CACHE = {}   # path -> ((mtime, size), (cwd, opening, turns))



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
    "system.subtype.local_command":
        ("local_command", "A slash command the CLI answered itself; its "
         "output is a system line, not an assistant turn.", "2026-09-08"),
    "system.level.error":
        ("error", "A system line the CLI marks as a failure. The phone "
         "paints both of these red.", "2026-09-08"),
    "tag.command_name":
        ("<command-name>", "The echo of a slash command a person sent, "
         "carried as a user turn.", "2026-09-08"),
    "tag.command_args":
        ("<command-args>", "Its arguments, in a second tag.", "2026-09-08"),
    "tag.local_command_out":
        ("<local-command-", "What the command printed: stdout and stderr are "
         "the same tag with a different word, which is why the reader below "
         "matches the stem.", "2026-09-08"),
    "text.nothing_to_add":
        ("No response requested.", "What Claude says when the CLI already "
         "answered and its own turn has nothing to add. Not a reply.",
         "2026-09-08"),
    "part.tool_result":
        ('"tool_result"', "A tool has answered, so nothing is running now.",
         "2026-09-04"),
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
_SYSTEM_OPENERS = ("<", "Caveat:", "[Request")


_COMMAND_NAME = re.compile(r"<command-name>\s*(/?[\w:-]+)\s*</command-name>")
_COMMAND_ARGS = re.compile(r"<command-args>(.*?)</command-args>", re.S)
_TAGGED_OUT = re.compile(r"<local-command-(?:stdout|stderr)>(.*?)</local-command-(?:stdout|stderr)>", re.S)


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
            text = plain_text((inner or value)[:32768])
            if len(text) > 12000:
                text = text[:12000].rsplit(" ", 1)[0] + " …"
            return text
    return ""


def _message_parts(content):
    """``(text, tool_use part)`` of a transcript message, in one pass: the
    first NON-EMPTY text part — Claude Code does emit empty leading text
    blocks, and taking the first one would drop the real reply — and the
    first tool_use part, or None. Both screens that read messages go
    through here, so an added part type is handled once."""
    if isinstance(content, str):
        return content, None
    text, tool = "", None
    if isinstance(content, list):
        for part in content:
            if not isinstance(part, dict):
                continue
            kind = part.get("type")
            if kind == "text" and not text:
                text = part.get("text", "")
            elif kind == "tool_use" and tool is None:
                tool = part
    return text, tool

def session_meta(path, scan_lines=600):
    """Cached front for :func:`_session_meta` —
    /sessions re-reads a dozen transcripts per watch visit otherwise."""
    return _stat_cached(_META_CACHE, path,
                        lambda: _session_meta(path, scan_lines),
                        extra=scan_lines)


def _session_meta(path, scan_lines=600):
    """Read what a transcript says about itself: real cwd, opening ask, size.

    Claude Code's directory names are the working directory with every
    non-alphanumeric character replaced by "-", which is lossy: a project
    called familia-gateway is indistinguishable from a folder "gateway"
    inside "familia". The transcript carries the true ``cwd``, so read it.
    Never raises.
    """
    cwd, opening, turns = None, None, 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= scan_lines and cwd and opening:
                    break
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if cwd is None and entry.get("cwd"):
                    cwd = entry["cwd"]
                message = entry.get("message") or {}
                if message.get("role") != "user":
                    continue
                turns += 1
                if opening is not None:
                    continue
                text, _ = _message_parts(message.get("content"))
                lead = str(text).lstrip()
                # Skip system-injected openers; we want what the human asked.
                if lead and not lead.startswith(_SYSTEM_OPENERS):
                    opening = " ".join(plain_text(text).split())[:120]
    except OSError:
        pass
    return cwd, opening, turns


def _audit_log_path():
    """Where the audit log lives — the hook's answer, not a second one.

    The environment variable was honoured but a path set in the policy file
    was not, so a user who moved their log saw a permanently empty Today
    screen with nothing to explain it. Ask the classifier when it is
    importable (the normal deployment) and fall back to the same default.
    """
    explicit = os.environ.get("CLAUDE_RISK_AUDIT_LOG")
    if explicit:
        return os.path.expanduser(explicit)
    try:
        from ClaudeRiskClassifier import _audit_path, load_policy
        return _audit_path(load_policy())
    except Exception:
        return os.path.expanduser("~/.claude/risk-audit.jsonl")


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


def activity_summary(audit_log=None, now=None):
    """What the triage actually did today, and the last few decisions.

    This is the product's own thesis made visible: how many prompts were
    handled without a human, and how few needed one. Never raises.
    """
    now = now or time.time()
    from datetime import datetime, timezone
    today = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
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
        state = fresh_state()
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
        if today not in line[:32]:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        tier = entry.get("tier", "?")
        state["tiers"][tier] = state["tiers"].get(tier, 0) + 1
        if _count_decision(state, entry):
            state["recent"].append({
                "verdict": entry.get("watch"),
                "tier": tier,
                "headline": entry.get("headline", ""),
                "project": entry.get("project") or "",
                "at": str(entry.get("ts", ""))[11:16],
            })
            state["recent"] = state["recent"][-12:]

    stats = {key: state[key] for key in
             ("total", "silenced", "asked", "answered_on_watch")}
    stats["tiers"] = dict(state["tiers"])
    stats["recent"] = list(reversed(state["recent"]))
    return _finish_counts(stats)


# The recap costs one full pass over the audit log, which the Today screen
# deliberately never does — that log grows for the product's whole lifetime.
#
# A plain (mtime, size) cache is not enough here, and this is the one route
# where that matters: the hook appends to the audit log throughout a
# session, so the key changes constantly and every open of the screen would
# re-read the whole file. Navigating in and out a few times would have the
# relay scanning a lifetime of decisions on the user's own machine, and
# nothing rate-limits a GET.
#
# So: return the cached answer when the file has not changed, and otherwise
# not more often than this. A lifetime figure does not notice a minute of
# staleness, and the work per caller is now bounded however the screen is
# used.
RECAP_MIN_INTERVAL = 60

_RECAP_CACHE = OrderedDict()   # path -> (stat_key, computed_at, stats)


def recap_summary(audit_log=None, now=None):
    """Everything the triage has done since the log began. Never raises.

    A lifetime figure by definition, so unlike :func:`activity_summary` it
    cannot read only what was appended since last time.
    """
    path = audit_log or _audit_log_path()
    clock = now or time.time()
    try:
        st = os.stat(path)
        key = (st.st_mtime, st.st_size)
    except OSError:
        key = None
    cached = _RECAP_CACHE.get(path)
    if cached is not None:
        cached_key, computed_at, stats = cached
        unchanged = key is not None and cached_key == key
        if unchanged or clock - computed_at < RECAP_MIN_INTERVAL:
            return stats
    stats = _recap_uncached(path, now)
    _RECAP_CACHE[path] = (key, clock, stats)
    while len(_RECAP_CACHE) > 8:
        _RECAP_CACHE.pop(next(iter(_RECAP_CACHE)), None)
    return stats


def _recap_uncached(path, now=None):
    stats = {"total": 0, "silenced": 0, "asked": 0, "answered_on_watch": 0,
             "critical": 0, "first_day": "", "days": 0,
             "silenced_percent": 0, "seconds_saved": 0}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue          # a torn last line is not a reason to fail
                _count_decision(stats, entry)
                day = str(entry.get("ts", ""))[:10]
                if day and (not stats["first_day"] or day < stats["first_day"]):
                    stats["first_day"] = day
                if entry.get("tier") == "CRITICAL":
                    stats["critical"] += 1
    except OSError:
        return stats

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


_TRANSCRIPT_PATHS = {}   # prefix -> path, validated with exists()


def _find_transcript(prefix, projects_dir=None):
    """Path of the transcript whose session id starts with ``prefix``.
    None when there is no match. Memoised — the watch resolves the same
    session every couple of seconds while a thread view is open. Never
    raises."""
    cached = _TRANSCRIPT_PATHS.get(prefix)
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
                        _TRANSCRIPT_PATHS[prefix] = path
                    return path
    except OSError:
        pass
    return None


# Markdown is noise at watch size. These turn Claude's replies into the
# plain lines a 40mm screen can show: structure kept (one line per list
# item or paragraph), markers gone.
_MD_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
_MD_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+")
_MD_QUOTE = re.compile(r"^\s{0,3}>\s?")
_MD_BULLET = re.compile(r"^(\s*)[-*+]\s+")
_MD_HR = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_MD_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_MD_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MD_CODE = re.compile(r"`+([^`]*)`+")
_MD_STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*"
                        r"|(?<!\w)__(?=\S)(.+?)(?<=\S)__(?!\w)")
_MD_EM = re.compile(r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])"
                    r"|(?<!\w)_(?=\S)([^_\n]+?)(?<=\S)_(?!\w)")
_MD_STRIKE = re.compile(r"~~(.+?)~~")
_MD_HTML = re.compile(r"</?[a-zA-Z][^>]*>")
_MD_ESCAPE = re.compile(r"\\([\\`*_{}\[\]()#+\-.!>])")


def blocks(markdown):
    """The same reply as ``plain_text`` gives, but with its code kept.

    A list of ``{"kind": "text", "text"}`` and ``{"kind": "code", "text",
    "lang"}`` in reading order. Text blocks are flattened exactly as
    ``plain_text`` flattens them except that inline marks — ``**bold**``,
    ``*em*``, ```` `code` ```` — survive, because a watch that renders
    them natively is better than one that strips them; a watch that does
    not simply shows the marks. Code blocks are verbatim, one per fence,
    with the language the fence named. A ``markdown`` fence is prose in
    disguise and lands in a text block, as in ``plain_text``.

    Returns ``[]`` when nothing would be gained — no fence at all — so a
    turn carries blocks only when it has code to show. Never raises.
    """
    lines = str(markdown or "").splitlines()
    if not any(_MD_FENCE.match(line) for line in lines):
        return []
    out, prose, code, lang = [], [], [], ""
    fence_len, fence_is_prose = 0, False

    def flush_prose():
        text = _flatten_lines(prose, keep_inline=True)
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
        prose.append(line)
    if code:
        # An unclosed fence at the end of a reply is still code.
        out.append({"kind": "code", "lang": lang, "text": "\n".join(code).strip("\n")})
    flush_prose()
    return out


def _flatten_lines(lines, keep_inline=False):
    """``plain_text``'s line pass over lines already stripped of fences."""
    out = []
    for line in lines:
        if not line.strip() or _MD_HR.match(line) or _MD_TABLE_SEP.match(line):
            if not line.strip() and out and out[-1]:
                out.append("")
            continue
        line = _MD_HEADING.sub("", line)
        line = _MD_QUOTE.sub("", line)
        line = _MD_BULLET.sub(r"\1• ", line)
        if line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            line = " · ".join(c for c in cells if c)
        line = _MD_IMAGE.sub(r"\1", line)
        line = _MD_LINK.sub(r"\1", line)
        if not keep_inline:
            line = _MD_CODE.sub(r"\1", line)
            line = _MD_STRONG.sub(lambda m: m.group(1) or m.group(2), line)
            line = _MD_EM.sub(lambda m: m.group(1) or m.group(2), line)
            line = _MD_STRIKE.sub(r"\1", line)
        line = _MD_HTML.sub("", line)
        line = _MD_ESCAPE.sub(r"\1", line)
        out.append(line.strip())
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
        line = _MD_HEADING.sub("", line)
        line = _MD_QUOTE.sub("", line)
        line = _MD_BULLET.sub(r"\1• ", line)
        if line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            line = " · ".join(c for c in cells if c)
        line = _MD_IMAGE.sub(r"\1", line)
        line = _MD_LINK.sub(r"\1", line)
        line = _MD_CODE.sub(r"\1", line)
        line = _MD_STRONG.sub(lambda m: m.group(1) or m.group(2), line)
        line = _MD_EM.sub(lambda m: m.group(1) or m.group(2), line)
        line = _MD_STRIKE.sub(r"\1", line)
        line = _MD_HTML.sub("", line)
        line = _MD_ESCAPE.sub(r"\1", line)
        line = " ".join(line.split())
        if line:
            out.append(line)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out)


# How many turns the watch's thread view shows — the ONE number the
# /thread handler, session_thread and the prewarmer all share, so a
# pre-warmed state can never hold a different depth than what is served.
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
    r"running in background with ID: ([\w-]+)|agentId: ([a-f0-9]+)")
_TASK_DONE = re.compile(r"<task-id>([\w-]+)</task-id>")


def _task_state(session_id, task_id):
    """Ground-truth a transcript-counted task against its output file.

    Launch-minus-receipt overcounts forever for a task that dies without
    a terminal notification; the phone knows better. Each task writes
    .../<session>/tasks/<id>.output. Returns one of three verdicts:
    "done" (an exit marker — terminal, safe to remember forever),
    "running" (a fresh file with no marker, or no file at all — the
    transcript's word stands), or "unknown" (stale or unreadable right
    now). "unknown" is deliberately NOT terminal: a long-quiet task that
    resumes writing, or a transient read error, must be able to come
    back — only an exit marker is forever.
    """
    return _judge_task_files(_task_output_files(session_id).get(task_id, ()))


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


def _judge_task_files(found):
    """The verdict for one task, from its output files (see _task_state)."""
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
            if "[exited" in tail or "[killed]" in tail:
                return "done"
            if time.time() - os.path.getmtime(path) <= 1800:
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


_last_prewarm = 0.0

# Warm the first screen's worth — the sessions a wrist can actually tap
# without scrolling far.
PREWARM_SESSIONS = 6


def prewarm_threads(session_ids):
    """Parse the visible sessions' transcripts BEFORE anyone opens them.

    The seconds of "Loading…" on first open are the cold full-file parse.
    The user's watch just fetched the session LIST — the sessions they
    can tap are known, so warm those states now, in the background, at
    most once per half minute. Smart, not chatty: an all-warm list costs
    a few dict lookups and no thread, and the warm state then serves
    every later poll incrementally.
    """
    global _last_prewarm
    now = time.monotonic()
    if now - _last_prewarm < 30.0:
        return
    _last_prewarm = now

    cold = [sid for sid in session_ids[:PREWARM_SESSIONS]
            if _TRANSCRIPT_PATHS.get(sid) not in _THREAD_STATE]
    if not cold:
        return

    def warm():
        for session_id in cold:
            try:
                path = _find_transcript(session_id)
                if path and path not in _THREAD_STATE:
                    _parse_thread(path, THREAD_TURN_LIMIT)
            except Exception:
                continue

    threading.Thread(target=warm, daemon=True).start()


def _fresh_thread_state():
    return {"offset": 0, "turns": [], "launched": set(),
            "finished": set(), "running_tool": None, "github": None,
            "latest_ask": None,
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
    the next poll cold-parsed from byte zero, which is the "Loading…" the
    prewarmer exists to prevent. The lock map also grew one entry per
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
    for tid in list(outstanding):
        verdict = _judge_task_files(files.get(tid, ()))
        if verdict == "done":
            state["finished"].add(tid)
        elif verdict == "running":
            running += 1
    return running


def _parse_thread_locked(path, limit):
    state = _thread_state_for(path)
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
            _thread_line(state, line, limit)
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
        state["result"] = (merged[-limit:], running, state["running_tool"])
        state["result_at"] = time.monotonic()
        state["limit"] = limit
    return state["result"]


def _thread_line(state, line, limit):
    """Fold one appended transcript line into the running thread state."""
    try:
        entry = json.loads(line)
    except ValueError:
        return
    message = entry.get("message") or {}
    role = message.get("role")
    # Task launches and receipts arrive as user-role tool results and
    # notifications — never in Claude's own prose. An assistant message
    # QUOTING an id (writing tests, discussing a task) must not count.
    if role != "assistant":
        if "background with ID" in line or "agentId" in line:
            for a, b in _TASK_LAUNCH.findall(line):
                state["launched"].add(a or b)
        if "<task-id>" in line:
            state["finished"].update(_TASK_DONE.findall(line))
    if shape("part.tool_result") in line:
        state["running_tool"] = None
    if entry.get("type") == "system":
        # A slash command the CLI answered itself — /recap, /cost, an
        # unknown command — writes its output here, not as an assistant
        # turn, and the phone paints it red with a warning triangle. So
        # does the watch now; it used to drop the line, and a send that
        # bounced showed nothing, which read as the watch being broken.
        subtype = entry.get("subtype")
        if subtype not in (shape("system.subtype.local_command"), None):
            note_unknown_subtype(subtype)
        if (subtype == shape("system.subtype.local_command")
                or entry.get("level") == shape("system.level.error")):
            text = _system_text(entry)
            if text:
                state["turns"].append({"role": "system", "kind": "notice", "text": text,
                                       "desc": "", "at": entry.get("timestamp", "")})
        return
    if role not in ("user", "assistant"):
        return
    text, part = _message_parts(message.get("content"))
    tool, tool_description = "", ""
    if part is not None:
        tool = part.get("name", "")
        inp = part.get("input") or {}
        tool_description = inp.get("description")
        phrase = _tool_phrase(tool)
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
    if not lead or lead.startswith(_SYSTEM_OPENERS):
        return
    # After the CLI has answered a slash command itself, the headless run
    # still gives Claude a turn, and Claude — having nothing to add —
    # says exactly this. It is not a reply; on the wrist it read as one,
    # right under a Recap that had already been answered in red.
    if (role == "assistant" and kind == "text"
            and lead.strip() == shape("text.nothing_to_add")):
        return
    # The watch shows the FULL text of a message, like the phone — a 2KB
    # cap here once cut a real reply mid-sentence on the wrist. Bound the
    # WORK, not the sentence: flatten up to 32KB of raw input and keep up
    # to 12KB flattened (far beyond any real reply); if something truly
    # enormous is ever cut, cut at a word and say so.
    raw_text = text
    text = (plain_text(str(text)[:32768]) if kind == "text" else lead)
    if len(text) > 12000:
        text = text[:12000].rsplit(" ", 1)[0] + " …"
    if role == "assistant" and kind == "text":
        fact = _last_github_fact(text)
        if fact:
            state["github"] = fact
    # The phone re-titles a session as its topic moves on; mirror that by
    # remembering the latest user ask with enough substance to BE a topic.
    # Not topics: short acks ("ok"/"det virker"), slash-command/skill
    # invocations, and the harness's own compaction hand-off message.
    lead_ask = text.strip()
    if (role == "user" and kind == "text" and len(lead_ask) >= 24
            and not lead_ask.startswith("/")
            and not lead_ask.startswith("This session is being continued")):
        state["latest_ask"] = lead_ask[:200]
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
    if kind == "text" and role == "assistant" and "[code]" in text:
        parts = blocks(str(raw_text)[:32768])
        if parts:
            turn["blocks"] = parts
    # A turn a headless run appended — the wrist's sends arrive this way
    # — is not one the session's live process has seen. Name it, so a
    # thread that forks here is legible on both devices rather than
    # mysterious on one.
    if role == "user" and kind == "text" and entry.get("entrypoint") == "sdk-cli":
        turn["origin"] = "headless"
    state["turns"].append(turn)
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
    running_tool, github, latest_ask). Same limit as /thread, so the list
    and the detail screen share one incremental parse per transcript."""
    _, running, running_tool = _parse_thread(path, THREAD_TURN_LIMIT)
    state = _THREAD_STATE.get(path) or {}
    return running, running_tool, state.get("github"), state.get("latest_ask")


def resolve_session(prefix, projects_dir=None):
    """Full session id and working directory from a truncated id.

    The watch carries short ids; resuming a session needs the whole one.
    Returns (session_id, cwd) or (None, None). Never raises.
    """
    path = _find_transcript(prefix, projects_dir)
    if not path:
        return None, None
    cwd, _, _ = session_meta(path, scan_lines=40)
    return os.path.basename(path)[:-6], cwd


def recent_sessions(limit=12, projects_dir=None, include_idle=False,
                    light=False):
    """The user's ACTIVE Claude Code sessions, straight from local storage.

    ``include_idle`` lifts the liveness filter. The session LIST never wants
    that — it mirrors the phone, which shows active sessions — but the
    "start a new session where?" list does: a project you worked in
    yesterday is exactly where you might start one today.

    ``light`` skips the per-session work only the list screen shows — the
    thread parse behind running_tasks/running_tool/github, and the git
    remote behind repo. The projects picker wants a path and an age per
    row and used to pay a full transcript parse for each of fifty rows:
    six seconds, on a blocked handler thread, to answer "where?".

    Claude Code keeps transcripts at ~/.claude/projects/<munged-path>/<id>.jsonl
    — the only sanctioned way to enumerate sessions today (no remote API).
    Only sessions with a live Claude process are returned: the phone app's
    list shows the active sessions, and the wrist mirrors the phone —
    never a graveyard of every transcript on disk. Newest first.
    Never raises.
    """
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
                path = os.path.join(pdir, entry)
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                found.append((mtime, path, project, entry[:-6]))
    except OSError:
        return []

    found.sort(reverse=True)
    # Two reads of the same directory, on purpose: live_sessions() is the
    # seam the tests patch to stage a live set, and a registry read costs
    # about 2 ms — not worth taking that seam away.
    live = live_sessions()
    registry = session_registry()
    if not include_idle:
        found = [f for f in found if f[3] in live]
        # Mirror the phone: when Remote Control has any session, the phone
        # lists exactly those, so the wrist does too. A watch whose owner
        # never turned Remote Control on still sees every live session.
        if any(entry["bridged"] for entry in registry.values()):
            found = [f for f in found
                     if f[3] not in registry or registry[f[3]]["bridged"]]
    found = found[:limit]
    sessions = []
    for mtime, path, project, session_id in found:
        # Only the ones we actually return are worth opening.
        cwd, opening, turns = session_meta(path)
        name = os.path.basename(str(cwd).rstrip("/")) if cwd else ""
        if not name:
            name = project.rstrip("-").rsplit("-", 1)[-1] or project
        if light:
            running_tasks, running_tool, github, repo = 0, None, None, ""
        else:
            running_tasks, running_tool, github, _ = _thread_activity(path)
            repo = repo_slug(cwd)
        # A name given with /rename wins outright. Otherwise the opening
        # ask: the phone titles a session once, from how it began, and a
        # wrist that re-titled by the newest message showed a different
        # name for the same session — which read as a different session.
        named = registry.get(session_id, {}).get("name", "")
        sessions.append({
            "title": named or derive_title(opening) or name,
            "project": name,
            "repo": repo,
            "status": live.get(session_id, ""),
            "live": session_id in live,
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
            "github": github,
        })
    return sessions
