"""Read Codex's local chat catalog and conversation without changing Codex.

Codex's native interactive chat catalog decides list membership, including
idle and unloaded chats visible in Remote. Rollouts supply conversation
content; an open file descriptor is not evidence of catalog membership.

The module is intentionally independent of Claude Code's transcript reader.
It owns only the small amount of Codex-specific file format knowledge needed
to make a session-list row.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from collections import OrderedDict

import tapproval_host as _host
import tapproval_wire as wire


_MAX_CANDIDATES = 128

# Observed in the owner's Codex 0.162.0-alpha.2 rollouts (2026-10-14).
# response_item is the conversation; event_msg also repeats completed
# items, so reading both as messages would duplicate the whole thread.
UPSTREAM_SHAPES = {
    "record.meta": ("session_meta", "Durable session identity", "2026-10-14"),
    "record.item": ("response_item", "Conversation items", "2026-10-14"),
    "record.event": ("event_msg", "Turn lifecycle, not message copies", "2026-10-14"),
    "record.context": ("turn_context", "Per-turn directory and permission policy", "2026-10-27"),
    "item.message": ("message", "A role and typed content parts", "2026-10-14"),
    "item.call": ("function_call", "Named tool call with call_id", "2026-10-14"),
    "item.custom_call": ("custom_tool_call", "Freeform tool call", "2026-10-14"),
    "item.output": ("function_call_output", "Receipt for call_id", "2026-10-14"),
    "item.custom_output": ("custom_tool_call_output", "Freeform receipt", "2026-10-14"),
    "part.input": ("input_text", "User text", "2026-10-14"),
    "part.output": ("output_text", "Assistant text", "2026-10-14"),
    "event.started": ("task_started", "Turn is in progress", "2026-10-14"),
    "event.complete": ("task_complete", "Turn has ended", "2026-10-14"),
    "event.aborted": ("turn_aborted", "Turn was interrupted", "2026-10-14"),
    "event.usage": ("token_count", "Cumulative total_token_usage counter", "2026-10-27"),
    "origin.cli": ("codex-tui", "Terminal session", "2026-10-14"),
    "origin.desktop": ("Codex Desktop", "ChatGPT desktop session", "2026-10-14"),
    "user.environment": ("<environment_context>", "Harness context, not a user message", "2026-10-14"),
}


def shape(name):
    return UPSTREAM_SHAPES[name][0]


def _home():
    # Read per call: profiles and the test suite isolate CODEX_HOME.
    return os.path.expanduser(os.environ.get("CODEX_HOME") or "~/.codex")


def _json_object(line):
    try:
        value = json.loads(line)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _rollouts(root):
    """Newest rollout paths under *root*, with their filesystem mtime."""
    found = []
    try:
        for base, _dirs, names in os.walk(root):
            for name in names:
                if not (name.startswith("rollout-") and name.endswith(".jsonl")):
                    continue
                path = os.path.join(base, name)
                try:
                    found.append((os.path.getmtime(path), path))
                except OSError:
                    continue
    except OSError:
        return []
    return sorted(found, reverse=True)[:_MAX_CANDIDATES]


def _index_titles(path):
    """``session id -> saved Codex title``.  Bad lines are ignored."""
    titles = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                row = _json_object(line)
                if not row:
                    continue
                session_id = str(row.get("id") or "").strip()
                title = str(row.get("thread_name") or "").strip()
                if session_id and title:
                    titles[session_id] = title
    except OSError:
        pass
    return titles


def _rollout_meta(path):
    """The durable identity fields from a rollout's session_meta record."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                row = _json_object(line)
                if not row or row.get("type") != shape("record.meta"):
                    continue
                payload = row.get("payload")
                if not isinstance(payload, dict):
                    return None
                session_id = str(payload.get("id") or payload.get("session_id") or "").strip()
                if not session_id:
                    return None
                return {
                    "session_id": session_id,
                    "cwd": str(payload.get("cwd") or "").strip(),
                    "originator": str(payload.get("originator") or "").strip(),
                }
    except OSError:
        pass
    return None


def _lsof_query(paths):
    """One bounded inspection; retain diagnostics for callers proving closure."""
    if not paths:
        return None
    try:
        # Absolute paths need no ``--`` (macOS lsof does not consistently
        # accept it); filtering by uid makes a file held by another account
        # insufficient evidence that *this* user's Codex session is active.
        return subprocess.run(["lsof", "-a", "-F", "n", "-u", _host.current_user() or ""] + list(paths),
                              capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None


def _lsof_open_paths(paths, inspection=None):
    """Paths lsof sees open; optionally reuse an inspection already performed."""
    run = inspection if inspection is not None else _lsof_query(paths)
    if run is None:
        return set()
    # lsof returns 1 when none of the requested paths is open.  Its field
    # output may also include unrelated file descriptors of the same process,
    # so retain only the exact candidate names.
    candidates = {os.path.realpath(path) for path in paths}
    return {os.path.realpath(line[1:]) for line in run.stdout.splitlines()
            if line.startswith("n") and os.path.realpath(line[1:]) in candidates}


def _proc_open_paths(paths):
    """Linux fallback for ``lsof``: inspect this user's open descriptors."""
    candidates = {os.path.realpath(path) for path in paths}
    opened = set()
    try:
        processes = os.listdir("/proc")
    except OSError:
        return opened
    for pid in processes:
        if not pid.isdigit():
            continue
        proc = os.path.join("/proc", pid)
        try:
            if os.stat(proc).st_uid != os.getuid():
                continue
            descriptors = os.listdir(os.path.join(proc, "fd"))
        except OSError:
            continue
        for fd in descriptors:
            try:
                target = os.path.realpath(os.readlink(os.path.join(proc, "fd", fd)))
            except OSError:
                continue
            if target in candidates:
                opened.add(target)
    return opened


def open_rollout_paths(paths):
    """The rollout files that currently have a local owner process."""
    opened = _lsof_open_paths(paths)
    return opened or _proc_open_paths(paths)


def _entrypoint(originator):
    if originator == shape("origin.cli"):
        return "Terminal"
    if originator == shape("origin.desktop"):
        return "Desktop"
    return "Connected"


def active_sessions(limit=12, sessions_dir=None, index_path=None, open_paths=None):
    """Codex Remote's local catalog, in the relay's existing row shape.

    Explicit ``sessions_dir`` / ``open_paths`` retain the isolated legacy
    transcript-fixture seam. Production membership uses native metadata,
    never file descriptors. ``limit=None`` supplies all rows for pagination.
    """
    if sessions_dir is None and open_paths is None:
        rows = catalog_snapshot()["sessions"]
        return rows if limit is None else rows[:limit]
    root = sessions_dir or os.path.join(_home(), "sessions")
    entries = _rollouts(root)
    paths = [path for _mtime, path in entries]
    active = ({os.path.realpath(path) for path in open_paths}
              if open_paths is not None else open_rollout_paths(paths))
    if not active:
        return []
    titles = _index_titles(index_path or os.path.join(_home(), "session_index.jsonl"))
    rows, seen = [], set()
    for mtime, path in entries:
        if os.path.realpath(path) not in active:
            continue
        meta = _rollout_meta(path)
        if not meta or meta["session_id"] in seen:
            continue
        seen.add(meta["session_id"])
        cwd = meta["cwd"]
        project = os.path.basename(cwd.rstrip("/")) if cwd else "Codex"
        session_id = meta["session_id"]
        info = thread_info(path)
        rows.append({
            "title": titles.get(session_id) or "Codex session",
            "project": project or "Codex",
            "repo": "",
            "status": _entrypoint(meta["originator"]),
            "live": True,
            "side_thread": False,
            "path": cwd,
            "session_id": session_id,
            "opening": "",
            "turns": 0,
            "modified": int(mtime),
            "minutes_ago": max(0, int((time.time() - mtime) / 60)),
            "active_seconds_ago": max(0, int(time.time() - mtime)),
            "running_tool": info["running_tool"],
            "running_tasks": 0,
            "running_label": None,
            "github": None,
            "state": info["state"],
            "state_reason": info["state_reason"],
            "wake_at": None,
            "agent": "codex",
            "can_send": True,
        })
        if limit is not None and len(rows) >= limit:
            break
    return rows


def _catalog_delivery_path(thread):
    """A local transcript supports the existing queue/resume dispatcher.

    This is an affordance, never a claim that a thread is closed or a grant
    to send. The dispatcher rechecks ownership, activity and policy on tap.
    """
    path, cwd = thread.get("path"), thread.get("cwd")
    if (not isinstance(path, str) or not isinstance(cwd, str)
            or not os.path.isabs(cwd) or not os.path.isdir(cwd)):
        return None
    root = os.path.realpath(os.path.join(_home(), "sessions"))
    real = os.path.realpath(path)
    if not real.startswith(root + os.sep):
        return None
    meta = _rollout_meta(real)
    return real if meta and meta["session_id"] == thread.get("id") else None


def _catalog_row(thread):
    """Membership is the native interactive catalog, not a file descriptor."""
    if not isinstance(thread, dict):
        raise ValueError("Invalid Codex catalog row")
    sid, cwd = thread.get("id"), thread.get("cwd")
    status = thread.get("status")
    if (not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,64}", sid)
            or not isinstance(cwd, str) or not isinstance(status, dict)
            or status.get("type") not in ("active", "idle", "notLoaded", "systemError")
            or type(thread.get("updatedAt")) is not int):
        raise ValueError("Invalid Codex catalog identity or status")
    if thread.get("ephemeral") or thread.get("parentThreadId"):
        return None
    source = thread.get("source")
    if isinstance(source, dict) or source in ("exec", "subAgent", "subAgentReview",
                                             "subAgentCompact", "subAgentThreadSpawn", "subAgentOther"):
        return None
    flags = status.get("activeFlags", [])
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        raise ValueError("Invalid Codex catalog flags")
    asking = any(flag in flags for flag in ("waitingOnApproval", "waitingOnUserInput"))
    state = "asking" if asking else "running" if status["type"] == "active" else "idle"
    stamp = thread.get("recencyAt")
    if type(stamp) is not int:
        stamp = thread["updatedAt"]
    title = thread.get("name")
    if not isinstance(title, str) or not title.strip():
        title = thread.get("preview")
    return {"session_id": sid, "title": title.strip() if isinstance(title, str) and title.strip()
            else "Codex session", "project": os.path.basename(cwd.rstrip("/")) or "Codex",
            "path": cwd, "repo": "", "status": "Terminal" if source == "cli" else "Desktop",
            "agent": "codex", "live": status["type"] in ("active", "idle"),
            "side_thread": False, "modified": stamp,
            "minutes_ago": max(0, int((time.time() - thread["updatedAt"]) / 60)),
            "active_seconds_ago": max(0, int(time.time() - thread["updatedAt"])),
            "state": state, "state_reason": "terminal" if asking else "turn" if state == "running" else "",
            "running_tool": None, "running_tasks": 0, "wake_at": None,
            # Visibility never grants a send capability. The send path still
            # rechecks unique native ownership and the permission context.
            "can_send": (thread.get("canAcceptDirectInput") is True
                         or _catalog_delivery_path(thread) is not None)}


def _read_catalog(client_factory=None, endpoints=None):
    from codex_desktop import server_sockets
    from codex_talk import Client
    client_factory = client_factory or Client
    endpoints = server_sockets() if endpoints is None else endpoints
    rows, paths, owners, succeeded = {}, {}, {}, False
    for endpoint in endpoints:
        client = None
        try:
            client = client_factory(socket_path=endpoint)
        except (OSError, EOFError, ValueError):
            continue  # the optional managed endpoint need not exist
        try:
            cursor, seen, server_rows, server_paths = None, set(), {}, {}
            deadline = time.monotonic() + 15
            for _page in range(64):
                if time.monotonic() > deadline:
                    raise ValueError("Codex catalog exceeded its time bound")
                page = client.rpc("thread/list", {"cursor": cursor, "limit": 100,
                    "archived": False, "sortKey": "recency_at", "sortDirection": "desc",
                    "useStateDbOnly": True})
                if not isinstance(page, dict) or not isinstance(page.get("data"), list):
                    raise ValueError("Invalid Codex catalog page")
                for thread in page["data"]:
                    row = _catalog_row(thread)
                    if row is not None:
                        sid = row["session_id"]
                        server_rows[sid] = row
                        path = thread.get("path")
                        if isinstance(path, str):
                            server_paths[sid] = path
                cursor = page.get("nextCursor")
                if cursor is None:
                    break
                if not isinstance(cursor, str) or not cursor or cursor in seen:
                    raise ValueError("Invalid Codex catalog cursor")
                seen.add(cursor)
            else:
                raise ValueError("Codex catalog exceeded its page bound")
            succeeded = True
            for sid, row in server_rows.items():
                owners[sid] = owners.get(sid, 0) + int(row["live"])
                old = rows.get(sid)
                newest = row if old is None or row["modified"] > old["modified"] else old
                # Servers share durable metadata, but only the owner knows
                # runtime state. A notLoaded copy must not erase a live one.
                rank = {"asking": 3, "running": 2, "idle": 1}
                runtime = row if old is None or (row["live"], rank[row["state"]]) > (old["live"], rank[old["state"]]) else old
                rows[sid] = dict(newest, **{key: runtime[key] for key in
                    ("live", "state", "state_reason", "can_send")})
                if owners[sid] > 1:
                    rows[sid]["can_send"] = False
                if sid in server_paths:
                    paths[sid] = server_paths[sid]
        finally:
            client.close()
    if not succeeded:
        raise OSError("Codex chat catalog is unavailable")
    return sorted(rows.values(), key=lambda row: (-row["modified"], row["session_id"])), paths


class SessionCatalog:
    """A complete snapshot, refreshed off the HTTP thread; failures retain it."""

    def __init__(self, reader=None):
        self.reader = reader or _read_catalog
        self.lock = threading.Lock()
        self.rows, self.paths = [], {}
        self.status, self.checked, self.busy = "loading", None, False

    def refresh(self):
        try:
            rows, paths = self.reader()
            with self.lock:
                self.rows, self.paths, self.status = rows, paths, "ready"
        except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError):
            with self.lock:
                self.status = "unavailable"
        finally:
            with self.lock:
                self.checked, self.busy = time.monotonic(), False

    def snapshot(self):
        with self.lock:
            if not self.busy and (self.checked is None or time.monotonic() - self.checked >= 4):
                self.busy = True
                threading.Thread(target=self.refresh, name="codex-chat-list", daemon=True).start()
            rows = [dict(row) for row in self.rows]
            if self.status != "ready":
                for row in rows:
                    row["can_send"] = False
            return {"sessions": rows, "status": self.status}


_CATALOG = None
_CATALOG_HOME = None
_CATALOG_LOCK = threading.Lock()


def catalog_snapshot():
    global _CATALOG, _CATALOG_HOME
    home = _home()
    # Claude-only installations do not need a Codex server or warning.
    if not os.path.isdir(home):
        return {"sessions": [], "status": "ready"}
    with _CATALOG_LOCK:
        if _CATALOG is None or _CATALOG_HOME != home:
            _CATALOG, _CATALOG_HOME = SessionCatalog(), home
        catalog = _CATALOG
    return catalog.snapshot()


def find_rollout(session_id, sessions_dir=None):
    """Resolve an unambiguous identity, never a caller-supplied path."""
    if not re.fullmatch(r"[A-Za-z0-9-]{8,64}", session_id or ""):
        return None
    # Native metadata resolves older chats beyond the 128-recent-rollout
    # discovery window. Never trust a server-provided path outside this home.
    if sessions_dir is None and _CATALOG is not None and _CATALOG_HOME == _home():
        with _CATALOG.lock:
            path = _CATALOG.paths.get(session_id)
        if path:
            root = os.path.realpath(os.path.join(_home(), "sessions"))
            real = os.path.realpath(path)
            if real.startswith(root + os.sep):
                meta = _rollout_meta(real)
                if meta and meta["session_id"] == session_id:
                    return real
    matches = []
    for _mtime, path in _rollouts(sessions_dir or os.path.join(_home(), "sessions")):
        if session_id not in os.path.basename(path):
            continue
        meta = _rollout_meta(path)
        if meta and meta["session_id"].startswith(session_id):
            matches.append(path)
    return matches[0] if len(matches) == 1 else None


_THREADS = OrderedDict()
_THREAD_LOCK = threading.Lock()


# Normalize only tools whose action is known. In particular, ``exec`` is a
# code-mode wrapper, not a shell command; its input must never be inspected
# or executed to guess what work it performed. Unknown names share ONE bin.
_TOOL_NAMES = {
    "exec_command": "Bash", "shell_command": "Bash", "shell": "Bash",
    "apply_patch": "Edit", "read_file": "Read",
    "grep": "Grep", "glob": "Grep", "web_search": "WebSearch",
    "write_stdin": "TerminalInput",
}
_TOOL_ACTIVITY = {
    "Bash": "Running a command", "Edit": "Editing files", "Read": "Reading a file",
    "Grep": "Searching the code", "WebSearch": "Searching the web",
    "TerminalInput": "Sending input to terminal", "ComputerUse": "Using the computer",
}


def _tool_category(payload):
    name = payload.get("name")
    if not isinstance(name, str):
        return "tool"
    namespace = payload.get("namespace")
    if namespace == "mcp__cua_repl" and name == "js":
        return "ComputerUse"
    if name == "mcp__cua_repl__js":
        return "ComputerUse"
    if namespace not in (None, "functions"):
        return "tool"
    if name.startswith("functions."):
        name = name[len("functions."):]
    return _TOOL_NAMES.get(name, "tool")


def _fold(state, row, number):
    """Read Codex shapes only; formatting below is shared with Claude."""
    payload = row.get("payload")
    if not isinstance(payload, dict):
        return
    kind = payload.get("type")
    if row.get("type") == shape("record.event"):
        if kind == shape("event.started"):
            state["busy"] = True
            state["tool_run"] = None
        elif kind in (shape("event.complete"), shape("event.aborted")):
            state["busy"] = False
            state["calls"].clear()
            state["tool_run"] = None
        return
    if row.get("type") != shape("record.item"):
        return
    call_id = payload.get("call_id")
    if kind in (shape("item.output"), shape("item.custom_output")):
        if isinstance(call_id, str):
            state["calls"].pop(call_id, None)
        return
    at = row.get("timestamp")
    at = at if isinstance(at, str) else ""
    if kind in (shape("item.call"), shape("item.custom_call")):
        # Tool arguments/results may contain large blobs and private data;
        # the thread shows activity, using only the tool's name.
        category = _tool_category(payload)
        if isinstance(call_id, str) and call_id:
            if call_id in state["seen_calls"]:
                return
            state["seen_calls"][call_id] = None
            while len(state["seen_calls"]) > 512:
                state["seen_calls"].popitem(last=False)
            state["calls"][call_id] = _TOOL_ACTIVITY.get(category)
            while len(state["calls"]) > 64:
                state["calls"].pop(next(iter(state["calls"])))
        from watch_dashboard import _ToolRun
        run = state["tool_run"]
        if run is None:
            run = state["tool_run"] = _ToolRun()
            state["turns"].append(None)
        # Store summaries rather than raw calls: a long burst must retain
        # its first identity and full count even past the history limit.
        state["turns"][-1] = run.add(category, at, number)
        # The first byte is the row's identity; the newest call determines
        # whether a delta poll must resend that row with its updated count.
        state["changed"][run.turn["n"]] = number
        return
    if kind != shape("item.message"):
        return                         # includes private reasoning records
    role = payload.get("role")
    if role not in ("user", "assistant") or payload.get("channel") == "analysis":
        return
    content = payload.get("content")
    if not isinstance(content, list):
        return
    parts = [part["text"] for part in content if isinstance(part, dict)
             and part.get("type") in (shape("part.input"), shape("part.output"))
             and isinstance(part.get("text"), str)]
    raw = "\n".join(parts).strip()
    if role == "user" and raw.startswith((shape("user.environment"),
                                           "# AGENTS.md instructions for ")):
        return
    if role == "user":
        decoder = getattr(wire, "codex_wrist_words", None)
        words = decoder(raw) if decoder else None
        if words is not None:
            raw = words
    if not raw:
        return
    from watch_dashboard import blocks, plain_text
    raw = raw[:32768] + ("\n[…]" if len(raw) > 32768 else "")
    text = plain_text(raw)
    if not text:
        return
    state["tool_run"] = None
    turn = {"role": role, "kind": "text", "text": text, "at": at, "n": number}
    if role == "assistant":
        marked = blocks(raw, always=True)
        if marked != [{"kind": "text", "text": text}]:
            turn["blocks"] = marked
    state["turns"].append(turn)
    if role == "user":
        state["last_said"] = turn


def thread_info(path, mark=None, limit=14, card_waiting=False):
    """The watch's existing thread wire shape, from complete rollout lines.

    Byte marks and turn numbers survive relay restarts. Only appended lines
    are parsed on a warm poll; a replaced/shrunken file resets the thread.
    The cache and cold read are bounded, as for Claude's transcript reader.
    """
    from watch_dashboard import _read_appended, _tail_start, _keep_what_was_said
    reply = {"turns": [], "running_tasks": 0, "running_tool": None,
             "modified_seconds_ago": None, "state": "idle",
             "state_reason": "", "wake_at": None}
    if mark is not None:
        reply.update(mark=0, reset=True)
    try:
        stat = os.stat(path)
    except OSError:
        return reply
    with _THREAD_LOCK:
        state = _THREADS.get(path)
        identity = (stat.st_dev, stat.st_ino)
        replaced = state is not None and (
            state["identity"] != identity or stat.st_size < state["offset"])
        if state is None or replaced:
            floor = _tail_start(path)
            state = {"identity": identity, "offset": floor, "floor": floor,
                     "turns": [], "calls": {}, "busy": None, "last_said": None,
                     "tool_run": None, "changed": {}, "seen_calls": OrderedDict()}
            _THREADS[path] = state
        _THREADS.move_to_end(path)
        while len(_THREADS) > 32:
            _THREADS.popitem(last=False)
        starts = []
        lines, offset, _shrunk = _read_appended(path, state["offset"], starts=starts)
        if _shrunk:                  # truncated between stat and the read
            state.update(turns=[], calls={}, busy=None, floor=0, last_said=None,
                         tool_run=None, changed={}, seen_calls=OrderedDict())
            replaced = True
        for index, line in enumerate(lines):
            row = _json_object(line)
            if row:
                _fold(state, row, starts[index])
            if len(state["turns"]) > 160:
                state["turns"] = state["turns"][-120:]
                state["floor"] = state["turns"][0]["n"]
                state["changed"] = {n: changed for n, changed in state["changed"].items()
                                    if n >= state["floor"]}
        state["offset"] = offset
        turns = state["turns"]
        said = state["last_said"]
        if mark is None:
            visible = _keep_what_was_said(turns, said, limit)
        else:
            reset = replaced or mark <= 0 or mark > offset or mark < state["floor"]
            visible = (_keep_what_was_said(turns, said, 40) if reset
                       else [t for t in turns
                             if state["changed"].get(t["n"], t["n"]) >= mark])
            if len(visible) > 60:
                visible, reset = visible[-60:], True
            reply.update(mark=offset, reset=reset)
        reply["turns"] = list(visible)
        active = max(0, int(time.time() - stat.st_mtime))
        reply["modified_seconds_ago"] = active
        tool = next(reversed(state["calls"].values()), None) if state["calls"] else None
        # Open does not mean working: task_complete/turn_aborted wins even
        # when the file was written a moment ago. An unknown lifecycle uses
        # the same short freshness window as an older Claude transcript.
        if card_waiting:
            reply.update(state="asking", state_reason="card", running_tool=tool)
        elif state["busy"] is True or (state["busy"] is None and active < 20):
            reply.update(state="running", state_reason="tool" if state["calls"] else "turn",
                         running_tool=tool)
        return reply
