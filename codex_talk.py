"""Codex wrist sends. No shell interpolation and no Claude fallback.

The shared app-server can apply a sandbox to a new turn. The CLI queue
cannot: its sandbox flags are ignored for an existing thread (verified on
0.164.0-alpha.11.1). Never enqueue into an unverified permission context.
"""
from __future__ import annotations

import os
import re
import subprocess
import time

import tapproval_host as _host
import tapproval_wire as wire

from codex_approvals import ApprovalSync, LocalWebSocket
import codex_sessions as sessions


POLICY = {"type": "workspaceWrite", "networkAccess": False,
          "writableRoots": [], "excludeTmpdirEnvVar": True,
          "excludeSlashTmp": True}
# Opening a chat loads the person's plugins first. The watch outwaits a
# slow answer through /new-receipt, so wait rather than call it lost.
START_TIMEOUT = 15
RECAP = "Summarise the goal, current task and next action in under forty words."
ARCHIVE_TIMEOUT = 15


class RpcRefused(ValueError):
    """A definitive server refusal, distinct from a missing receipt."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__("Codex refused the message: %s" % reason)


def message(text, brief=True):
    if text == "/recap":
        text = RECAP
    elif text.startswith("/"):
        raise ValueError("Codex wrist messages use words, not Claude Code commands")
    # A checkout may update while a pending card defers the relay restart.
    # Its cached wire module must keep serving the old format until then.
    formatter = getattr(wire, "codex_wrist_message", None)
    if formatter is None:
        return text + ("\n\nReply concisely for the watch." if brief else "")
    return formatter(text, brief)


class Client:
    """Short-lived RPC client; the shared server owns accepted turns."""

    def __init__(self, connect=None, socket_path=None):
        path = socket_path or shared_socket()
        if connect is None:
            # Establish absence before a platform's socket support is needed.
            os.stat(path)
        self.wire = (connect or (lambda: LocalWebSocket(path)))()
        self.sequence = 0
        try:
            self.rpc("initialize", {"clientInfo": {"name": "tapproval_send", "version": "1"},
                                    "capabilities": {"experimentalApi": True}})
            self.wire.send({"method": "initialized"})
        except Exception:
            self.wire.close()
            raise

    def rpc(self, method, params, timeout=3):
        self.sequence += 1
        identity = "wrist-%d" % self.sequence
        self.wire.send({"id": identity, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receive_until = getattr(self.wire, "receive_until", None)
            value = receive_until(deadline) if receive_until else self.wire.receive()
            if value.get("id") != identity or "method" in value:
                continue
            if "error" in value:
                raise RpcRefused(str(value["error"].get("message", "unsupported interface"))[:200])
            if "result" not in value:
                raise ValueError("Codex returned an invalid receipt")
            return value["result"]
        raise OSError("Codex did not acknowledge the message; check the session before retrying")

    def close(self):
        self.wire.close()


def _owner_client(sid, connect):
    from codex_desktop import server_sockets
    selected = None
    try:
        for endpoint in ([None] if connect is not None else server_sockets()):
            try:
                candidate = Client(connect, socket_path=endpoint)
            except (FileNotFoundError, ConnectionRefusedError):
                continue
            except (OSError, EOFError) as error:
                raise ValueError("Codex server ownership could not be verified; "
                                 "reopen the session before sending") from error
            try:
                for loaded in ApprovalSync._loaded_pages(candidate.rpc):
                    if sid in loaded:
                        if selected is not None:
                            raise ValueError("Thread is loaded on multiple Codex servers; close the duplicate before sending")
                        selected, candidate = candidate, None
                        break
            except (OSError, EOFError) as error:
                raise ValueError("Codex connection lost; check the session before retrying") from error
            finally:
                if candidate is not None:
                    candidate.close()
        return selected
    except BaseException:
        if selected is not None:
            selected.close()
        raise


def _archive_thread(thread_id, method):
    client = None
    try:
        try:
            client = _owner_client(thread_id, None)
            if client is None:
                client = Client()
        except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError) as error:
            reason = ("Codex is open on two servers" if "multiple Codex servers" in str(error)
                      else "Can't reach Codex on this Mac" if isinstance(error, (OSError, EOFError))
                      else "Can't verify which Codex server owns this chat")
            return {"ok": False, "reason": reason}
        try:
            receipt = client.rpc(method, {"threadId": thread_id}, timeout=ARCHIVE_TIMEOUT)
            if not isinstance(receipt, dict):
                raise ValueError("invalid archive receipt")
            return {"ok": True}
        except RpcRefused as error:
            return {"ok": False, "reason": ("Codex refused: " + error.reason)[:60]}
        except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError):
            # The mutation may have happened. Never fall back or retry it.
            action = "archive" if method == "thread/archive" else "restore"
            return {"ok": False, "uncertain": True,
                    "reason": "Couldn't confirm %s; check Codex" % action}
    finally:
        if client is not None:
            client.close()


def archive_codex_thread(thread_id):
    """Archive on the single owner, or the default socket if loaded nowhere."""
    return _archive_thread(thread_id, "thread/archive")


def unarchive_codex_thread(thread_id):
    """Restore through the same routing seam; confirmation belongs to the UI."""
    return _archive_thread(thread_id, "thread/unarchive")


def context(path):
    """Newest permission context, not a saved session's initial settings."""
    found = None
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                row = sessions._json_object(line)
                if row and row.get("type") == sessions.shape("record.context"):
                    found = row.get("payload")
    except OSError:
        return None
    return found if isinstance(found, dict) else None


def queue_safe(path):
    """The native queue inherits these limits; it cannot establish them.

    Approval requests must already use human review. A queued follow-up
    cannot change the reviewer or narrow the filesystem or network policy.
    """
    row = context(path) or {}
    sandbox = row.get("sandbox_policy")
    if not isinstance(sandbox, dict):
        return False
    cwd = row.get("cwd") or (sessions._rollout_meta(path) or {}).get("cwd")
    roots = sandbox.get("writable_roots") or []
    if not isinstance(cwd, str) or not isinstance(roots, list):
        return False
    root = os.path.realpath(cwd)
    if any(not isinstance(p, str) or not os.path.isabs(p)
           or (os.path.realpath(p) != root and not os.path.realpath(p).startswith(root + os.sep))
           for p in roots):
        return False
    return (row.get("approvals_reviewer") == "user"
            and row.get("approval_policy") in ("never", "on-request", "untrusted")
            and sandbox.get("type") in ("workspace-write", "read-only")
            and sandbox.get("network_access") is False)


def _lsof_complete_for(path, stderr):
    """Only tolerate missing DeviceFS mount metadata on a different device.

    Darwin lsof can recover a mount's device number from its mount table
    when stat fails. That warning cannot hide a reference to our file on
    another device. All other diagnostics, including an unknown device or
    a warning about the target's own filesystem, still make absence unknown.
    Never use -w: it also hides diagnostics that do affect this search.
    """
    if not stderr.strip():
        return True
    if not _host.is_mac():
        return False
    warning = re.compile(
        r"lsof: WARNING: can't stat\(\) devicefs file system ([^\r\n]+)\n"
        r'[ \t]+Output information may be incomplete\.\n'
        r'[ \t]+assuming "dev=([0-9a-fA-F]+)" from mount table(?:\n|$)')
    try:
        target = os.path.realpath(path)
        device = os.stat(target).st_dev
        offset = 0
        while offset < len(stderr):
            match = warning.match(stderr, offset)
            if not match:
                return False
            mount = os.path.realpath(match[1])
            if (not os.path.isabs(match[1]) or device == int(match[2], 16)
                    or os.path.commonpath([target, mount]) == mount):
                return False
            offset = match.end()
        return True
    except (OSError, ValueError):
        return False


def activity(path, sid):
    """True/False/unknown; failure to inspect activity is never 'closed'."""
    # Keep one result for both positive discovery and legacy closure proof.
    # Repeating lsof here could consume two three-second process deadlines
    # inside a wrist request, even when both searches completed normally.
    result = sessions._lsof_query([path])
    opened = sessions._lsof_open_paths([path], result) if result is not None else set()
    target = os.path.realpath(path)
    if target in opened or target in sessions._proc_open_paths([path]):
        return True
    lock = os.path.join(sessions._home(), "thread-writer-locks", sid + ".lock")
    try:
        with open(lock, "rb") as handle:
            if not _host.try_lock(handle.fileno()):
                return True
            _host.unlock(handle.fileno())
            return False
    except FileNotFoundError:
        # Legacy rollouts predate writer locks. lsof's empty successful
        # search is different from not being able to inspect processes.
        if (result is not None and result.returncode in (0, 1)
                and _lsof_complete_for(path, result.stderr)):
            return False
    except OSError:
        pass
    return None


def send(prefix, text, binary, spawn, log, brief=True, connect=None, runner=None):
    path = sessions.find_rollout(prefix)
    if not path:
        return "unknown Codex session"
    meta = sessions._rollout_meta(path)
    latest = context(path) or {}
    cwd = latest.get("cwd") or (meta or {}).get("cwd")
    if (not meta or not isinstance(cwd, str) or not os.path.isabs(cwd)
            or not os.path.isdir(cwd)):
        return "Codex project is unavailable"
    sid = meta["session_id"]
    try:
        text = message(text, brief)
    except ValueError as error:
        return str(error)
    # A successful connection is not permission to resume a thread held by
    # a different process. Only loaded/list proves this server owns it.
    client = None
    try:
        client = _owner_client(sid, connect)
        if client is not None:
            client.rpc("thread/resume", {"threadId": sid, "excludeTurns": True})
            # One mutation, never retried on a transport failure. The
            # server accepts input into the same thread, including while
            # working; no second transcript or Claude process is created.
            receipt = client.rpc("turn/start", {"threadId": sid,
                "input": [{"type": "text", "text": text}],
                "sandboxPolicy": dict(POLICY), "approvalPolicy": "on-request",
                "approvalsReviewer": "user", "runtimeWorkspaceRoots": [cwd]})
            if not isinstance(receipt, dict) or not (receipt.get("turn") or {}).get("id"):
                return "Codex returned an invalid receipt; check the session before retrying"
            return "sent"
    except (OSError, EOFError) as error:
        if client is not None:
            return "Codex connection lost; check the session before retrying: %s" % error
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        return str(error)
    finally:
        if client is not None:
            client.close()
    # Do not start a second writer beside a live Terminal or desktop.
    live = activity(path, sid)
    if live is None:
        return "Codex activity could not be verified; reopen the session before sending"
    if live:
        if not queue_safe(path):
            return ("Open this Codex session through the shared app-server to send from your watch; "
                    "its current connection cannot enforce the watch's permission limits "
                    "and human approval review")
        try:
            result = (runner or subprocess.run)(
                [binary, "queue", "--thread", sid, "--message", text],
                cwd=cwd, capture_output=True, text=True, timeout=3)
            return "sent" if result.returncode == 0 else "Codex could not queue the message"
        except (OSError, subprocess.SubprocessError):
            return "Codex queue did not acknowledge the message; check the session before retrying"
    # A private exec-resume would take the writer away from the phone and
    # Desktop. Reopen the same UUID on the shared owner instead. Native
    # writer locking still refuses a different process that appeared
    # after the activity census; never fall back after that refusal.
    try:
        client = _shared_client(binary=binary, connect=connect)
        reopened = client.rpc("thread/resume", dict(_thread_defaults(cwd),
            threadId=sid, excludeTurns=True), timeout=START_TIMEOUT)
        if (not isinstance(reopened, dict) or not isinstance(reopened.get("thread"), dict)
                or reopened["thread"].get("id") != sid):
            return "Codex returned an invalid resume receipt; check the session before retrying"
        receipt = client.rpc("turn/start", {"threadId": sid,
            "input": [{"type": "text", "text": text}], "sandboxPolicy": dict(POLICY),
            "approvalPolicy": "on-request", "approvalsReviewer": "user",
            "runtimeWorkspaceRoots": [cwd]}, timeout=START_TIMEOUT)
        if not isinstance(receipt, dict) or not (receipt.get("turn") or {}).get("id"):
            return "Codex returned an invalid receipt; check the session before retrying"
        return "sent"
    except (OSError, EOFError, ValueError, TypeError, KeyError, AttributeError) as error:
        return "Codex shared resume could not be confirmed; check the session before retrying: %s" % error
    finally:
        if client is not None:
            client.close()


def shared_socket():
    """The shared server Codex's own Terminal and the phone both reach."""
    return sessions.control_socket()


def _start_shared_service(binary):
    """Idempotent native start, never restart/update or a private fallback."""
    try:
        result = subprocess.run([binary, "app-server", "daemon", "start"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=START_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Codex's background service start could not be confirmed; "
                         "check Codex on your computer before trying again") from error
    if result.returncode:
        raise ValueError("Codex's background service could not start; "
                         "open Codex on your computer before trying again")


def _shared_client(binary=None, connect=None):
    """Reach the common owner; only proven absence permits an idempotent start.

    No thread mutation has happened yet, so retrying an absent socket is
    safe. An uncertain handshake or permission error is never absence.
    """
    try:
        return Client(connect, socket_path=shared_socket())
    except (FileNotFoundError, ConnectionRefusedError):
        pass
    except (OSError, EOFError) as error:
        raise ValueError("Codex's background service did not answer; "
                         "check the connection before trying again") from error
    if not binary:
        from ClaudeRiskClassifier import ensure_codex_on_path
        binary = ensure_codex_on_path()
    if not binary:
        raise ValueError("Codex's background service is unavailable; "
                         "Codex is not installed on your computer")
    _start_shared_service(binary)
    deadline = time.monotonic() + START_TIMEOUT
    while True:
        try:
            return Client(connect, socket_path=shared_socket())
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise ValueError("Codex's background service is not ready; "
                                 "check Codex on your computer before trying again") from None
            time.sleep(.05)
        except (OSError, EOFError) as error:
            raise ValueError("Codex's background service did not answer; "
                             "check the connection before trying again") from error


def _thread_defaults(cwd):
    """Same permissions for a wrist-created thread and a closed-thread resume."""
    return {"approvalPolicy": "on-request", "approvalsReviewer": "user",
        "runtimeWorkspaceRoots": [cwd], "sandbox": "workspace-write",
        "config": {"sandbox_workspace_write": {
            "network_access": False, "writable_roots": [],
            "exclude_tmpdir_env_var": True, "exclude_slash_tmp": True}}}


def start(cwd, text, connect=None, binary=None):
    """Begin a wrist session on the shared server; return its thread id.

    A Terminal started with ``flags()`` runs a private server of its own:
    Codex joins the shared one only when a start carries no overrides
    (0.166), and the phone then refuses the chat as "used by another
    session". thread/start carries the same limits instead, the human
    reviewer included, and they stay with the chat for every later turn,
    whoever types it. A missing shared service is started idempotently;
    failure is an explicit refusal, never a Terminal-only private chat.
    Raises ValueError in words; a lost receipt is never retried.
    """
    client = _shared_client(binary=binary, connect=connect)
    try:
        limits = {"approvalPolicy": "on-request", "approvalsReviewer": "user",
                  "runtimeWorkspaceRoots": [cwd]}
        thread = client.rpc("thread/start", dict(_thread_defaults(cwd), cwd=cwd),
            timeout=START_TIMEOUT)
        sid = ((thread or {}).get("thread") or {}).get("id") if isinstance(thread, dict) else None
        if not isinstance(sid, str) or not sid:
            raise ValueError("Codex returned an invalid receipt")
        receipt = client.rpc("turn/start", dict(limits, threadId=sid,
            input=[{"type": "text", "text": text}], sandboxPolicy=dict(POLICY)),
            timeout=START_TIMEOUT)
        if not isinstance(receipt, dict) or not (receipt.get("turn") or {}).get("id"):
            raise ValueError("Codex returned an invalid receipt")
        return sid
    except (OSError, EOFError) as error:
        raise ValueError("Codex connection lost; check the session before retrying: %s" % error) from error
    finally:
        client.close()


def attach_flags():
    """What a Terminal attaching to a watch chat must carry.

    The first client to open a chat applies its own config to it, which
    without these would hand back the temporary folders (verified on
    0.166). --remote refuses writable_roots, so folders the person lists
    in their own config apply to what they type there; each wrist send
    resets them through turn/start.
    """
    return ["-c", 'approval_policy="on-request"', "-c", 'approvals_reviewer="user"',
        "-c", "sandbox_workspace_write.network_access=false",
        "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
        "-c", "sandbox_workspace_write.exclude_slash_tmp=true"]


def flags():
    return ["--sandbox", "workspace-write", "-c", 'approval_policy="on-request"',
            "-c", 'approvals_reviewer="user"',
            "-c", "sandbox_workspace_write.network_access=false",
            "-c", "sandbox_workspace_write.writable_roots=[]",
            "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
            "-c", "sandbox_workspace_write.exclude_slash_tmp=true"]
