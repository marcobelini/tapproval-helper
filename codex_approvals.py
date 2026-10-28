"""Mirror Codex's own pending approvals, without holding its permission hook.

The private local app-server socket speaks WebSocket JSON-RPC. A metadata-only
resume of a *loaded* thread attaches another client to the same running session;
it neither starts a turn nor creates a second Codex process. The server owns the
first answer and broadcasts serverRequest/resolved to clear every client's UI.
Standard library only. No account tokens or public listener are involved.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict


MAX_MESSAGE = 2 * 1024 * 1024
APPROVAL_METHODS = {
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval",
    "mcpServer/elicitation/request",
}


class LocalWebSocket:
    """A bounded RFC 6455 client for Codex's user-private Unix socket."""

    def __init__(self, path, timeout=3):
        if not hasattr(socket, "AF_UNIX"):
            raise OSError("this computer's Python has no Unix sockets")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self._buffer = b""
        self._ready = False
        self._write_lock = threading.Lock()
        try:
            self.sock.connect(path)
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            self.sock.sendall((
                "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n" % key).encode("ascii"))
            while b"\r\n\r\n" not in self._buffer:
                self._buffer += self._read()
                if len(self._buffer) > 16384:
                    raise ValueError("oversized WebSocket handshake")
            header, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
            lines = header.decode("ascii").split("\r\n")
            fields = {name.lower(): value.strip() for name, value in
                      (line.split(":", 1) for line in lines[1:] if ":" in line)}
            expected = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()).decode("ascii")
            if (lines[0].split()[1] != "101"
                    or fields.get("sec-websocket-accept") != expected
                    or fields.get("upgrade", "").lower() != "websocket"):
                raise ValueError("invalid WebSocket handshake")
            self._ready = True
        except BaseException:
            self.close()
            raise

    def _read(self):
        while True:
            try:
                data = self.sock.recv(65536)
                break
            except socket.timeout:
                if not self._ready:
                    raise
        if not data:
            raise EOFError("Codex disconnected")
        return data

    def _take(self, size):
        while len(self._buffer) < size:
            self._buffer += self._read()
        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def _send(self, payload, opcode=1):
        if len(payload) > MAX_MESSAGE:
            raise ValueError("oversized WebSocket message")
        length = len(payload)
        prefix = (bytes([128 | opcode, 128 | length]) if length < 126
                  else bytes([128 | opcode, 254]) + struct.pack("!H", length)
                  if length <= 65535 else
                  bytes([128 | opcode, 255]) + struct.pack("!Q", length))
        mask = os.urandom(4)
        masked = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
        with self._write_lock:
            self.sock.sendall(prefix + mask + masked)

    def send(self, message):
        self._send(json.dumps(message, ensure_ascii=False).encode("utf-8"))

    def receive(self):
        fragments = bytearray()
        started = False
        while True:
            first, second = self._take(2)
            opcode, final = first & 15, bool(first & 128)
            if first & 112 or second & 128:
                raise ValueError("unsupported WebSocket frame")
            length = second & 127
            if length == 126:
                length = struct.unpack("!H", self._take(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._take(8))[0]
            if length + len(fragments) > MAX_MESSAGE:
                raise ValueError("oversized WebSocket message")
            if opcode >= 8 and (not final or length > 125):
                raise ValueError("invalid WebSocket control frame")
            payload = self._take(length)
            if opcode == 8:
                raise EOFError("Codex closed WebSocket")
            if opcode == 9:
                self._send(payload, opcode=10)
                continue
            if opcode == 10:
                continue
            if opcode == 1 and not started:
                started = True
            elif opcode != 0 or not started:
                raise ValueError("unexpected WebSocket opcode")
            fragments.extend(payload)
            if final:
                value = json.loads(fragments.decode("utf-8"))
                if not isinstance(value, dict):
                    raise ValueError("expected a JSON-RPC object")
                return value

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def denial_action(params):
    """Use the refusal Codex actually offers, preserving its turn semantics."""
    decisions = params.get("availableDecisions")
    if decisions is None:
        return "decline"
    if not isinstance(decisions, list) or "accept" not in decisions:
        return None
    return "decline" if "decline" in decisions else "cancel" if "cancel" in decisions else None


def file_hook_input(params, event):
    """Bind a hook's patch to the exact native call, before its item is persisted.

    Codex 0.162 omits a call ID from PermissionRequest and pending file items
    from history pages. Its already-written model call supplies that missing ID.
    Neither a matching path nor the most recent edit is sufficient evidence.
    """
    if (not isinstance(event, dict) or event.get("tool_name") != "apply_patch"
            or event.get("session_id") != params["threadId"]
            or event.get("turn_id") != params["turnId"]):
        return None
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    path = event.get("transcript_path")
    if not isinstance(command, str) or not command or not isinstance(path, str):
        return None
    try:
        with open(path, "rb") as source:
            first = json.loads(source.readline(MAX_MESSAGE))
            if first.get("type") != "session_meta" or (
                    first.get("payload") or {}).get("id") != params["threadId"]:
                return None
            source.seek(0, os.SEEK_END)
            start = max(0, source.tell() - MAX_MESSAGE)
            source.seek(start)
            if start:
                source.readline()  # discard the incomplete leading record
            records = source.read(MAX_MESSAGE).splitlines()
        matches = []
        for raw in records:
            row = json.loads(raw)
            call = row.get("payload") or {}
            if (row.get("type") != "response_item" or call.get("name") != "apply_patch"
                    or call.get("call_id") != params["itemId"]
                    or (call.get("internal_chat_message_metadata_passthrough") or {}).get(
                        "turn_id") != params["turnId"]):
                continue
            patch = call.get("input") if call.get("type") == "custom_tool_call" else None
            if call.get("type") == "function_call":
                patch = json.loads(call.get("arguments") or "{}").get("input")
            matches.append(patch)
        return dict(event) if matches == [command] else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def approval_card(message, item=None, hook_event=None):
    """Render only native approval types with known one-shot answer semantics.

    Unsupported prompts stay with Codex. A missing file diff is never guessed:
    the native item or an exactly correlated hook must supply the patch.
    """
    import ClaudeRiskClassifier as classifier

    method, params = message.get("method"), message.get("params")
    if method not in {"item/commandExecution/requestApproval", "item/fileChange/requestApproval"} or not isinstance(params, dict):
        return None
    if not all(isinstance(params.get(k), str) and params[k]
               for k in ("threadId", "turnId", "itemId")):
        return None
    refusal = denial_action(params)
    if refusal is None:
        return None
    if method == "item/commandExecution/requestApproval":
        command = params.get("command")
        kind = params.get("kind", "command")
        # Managed-network requests aren't shell-command approvals.
        if (params.get("networkApprovalContext") or params.get("additionalPermissions")
                or kind not in ("command", "writeStdin")
                or not isinstance(command, str) or not command):
            return None
        event = {"tool_name": "write_stdin" if kind == "writeStdin" else "Bash",
                 "tool_input": {"command": command}}
    elif hook_event is not None:
        event = file_hook_input(params, hook_event)
        if event is None:
            return None
    else:
        changes = (item or {}).get("changes")
        if not isinstance(changes, list) or not changes:
            return None
        paths = [change.get("path") for change in changes if isinstance(change, dict)]
        if len(paths) != len(changes) or not all(
                isinstance(p, str) and p and "\n" not in p for p in paths):
            return None
        if not all(isinstance(change.get("kind"), dict)
                   and change["kind"].get("type") in ("add", "delete", "update")
                   and isinstance(change.get("diff"), str) for change in changes):
            return None
        # The classifier's native apply_patch path parser accepts this syntax.
        patch = "*** Begin Patch\n"
        for change in changes:
            patch += "*** %s File: %s\n" % (change["kind"]["type"].title(), change["path"])
            move = change["kind"].get("move_path")
            if move:
                if not isinstance(move, str) or "\n" in move:
                    return None
                patch += "*** Move to: %s\n" % move
            patch += change["diff"] + "\n"
        patch += "*** End Patch"
        event = {"tool_name": "apply_patch", "tool_input": {"command": patch}}
    event.update(session_id=params["threadId"], cwd=params.get("cwd"))
    policy = classifier.load_policy(dict(classifier._shared_settings_env(), **os.environ))
    _response, _audit, card = classifier.build_response(event, policy, agent="codex")
    if event["tool_name"] == "write_stdin":
        card["headline"] = "Send input to terminal"
        card["detail"] = classifier._fit_lines(
            "Codex terminal input approval\n" + command, classifier.DETAIL_CHARS)
    card["can_always"] = False
    if refusal == "cancel":
        card["deny_label"] = "No, stop this turn"
    reason = params.get("reason")
    if isinstance(reason, str) and reason:
        card["detail"] += "\n\n" + reason
    return card


def handoff_card(message):
    """Keep native consent visible without inventing a compatible answer."""
    params = message["params"]
    method = message["method"]
    network = params.get("networkApprovalContext") or {}
    title = ("Allow network access?" if network else
             "Approve permissions?" if method == "item/permissions/requestApproval" else
             "Approve connected tool?" if method == "mcpServer/elicitation/request" else
             "Codex needs your approval")
    detail = params.get("message") or params.get("reason") or ""
    if not isinstance(detail, str):
        detail = ""
    if isinstance(network, dict) and isinstance(network.get("host"), str):
        detail = network["host"] + ("\n" + detail if detail else "")
    if not detail and isinstance(params.get("command"), str):
        detail = params["command"]
    if not detail and isinstance(params.get("serverName"), str):
        detail = params["serverName"]
    return {"agent": "codex", "kind": "handoff", "tier": "MEDIUM",
            "headline": title, "detail": detail[:2000], "can_always": False,
            "session_id": params["threadId"], "project": "Codex"}


class ApprovalSync:
    """One local Codex connection, with Codex as the authority for resolution."""

    def __init__(self, queue, connect=None, card_title=None, status=None):
        self.queue = queue
        home = os.path.expanduser(os.environ.get("CODEX_HOME") or "~/.codex")
        self.socket_path = os.path.join(home, "app-server-control", "app-server-control.sock")
        self.connect = connect or (lambda: LocalWebSocket(self.socket_path))
        self._custom_connect = connect is not None
        self.card_title = card_title or (lambda card: card)
        self.status = status or (lambda error: None)
        self._lock = threading.RLock()
        self._rpc_lock = threading.RLock()
        self._socket = None
        self._responses = {}
        self._attached = set()
        self._generations = {}
        self._pending = {}
        self._items = {}
        self._cwd = {}
        self._hook_events = {}
        self._sequence = 0
        self._finished = OrderedDict()
        self._request_items = {}
        self._instance = None
        self._stop = threading.Event()
        self._monitor = None
        self._ever_connected = False
        self.last_error = None

    def _ensure_connection(self):
        """Called under the RPC lock, never changes session configuration."""
        with self._lock:
            if self._socket is not None:
                return
            if self._custom_connect:
                instance = "injected"
            else:
                identity = os.stat(self.socket_path)
                instance = str((identity.st_dev, identity.st_ino))
            sock = self.connect()
            if instance != self._instance:
                self._finished.clear()
                self._instance = instance
            self._socket = sock
            threading.Thread(target=self._read, args=(sock,),
                             name="codex-approvals", daemon=True).start()
        self._rpc("initialize", {
            "clientInfo": {"name": "tapproval", "version": "1"},
            "capabilities": {"experimentalApi": True}})
        sock.send({"method": "initialized"})
        self._ever_connected = True
        self.last_error = None
        self.status(None)

    def start(self):
        """Observe loaded sessions even when an approval has no hook."""
        with self._lock:
            if self._monitor is not None:
                return
            self._monitor = threading.Thread(target=self._observe, name="codex-approval-look",
                                             daemon=True)
            self._monitor.start()

    def _observe(self):
        while not self._stop.is_set():
            try:
                self.reconcile()
            except (OSError, ValueError, EOFError, TypeError, KeyError, AttributeError) as error:
                self.last_error = str(error)
                self.close()
                if self._ever_connected and not self._stop.is_set():
                    self.status(self.last_error)
            self._stop.wait(1)

    def reconcile(self):
        """Recover pending requests, not historical/stored conversations."""
        with self._rpc_lock:
            self._ensure_connection()
            loaded = set()
            cursor = None
            while True:
                page = self._rpc("thread/loaded/list", {"cursor": cursor})
                loaded.update(sid for sid in page.get("data", []) if isinstance(sid, str))
                cursor = page.get("nextCursor")
                if not cursor:
                    break
            for sid in loaded:
                with self._lock:
                    if sid in self._attached:
                        continue
                info = self._rpc("thread/read", {"threadId": sid, "includeTurns": False})
                status = (info.get("thread") or {}).get("status") or {}
                if any(flag in status.get("activeFlags", [])
                       for flag in ("waitingOnApproval", "waitingOnUserInput")):
                    self.attach(sid)
            with self._lock:
                for sid in self._attached - loaded:
                    self._finish_thread(sid)

    def stop(self):
        self._stop.set()
        self.close()

    def _card_id(self, key):
        # JSON preserves integer vs string request IDs. The server socket
        # inode distinguishes a new server reusing an old numeric ID.
        raw = json.dumps([self._instance, *key], ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:12]

    def _trace(self, action, key, method=None):
        print("codex approval: " + json.dumps({"event": action, "at_ms": int(time.time() * 1000),
              "server": self._instance, "thread_id": key[0],
              "request_id": key[1], "card_id": self._card_id(key), "method": method},
              ensure_ascii=False), file=sys.stderr)

    def _finish(self, key, terminal=True):
        pending = self._pending.pop(key, None)
        self._request_items.pop(key, None)
        if terminal:
            self._finished[key] = None
        if pending:
            pending[0].set()
            self.queue.withdraw(self._card_id(key))
            self._trace("resolved" if terminal else "disconnected", key)
        if len(self._finished) > 4096:
            # Reconnect/replay gives an authoritative pending set rather
            # than silently forgetting tombstones on a live event stream.
            self._finished.popitem(last=False)
            self.close()

    def _finish_thread(self, thread_id):
        for key in list(self._pending):
            if key[0] == thread_id:
                self._finish(key)
        self._attached.discard(thread_id)
        self._generations.pop(thread_id, None)
        self._cwd.pop(thread_id, None)
        self._hook_events.pop(thread_id, None)
        self._items = {key: item for key, item in self._items.items() if key[0] != thread_id}

    def _rpc(self, method, params, timeout=3):
        with self._lock:
            self._sequence += 1
            request_id = "tapproval-%d" % self._sequence
            done, result = threading.Event(), {}
            self._responses[request_id] = (done, result)
            sock = self._socket
        try:
            if sock is None:
                raise OSError("Codex disconnected")
            sock.send({"id": request_id, "method": method, "params": params})
            if not done.wait(timeout) or "result" not in result:
                error = result.get("error") or {}
                if isinstance(error, dict) and error.get("message"):
                    raise OSError("Codex rejected %s: %s" % (method, error["message"]))
                raise OSError("Codex did not accept %s" % method)
            return result["result"]
        finally:
            with self._lock:
                self._responses.pop(request_id, None)

    def attach(self, thread_id, approval=None):
        """True only after this client has joined that already-loaded thread."""
        if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 64:
            return False
        # Serialize initial handshakes/resumes, not the reader or watch answers.
        with self._rpc_lock:
            try:
                with self._lock:
                    if (isinstance(approval, dict) and approval.get("session_id") == thread_id
                            and approval.get("tool_name") == "apply_patch"):
                        events = self._hook_events.setdefault(thread_id, [])
                        if approval not in events:
                            events.append(approval)
                            del events[:-32]
                    if thread_id in self._attached and self._socket is not None:
                        self._generations[thread_id] += 1
                        return True
                self._ensure_connection()
                cursor = None
                while True:
                    page = self._rpc("thread/loaded/list", {"cursor": cursor})
                    if thread_id in page.get("data", []):
                        break
                    cursor = page.get("nextCursor")
                    if not cursor:
                        self.last_error = "Thread is not loaded on this Codex server"
                        self.status(self.last_error)
                        return False
                # No config/model/permission overrides: join the live session.
                # Register the lease before sending: resume can replay a request
                # and its resolution immediately after its response, before the
                # waiting caller gets CPU time to observe that response.
                with self._lock:
                    self._attached.add(thread_id)
                    self._generations[thread_id] = self._generations.get(thread_id, 0) + 1
                self._rpc("thread/resume", {"threadId": thread_id, "excludeTurns": True})
                with self._lock:
                    if self._socket is None:
                        return False
                return True
            except (OSError, ValueError, EOFError, TypeError, KeyError, AttributeError) as error:
                self.last_error = str(error)
                self.close()
                self.status(self.last_error)
                return False

    def _read(self, sock):
        try:
            while True:
                self.handle(sock.receive(), sock)
        except (OSError, ValueError, EOFError, TypeError, KeyError, AttributeError):
            pass
        finally:
            with self._lock:
                if self._socket is sock:
                    self.close()

    def handle(self, message, sock):
        with self._lock:
            if self._socket is not sock:
                return
            request_id = message.get("id")
            if "method" not in message:
                waiting = self._responses.get(request_id)
                if waiting:
                    result = message.get("result")
                    if isinstance(result, dict) and isinstance(result.get("thread"), dict):
                        identity, cwd = result["thread"].get("id"), result.get("cwd")
                        if isinstance(identity, str) and isinstance(cwd, str):
                            self._cwd[identity] = cwd
                    waiting[1].update(message)
                    waiting[0].set()
                return
            method, params = message["method"], message.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("expected JSON-RPC params object")
            thread_id = params.get("threadId")
            if method == "serverRequest/resolved":
                identity = params.get("requestId")
                if isinstance(thread_id, str) and type(identity) in (str, int):
                    self._finish((thread_id, identity))
            elif method == "item/started" and isinstance(params.get("item"), dict):
                item = params["item"]
                if item.get("type") in ("fileChange", "mcpToolCall"):
                    self._items[(thread_id, item.get("id"))] = item
            elif method == "item/completed":
                item_id = (params.get("item") or {}).get("id")
                self._items.pop((thread_id, item_id), None)
                for key, item in list(self._request_items.items()):
                    if key[0] == thread_id and item == item_id:
                        self._finish(key)
            elif method == "thread/closed":
                self._finish_thread(thread_id)
            elif method == "turn/completed" and thread_id in self._attached:
                turn_id = (params.get("turn") or {}).get("id")
                self._hook_events[thread_id] = [event for event in self._hook_events.get(thread_id, [])
                                                if event.get("turn_id") != turn_id]
                for key, (_done, pending_turn) in list(self._pending.items()):
                    if key[0] == thread_id and pending_turn == turn_id:
                        self._finish(key)
                # Don't keep a closed desktop conversation loaded merely
                # because its last permission request once visited a watch.
                generation = self._generations[thread_id]
                threading.Thread(target=self._release, args=(thread_id, generation),
                                 name="codex-detach", daemon=True).start()
            elif (method in APPROVAL_METHODS or method.endswith("/requestApproval")
                  or (method == "item/tool/requestUserInput" and
                      self._items.get((thread_id, params.get("itemId")), {}).get("type") == "mcpToolCall")):
                if (type(request_id) not in (str, int) or not isinstance(thread_id, str)
                        or not thread_id or thread_id not in self._attached):
                    return
                key = (thread_id, request_id)
                if key in self._pending or key in self._finished:
                    return
                if not params.get("cwd"):
                    message = dict(message, params=dict(params, cwd=self._cwd.get(thread_id)))
                if (method == "item/fileChange/requestApproval"
                        and all(isinstance(params.get(k), str) and params[k]
                                for k in ("turnId", "itemId")) and (
                        thread_id, params.get("itemId")) not in self._items):
                    done = threading.Event()
                    self._pending[key] = (done, params.get("turnId"))
                    self._request_items[key] = params.get("itemId")
                    self._trace("received", key, method)
                    threading.Thread(target=self._fetch_file, args=(key, message, done, sock),
                                     name="codex-file-card", daemon=True).start()
                    return
                card = approval_card(message, self._items.get((thread_id, params.get("itemId"))))
                if card is None:
                    card = handoff_card(message)
                done = threading.Event()
                self._pending[key] = (done, params.get("turnId"))
                self._request_items[key] = params.get("itemId")
                self._trace("received", key, method)
                threading.Thread(target=self._mirror, args=(key, card, done, sock, denial_action(params)),
                                 name="codex-card", daemon=True).start()

    def _fetch_file(self, key, message, done, sock):
        # Joining during a permission hook may miss the earlier item/started.
        # Read that exact native item; never borrow another concurrent edit's
        # paths or reconstruct a second session from a rollout file.
        params = message["params"]
        cursor = None
        try:
            for _ in range(4):
                if done.is_set():
                    return
                page = self._rpc("thread/items/list", {
                    "threadId": key[0], "turnId": params["turnId"],
                    "limit": 100, "sortDirection": "desc", "cursor": cursor})
                for entry in page.get("data", []):
                    item = entry.get("item") or {}
                    if item.get("id") == params["itemId"] and item.get("type") == "fileChange":
                        card = approval_card(message, item)
                        if not done.is_set():
                            self._mirror(key, card or handoff_card(message), done, sock, denial_action(params))
                        return
                cursor = page.get("nextCursor")
                if not cursor:
                    break
            with self._lock:
                events = list(self._hook_events.get(key[0], []))
            for event in events:
                card = approval_card(message, hook_event=event)
                if card is not None:
                    if not done.is_set():
                        self._mirror(key, card, done, sock, denial_action(params))
                    return
        except (OSError, EOFError, ValueError, TypeError, AttributeError):
            pass
        # Missing/unrenderable details are not a reason to silently omit
        # an actual native approval. Never guess an answer from hook text.
        self._mirror(key, handoff_card(message), done, sock)

    def _release(self, thread_id, generation):
        with self._rpc_lock:
            with self._lock:
                # A newer permission hook may already have re-used this
                # subscription for the next turn. Its lease must survive.
                if self._generations.get(thread_id) != generation:
                    return
                if any(key[0] == thread_id for key in self._pending):
                    return
                self._attached.discard(thread_id)
                self._generations.pop(thread_id, None)
                self._cwd.pop(thread_id, None)
                self._hook_events.pop(thread_id, None)
                self._items = {key: value for key, value in self._items.items()
                               if key[0] != thread_id}
                if not self._attached and self._monitor is None:
                    self.close()
                    return
            try:
                self._rpc("thread/unsubscribe", {"threadId": thread_id})
            except (OSError, EOFError, ValueError):
                # Older servers may not support unsubscribe. Closing the
                # shared socket after its last active turn still detaches all.
                pass

    def _mirror(self, key, card, done, sock, refusal="decline"):
        try:
            if done.is_set():
                return
            card = dict(self.card_title(card), post_id=self._card_id(key))
            _card_id, decision, _answer = self.queue.submit(
                card, float("inf"), resolved_elsewhere=done.is_set, admission_lock=self._lock)
            with self._lock:
                if (decision in ("allow", "deny") and not done.is_set()
                        and card.get("kind") != "handoff"
                        and self._socket is sock
                        and self._pending.get(key, (None, None))[0] is done):
                    sock.send({"id": key[1], "result": {
                        "decision": "accept" if decision == "allow" else refusal}})
                    self._audit_answer(card, decision)
        except (OSError, ValueError, EOFError):
            self.close()

    @staticmethod
    def _audit_answer(card, decision):
        """The native hook returns before the wrist answers; record its receipt.

        This is not a second permission request. The dashboard joins it to
        its counts as a watch answer only, including for older watch clients.
        """
        from datetime import datetime, timezone
        import ClaudeRiskClassifier as classifier
        classifier.write_audit({
            "ts": datetime.now(timezone.utc).isoformat(), "agent": "codex",
            "audit_type": "watch_receipt", "session_id": card.get("session_id"),
            "decision": "receipt", "mode": "enforce", "watch": decision,
            "tier": card.get("tier"), "headline": card.get("headline", ""),
            "project": card.get("project", ""),
        }, classifier.load_policy())

    def close(self):
        with self._lock:
            sock, self._socket = self._socket, None
            self._attached.clear()
            self._generations.clear()
            self._items.clear()
            self._cwd.clear()
            self._hook_events.clear()
            for key in list(self._pending):
                self._finish(key, terminal=False)
            for done, _result in self._responses.values():
                done.set()
            if sock is not None:
                sock.close()
