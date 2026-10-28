"""Native approval synchronization: one server request, two answering clients."""
import io
import base64
import hashlib
import json
import queue
import threading
import time

import pytest

import ClaudeRiskClassifier as classifier
from codex_approvals import ApprovalSync, LocalWebSocket, MAX_MESSAGE, approval_card
from watch_relay import CardQueue


def request(request_id=10, command="rm -r build", thread="thread-1"):
    return {"id": request_id, "method": "item/commandExecution/requestApproval",
            "params": {"threadId": thread, "turnId": "turn-1", "itemId": "item-1",
                       "command": command, "cwd": "/repo"}}


def until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail("synchronization did not settle")
        threading.Event().wait(.005)


class Wire:
    def __init__(self, loaded=None):
        self.incoming = queue.Queue()
        self.sent = []
        self.loaded = ["thread-1"] if loaded is None else loaded
        self.closed = False
        self.file_item = None
        self.complete_during_resume = False
        self.statuses = {}
        self.replay = []

    def send(self, message):
        self.sent.append(message)
        if message.get("method") == "initialize":
            result = {"userAgent": "test"}
        elif message.get("method") == "thread/loaded/list":
            result = {"data": self.loaded, "nextCursor": None}
        elif message.get("method") == "thread/resume":
            result = {"thread": {"id": message["params"]["threadId"]}}
            for event in self.replay:
                self.incoming.put(event)
            if self.complete_during_resume:
                self.incoming.put({"method": "turn/completed", "params": {
                    "threadId": message["params"]["threadId"], "turn": {"id": "turn-1"}}})
        elif message.get("method") == "thread/items/list":
            result = {"data": [{"item": self.file_item}] if self.file_item else [], "nextCursor": None}
        elif message.get("method") == "thread/read":
            sid = message["params"]["threadId"]
            result = {"thread": {"id": sid, "status": self.statuses.get(sid, {"type": "idle"})}}
        elif message.get("method") == "thread/unsubscribe":
            result = {}
        else:
            return
        self.incoming.put({"id": message["id"], "result": result})

    def receive(self):
        message = self.incoming.get(timeout=5)
        if message is None:
            raise EOFError()
        return message

    def close(self):
        self.closed = True
        self.incoming.put(None)


@pytest.fixture
def sync(monkeypatch):
    # Native watch receipts are durable in production, never in the owner's log here.
    monkeypatch.setattr(classifier, "write_audit", lambda *_args: None)
    wire, cards = Wire(), CardQueue()
    cards.PROBE_SECONDS = .01
    adapter = ApprovalSync(cards, connect=lambda: wire)
    assert adapter.attach("thread-1")
    yield adapter, wire, cards
    adapter.close()
    until(lambda: not cards.pending())


def resolved(wire, request_id=10, thread="thread-1"):
    wire.incoming.put({"method": "serverRequest/resolved", "params": {
        "threadId": thread, "requestId": request_id}})


def test_attaches_to_existing_session_without_starting_or_changing_it(sync):
    adapter, wire, _cards = sync
    assert [m.get("method") for m in wire.sent] == [
        "initialize", "initialized", "thread/loaded/list", "thread/resume"]
    assert wire.sent[-1]["params"] == {"threadId": "thread-1", "excludeTurns": True}
    assert adapter.attach("thread-1")
    assert len(wire.sent) == 4


def test_wrong_server_never_resumes_a_stored_conversation():
    wire = Wire(loaded=[])
    adapter = ApprovalSync(CardQueue(), connect=lambda: wire)
    try:
        assert adapter.attach("thread-1") is False
        assert not any(m.get("method") == "thread/resume" for m in wire.sent)
    finally:
        adapter.close()


def test_resolution_replayed_during_attach_does_not_leave_idle_subscription():
    wire = Wire()
    wire.complete_during_resume = True
    adapter = ApprovalSync(CardQueue(), connect=lambda: wire)
    try:
        adapter.attach("thread-1")
        until(lambda: wire.closed)
        assert not adapter._attached
    finally:
        adapter.close()


@pytest.mark.parametrize("answer,decision", [("allow", "accept"), ("deny", "decline")])
def test_watch_answers_same_native_request_once(sync, answer, decision):
    _adapter, wire, cards = sync
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    card = cards.pending()[0]
    assert card["agent"] == "codex"
    assert cards.decide(card["id"], answer)
    until(lambda: any("result" in m for m in wire.sent))
    assert [m for m in wire.sent if "result" in m] == [
        {"id": 10, "result": {"decision": decision}}]
    resolved(wire)
    until(lambda: not cards.pending())
    assert not cards.decide(card["id"], "allow")


def test_phone_answer_retracts_watch_and_late_watch_tap_does_nothing(sync):
    _adapter, wire, cards = sync
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    card_id = cards.pending()[0]["id"]
    resolved(wire)
    until(lambda: not cards.pending())
    assert cards.decide(card_id, "allow") is False
    assert not any("result" in m for m in wire.sent)


def test_cancel_only_native_prompt_has_truthful_label_and_stops_turn(sync):
    _adapter, wire, cards = sync
    message = request()
    message["params"]["availableDecisions"] = ["accept", "cancel"]
    wire.incoming.put(message)
    until(lambda: len(cards.pending()) == 1)
    card = cards.pending()[0]
    assert card["deny_label"] == "No, stop this turn"
    assert cards.decide(card["id"], "deny")
    until(lambda: any("result" in m for m in wire.sent))
    assert [m for m in wire.sent if "result" in m] == [{"id": 10, "result": {"decision": "cancel"}}]
    resolved(wire)


def test_decline_is_preferred_when_codex_also_offers_cancel():
    message = request()
    message["params"]["availableDecisions"] = ["accept", "decline", "cancel"]
    assert approval_card(message)["deny_label"] == "No, continue without running it"


def test_replayed_request_does_not_duplicate_watch_card(sync):
    _adapter, wire, cards = sync
    wire.incoming.put(request())
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    assert len(cards.pending()) == 1


def test_resolution_is_scoped_to_thread_and_request(sync):
    _adapter, wire, cards = sync
    wire.incoming.put(request())
    wire.incoming.put(request(11, command="git push --force"))
    until(lambda: len(cards.pending()) == 2)
    resolved(wire, thread="another-thread")
    resolved(wire, 11)
    until(lambda: len(cards.pending()) == 1)
    assert cards.pending()[0]["detail"] == "rm -r build"


def test_disconnect_removes_cards_and_never_sends_an_answer(sync):
    adapter, wire, cards = sync
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    wire.incoming.put(None)
    until(lambda: not cards.pending())
    assert not adapter._attached
    assert not any("result" in m for m in wire.sent)


def test_finished_turn_releases_subscription_without_keeping_session_alive(sync):
    adapter, wire, _cards = sync
    wire.incoming.put({"method": "turn/completed", "params": {"threadId": "thread-1"}})
    until(lambda: wire.closed)
    assert not adapter._attached


def test_new_hook_lease_cannot_be_removed_by_old_turn_cleanup(sync):
    adapter, wire, _cards = sync
    generation = adapter._generations["thread-1"]
    assert adapter.attach("thread-1")
    adapter._release("thread-1", generation)
    assert "thread-1" in adapter._attached
    assert not wire.closed


def test_interrupted_turn_retracts_its_card_even_without_resolution_event(sync):
    _adapter, wire, cards = sync
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    wire.incoming.put({"method": "turn/completed", "params": {
        "threadId": "thread-1", "turn": {"id": "turn-1", "status": "interrupted"}}})
    until(lambda: not cards.pending())
    assert not any("result" in m for m in wire.sent)


def test_missing_socket_falls_back_to_hook():
    def unavailable():
        raise OSError("socket unavailable")
    assert not ApprovalSync(CardQueue(), connect=unavailable).attach("thread-1")


def test_unknown_decision_options_stay_with_codex():
    message = request()
    message["params"]["availableDecisions"] = ["acceptForSession", "cancel"]
    assert approval_card(message) is None


@pytest.mark.parametrize("tool", ["Bash", "apply_patch", "write_stdin", "mcp__custom__write"])
@pytest.mark.parametrize("attached", [True, False])
@pytest.mark.parametrize("policy_change", [dict(auto_allow_at_or_below="CRITICAL"),
                                          dict(critical_action="deny")])
def test_codex_hook_never_overrides_native_policy(monkeypatch, tool, attached, policy_change):
    monkeypatch.setattr(classifier, "load_policy", lambda *a: dict(
        classifier.DEFAULT_POLICY, mode="enforce", relay="http://127.0.0.1:1", **policy_change))
    monkeypatch.setattr(classifier, "prepare_codex_sync", lambda *a: attached)
    monkeypatch.setattr(classifier, "write_audit", lambda *a: None)
    monkeypatch.setattr(classifier, "ask_watch", lambda *a, **kw: pytest.fail("watch-only approval"))
    output = io.StringIO()
    classifier.run_hook(stdin=io.StringIO(json.dumps({"hook_event_name": "PermissionRequest",
        "tool_name": tool, "session_id": "thread-1",
        "tool_input": {"command": "rm -rf /"}})), stdout=output, agent="codex")
    assert json.loads(output.getvalue()) == classifier.ESCALATE_FALLBACK


@pytest.mark.parametrize("method,extra", [
    ("mcpServer/elicitation/request", {"serverName": "example", "mode": "form",
                                    "message": "Approve this action?"}),
    ("mcpServer/elicitation/request", {"serverName": "example", "mode": "url",
                                    "url": "https://example.invalid/private-token"}),
    ("mcpServer/elicitation/request", {"mode": "openai/userVerification", "challenge": "secret"}),
    ("item/permissions/requestApproval", {"permissions": {"network": {"enabled": True}}}),
    ("item/commandExecution/requestApproval", {"networkApprovalContext": {"host": "example.invalid"}}),
    ("item/commandExecution/requestApproval", {"additionalPermissions": {"network": {"enabled": True}}}),
    ("item/commandExecution/requestApproval", {"availableDecisions": ["acceptForSession", "cancel"]}),
    ("item/future/requestApproval", {}),
])
def test_complex_native_request_has_one_non_answerable_card(sync, method, extra):
    _adapter, wire, cards = sync
    event = request()
    event["method"] = method
    event["params"].update(extra)
    wire.incoming.put(event)
    until(lambda: len(cards.pending()) == 1)
    card = cards.pending()[0]
    assert card["kind"] == "handoff" and card["alert"] == "ask"
    assert "private-token" not in json.dumps(card) and "secret" not in json.dumps(card)
    assert not cards.decide(card["id"], "allow")
    assert not cards.decide(card["id"], "deny")
    assert not any("result" in m for m in wire.sent)
    resolved(wire)
    until(lambda: not cards.pending())


def test_standalone_mcp_request_needs_no_turn_or_item_id(sync):
    _adapter, wire, cards = sync
    wire.incoming.put({"id": "consent", "method": "mcpServer/elicitation/request", "params": {
        "threadId": "thread-1", "serverName": "example", "mode": "form", "message": "Approve?"}})
    until(lambda: len(cards.pending()) == 1)
    resolved(wire, "consent")
    until(lambda: not cards.pending())


def test_agent_question_is_not_an_approval_but_mcp_consent_is(sync):
    _adapter, wire, cards = sync
    question = request()
    question["method"] = "item/tool/requestUserInput"
    _adapter.handle(question, wire)
    assert not cards.pending() and not _adapter._pending
    wire.incoming.put({"method": "item/started", "params": {
        "threadId": "thread-1", "item": {"id": "item-1", "type": "mcpToolCall"}}})
    wire.incoming.put(question)
    until(lambda: len(cards.pending()) == 1)
    assert cards.pending()[0]["kind"] == "handoff"
    resolved(wire)


def test_resolved_replay_cannot_recreate_a_card(sync):
    adapter, wire, cards = sync
    wire.incoming.put(request())
    until(lambda: len(cards.pending()) == 1)
    adapter.handle({"method": "serverRequest/resolved", "params": {
        "threadId": "thread-1", "requestId": 10}}, wire)
    assert cards.pending() == [], "resolution must remove the card synchronously"
    adapter.handle(request(), wire)
    assert not adapter._pending and not cards.pending()


def test_resolution_during_queue_admission_never_publishes(sync, monkeypatch, capsys):
    adapter, wire, cards = sync
    entered, release, exited = threading.Event(), threading.Event(), threading.Event()
    submit = cards.submit

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        result = submit(*args, **kwargs)
        exited.set()
        return result

    monkeypatch.setattr(cards, "submit", delayed)
    adapter.handle(request(), wire)
    assert entered.wait(2)
    adapter.handle({"method": "serverRequest/resolved", "params": {
        "threadId": "thread-1", "requestId": 10}}, wire)
    release.set()
    assert exited.wait(2)
    assert not cards.pending()
    assert "relay: queued" not in capsys.readouterr().err


def test_many_native_requests_and_integer_vs_string_ids_remain_distinct(sync):
    adapter, wire, cards = sync
    ids = list(range(48)) + ["0"]
    for identity in ids:
        adapter.handle(request(request_id=identity), wire)
    until(lambda: len(cards.pending()) == len(ids))
    assert len({c["id"] for c in cards.pending()}) == len(ids)
    for identity in ids:
        adapter.handle({"method": "serverRequest/resolved", "params": {
            "threadId": "thread-1", "requestId": identity}}, wire)
    assert not cards.pending()


def test_unattached_session_cannot_inject_an_approval(sync):
    adapter, wire, cards = sync
    adapter.handle(request(thread="unrelated"), wire)
    assert not adapter._pending and not cards.pending()


def test_reconciliation_recovers_only_loaded_waiting_sessions(monkeypatch):
    monkeypatch.setattr(classifier, "write_audit", lambda *_a: None)
    wire, cards = Wire(loaded=["waiting", "idle"]), CardQueue()
    wire.statuses["waiting"] = {"type": "active", "activeFlags": ["waitingOnApproval"]}
    wire.replay = [request(thread="waiting")]
    adapter = ApprovalSync(cards, connect=lambda: wire)
    try:
        adapter.reconcile()
        until(lambda: len(cards.pending()) == 1)
        resumes = [m["params"]["threadId"] for m in wire.sent if m.get("method") == "thread/resume"]
        assert resumes == ["waiting"]
        assert cards.pending()[0]["session_id"] == "waiting"
    finally:
        adapter.close()


def test_reconnect_reuses_pending_card_identity_and_keeps_resolved_tombstones(monkeypatch):
    monkeypatch.setattr(classifier, "write_audit", lambda *_a: None)
    first, second, third = Wire(), Wire(), Wire()
    connections = iter([first, second, third])
    cards = CardQueue()
    adapter = ApprovalSync(cards, connect=lambda: next(connections))
    try:
        assert adapter.attach("thread-1")
        adapter.handle(request(), first)
        until(lambda: len(cards.pending()) == 1)
        card_id = cards.pending()[0]["id"]
        adapter.close()
        assert not cards.pending()
        assert adapter.attach("thread-1")
        adapter.handle(request(), second)
        until(lambda: len(cards.pending()) == 1)
        assert cards.pending()[0]["id"] == card_id
        adapter.handle({"method": "serverRequest/resolved", "params": {
            "threadId": "thread-1", "requestId": 10}}, second)
        adapter.close()
        assert adapter.attach("thread-1")
        adapter.handle(request(), third)
        assert not cards.pending() and not adapter._pending
    finally:
        adapter.close()


def test_connection_notice_reports_failure_and_recovery():
    import watch_relay as relay
    relay._codex_sync_status("unavailable")
    assert "codex_sync" in relay._CONDITIONS
    relay._codex_sync_status(None)
    assert "codex_sync" not in relay._CONDITIONS


def test_terminal_input_is_a_native_approval_with_its_own_description(sync):
    _adapter, wire, cards = sync
    message = request(command="\n")
    message["params"].update(kind="writeStdin", approvalId="stdin-callback",
                             availableDecisions=["accept", "cancel"])
    wire.incoming.put(message)
    until(lambda: len(cards.pending()) == 1)
    card = cards.pending()[0]
    assert card["headline"] == "Send input to terminal"
    assert card["tier"] == "MEDIUM"
    assert card["deny_label"] == "No, stop this turn"
    assert cards.decide(card["id"], "allow")
    until(lambda: any(m.get("id") == 10 and m.get("result") == {"decision": "accept"}
                      for m in wire.sent))
    resolved(wire)


def test_joining_during_file_hook_fetches_the_exact_native_file_item(sync):
    _adapter, wire, cards = sync
    wire.file_item = {"id": "item-1", "type": "fileChange", "changes": [
        {"path": "/repo/app.py", "kind": {"type": "update"}, "diff": "+x"}]}
    message = request()
    message["method"] = "item/fileChange/requestApproval"
    wire.incoming.put(message)
    until(lambda: len(cards.pending()) == 1)
    assert "app.py" in cards.pending()[0]["headline"]
    rpc = next(m for m in wire.sent if m.get("method") == "thread/items/list")
    assert rpc["params"]["threadId"] == "thread-1"
    assert rpc["params"]["turnId"] == "turn-1"
    resolved(wire)
    until(lambda: not cards.pending())


def file_hook(tmp_path):
    patch = "*** Begin Patch\n*** Add File: /repo/app.py\n+approved\n*** End Patch"
    path = tmp_path / "rollout.jsonl"
    rows = [{"type": "session_meta", "payload": {"id": "thread-1"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call",
             "name": "apply_patch", "call_id": "item-1", "input": patch,
             "internal_chat_message_metadata_passthrough": {"turn_id": "turn-1"}}}]
    path.write_text("\n".join(map(json.dumps, rows)) + "\n")
    return {"session_id": "thread-1", "turn_id": "turn-1", "tool_name": "apply_patch",
            "transcript_path": str(path), "tool_input": {"command": patch}, "cwd": "/repo"}


def test_pending_file_card_uses_exact_hook_call_before_history_is_persisted(sync, tmp_path):
    adapter, wire, cards = sync
    assert adapter.attach("thread-1", approval=file_hook(tmp_path))
    message = request()
    message["method"] = "item/fileChange/requestApproval"
    wire.incoming.put(message)
    until(lambda: len(cards.pending()) == 1)
    assert "app.py" in cards.pending()[0]["headline"]
    assert "/repo/app.py" in cards.pending()[0]["detail"]
    resolved(wire)
    until(lambda: not cards.pending())


@pytest.mark.parametrize("mismatch", ["session_id", "turn_id", "itemId", "command", "metadata", "malformed"])
def test_file_hook_never_borrows_another_edit(tmp_path, mismatch):
    event = file_hook(tmp_path)
    message = request()
    message["method"] = "item/fileChange/requestApproval"
    if mismatch in ("session_id", "turn_id"):
        event[mismatch] = "another"
    elif mismatch == "itemId":
        message["params"]["itemId"] = "another"
    elif mismatch == "command":
        event["tool_input"]["command"] += "\n+another"
    elif mismatch == "metadata":
        path = tmp_path / "rollout.jsonl"
        path.write_text(path.read_text().replace('"id": "thread-1"', '"id": "another"'))
    else:
        event["tool_input"] = "invalid"
    assert approval_card(message, hook_event=event) is None


def test_native_attach_route_requires_local_bootstrap_proof():
    from watch_relay import RelayHandler
    _handler, rules = RelayHandler.ROUTES["POST"]["/codex/attach"]
    assert rules == {"local": True, "lan_only": True, "key_file": True}


def test_hook_without_relay_configuration_cannot_attach():
    assert not classifier.prepare_codex_sync({"tool_name": "mcp__custom__tool"}, {})


def test_file_approval_requires_actual_changed_paths():
    message = request()
    message["method"] = "item/fileChange/requestApproval"
    assert approval_card(message) is None
    item = {"changes": [{"path": "/repo/app.py", "kind": {"type": "update"}, "diff": "+x"}]}
    card = approval_card(message, item)
    assert card["tool"] == "apply_patch"
    assert "app.py" in card["headline"]


def test_file_approval_keeps_content_risk_and_rename_destination():
    message = request()
    message["method"] = "item/fileChange/requestApproval"
    item = {"changes": [{"path": "/repo/migrate.sql", "kind": {
        "type": "update", "move_path": "/repo/new.sql"}, "diff": "+DROP TABLE users;"}]}
    card = approval_card(message, item)
    assert card["tier"] == "CRITICAL"
    assert "new.sql" in card["detail"]


class HandshakeSocket:
    def __init__(self, frames=b"", bad_accept=False):
        self.data = bytearray()
        self.frames = frames
        self.bad_accept = bad_accept
        self.writes = []
        self.closed = False

    def settimeout(self, timeout):
        pass

    def connect(self, path):
        pass

    def sendall(self, data):
        self.writes.append(data)
        if data.startswith(b"GET "):
            key = data.split(b"Sec-WebSocket-Key: ")[1].split(b"\r\n")[0]
            accept = base64.b64encode(hashlib.sha1(
                key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
            if self.bad_accept:
                accept = b"untrusted"
            self.data.extend(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n" + self.frames)

    def recv(self, size):
        data = bytes(self.data[:min(size, 7)])
        del self.data[:len(data)]
        return data

    def shutdown(self, *args):
        pass

    def close(self):
        self.closed = True


def websocket(monkeypatch, frames=b"", bad_accept=False):
    fake = HandshakeSocket(frames, bad_accept)
    monkeypatch.setattr("codex_approvals.socket.socket", lambda *a: fake)
    # The frames are this test's subject, not the socket family: a host
    # without Unix sockets still reads them through the fake.
    monkeypatch.setattr("codex_approvals.socket.AF_UNIX", 1, raising=False)
    return LocalWebSocket("/test/socket"), fake


def test_websocket_fragmentation_and_ping_preserve_json_message(monkeypatch):
    conn, fake = websocket(monkeypatch, b'\x01\x05{"id"\x89\x01?\x80\x03:1}')
    assert conn.receive() == {"id": 1}
    assert fake.writes[-1][0] == 138  # masked pong, not a JSON-RPC response
    conn.close()


def test_websocket_sends_masked_text_with_exact_payload(monkeypatch):
    conn, fake = websocket(monkeypatch)
    conn.send({"hello": "world"})
    frame = fake.writes[-1]
    assert frame[0] == 129 and frame[1] & 128
    mask = frame[2:6]
    payload = bytes(c ^ mask[i % 4] for i, c in enumerate(frame[6:]))
    assert json.loads(payload) == {"hello": "world"}
    conn.close()


def test_websocket_refuses_invalid_handshake(monkeypatch):
    with pytest.raises(ValueError, match="handshake"):
        websocket(monkeypatch, bad_accept=True)


def test_websocket_refuses_oversized_frame_before_reading_it(monkeypatch):
    import struct
    conn, _fake = websocket(monkeypatch, b"\x81\x7f" + struct.pack("!Q", MAX_MESSAGE + 1))
    with pytest.raises(ValueError, match="oversized"):
        conn.receive()
    conn.close()


@pytest.mark.parametrize("tamper", [False, True])
@pytest.mark.parametrize("tool", ["Bash", "mcp__custom__tool"])
def test_native_handoff_requires_relay_proof(monkeypatch, tamper, tool):
    raw = b'{"attached":true}'
    proof = classifier._relay_proof2("key", "nonce", 200, raw)

    class Reply:
        status = 200
        headers = {"X-Tapproval-Proof2": "forged" if tamper else proof}

        def read(self):
            return raw

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(classifier, "_relay_key", lambda policy: "key")
    monkeypatch.setattr(classifier.wire, "signed_header", lambda *a: ("sig", "nonce"))
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: Reply())
    assert classifier.prepare_codex_sync({"session_id": "thread-1", "tool_name": tool}, {
        "relay": "http://127.0.0.1:8977"}) is (not tamper)


def test_native_handoff_returns_no_hook_decision(monkeypatch):
    monkeypatch.setattr(classifier, "load_policy", lambda *a: dict(
        classifier.DEFAULT_POLICY, mode="enforce", relay="http://127.0.0.1:8977"))
    monkeypatch.setattr(classifier, "prepare_codex_sync", lambda *a: True)
    monkeypatch.setattr(classifier, "write_audit", lambda *a: None)
    monkeypatch.setattr(classifier, "ask_watch", lambda *a, **kw: pytest.fail("blocking hook used"))
    output = io.StringIO()
    classifier.run_hook(stdin=io.StringIO(json.dumps({"tool_name": "Bash",
        "session_id": "thread-1", "tool_input": {"command": "rm -r build"}})),
        stdout=output, agent="codex")
    assert "decision" not in json.loads(output.getvalue()).get("hookSpecificOutput", {})


def test_unavailable_native_handoff_never_creates_watch_only_approval(monkeypatch):
    monkeypatch.setattr(classifier, "load_policy", lambda *a: dict(
        classifier.DEFAULT_POLICY, mode="enforce", relay="http://127.0.0.1:8977"))
    monkeypatch.setattr(classifier, "prepare_codex_sync", lambda *a: False)
    monkeypatch.setattr(classifier, "write_audit", lambda *a: None)
    monkeypatch.setattr(classifier, "ask_watch", lambda *a, **kw: pytest.fail("watch-only approval"))
    output = io.StringIO()
    classifier.run_hook(stdin=io.StringIO(json.dumps({"tool_name": "Bash",
        "session_id": "thread-1", "tool_input": {"command": "rm -r build"}})),
        stdout=output, agent="codex")
    assert "decision" not in json.loads(output.getvalue())["hookSpecificOutput"]


@pytest.mark.parametrize("verdict", ["allow", "deny"])
def test_claude_watch_answers_never_enter_codex_adapter(monkeypatch, verdict):
    monkeypatch.setattr(classifier, "load_policy", lambda *a: dict(
        classifier.DEFAULT_POLICY, mode="enforce", auto_allow="NONE",
        relay="http://127.0.0.1:8977"))
    monkeypatch.setattr(classifier, "prepare_codex_sync",
                        lambda *a: pytest.fail("Claude approval entered Codex adapter"))
    monkeypatch.setattr(classifier, "write_audit", lambda *a: None)
    monkeypatch.setattr(classifier, "matches_user_allowlist", lambda *a: False)
    monkeypatch.setattr(classifier, "ask_watch", lambda *a, **kw: (verdict, None))
    output = io.StringIO()
    classifier.run_hook(stdin=io.StringIO(json.dumps({"tool_name": "Bash",
        "session_id": "claude-session", "tool_input": {"command": "rm -r build"}})),
        stdout=output)
    assert json.loads(output.getvalue())["hookSpecificOutput"]["decision"]["behavior"] == verdict


def test_same_native_id_in_different_active_sessions_is_independent(sync):
    adapter, wire, cards = sync
    wire.loaded.append("thread-2")
    assert adapter.attach("thread-2")
    adapter.handle(request(), wire)
    adapter.handle(request(thread="thread-2"), wire)
    until(lambda: len(cards.pending()) == 2)
    assert len({card["id"] for card in cards.pending()}) == 2
    adapter.handle({"method": "serverRequest/resolved", "params": {
        "threadId": "thread-1", "requestId": 10}}, wire)
    assert [card["session_id"] for card in cards.pending()] == ["thread-2"]


def test_review_notifications_do_not_create_human_approval_cards(sync):
    adapter, wire, cards = sync
    for method in ("item/started", "item/completed"):
        adapter.handle({"method": method, "params": {"threadId": "thread-1",
            "item": {"id": "review", "type": "commandExecution", "status": "completed"}}}, wire)
    assert not adapter._pending and not cards.pending()


def test_legacy_codex_hook_post_cannot_create_an_extra_card():
    from types import SimpleNamespace
    from watch_relay import RelayHandler
    replies = []
    handler = SimpleNamespace(_read_json=lambda: {"card": {"agent": "codex"}},
                              _send_json=lambda body: replies.append(body))
    RelayHandler._post_card(handler, "/card", {})
    assert replies == [{"id": "", "decision": "none"}]


def test_new_server_epoch_can_reuse_a_resolved_native_request_id(monkeypatch):
    from types import SimpleNamespace
    first, second = Wire(), Wire()
    connections = iter([first, second])
    cards = CardQueue()
    adapter = ApprovalSync(cards, connect=lambda: next(connections))
    adapter._custom_connect = False
    inode = [1]
    import codex_approvals
    monkeypatch.setattr(codex_approvals, "os", SimpleNamespace(
        path=codex_approvals.os.path, environ=codex_approvals.os.environ,
        stat=lambda _path: SimpleNamespace(st_dev=1, st_ino=inode[0])))
    try:
        assert adapter.attach("thread-1")
        adapter.handle(request(), first)
        until(lambda: len(cards.pending()) == 1)
        old_id = cards.pending()[0]["id"]
        adapter.handle({"method": "serverRequest/resolved", "params": {
            "threadId": "thread-1", "requestId": 10}}, first)
        adapter.close()
        inode[0] = 2
        assert adapter.attach("thread-1")
        adapter.handle(request(), second)
        until(lambda: len(cards.pending()) == 1)
        assert cards.pending()[0]["id"] != old_id
    finally:
        adapter.close()


class TestCodexTalkingBack:
    @pytest.fixture
    def setup(self, tmp_path, monkeypatch):
        import codex_sessions as sessions
        import codex_talk as talk
        sid = 'a0000000-0000-4000-8000-000000000001'
        home = tmp_path / 'codex'
        root = home / 'sessions'
        root.mkdir(parents=True)
        locks = home / 'thread-writer-locks'
        locks.mkdir()
        (locks / (sid + '.lock')).touch()
        workspace = tmp_path / 'workspace'
        workspace.mkdir()
        rollout = root / ('rollout-' + sid + '.jsonl')
        rollout.write_text(json.dumps({'type': 'session_meta', 'payload': {
            'id': sid, 'cwd': str(workspace), 'originator': 'codex-tui'}}) + '\n')
        monkeypatch.setenv('CODEX_HOME', str(home))
        monkeypatch.setattr(sessions, 'open_rollout_paths', lambda _paths: set())
        spawned = []
        def spawn(command, log, cwd=None):
            spawned.append((command, log, cwd))
            return ''
        class Socket:
            def __init__(self):
                self.sent = []
                self.responses = []
                self.closed = False
                self.fail = None
                self.loaded = [sid]
            def send(self, value):
                self.sent.append(value)
                method = value.get('method')
                if method == 'initialized':
                    return
                if self.fail == method:
                    self.responses.append(EOFError('closed'))
                    return
                result = {'thread/loaded/list': {'data': self.loaded, 'nextCursor': None},
                          'thread/resume': {'thread': {'id': sid}},
                          'turn/start': {'turn': {'id': 'turn-2', 'status': 'inProgress'}}}.get(method, {})
                self.responses.append({'id': value['id'], 'result': result})
            def receive(self):
                value = self.responses.pop(0)
                if isinstance(value, Exception):
                    raise value
                return value
            def close(self):
                self.closed = True
        socket = Socket()
        def unavailable():
            raise OSError('no control socket')
        def send(text='check the fix', connect=None, **kwargs):
            return talk.send(sid, text, '/bin/codex', spawn, '/tmp/isolated-say.log',
                             connect=connect or unavailable, **kwargs)
        return talk, sessions, sid, rollout, workspace, socket, spawned, send

    def test_live_reply_is_one_same_thread_mutation_with_limits(self, setup):
        talk, _, sid, _, workspace, socket, spawned, send = setup
        assert send(connect=lambda: socket) == 'sent'
        calls = [m for m in socket.sent if m.get('method') == 'turn/start']
        assert len(calls) == 1
        params = calls[0]['params']
        assert params['threadId'] == sid
        assert params['sandboxPolicy'] == talk.POLICY
        assert params['approvalPolicy'] == 'on-request'
        assert params['runtimeWorkspaceRoots'] == [str(workspace)]
        assert 'check the fix' in params['input'][0]['text']
        assert spawned == [] and socket.closed

    def test_codex_row_advertises_same_thread_sends(self, setup):
        _, sessions, _, path, _, _, _, _ = setup
        [row] = sessions.active_sessions(open_paths=[str(path)])
        assert row['can_send'] is True
        assert row['side_thread'] is False

    def test_a_moved_session_uses_its_latest_working_directory(self, setup):
        _, _, _, path, workspace, _, spawned, send = setup
        moved = workspace.parent / 'moved-workspace'
        moved.mkdir()
        workspace.rmdir()
        with path.open('a') as handle:
            handle.write(json.dumps({'type': 'turn_context', 'payload': {'cwd': str(moved)}}) + '\n')
        assert send() == 'sent'
        assert spawned[0][2] == str(moved)

    def test_lost_mutation_receipt_never_falls_back_or_retries(self, setup):
        _, _, _, _, _, socket, spawned, send = setup
        socket.fail = 'turn/start'
        assert 'check the session before retrying' in send(connect=lambda: socket)
        assert len([m for m in socket.sent if m.get('method') == 'turn/start']) == 1
        assert not spawned

    def test_saved_session_resumes_its_exact_uuid_with_bounded_permissions(self, setup):
        talk, _, sid, _, workspace, _, spawned, send = setup
        assert send('--dangerously-bypass-approvals-and-sandbox') == 'sent'
        [call] = spawned
        command, _, cwd = call
        assert cwd == str(workspace)
        assert command[:2] == ['/bin/codex', 'exec']
        assert command[2] == '--skip-git-repo-check'
        assert command[3:3 + len(talk.flags())] == talk.flags()
        assert command[-4:-1] == ['resume', sid, '--']
        assert command[-1].startswith('--dangerously-bypass-approvals-and-sandbox')

    def test_a_live_thread_on_another_server_is_never_resumed_headlessly(self, setup, monkeypatch):
        _, sessions, _, path, _, socket, spawned, send = setup
        monkeypatch.setattr(sessions, 'open_rollout_paths', lambda _: {str(path)})
        socket.loaded = []
        assert 'permission limits' in send(connect=lambda: socket)
        assert not spawned
        assert not any(m['method'] in ('thread/resume', 'turn/start') for m in socket.sent)

    @pytest.mark.parametrize('policy', [None, {}, {'approval_policy': 'never'},
        {'approval_policy': 'never', 'sandbox_policy': {'type': 'danger-full-access'}},
        {'approval_policy': 'unknown', 'sandbox_policy': {
            'type': 'workspace-write', 'network_access': False}},
        {'approval_policy': 'never', 'sandbox_policy': {
            'type': 'workspace-write', 'network_access': True}}])
    def test_queue_does_not_pretend_to_apply_limits(self, setup, monkeypatch, policy):
        talk, sessions, _, path, _, _, spawned, send = setup
        monkeypatch.setattr(sessions, 'open_rollout_paths', lambda _: {str(path)})
        with path.open('a') as handle:
            handle.write(json.dumps({'type': 'turn_context', 'payload': policy}) + '\n')
        assert not talk.queue_safe(str(path))
        assert 'permission limits' in send()
        assert not spawned

    def test_a_verified_restricted_live_queue_uses_only_its_uuid(self, setup, monkeypatch):
        import subprocess
        _, sessions, sid, path, _, _, spawned, send = setup
        monkeypatch.setattr(sessions, 'open_rollout_paths', lambda _: {str(path)})
        with path.open('a') as handle:
            handle.write(json.dumps({'type': 'turn_context', 'payload': {
                'approval_policy': 'never', 'sandbox_policy': {
                    'type': 'workspace-write', 'network_access': False}}}) + '\n')
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, '', '')
        assert send(runner=run) == 'sent'
        assert commands[0][:4] == ['/bin/codex', 'queue', '--thread', sid]
        assert not spawned

    def test_claude_commands_are_not_sent_to_codex(self, setup):
        talk, _, _, _, _, _, spawned, send = setup
        assert 'not Claude Code commands' in send('/security-review')
        assert talk.message('/recap', brief=False) == talk.RECAP
        assert not spawned

    def test_missing_codex_identity_never_falls_back_to_claude(self, setup, monkeypatch):
        import watch_relay as relay
        monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
        monkeypatch.setattr(relay, 'session_registry', lambda: pytest.fail('Claude path reached'))
        assert relay.say_to_session('missing-uuid', 'hi', agent='codex') == 'unknown Codex session'

    def test_codex_is_recognised_for_older_callers_without_an_agent(self, setup, monkeypatch):
        import watch_relay as relay
        import codex_talk
        _, _, sid, _, _, _, _, _ = setup
        monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
        monkeypatch.setattr(codex_talk, 'send', lambda *args, **kwargs: 'sent')
        monkeypatch.setattr(relay, 'session_registry', lambda: pytest.fail('Claude path reached'))
        assert relay.say_to_session(sid, 'hi') == 'sent'
        assert relay.say_to_session(sid, 'hi', agent='claude') == 'session belongs to Codex'

    def test_new_session_uses_last_agent_even_within_one_minute(self, setup, monkeypatch):
        import os
        import watch_relay as relay
        _, _, _, path, workspace, _, _, _ = setup
        mtime = path.stat().st_mtime
        row = {'name': 'workspace', 'path': str(workspace), 'minutes_ago': 0}
        monkeypatch.setattr(relay, '_claude_projects', lambda *_args: [row])
        monkeypatch.setattr(relay, 'transcript_origin', lambda _path: (str(workspace), 'cli'))
        monkeypatch.setattr(relay, 'transcripts_newest_first', lambda *_args: [(mtime - 1, 'cc', '', '')])
        # On Linux the workspace sits under /tmp, which is never offered as a project.
        monkeypatch.setattr(relay, 'SCRATCH_ROOTS', ())
        [project] = relay.known_projects()
        assert project['agent'] == 'codex'
        os.utime(path, (mtime - 2, mtime - 2))
        [project] = relay.known_projects()
        assert project.get('agent') is None  # Claude was later by one second.

    def test_new_codex_terminal_is_quoted_and_never_uses_claude_trust(self, setup, monkeypatch):
        import os
        import subprocess
        import watch_relay as relay
        talk, _, _, _, workspace, _, _, _ = setup
        monkeypatch.setattr(relay, 'known_projects', lambda *_args: [{
            'path': str(workspace), 'name': 'workspace', 'minutes_ago': 0, 'agent': 'codex'}])
        monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/opt/a path/codex')
        monkeypatch.setattr(relay, 'trust_folder', lambda _: pytest.fail('Claude trust reached'))
        monkeypatch.setattr(relay, 'signed_in', lambda: pytest.fail('Claude auth reached'))
        scripts = []
        def opened(command, **kwargs):
            assert command[0] == 'open'
            with open(command[1]) as handle:
                scripts.append(handle.read())
            os.unlink(command[1])
            return subprocess.CompletedProcess(command, 0, '', '')
        monkeypatch.setattr(relay.subprocess, 'run', opened)
        text = '--dangerously-bypass-approvals-and-sandbox $(touch no) å'
        assert relay.start_session(str(workspace), text, platform='darwin') == 'started'
        import shlex
        script = scripts[0].split(' && ', 1)[1].strip()
        assert shlex.split(script) == ['/opt/a path/codex'] + talk.flags() + ['--', text]

    def test_unknown_activity_never_starts_a_second_writer(self, setup, monkeypatch):
        talk, _, _, _, _, _, spawned, send = setup
        monkeypatch.setattr(talk, 'activity', lambda *_args: None)
        assert 'activity could not be verified' in send()
        assert not spawned

    def test_an_existing_writer_lock_is_live_even_if_lsof_finds_nothing(self, setup):
        import tapproval_host
        talk, sessions, sid, path, _, _, spawned, send = setup
        lock_path = sessions._home() + '/thread-writer-locks/' + sid + '.lock'
        with open(lock_path, 'rb') as handle:
            assert tapproval_host.try_lock(handle.fileno())
            assert talk.activity(str(path), sid) is True
            assert 'permission limits' in send()
        assert not spawned
        assert talk.activity(str(path), sid) is False

    @pytest.mark.parametrize('roots', [['/outside'], 'not-a-list', [None]])
    def test_queue_refuses_external_or_malformed_write_grants(self, setup, roots):
        talk, _, _, path, workspace, _, _, _ = setup
        with path.open('a') as handle:
            handle.write(json.dumps({'type': 'turn_context', 'payload': {
                'cwd': str(workspace), 'approval_policy': 'on-request', 'sandbox_policy': {
                    'type': 'workspace-write', 'network_access': False, 'writable_roots': roots}}}) + '\n')
        assert not talk.queue_safe(str(path))
