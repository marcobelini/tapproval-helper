"""Desktop transport ownership, safe discovery and independent native servers."""
import json
import os
import plistlib
import stat
import socket
import time

import pytest

import codex_desktop as desktop
import codex_talk as talk
from codex_approvals import ApprovalHub, ApprovalSync, LocalWebSocket
from watch_relay import CardQueue
from test_codex_approvals import Wire, HandshakeSocket, request, until, resolved


@pytest.mark.parametrize('transport', [[], ['--stdio'], ['--listen', 'stdio://'], ['--listen=stdio://']])
def test_desktop_joins_the_phone_server_without_creating_a_private_writer(tmp_path, monkeypatch, transport):
    monkeypatch.setattr(desktop.host, 'native_windows', lambda: False)
    real = tmp_path / 'codex'
    real.touch()
    calls = []
    class Shared:
        def close(self):
            calls.append('closed-preflight')
    monkeypatch.setattr(talk, '_shared_client', lambda **kwargs: Shared(), raising=False)
    monkeypatch.setattr(desktop.subprocess, 'Popen',
                        lambda *args, **kwargs: pytest.fail('must not create a private Desktop server'))
    monkeypatch.setattr(desktop, 'proxy_stdio',
                        lambda path, **kwargs: calls.append((path, kwargs)) or 0)
    assert desktop.run(str(real), ['app-server'] + transport + ['-c', 'features.code_mode_host=true']) == 0
    assert calls == ['closed-preflight', (talk.shared_socket(), {
        'overrides': {'features': {'code_mode_host': True}}})]


def test_desktop_overrides_keep_app_tools_bound_to_the_desktop_connection():
    values = desktop.shared_overrides([
        '-c', 'features.code_mode_host=true', 'app-server', '--analytics-default-enabled',
        '-c', 'plugins.codex-app-tools@openai-bundled.mcp_servers.codex_app.enabled=true',
    ], {'CODEX_APP_TOOLS_PIPE_PATH': '/private/desktop-pipe',
        'CODEX_MCP_NODE_PATH': '/signed/node', 'UNRELATED_SECRET': 'never-forward'})
    assert values == {
        'features': {'code_mode_host': True},
        'plugins': {'codex-app-tools@openai-bundled': {'mcp_servers': {'codex_app': {
            'enabled': True, 'env': {'CODEX_APP_TOOLS_PIPE_PATH': '/private/desktop-pipe',
                                    'CODEX_MCP_NODE_PATH': '/signed/node'}}}}}}


@pytest.mark.parametrize('method', ['thread/start', 'thread/resume', 'thread/fork'])
def test_shared_desktop_defaults_preserve_explicit_thread_settings(method):
    original = {'id': 7, 'method': method, 'params': {'threadId': 'same-id',
        'approvalsReviewer': 'user', 'config': {'features': {'code_mode_host': False}}}}
    updated = desktop.thread_request(original, {'features': {'code_mode_host': True},
        'plugins': {'app': {'enabled': True}}})
    assert updated['id'] == 7 and updated['params']['threadId'] == 'same-id'
    assert updated['params']['approvalsReviewer'] == 'user'
    assert updated['params']['config'] == {
        'features': {'code_mode_host': False}, 'plugins': {'app': {'enabled': True}}}
    assert original['params']['config'] == {'features': {'code_mode_host': False}}


@pytest.mark.parametrize('message', [
    {'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'desktop'}}},
    {'id': 2, 'method': 'turn/start', 'params': {'threadId': 'same-id'}},
    {'id': 3, 'result': {'decision': 'decline'}},
    {'method': 'initialized'},
])
def test_shared_desktop_does_not_change_other_protocol_messages(message):
    assert desktop.thread_request(message, {'features': {'code_mode_host': True}}) is message


@pytest.mark.parametrize('args', [
    ['app-server', '--code-mode-host', 'http://a-host'],
    ['app-server', '-c', 'features.code_mode_host={unsupported=true}'],
])
def test_shared_desktop_refuses_untranslatable_startup_options(args):
    with pytest.raises(ValueError, match='shared'):
        desktop.shared_overrides(args, {})


@pytest.mark.parametrize('value', [False, 0, [], 'not-an-object'])
def test_shared_desktop_refuses_malformed_thread_config_without_sending(value):
    with pytest.raises(ValueError, match='configuration'):
        desktop.thread_request({'id': 3, 'method': 'thread/start', 'params': {'config': value}},
                               {'features': {'code_mode_host': True}})


def test_shared_desktop_supports_quoted_plugin_names_and_typed_defaults():
    assert desktop.shared_overrides(['app-server', '--config=model="local"', '-c',
        'plugins."a.plugin@bundled".enabled=true', '--enable=code_mode_host',
        '--disable', 'apps'], {}) == {
            'model': 'local', 'plugins': {'a.plugin@bundled': {'enabled': True}},
            'features': {'code_mode_host': True, 'apps': False}}


@pytest.mark.parametrize("args,expected", [
    (["-c", "features.code_mode_host=true", "app-server", "--analytics-default-enabled",
      "-c", "plugins.codex-app-tools.enabled=true"], True),
    (["app-server", "--print-startup-config"], False),
    (["app-server", "--startup-sign-out"], False),
    (["app-server", "proxy", "--sock", "/private/socket"], False),
    (["app-server", "daemon", "version"], False),
    (["app-server", "generate-json-schema"], False),
    (["app-server", "--listen=unix:///custom"], False),
    (["app-server", "--stdio"], True),
    (["app-server", "--listen", "stdio://"], True),
    (["app-server", "--listen=stdio://"], True),
    (["app-server", "--help"], False),
    (["-c", "app-server", "exec", "hi"], False),
    (["exec", "app-server"], False),
    (["--config=model='offline'", "app-server"], True),
])
def test_only_intercepts_ordinary_server_starts(args, expected):
    assert desktop.bridge_args(args) is expected


@pytest.fixture
def endpoint(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Desktop adapter is opt-in on POSIX")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    root = tmp_path / "tapproval-desktop"
    root.mkdir(mode=0o700)
    folder = root / "s-test"
    folder.mkdir(mode=0o700)
    # AF_UNIX paths on macOS are short; create the actual socket outside
    # pytest's deeply nested temporary root, then inject its stat result.
    record = folder / "owner.json"
    record.write_text(json.dumps({"pid": os.getpid(), "home": str(tmp_path.resolve())}))
    record.chmod(0o600)
    path = folder / "rpc.sock"
    original = desktop.Path.lstat
    def info(self):
        if self == path:
            return os.stat_result((stat.S_IFSOCK | 0o600, 0, 0, 1, os.getuid(), 0, 0, 0, 0, 0))
        return original(self)
    monkeypatch.setattr(desktop.Path, "lstat", info)
    descriptor = os.open(folder / "live.lock", os.O_CREAT | os.O_RDWR, 0o600)
    assert desktop.host.try_lock(descriptor)
    try:
        yield root, folder, record, str(path)
    finally:
        os.close(descriptor)


def test_discovers_only_live_private_owned_endpoint(endpoint):
    _root, _folder, _record, path = endpoint
    assert desktop.desktop_sockets() == [path]
    assert desktop.server_sockets()[0] == path


@pytest.mark.parametrize("part", ["root", "folder", "record"])
def test_rejects_shared_registry_or_record(endpoint, part):
    root, folder, record, _path = endpoint
    {"root": root, "folder": folder, "record": record}[part].chmod(0o755)
    assert desktop.desktop_sockets() == []


def test_rejects_stale_process_and_other_codex_home(endpoint, monkeypatch):
    _root, _folder, record, _path = endpoint
    def dead(*_args):
        raise ProcessLookupError()
    monkeypatch.setattr(desktop.os, "kill", dead)
    assert desktop.desktop_sockets() == []
    record.write_text(json.dumps({"pid": os.getpid(), "home": "/different"}))
    assert desktop.desktop_sockets() == []


def test_dead_wrapper_lease_does_not_adopt_a_live_orphan(endpoint, monkeypatch):
    monkeypatch.setattr(desktop.host, "try_lock", lambda _descriptor: True)
    assert desktop.desktop_sockets() == []


def test_rejects_symlinked_session_directory(endpoint):
    root, folder, _record, _path = endpoint
    moved = root / "real"
    folder.rename(moved)
    folder.symlink_to(moved, target_is_directory=True)
    assert desktop.desktop_sockets() == []


def test_startup_defaults_follow_desktop_threads_without_owning_the_shared_service(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Desktop adapter is opt-in on POSIX")
    calls = []
    class Shared:
        def close(self):
            calls.append('closed-only-this-client')
    monkeypatch.setattr(talk, '_shared_client', lambda **kwargs: Shared())
    monkeypatch.setattr(desktop.subprocess, 'Popen',
                        lambda *args, **kwargs: pytest.fail('a private server was spawned'))
    monkeypatch.setattr(desktop, "proxy_stdio", lambda path, **kwargs:
                        calls.append((path, kwargs)) or 0)
    real = tmp_path / "codex"
    real.touch()
    args = ["-c", "features.code_mode_host=true", "app-server", "-c",
            'approval_policy="on-request"', "-c", "plugins.codex-app-tools.enabled=true"]
    monkeypatch.setenv("CODEX_CLI_PATH", "/wrapper")
    assert desktop.run(str(real), args) == 0
    assert calls == ['closed-only-this-client', (talk.shared_socket(), {'overrides': {
        'features': {'code_mode_host': True}, 'approval_policy': 'on-request',
        'plugins': {'codex-app-tools': {'enabled': True}}}})]
    assert not (tmp_path / 'tapproval-desktop').exists()


def test_hub_routes_native_answers_to_the_owning_server(monkeypatch):
    monkeypatch.setattr("ClaudeRiskClassifier.write_audit", lambda *_: None)
    wires = {"desktop": Wire(["desktop-thread"]), "default": Wire(["cli-thread"])}
    def make(queue, socket_path=None, **kwargs):
        return ApprovalSync(queue, connect=lambda: wires[socket_path], **kwargs)
    monkeypatch.setattr("codex_approvals.ApprovalSync", make)
    cards = CardQueue()
    cards.PROBE_SECONDS = .01
    hub = ApprovalHub(cards, paths=lambda: list(wires))
    try:
        assert hub.attach("desktop-thread")
        assert hub.attach("cli-thread")
        wires["desktop"].incoming.put(request(10, thread="desktop-thread"))
        wires["default"].incoming.put(request(10, thread="cli-thread"))
        until(lambda: len(cards.pending()) == 2)
        by_thread = {row["session_id"]: row for row in cards.pending()}
        assert by_thread["desktop-thread"]["id"] != by_thread["cli-thread"]["id"]
        cards.decide(by_thread["desktop-thread"]["id"], "allow")
        until(lambda: any(m.get("result") == {"decision": "accept"}
                          for m in wires["desktop"].sent))
        assert not any(m.get("result") for m in wires["default"].sent)
        resolved(wires["default"], thread="cli-thread")
        resolved(wires["desktop"], thread="desktop-thread")
        until(lambda: not cards.pending())
    finally:
        hub.stop()


def test_unowned_thread_never_resumes_on_another_server(monkeypatch):
    wires = [Wire([]), Wire([])]
    def make(queue, **kwargs):
        wire = wires.pop(0)
        retained.append(wire)
        kwargs.pop("socket_path")
        return ApprovalSync(queue, connect=lambda: wire, **kwargs)
    retained = []
    monkeypatch.setattr("codex_approvals.ApprovalSync", make)
    hub = ApprovalHub(CardQueue(), paths=lambda: ["desktop", "default"])
    try:
        assert not hub.attach("missing")
        assert not any(m.get("method") == "thread/resume" for w in retained for m in w.sent)
    finally:
        hub.stop()


def test_duplicate_thread_on_two_servers_is_not_resumed(monkeypatch):
    retained = []
    def make(queue, **kwargs):
        wire = Wire(["duplicate"])
        retained.append(wire)
        kwargs.pop("socket_path")
        return ApprovalSync(queue, connect=lambda: wire, **kwargs)
    monkeypatch.setattr("codex_approvals.ApprovalSync", make)
    hub = ApprovalHub(CardQueue(), paths=lambda: ["desktop", "default"])
    try:
        assert not hub.attach("duplicate")
        assert "multiple" in hub.last_error
        assert not any(m.get("method") == "thread/resume" for w in retained for m in w.sent)
    finally:
        hub.stop()


def test_launcher_preparation_does_not_stop_or_open_running_desktop(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Desktop launcher requires a POSIX host")
    monkeypatch.setattr(desktop.host, "is_mac", lambda: True)
    monkeypatch.setattr(desktop.Path, "home", lambda: tmp_path)
    cli = tmp_path / "real codex"
    cli.touch()
    app = tmp_path / "Desktop.app"
    (app / "Contents").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Desktop"}))
    launcher = desktop.prepare_launcher(str(cli), str(app))
    assert launcher.is_file()
    assert 'TAPPROVAL_CODEX_REAL_CLI=' in launcher.read_text()
    assert not launcher.stat().st_mode & 0o077
    class Processes:
        stdout = str(app / "Contents/MacOS/Desktop") + "\n"
    monkeypatch.setattr(desktop.subprocess, "run", lambda *_a, **_k: Processes())
    def forbidden(*_a, **_k):
        pytest.fail("running Desktop must not be restarted or launched")
    monkeypatch.setattr(desktop.subprocess, "call", forbidden)
    assert desktop.launch(str(app), str(cli)) == 2


def test_watch_sender_refuses_duplicate_native_owners(monkeypatch):
    import codex_talk
    opened = []
    class Connection:
        closed = False
        def rpc(self, method, params):
            assert method == "thread/loaded/list"
            return {"data": ["duplicate"], "nextCursor": None}
        def close(self):
            self.closed = True
    def client(*_args, **_kwargs):
        result = Connection()
        opened.append(result)
        return result
    monkeypatch.setattr(codex_talk, "Client", client)
    monkeypatch.setattr(desktop, "server_sockets", lambda: ["one", "two"])
    with pytest.raises(ValueError, match="multiple"):
        codex_talk._owner_client("duplicate", None)
    assert len(opened) == 2
    assert all(connection.closed for connection in opened)


def test_absent_socket_is_known_absent_without_transport_support(tmp_path, monkeypatch):
    """CLI routes do not require Unix-socket support when no socket exists."""
    import codex_talk
    def unsupported(_path):
        raise OSError('this Python has no Unix sockets')
    monkeypatch.setattr(codex_talk, 'LocalWebSocket', unsupported)
    with pytest.raises(FileNotFoundError):
        codex_talk.Client(socket_path=str(tmp_path / 'missing.sock'))


@pytest.mark.parametrize('page', [
    {'data': 'target'}, {'data': ['target', {}]},
    {'data': ['target'], 'nextCursor': 1},
])
def test_watch_sender_refuses_malformed_loaded_owner_page(monkeypatch, page):
    import codex_talk
    class Connection:
        closed = False
        def rpc(self, method, params):
            assert method == 'thread/loaded/list'
            return page
        def close(self):
            self.closed = True
    connection = Connection()
    monkeypatch.setattr(codex_talk, 'Client', lambda *args, **kwargs: connection)
    monkeypatch.setattr(desktop, 'server_sockets', lambda: ['desktop'])
    with pytest.raises(ValueError, match='loaded-thread page'):
        codex_talk._owner_client('target', None)
    assert connection.closed


@pytest.mark.parametrize('failure', [TimeoutError, PermissionError, EOFError, OSError])
@pytest.mark.parametrize('paths', [['owner', 'uncertain'], ['uncertain', 'owner']])
def test_watch_sender_refuses_uncertain_other_server(monkeypatch, failure, paths):
    import codex_talk
    opened = []
    class Connection:
        closed = False
        def rpc(self, method, params):
            assert method == 'thread/loaded/list'
            return {'data': ['target'], 'nextCursor': None}
        def close(self):
            self.closed = True
    def client(*args, socket_path=None, **kwargs):
        if socket_path == 'uncertain':
            raise failure('not verified')
        connection = Connection()
        opened.append(connection)
        return connection
    monkeypatch.setattr(codex_talk, 'Client', client)
    monkeypatch.setattr(desktop, 'server_sockets', lambda: paths)
    with pytest.raises(ValueError, match='ownership could not be verified'):
        codex_talk._owner_client('target', None)
    assert all(connection.closed for connection in opened)


@pytest.fixture
def health_hub(monkeypatch):
    monkeypatch.setattr("ClaudeRiskClassifier.write_audit", lambda *_: None)
    wires = {"desktop": Wire([]), "default": Wire([])}
    def make(queue, socket_path=None, **kwargs):
        return ApprovalSync(queue, connect=lambda: wires[socket_path], **kwargs)
    monkeypatch.setattr("codex_approvals.ApprovalSync", make)
    events = []
    hub = ApprovalHub(CardQueue(), paths=lambda: list(wires), status=events.append)
    try:
        yield hub, wires, events
    finally:
        hub.stop()


def test_hub_recovers_each_failed_target_only_after_its_owner_poll(health_hub):
    hub, wires, events = health_hub
    assert not hub.attach("first")
    assert not hub.attach("second")
    default = hub._syncs["default"]
    default.reconcile()
    assert events[-1], "an unrelated healthy server hid the failed targets"
    wires["desktop"].loaded = ["first"]
    assert hub.attach("first")
    assert events[-1], "attachment alone is not a complete recovery poll"
    hub._syncs["desktop"].reconcile()
    assert events[-1], "the second failed target is still unresolved"
    wires["desktop"].loaded.append("second")
    assert hub.attach("second")
    default._report_failure(OSError("temporary"), "test")
    default.reconcile()
    assert events[-1], "unrelated recovery cannot replace the owning poll"
    hub._syncs["desktop"].reconcile()
    assert events[-1] is None
    assert hub.last_error is None


def test_hub_disconnect_recovers_only_after_the_affected_server_poll(health_hub):
    hub, wires, events = health_hub
    wires["desktop"].loaded = ["desktop-thread"]
    assert hub.attach("desktop-thread")
    hub._syncs["desktop"].reconcile()
    hub._syncs["default"].reconcile()
    assert events[-1] is None
    wires["desktop"].incoming.put(None)
    until(lambda: hub.last_error)
    default = hub._syncs["default"]
    default._report_failure(OSError("temporary"), "test")
    default.reconcile()
    assert events[-1], "a healthy CLI server hid the Desktop disconnect"
    wires["desktop"] = Wire(["desktop-thread"])
    hub._syncs["desktop"].reconcile()
    assert events[-1] is None


def test_hub_rejects_an_uncertain_second_owner_without_resuming(health_hub):
    hub, wires, _events = health_hub
    class Uncertain(Wire):
        def send(self, message):
            if message.get("method") == "thread/loaded/list":
                self.sent.append(message)
                self.incoming.put({"id": message["id"],
                                   "error": {"code": -32000, "message": "unavailable"}})
            else:
                super().send(message)
    wires["desktop"].loaded = ["target"]
    wires["default"] = Uncertain([])
    assert not hub.attach("target")
    assert "ownership" in hub.last_error
    assert not any(row.get("method") == "thread/resume"
                   for wire in wires.values() for row in wire.sent)


def test_retired_server_callback_cannot_poison_its_replacement(health_hub):
    hub, wires, events = health_hub
    hub._refresh()
    retired = hub._syncs["desktop"]
    del wires["desktop"]
    hub._refresh()
    wires["desktop"] = Wire(["target"])
    assert hub.attach("target")
    hub._syncs["desktop"].reconcile()
    assert events[-1] is None
    retired.status("stale failure")
    assert events[-1] is None
    assert hub.last_error is None


def test_background_observation_refuses_duplicate_owners_and_recovers(health_hub):
    hub, wires, events = health_hub
    for wire in wires.values():
        wire.loaded = ["target"]
        wire.statuses["target"] = {"type": "active", "activeFlags": ["waitingOnApproval"]}
    syncs = hub._refresh()
    for sync in syncs:
        sync.reconcile()
    assert not any(row.get("method") == "thread/resume"
                   for wire in wires.values() for row in wire.sent)
    assert events[-1]
    assert not hub.queue.pending()
    wires["default"].loaded = []
    hub._syncs["desktop"].reconcile()
    hub._syncs["default"].reconcile()
    assert events[-1] is None
    assert any(row.get("method") == "thread/resume" for row in wires["desktop"].sent)
    assert not any(row.get("method") == "thread/resume" for row in wires["default"].sent)


def test_answer_checks_ownership_again_and_replay_keeps_the_card_identity(health_hub):
    hub, wires, _events = health_hub
    wires["desktop"].loaded = ["target"]
    wires["desktop"].statuses["target"] = {"type": "active", "activeFlags": ["waitingOnApproval"]}
    assert hub.attach("target")
    hub._syncs["desktop"].reconcile()
    wires["desktop"].incoming.put(request(thread="target"))
    until(lambda: len(hub.queue.pending()) == 1)
    card_id = hub.queue.pending()[0]["id"]
    # A duplicate appeared after publication and before the wearer's tap.
    wires["default"].loaded = ["target"]
    assert hub.queue.decide(card_id, "allow")
    until(lambda: any(row.get("result") for wire in wires.values() for row in wire.sent)
          or (hub.last_error and not hub._syncs["desktop"]._pending))
    assert not any(row.get("result") for wire in wires.values() for row in wire.sent)
    wires["default"].loaded = []
    wires["desktop"].replay = [request(thread="target")]
    hub._syncs["desktop"].reconcile()
    until(lambda: len(hub.queue.pending()) == 1)
    assert hub.queue.pending()[0]["id"] == card_id
    assert hub.queue.decide(card_id, "deny")
    until(lambda: any(row.get("result") == {"decision": "decline"}
                      for row in wires["desktop"].sent))
    assert not any(row.get("result") == {"decision": "accept"}
                   for wire in wires.values() for row in wire.sent)


@pytest.mark.parametrize("raises", [False, True])
def test_retired_waiter_cannot_remove_a_reposted_native_card(raises):
    import threading
    cards = CardQueue()
    cards.PROBE_SECONDS = .01
    entered, release = threading.Event(), threading.Event()
    new_entered, new_release = threading.Event(), threading.Event()
    card_id = "ab" * 6
    old_result, new_result = [], []
    def old_probe():
        entered.set()
        assert release.wait(3)
        if raises:
            raise OSError("old transport disappeared")
        return True
    def old_waiter():
        try:
            old_result.append(cards.submit({"post_id": card_id, "headline": "request"}, 3,
                                           resolved_elsewhere=old_probe))
        except OSError:
            old_result.append("old transport disappeared")
    first = threading.Thread(target=old_waiter, daemon=True)
    def new_probe():
        new_entered.set()
        assert new_release.wait(3)
        return False
    second = threading.Thread(target=lambda: new_result.append(cards.submit(
        {"post_id": card_id, "headline": "request"}, 3,
        resolved_elsewhere=new_probe)), daemon=True)
    try:
        first.start()
        assert entered.wait(2)
        cards.withdraw(card_id)
        second.start()
        assert new_entered.wait(2)
        assert cards.decide(card_id, "deny")
        release.set()
        first.join(2)
        assert not first.is_alive()
        assert cards.pending(), "the retired waiter retracted its replacement"
        assert cards.pending()[0]["id"] == card_id
        new_release.set()
        second.join(2)
        assert not second.is_alive()
        assert new_result[0][1] == "deny"
    finally:
        release.set()
        new_release.set()
        cards.withdraw(card_id)
        first.join(3)
        if second.ident is not None:
            second.join(3)


@pytest.mark.parametrize("malformed", ["target", ["target", {}]])
def test_malformed_owner_listing_is_not_accepted(monkeypatch, malformed):
    class Invalid(Wire):
        def send(self, message):
            if message.get("method") == "thread/loaded/list":
                self.sent.append(message)
                self.incoming.put({"id": message["id"], "result": {"data": malformed}})
            else:
                super().send(message)
    wire = Invalid([])
    sync = ApprovalSync(CardQueue(), connect=lambda: wire)
    try:
        with pytest.raises(ValueError, match="loaded-thread page"):
            sync.owns("target")
        assert not any(row.get("method") == "thread/resume" for row in wire.sent)
    finally:
        sync.stop()


def test_loaded_listing_cannot_keep_the_observer_in_an_endless_cursor_loop():
    class Repeating(Wire):
        def send(self, message):
            if message.get("method") == "thread/loaded/list":
                self.sent.append(message)
                self.incoming.put({"id": message["id"],
                                   "result": {"data": [], "nextCursor": "again"}})
            else:
                super().send(message)
    wire = Repeating([])
    sync = ApprovalSync(CardQueue(), connect=lambda: wire)
    try:
        with pytest.raises(ValueError, match="exceeded its bound"):
            sync.reconcile()
        assert sum(row.get("method") == "thread/loaded/list" for row in wire.sent) == 64
        assert not sync.attach("target")
        assert not any(row.get("method") == "thread/resume" for row in wire.sent)
    finally:
        sync.stop()


def test_one_hub_monitor_observes_both_servers_and_routes_concurrent_answers(health_hub):
    hub, wires, _events = health_hub
    for path, wire in wires.items():
        wire.loaded = [path]
        wire.statuses[path] = {"type": "active", "activeFlags": ["waitingOnApproval"]}
        wire.replay = [request(thread=path)]
    hub.start()
    until(lambda: len(hub.queue.pending()) == 2)
    assert all(sync._monitor is None for sync in hub._syncs.values())
    for card in hub.queue.pending():
        assert hub.queue.decide(card["id"], "deny")
    until(lambda: all(any(row.get("result") == {"decision": "decline"}
                         for row in wire.sent) for wire in wires.values()))
    for path, wire in wires.items():
        resolved(wire, thread=path)
    until(lambda: not hub.queue.pending())


def test_hub_recovery_accepts_verified_native_closure_but_not_an_unknown_target(health_hub):
    hub, wires, events = health_hub
    class RefusedResume(Wire):
        def send(self, message):
            if message.get("method") == "thread/resume":
                self.sent.append(message)
                self.incoming.put({"id": message["id"],
                                   "error": {"code": -32000, "message": "not ready"}})
            else:
                super().send(message)
    wires["desktop"] = RefusedResume(["target"])
    assert not hub.attach("target")
    wires["desktop"] = Wire([])
    for sync in hub._syncs.values():
        sync.reconcile()
    hub._retry_targets()
    assert events[-1] is None
    assert not hub.attach("never-observed")
    for sync in hub._syncs.values():
        sync.reconcile()
    hub._retry_targets()
    assert events[-1], "absence is not closure proof for a never-observed target"


def test_prepared_wrapper_runs_without_launcher_environment(tmp_path, monkeypatch):
    """Desktop tool subprocesses can retain the wrapper path but drop its env."""
    import subprocess
    import sys
    if not hasattr(os, "getuid"):
        pytest.skip("Desktop launcher requires a POSIX host")
    monkeypatch.setattr(desktop.host, "is_mac", lambda: True)
    monkeypatch.setattr(desktop.Path, "home", lambda: tmp_path)
    cli = tmp_path / "real codex's executable"
    cli.write_text("#!%s\nimport json, os, sys\nprint(json.dumps({"
                   "'args': sys.argv[1:], 'path': os.environ.get('CODEX_CLI_PATH'), "
                   "'adapter_env': os.environ.get('TAPPROVAL_CODEX_REAL_CLI')}))\n" % sys.executable)
    cli.chmod(0o700)
    app = tmp_path / "Desktop.app"
    (app / "Contents").mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Desktop"}))
    launcher = desktop.prepare_launcher(str(cli), str(app))
    wrapper = launcher.parent / "codex"
    env = dict(os.environ)
    env.pop("TAPPROVAL_CODEX_REAL_CLI", None)
    env["CODEX_CLI_PATH"] = str(wrapper)
    result = subprocess.run([str(wrapper), "--version", "argument with spaces"],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "args": ["--version", "argument with spaces"],
        "path": str(cli), "adapter_env": None}


@pytest.fixture
def servers(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    default = str(tmp_path / "app-server-control" / "app-server-control.sock")
    loaded = {"desktop": ["target"], default: []}
    opened = []
    faults = {}
    client = talk.Client

    class ArchiveWire(Wire):
        def send(self, message):
            method = message.get("method")
            fault = faults.get((self.path, method))
            if fault is not None:
                self.sent.append(message)
                if isinstance(fault, Exception):
                    self.incoming.put(fault)
                else:
                    self.incoming.put({"id": message["id"], **fault})
            elif method in ("thread/archive", "thread/unarchive"):
                self.sent.append(message)
                # Success needs no notification, including already archived.
                self.incoming.put({"id": message["id"], "result": {}})
            else:
                super().send(message)

        def receive(self):
            value = super().receive()
            if isinstance(value, Exception):
                raise value
            return value

    def make(connect=None, socket_path=None):
        assert connect is None
        path = socket_path or default
        if path not in loaded:
            raise FileNotFoundError(path)
        wire = ArchiveWire(loaded[path])
        wire.path = path
        opened.append(wire)
        return client(connect=lambda: wire)

    monkeypatch.setattr(talk, "Client", make)
    monkeypatch.setattr(desktop, "server_sockets", lambda: list(loaded))
    yield loaded, opened, faults, default
    assert all(w.closed for w in opened)


def mutations(opened):
    return [(w.path, m) for w in opened for m in w.sent
            if m.get("method") in ("thread/archive", "thread/unarchive")]


@pytest.mark.parametrize("method", ["archive", "unarchive"])
@pytest.mark.parametrize("owner", ["desktop", "default", None])
def test_routes_to_single_owner_or_default_without_resuming(servers, method, owner):
    loaded, opened, _faults, default = servers
    loaded["desktop"] = ["target"] if owner == "desktop" else []
    loaded[default] = ["target"] if owner == "default" else []
    assert getattr(talk, method + "_codex_thread")("target") == {"ok": True}
    calls = mutations(opened)
    assert len(calls) == 1
    assert calls[0][0] == ("desktop" if owner == "desktop" else default)
    assert calls[0][1]["method"] == "thread/" + method
    assert calls[0][1]["params"] == {"threadId": "target"}
    assert not any(m.get("method") in ("thread/resume", "turn/start")
                   for w in opened for m in w.sent)


@pytest.mark.parametrize("method", ["archive", "unarchive"])
@pytest.mark.parametrize("failure", ["duplicate", "discovery", "malformed", "absent",
                                    "default_absent", "init", "discovery_refused"])
def test_refuses_before_mutation_and_closes_all_clients(servers, method, failure):
    loaded, opened, faults, default = servers
    if failure == "duplicate":
        loaded[default] = ["target"]
    elif failure == "discovery":
        faults[(default, "thread/loaded/list")] = EOFError("lost")
    elif failure == "malformed":
        faults[(default, "thread/loaded/list")] = {"result": {"data": "target"}}
    elif failure == "init":
        faults[(default, "initialize")] = TimeoutError("silent")
    elif failure == "default_absent":
        loaded["desktop"] = []
        del loaded[default]
    elif failure == "discovery_refused":
        faults[(default, "thread/loaded/list")] = {"error": {"message": "unavailable"}}
    else:
        loaded.clear()
    result = getattr(talk, method + "_codex_thread")("target")
    assert result["ok"] is False
    assert not result.get("uncertain")
    assert 0 < len(result["reason"]) <= 60
    if failure == "duplicate":
        assert result["reason"] == "Codex is open on two servers"
    if failure in ("absent", "default_absent"):
        assert result["reason"] == "Can't reach Codex on this Mac"
    assert not mutations(opened)


@pytest.mark.parametrize("method", ["archive", "unarchive"])
@pytest.mark.parametrize("failure", [TimeoutError("late"), EOFError("lost"),
                                    OSError("connection reset")])
def test_lost_mutation_receipt_is_uncertain_and_never_retried(servers, method, failure):
    _loaded, opened, faults, _default = servers
    faults[("desktop", "thread/" + method)] = failure
    result = getattr(talk, method + "_codex_thread")("target")
    assert result["ok"] is False and result["uncertain"] is True
    assert "confirm" in result["reason"].lower()
    assert len(result["reason"]) <= 60
    assert len(mutations(opened)) == 1


@pytest.mark.parametrize("method", ["archive", "unarchive"])
@pytest.mark.parametrize("reason", ["active writer", "conflict: thread is busy", "x" * 200])
def test_rpc_refusal_uses_archive_words_and_preserves_reason(servers, method, reason):
    _loaded, opened, faults, _default = servers
    faults[("desktop", "thread/" + method)] = {"error": {"message": reason}}
    result = getattr(talk, method + "_codex_thread")("target")
    assert result == {"ok": False, "reason": ("Codex refused: " + reason)[:60]}
    assert len(mutations(opened)) == 1


def test_archive_uses_named_longer_rpc_deadline(servers, monkeypatch):
    _loaded, _opened, _faults, _default = servers
    original = talk.Client
    calls = []
    def make(*args, **kwargs):
        client = original(*args, **kwargs)
        rpc = client.rpc
        def record(method, params, **options):
            calls.append((method, options))
            return rpc(method, params, **options)
        client.rpc = record
        return client
    monkeypatch.setattr(talk, "Client", make)
    assert talk.archive_codex_thread("target") == {"ok": True}
    assert talk.ARCHIVE_TIMEOUT == 15
    assert ("thread/archive", {"timeout": talk.ARCHIVE_TIMEOUT}) in calls


@pytest.mark.parametrize("receipt", [None, "archived", [], 1])
def test_invalid_mutation_receipt_is_uncertain(servers, receipt):
    _loaded, opened, faults, _default = servers
    faults[("desktop", "thread/archive")] = {"result": receipt}
    result = talk.archive_codex_thread("target")
    assert result["ok"] is False and result["uncertain"] is True
    assert len(mutations(opened)) == 1


def test_rpc_can_wait_past_send_deadline_and_ignore_notifications(monkeypatch):
    clock = [0]
    monkeypatch.setattr(talk.time, "monotonic", lambda: clock[0])
    class DelayedWire:
        def send(self, message):
            assert message["method"] == "thread/archive"
        def receive_until(self, deadline):
            assert deadline == 15
            clock[0] += 4
            if clock[0] == 4:
                return {"method": "thread/archived", "params": {"threadId": "target"}}
            return {"id": "wrist-1", "result": {}}
    client = talk.Client.__new__(talk.Client)
    client.sequence, client.wire = 0, DelayedWire()
    assert client.rpc("thread/archive", {"threadId": "target"},
                      timeout=talk.ARCHIVE_TIMEOUT) == {}
    assert clock[0] == 8


@pytest.mark.parametrize("frames", [b"", b"\x81\x10{", b"\x89\x01?"])
def test_rpc_deadline_bounds_silent_partial_and_ping_only_transport(monkeypatch, frames):
    fake = HandshakeSocket(frames)
    fake.gettimeout = lambda: 3
    original_recv = fake.recv
    def recv(size):
        if fake.data:
            return original_recv(size)
        time.sleep(.002)
        raise socket.timeout()
    fake.recv = recv
    monkeypatch.setattr("codex_approvals.socket.socket", lambda *args: fake)
    monkeypatch.setattr("codex_approvals.socket.AF_UNIX", 1, raising=False)
    wire = LocalWebSocket("/isolated")
    start = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            client = talk.Client.__new__(talk.Client)
            client.sequence, client.wire = 0, wire
            client.rpc("thread/archive", {"threadId": "target"}, timeout=.02)
        assert time.monotonic() - start < .5
        assert wire._receive_deadline is None
    finally:
        wire.close()
