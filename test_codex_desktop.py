"""Desktop transport ownership, safe discovery and independent native servers."""
import json
import os
import plistlib
import stat

import pytest

import codex_desktop as desktop
from codex_approvals import ApprovalHub, ApprovalSync
from watch_relay import CardQueue
from test_codex_approvals import Wire, request, until, resolved


@pytest.mark.parametrize("args,expected", [
    (["-c", "features.code_mode_host=true", "app-server", "--analytics-default-enabled",
      "-c", "plugins.codex-app-tools.enabled=true"], True),
    (["app-server", "--print-startup-config"], False),
    (["app-server", "--startup-sign-out"], False),
    (["app-server", "proxy", "--sock", "/private/socket"], False),
    (["app-server", "daemon", "version"], False),
    (["app-server", "generate-json-schema"], False),
    (["app-server", "--listen=unix:///custom"], False),
    (["app-server", "--stdio"], False),
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


def test_server_args_are_preserved_and_only_own_children_are_stopped(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Desktop adapter is opt-in on POSIX")
    # Use a short root; no real process or socket is launched in this test.
    monkeypatch.setattr(desktop, "codex_home", lambda: tmp_path)
    monkeypatch.setattr(desktop.os, "fsencode", lambda _path: b"short")
    monkeypatch.setattr(desktop.Path, "exists", lambda _path: True)
    calls = []
    class Child:
        pid = os.getpid()
        returncode = None
        def poll(self):
            return self.returncode
        def wait(self, timeout=None):
            self.returncode = 0
            return 0
        def terminate(self):
            self.returncode = 0
        def kill(self):
            pytest.fail("graceful child cleanup should suffice")
    def spawn(args, **kwargs):
        calls.append((args, kwargs))
        return Child()
    monkeypatch.setattr(desktop.subprocess, "Popen", spawn)
    proxied = []
    monkeypatch.setattr(desktop, "proxy_stdio", lambda path: proxied.append(path) or 0)
    real = tmp_path / "codex"
    real.touch()
    args = ["-c", "features.code_mode_host=true", "app-server", "-c",
            'approval_policy="on-request"', "-c", "plugins.codex-app-tools.enabled=true"]
    monkeypatch.setenv("CODEX_CLI_PATH", "/wrapper")
    assert desktop.run(str(real), args) == 0
    assert calls[0][0][1:-2] == args
    assert calls[0][0][-2] == "--listen"
    assert proxied == [calls[0][0][-1].removeprefix("unix://")]
    assert calls[0][1]["env"]["CODEX_CLI_PATH"] == str(real)
    assert not list((tmp_path / "tapproval-desktop").iterdir())


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
