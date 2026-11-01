"""An explicit wrist choice wins over recent project history."""
import pytest
import watch_relay as relay
import ClaudeRiskClassifier as classifier


@pytest.mark.parametrize('chosen,recent', [('codex', None), ('claude', 'codex')])
def test_explicit_agent_controls_the_launched_command(monkeypatch, chosen, recent):
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [
        {'path': '/project', 'agent': recent}])
    monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: True)
    monkeypatch.setattr(relay, 'signed_in', lambda: True)
    monkeypatch.setattr(relay, 'trust_folder', lambda _: True)
    commands = []
    monkeypatch.setattr(relay._host, 'is_windows', lambda: False)
    monkeypatch.setattr(relay._host, 'open_terminal',
                        lambda script, windows: (commands.append(script) or True, ''))
    assert relay.start_session('/project', 'hello', platform='linux', agent=chosen) == 'started'
    assert ('/bin/codex' in commands[0]) == (chosen == 'codex')
    assert ('claude --settings' in commands[0]) == (chosen == 'claude')


@pytest.mark.parametrize('agent', ['', 'other', ['codex']])
def test_invalid_explicit_agent_is_refused_before_launch(monkeypatch, agent):
    monkeypatch.setattr(relay, 'known_projects', lambda *_: pytest.fail('must refuse first'))
    assert relay.start_session('/project', 'hello', agent=agent) == 'unknown agent'


def test_explicit_codex_never_falls_back_when_missing(monkeypatch):
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project'}])
    monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: None)
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: pytest.fail('fallback'))
    assert relay.start_session('/project', 'hello', agent='codex') == 'Codex is not installed on your computer'


@pytest.fixture(autouse=True)
def _no_real_codex(tmp_path, monkeypatch):
    """A Codex start may reach the shared server in CODEX_HOME. Never the
    owner's: it would open a real chat on his phone."""
    monkeypatch.setenv('CODEX_HOME', str(tmp_path / 'no-codex'))
    relay.clear_condition('codex_shared_service')


class Wire:
    """A shared server that answers each request, or drops one."""

    def __init__(self, drop=None):
        self.sent, self.responses, self.drop, self.closed = [], [], drop, False

    def send(self, value):
        self.sent.append(value)
        method = value.get('method')
        if method == 'initialized':
            return
        if method == self.drop:
            self.responses.append(EOFError('closed'))
            return
        result = {'thread/start': {'thread': {'id': 'thread-new'}},
                  'turn/start': {'turn': {'id': 'turn-1'}}}.get(method, {})
        self.responses.append({'id': value['id'], 'result': result})

    def receive(self):
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        self.closed = True

    def calls(self, method):
        return [m['params'] for m in self.sent if m.get('method') == method]


def test_codex_start_carries_the_watch_limits_on_the_shared_server():
    import codex_talk
    wire = Wire()
    assert codex_talk.start('/project', 'hello', connect=lambda: wire) == 'thread-new'
    [thread] = wire.calls('thread/start')
    assert thread['cwd'] == '/project' and thread['sandbox'] == 'workspace-write'
    assert thread['approvalsReviewer'] == 'user' and thread['approvalPolicy'] == 'on-request'
    assert thread['config'] == {'sandbox_workspace_write': {
        'network_access': False, 'writable_roots': [],
        'exclude_tmpdir_env_var': True, 'exclude_slash_tmp': True}}
    [turn] = wire.calls('turn/start')
    assert turn['threadId'] == 'thread-new' and turn['input'] == [{'type': 'text', 'text': 'hello'}]
    assert turn['sandboxPolicy'] == codex_talk.POLICY and turn['approvalsReviewer'] == 'user'
    assert wire.closed


def test_codex_start_lost_receipt_is_uncertain_and_never_retried():
    import codex_talk
    wire = Wire(drop='turn/start')
    with pytest.raises(ValueError, match='check the session before retrying'):
        codex_talk.start('/project', 'hello', connect=lambda: wire)
    assert len(wire.calls('turn/start')) == 1 and wire.closed


def test_codex_start_without_a_shared_server_says_so():
    import codex_talk
    assert codex_talk.start('/project', 'hello') is None   # CODEX_HOME has no socket


def _codex_project(monkeypatch, start):
    import codex_talk
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project', 'agent': 'codex'}])
    monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
    monkeypatch.setattr(relay, 'trust_folder', lambda _: pytest.fail('Claude trust reached'))
    monkeypatch.setattr(relay._host, 'is_windows', lambda: False)
    monkeypatch.setattr(codex_talk, 'start', start)
    scripts = []
    monkeypatch.setattr(relay._host, 'open_terminal',
                        lambda script, windows: (scripts.append(script) or True, ''))
    return scripts


def test_new_codex_session_starts_on_the_shared_server_and_terminal_only_shows_it(monkeypatch):
    # Before 2026-11-01 the Terminal ran `codex <flags> -- text`: a private
    # server the phone refused as "used by another session".
    import shlex
    import codex_talk
    begun = []
    scripts = _codex_project(monkeypatch, lambda cwd, text: begun.append((cwd, text)) or 'thread-new')
    relay.note_condition('codex_shared_service', 'stale')
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex') == 'started'
    assert begun == [('/project', 'hello')]
    words = shlex.split(scripts[0].split(' && ', 1)[1])
    assert words == (['/bin/codex', 'resume', '--remote', 'unix://' + codex_talk.shared_socket()]
                     + codex_talk.attach_flags() + ['thread-new'])
    # --remote refuses these; a refused Terminal never opens (0.166).
    assert '--sandbox' not in words and not any('writable_roots' in word for word in words)
    assert 'sandbox_workspace_write.exclude_slash_tmp=true' in words
    assert 'codex_shared_service' not in {c['key'] for c in relay.conditions()}


def test_without_the_shared_server_a_codex_session_still_starts_and_says_why(monkeypatch):
    import shlex
    import codex_talk
    scripts = _codex_project(monkeypatch, lambda cwd, text: None)
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex') == 'started'
    assert shlex.split(scripts[0].split(' && ', 1)[1]) == ['/bin/codex'] + codex_talk.flags() + ['--', 'hello']
    [condition] = [c for c in relay.conditions() if c['key'] == 'codex_shared_service']
    assert 'iPhone' in condition['detail']


def test_a_shared_codex_session_is_started_even_if_no_window_opens(monkeypatch):
    _codex_project(monkeypatch, lambda cwd, text: 'thread-new')
    monkeypatch.setattr(relay._host, 'open_terminal', lambda script, windows: (False, 'no display'))
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex') == 'started'


def test_a_refused_codex_start_opens_nothing(monkeypatch):
    def refuse(cwd, text):
        raise ValueError('Codex refused the message: no')
    scripts = _codex_project(monkeypatch, refuse)
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex') == 'Codex refused the message: no'
    assert scripts == []


# "Open a window" on the watch, off (owner, 2026-11-01).

def test_with_the_window_off_a_shared_codex_session_opens_no_window(monkeypatch):
    begun = []
    scripts = _codex_project(monkeypatch, lambda cwd, text: begun.append(text) or 'thread-new')
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex',
                               window=False) == 'started'
    assert begun == ['hello'] and scripts == []


def test_with_the_window_off_codex_without_the_shared_server_still_opens_one(monkeypatch):
    # Its window is the only place it can run.
    scripts = _codex_project(monkeypatch, lambda cwd, text: None)
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex',
                               window=False) == 'started'
    assert len(scripts) == 1


def _claude_on_a_mac(monkeypatch):
    import subprocess
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project'}])
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: True)
    monkeypatch.setattr(relay, 'signed_in', lambda: True)
    monkeypatch.setattr(relay, 'trust_folder', lambda _: True)
    opened = []

    def run(command, **_):
        # The .command file removes itself only when Terminal runs it.
        with open(command[-1], encoding='utf-8') as handle:
            opened.append((command[:-1], handle.read()))
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(relay.subprocess, 'run', run)
    monkeypatch.setattr(relay, '_run_osascript', lambda script: pytest.fail('fallback'))
    return opened


def test_with_the_window_off_a_claude_session_goes_straight_to_the_dock(monkeypatch):
    # Not headless: a headless run is left out of the session list and the
    # phone, so the window stays and is minimized instead.
    opened = _claude_on_a_mac(monkeypatch)
    assert relay.start_session('/project', 'hello', platform='darwin', agent='claude',
                               window=False) == 'started'
    [(command, body)] = opened
    assert command == ['open', '-g']
    minimize = body.index("printf '\\033[2t'")
    assert minimize < body.index('claude --settings')


def test_by_default_a_claude_session_window_comes_forward(monkeypatch):
    opened = _claude_on_a_mac(monkeypatch)
    assert relay.start_session('/project', 'hello', platform='darwin', agent='claude') == 'started'
    [(command, body)] = opened
    assert command == ['open'] and '[2t' not in body


def test_with_the_window_off_the_applescript_route_does_not_bring_terminal_forward(monkeypatch):
    import subprocess
    asked = []
    monkeypatch.setattr(relay.subprocess, 'run', lambda command, **_: subprocess.CompletedProcess(
        command, 1, '', 'refused'))
    monkeypatch.setattr(relay, '_run_osascript', lambda script: (asked.append(script) or True, ''))
    assert relay._open_session_window('/project', 'echo hi', ['echo', 'hi'], True,
                                      minimized=True) is None
    assert 'activate' not in asked[0] and '[2t' in asked[0]
    assert relay._open_session_window('/project', 'echo hi', ['echo', 'hi'], True) is None
    assert 'activate' in asked[1]


@pytest.mark.parametrize('sent,window', [({}, True), ({'window': False}, False),
                                         ({'window': True}, True), ({'window': 'false'}, True),
                                         ({'window': 0}, True), ({'window': None}, True)])
def test_only_an_explicit_false_turns_the_window_off(monkeypatch, sent, window):
    # A watch older than the setting sends nothing and keeps its window.
    seen = []
    monkeypatch.setattr(relay, 'start_session', lambda path, text, **choice: seen.append(choice))
    relay.start_session_from_request(dict(sent, path='/project', text='hello'))
    assert seen[0].get('window', True) is window
