"""An explicit wrist choice wins over recent project history."""
import pytest
import watch_relay as relay
import ClaudeRiskClassifier as classifier


@pytest.mark.parametrize('chosen,recent', [('codex', None), ('claude', 'codex')])
def test_explicit_agent_controls_the_launched_command(monkeypatch, chosen, recent):
    import codex_talk
    monkeypatch.setattr(codex_talk, 'start', lambda *_: 'thread-new')
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [
        {'path': '/project', 'agent': recent}])
    monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: True)
    monkeypatch.setattr(relay, 'signed_in', lambda **_: True)
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
    # No sign-in answer kept from an earlier test, or from this computer's
    # own Codex: on 2026-11-20 one read "signed out" for two minutes and
    # six starts below said "codex signed out" on the Mac mini.
    monkeypatch.setattr(relay, '_SIGNIN_CODEX', {'at': 0.0, 'in': None, 'asked': False})
    import codex_talk
    native_start = codex_talk._start_shared_service
    def refuse(_binary):
        raise ValueError('Codex background service unavailable in isolated test')
    monkeypatch.setattr(codex_talk, '_start_shared_service', refuse)
    relay.clear_condition('codex_shared_service')
    yield native_start


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


def test_new_codex_bootstraps_only_the_shared_service_before_creating_a_chat(monkeypatch):
    import codex_talk
    calls = []
    wire = Wire()
    attempts = []
    def connect():
        attempts.append(1)
        if len(attempts) == 1:
            raise FileNotFoundError('background service absent')
        return wire
    monkeypatch.setattr(codex_talk, '_start_shared_service',
                        lambda binary: calls.append(binary), raising=False)
    assert codex_talk.start('/project', 'hello', connect=connect,
                           binary='/bin/codex') == 'thread-new'
    assert calls == ['/bin/codex'] and len(wire.calls('thread/start')) == 1
    assert len(wire.calls('turn/start')) == 1 and wire.closed


@pytest.mark.parametrize('failure', [PermissionError, TimeoutError, EOFError])
def test_uncertain_shared_service_never_bootstraps_or_creates_a_private_chat(monkeypatch, failure):
    import codex_talk
    def connect():
        raise failure('uncertain')
    monkeypatch.setattr(codex_talk, '_start_shared_service',
                        lambda binary: pytest.fail('must not start another server'), raising=False)
    with pytest.raises(ValueError, match='background service'):
        codex_talk.start('/project', 'hello', connect=connect, binary='/bin/codex')


def test_shared_service_start_is_native_idempotent_and_has_no_permission_overrides(monkeypatch, _no_real_codex):
    import subprocess
    import codex_talk
    called = []
    monkeypatch.setattr(codex_talk.subprocess, 'run', lambda args, **kwargs:
        called.append((args, kwargs)) or subprocess.CompletedProcess(args, 0, '', ''))
    _no_real_codex('/path with spaces/codex')
    [(args, kwargs)] = called
    assert args == ['/path with spaces/codex', 'app-server', 'daemon', 'start']
    assert kwargs == {'stdin': subprocess.DEVNULL, 'capture_output': True,
                      'text': True, 'timeout': codex_talk.START_TIMEOUT}


def test_a_running_shared_service_is_not_started_again(monkeypatch):
    import codex_talk
    monkeypatch.setattr(codex_talk, '_start_shared_service',
                        lambda binary: pytest.fail('an existing service must be untouched'))
    wire = Wire()
    client = codex_talk._shared_client(binary='/bin/codex', connect=lambda: wire)
    client.close()
    assert wire.closed and not wire.calls('thread/start')


def test_shared_start_failure_never_creates_a_thread_or_retries_service_start(monkeypatch):
    import codex_talk
    attempts, starts = [], []
    def absent():
        attempts.append(1)
        raise FileNotFoundError('absent')
    def failed(binary):
        starts.append(binary)
        raise ValueError('background service start could not be confirmed')
    monkeypatch.setattr(codex_talk, '_start_shared_service', failed)
    with pytest.raises(ValueError, match='could not be confirmed'):
        codex_talk.start('/project', 'hello', connect=absent, binary='/bin/codex')
    assert attempts == [1] and starts == ['/bin/codex']


def test_codex_start_lost_receipt_is_uncertain_and_never_retried():
    import codex_talk
    wire = Wire(drop='turn/start')
    with pytest.raises(ValueError, match='check the session before retrying'):
        codex_talk.start('/project', 'hello', connect=lambda: wire)
    assert len(wire.calls('turn/start')) == 1 and wire.closed


def test_codex_start_without_a_shared_server_says_so():
    import codex_talk
    with pytest.raises(ValueError, match='background service'):
        codex_talk.start('/project', 'hello', binary='/bin/codex')


def _codex_project(monkeypatch, start):
    import codex_talk
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project', 'agent': 'codex'}])
    monkeypatch.setattr(classifier, 'ensure_codex_on_path', lambda: '/bin/codex')
    monkeypatch.setattr(relay, 'signed_in', lambda **_: True)
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
    monkeypatch.setattr(relay, 'signed_in', lambda **_: True)
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


# ---- Choosing a model for a new session --------------------------------
#
# The lists are Claude Code's and Codex's own; these answers are trimmed
# copies of what each said on 2026-11-23 (Claude Code 2.1.330, Codex 0.169).

CLAUDE_INITIALIZE = {'type': 'control_response', 'response': {'subtype': 'success',
    'request_id': 'tapproval-models', 'response': {'models': [
        {'value': 'default', 'resolvedModel': 'claude-opus-5-5',
         'displayName': 'Default (recommended)',
         'description': 'Opus 5.5 · Best for everyday, complex tasks'},
        {'value': 'opus', 'resolvedModel': 'claude-opus-5-5', 'displayName': 'Opus 5.5',
         'description': 'Best for everyday, complex tasks'},
        {'value': 'sonnet', 'resolvedModel': 'claude-sonnet-5-5', 'displayName': 'Sonnet 5.5',
         'description': 'Efficient for routine tasks'},
        {'value': 'claude-opus-4-8', 'resolvedModel': 'claude-opus-4-8',
         'displayName': 'Opus 4.8', 'description': 'Best for everyday, complex tasks'}]}}}

CODEX_MODELS = {'data': [
    {'id': 'gpt-6.2-sol', 'displayName': 'GPT-6.2-Sol', 'hidden': False, 'isDefault': True,
     'description': 'Fast, go-to model for coding and everyday work.'},
    {'id': 'gpt-6-astra', 'displayName': 'GPT-6-Astra', 'hidden': False, 'isDefault': False,
     'description': 'Previous generation model for complex coding and professional work.'},
    {'id': 'gpt-internal', 'displayName': 'Internal', 'hidden': True, 'isDefault': False}],
    'nextCursor': None}


@pytest.fixture(autouse=True)
def _fresh_model_lists():
    relay.forget_session_models()
    yield
    relay.forget_session_models()


def _answering(*values):
    """A stand-in for the program: replays what it would print."""
    asked = []

    def exchange(argv, messages, pick, **kwargs):
        asked.append((argv, messages, kwargs))
        for value in values:
            got = pick(value)
            if got is not None:
                return got
        return None
    return exchange, asked


def test_claude_list_is_its_own_without_default_and_names_what_default_is(tmp_path):
    exchange, asked = _answering({'type': 'system'}, CLAUDE_INITIALIZE)
    listed = relay.claude_session_models('/bin/claude', home=str(tmp_path), environ={},
                                         exchange=exchange)
    assert [m['id'] for m in listed['models']] == ['opus', 'sonnet', 'claude-opus-4-8']
    assert listed['models'][1] == {'id': 'sonnet', 'name': 'Sonnet 5.5',
                                   'note': 'Efficient for routine tasks'}
    assert listed['default'] == 'Opus 5.5'
    [(argv, messages, kwargs)] = asked
    # Asking starts none of the person's hooks, plugins or MCP servers,
    # and leaves no session behind.
    assert argv[:2] == ['/bin/claude', '-p']
    assert '--safe-mode' in argv and '--no-session-persistence' in argv
    assert messages == [{'type': 'control_request', 'request_id': 'tapproval-models',
                         'request': {'subtype': 'initialize'}}]


def test_claude_default_follows_the_persons_own_setting(tmp_path):
    (tmp_path / '.claude').mkdir()
    (tmp_path / '.claude' / 'settings.json').write_text('{"model": "sonnet"}')
    exchange, _ = _answering(CLAUDE_INITIALIZE)
    assert relay.claude_session_models('/bin/claude', home=str(tmp_path), environ={},
                                       exchange=exchange)['default'] == 'Sonnet 5.5'
    exchange, _ = _answering(CLAUDE_INITIALIZE)
    assert relay.claude_session_models('/bin/claude', home=str(tmp_path),
                                       environ={'ANTHROPIC_MODEL': 'claude-opus-4-8'},
                                       exchange=exchange)['default'] == 'Opus 4.8'


def test_claude_probe_is_not_a_child_of_this_session_and_reaches_no_wrist(tmp_path):
    exchange, asked = _answering(CLAUDE_INITIALIZE)
    relay.claude_session_models('/bin/claude', home=str(tmp_path), exchange=exchange,
                                environ={'CLAUDECODE': '1', 'CLAUDE_RISK_RELAY': 'http://x',
                                         'CLAUDE_RISK_MODE': 'enforce', 'PATH': '/bin'})
    env = asked[0][2]['env']
    assert env == {'PATH': '/bin'}


def test_codex_list_skips_hidden_models_and_names_the_persons_default():
    exchange, asked = _answering({'id': 1, 'result': {}}, {'id': 2, 'result': CODEX_MODELS},
                                 {'id': 3, 'result': {'config': {'model': 'gpt-6-astra'}}})
    listed = relay.codex_session_models('/bin/codex', exchange=exchange)
    assert [m['id'] for m in listed['models']] == ['gpt-6.2-sol', 'gpt-6-astra']
    assert listed['default'] == 'GPT-6-Astra'
    # A private app-server: never the shared one a phone or Terminal holds.
    assert asked[0][0] == ['/bin/codex', 'app-server']
    exchange, _ = _answering({'id': 2, 'result': CODEX_MODELS}, {'id': 3, 'result': {'config': {}}})
    assert relay.codex_session_models('/bin/codex', exchange=exchange)['default'] == 'GPT-6.2-Sol'


@pytest.mark.parametrize('reader,answer', [
    (relay.claude_session_models, {'type': 'control_response', 'response': {'response': {}}}),
    (relay.codex_session_models, {'id': 2, 'error': {'message': 'unknown method'}}),
])
def test_an_unreadable_list_is_none_never_a_raise(reader, answer):
    exchange, _ = _answering(answer, {'id': 3, 'result': {}})
    assert reader('/bin/x', exchange=exchange) is None


def test_a_model_id_the_list_could_not_have_offered_is_dropped():
    odd = {'type': 'control_response', 'response': {'response': {'models': [
        {'value': '--dangerously-skip-permissions', 'displayName': 'x'},
        {'value': 'a b', 'displayName': 'x'}, {'value': 'opus', 'displayName': 'Opus 5.5'}]}}}
    exchange, _ = _answering(odd)
    listed = relay.claude_session_models('/bin/claude', environ={}, exchange=exchange)
    assert [m['id'] for m in listed['models']] == ['opus']


def _program(tmp_path, name='claude'):
    program = tmp_path / name
    program.write_text('v1')
    return program


def test_the_list_is_kept_until_the_program_changes(tmp_path):
    program = _program(tmp_path)
    reads = []
    def read(binary):
        reads.append(binary)
        return {'default': 'Opus 5.5', 'models': [{'id': 'opus', 'name': 'Opus 5.5', 'note': ''}]}
    def ask(now):
        return relay.session_models('claude', now=now, locate=lambda _: str(program), read=read)
    assert ask(1000)['models'][0]['id'] == 'opus'
    assert ask(1000 + 3600)['default'] == 'Opus 5.5'
    assert len(reads) == 1
    # An update writes a new program: the next answer asks again.
    program.write_text('version two')
    ask(1000 + 3601)
    import time
    deadline = time.monotonic() + 5
    while len(reads) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(reads) == 2


def test_a_failed_list_is_default_alone_and_asked_again_soon(tmp_path):
    program = _program(tmp_path)
    reads = []
    def ask(now):
        return relay.session_models('claude', now=now, locate=lambda _: str(program),
                                    read=lambda binary: reads.append(1))
    assert ask(1000) == {'default': None, 'models': []}
    assert ask(1000 + relay.SESSION_MODELS_RETRY_AFTER - 1) == {'default': None, 'models': []}
    assert len(reads) == 1
    ask(1000 + relay.SESSION_MODELS_RETRY_AFTER + 1)
    assert len(reads) == 2


def test_a_program_that_is_not_installed_has_no_list():
    assert relay.session_models('codex', locate=lambda _: None,
                                read=lambda _: pytest.fail('nothing to ask')) == {
        'default': None, 'models': []}


def _offering(monkeypatch, *ids):
    monkeypatch.setattr(relay, 'session_models', lambda agent, **_: {
        'default': None, 'models': [{'id': i, 'name': i, 'note': ''} for i in ids]})


def test_a_claude_session_starts_on_the_chosen_model(monkeypatch):
    _offering(monkeypatch, 'opus', 'sonnet')
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project'}])
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: True)
    monkeypatch.setattr(relay, 'signed_in', lambda **_: True)
    monkeypatch.setattr(relay, 'trust_folder', lambda _: True)
    monkeypatch.setattr(relay._host, 'is_windows', lambda: False)
    scripts = []
    monkeypatch.setattr(relay._host, 'open_terminal',
                        lambda script, windows: (scripts.append(script) or True, ''))
    assert relay.start_session('/project', 'hello', platform='linux', agent='claude',
                               model='sonnet') == 'started'
    assert "--model sonnet -- hello" in scripts[0]
    assert relay.start_session('/project', 'hello', platform='linux', agent='claude') == 'started'
    assert '--model' not in scripts[1]


@pytest.mark.parametrize('model', ['haiku', '--dangerously-skip-permissions', '', 'a b', ['opus']])
def test_a_model_not_on_the_programs_list_is_refused_before_a_window(monkeypatch, model):
    _offering(monkeypatch, 'opus')
    monkeypatch.setattr(relay, 'known_projects', lambda *_: [{'path': '/project'}])
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: pytest.fail('no launch'))
    monkeypatch.setattr(relay._host, 'open_terminal', lambda *_: pytest.fail('no window'))
    assert relay.start_session('/project', 'hello', agent='claude', model=model) == 'unknown model'


def test_session_model_offered_checks_the_id_before_the_list(monkeypatch):
    monkeypatch.setattr(relay, 'session_models', lambda *a, **k: pytest.fail('junk never asked'))
    assert relay.session_model_offered('claude', '-x') is False
    assert relay.session_model_offered('claude', None) is False


def test_a_codex_chat_starts_on_the_chosen_model_and_its_terminal_keeps_it(monkeypatch):
    _offering(monkeypatch, 'gpt-6.2-astra')
    started = []
    scripts = _codex_project(monkeypatch, lambda path, text, **kw: started.append(kw) or 'thread-new')
    monkeypatch.setattr(relay, 'shared_socket', lambda: '/tmp/codex.sock', raising=False)
    import codex_talk
    monkeypatch.setattr(codex_talk, 'shared_socket', lambda: '/tmp/codex.sock')
    assert relay.start_session('/project', 'hello', platform='linux', agent='codex',
                               model='gpt-6.2-astra') == 'started'
    assert started == [{'model': 'gpt-6.2-astra'}]
    assert '-c \'model="gpt-6.2-astra"\' thread-new' in scripts[0]


def test_codex_thread_start_names_the_model_only_when_one_was_chosen():
    import codex_talk
    wire = Wire()
    codex_talk.start('/project', 'hello', connect=lambda: wire, model='gpt-6-astra')
    assert wire.calls('thread/start')[0]['model'] == 'gpt-6-astra'
    wire = Wire()
    codex_talk.start('/project', 'hello', connect=lambda: wire)
    assert 'model' not in wire.calls('thread/start')[0]


def test_the_request_carries_the_model_and_an_older_watch_sends_none(monkeypatch):
    seen = []
    monkeypatch.setattr(relay, 'start_session', lambda path, text, **kw: seen.append(kw) or 'started')
    relay.start_session_from_request({'path': '/p', 'text': 't', 'agent': 'claude', 'model': 'opus'})
    relay.start_session_from_request({'path': '/p', 'text': 't', 'agent': 'claude'})
    assert seen == [{'agent': 'claude', 'model': 'opus'}, {'agent': 'claude'}]


def test_the_list_needs_a_device_and_says_both_programs(monkeypatch):
    handler, options = relay.RelayHandler.ROUTES['GET']['/models']
    assert handler == '_get_models' and options.get('token') is True
    _offering(monkeypatch, 'x')
    assert set(relay.all_session_models(wait=0)) == {'claude', 'codex'}


def test_a_start_after_an_update_is_checked_against_the_new_list(tmp_path, monkeypatch):
    # Review 2026-11-23: the old list answered while the new one was read,
    # so a model the update removed still opened a window.
    program = _program(tmp_path)
    lists = [['opus', 'haiku'], ['opus']]

    def read(binary):
        return {'default': None, 'models': [{'id': i, 'name': i, 'note': ''} for i in lists.pop(0)]}
    monkeypatch.setattr(relay, '_session_model_program', lambda _agent: str(program))
    monkeypatch.setitem(relay._SESSION_MODEL_READERS, 'claude', read)
    assert relay.session_model_offered('claude', 'haiku') is True
    program.write_text('version two')
    assert relay.session_model_offered('claude', 'haiku') is False
    assert relay.session_model_offered('claude', 'opus') is True


def test_claude_is_found_the_way_every_other_claude_run_finds_it(monkeypatch):
    # Review 2026-11-23: a relay started on launchd's bare PATH found no
    # list, while a new session found claude through ensure_claude_on_path.
    found = []
    monkeypatch.setattr(relay, 'ensure_claude_on_path', lambda: found.append(1) or True)
    monkeypatch.setattr(relay.shutil, 'which', lambda name: '/found/claude' if found else None)
    assert relay._session_model_program('claude') == '/found/claude'


def test_a_setting_of_default_is_no_setting(tmp_path):
    (tmp_path / '.claude').mkdir()
    (tmp_path / '.claude' / 'settings.json').write_text('{"model": "default"}')
    exchange, _ = _answering(CLAUDE_INITIALIZE)
    assert relay.claude_session_models('/bin/claude', home=str(tmp_path), environ={},
                                       exchange=exchange)['default'] == 'Opus 5.5'


def test_asking_leaves_no_pipe_open(monkeypatch):
    import subprocess
    import sys
    made = []
    real = subprocess.Popen

    def recording(*args, **kwargs):
        made.append(real(*args, **kwargs))
        return made[-1]
    monkeypatch.setattr(relay.subprocess, 'Popen', recording)
    script = 'import sys\nsys.stdin.readline()\nprint("{\\"ok\\": 1}", flush=True)\n'
    assert relay._json_lines_exchange([sys.executable, '-c', script], [{}],
                                      lambda v: v.get('ok'), timeout=10) == 1
    assert made[0].stdin.closed and made[0].stdout.closed
