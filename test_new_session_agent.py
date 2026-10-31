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
