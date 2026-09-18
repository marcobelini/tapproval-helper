# -*- coding: utf-8 -*-
"""
Tests for ClaudeRiskClassifier.py

Covers:
- classify_bash(): shell command risk tiers, chaining, fail-closed defaults
- classify_path(): write-target risk tiers, project boundary, repo-specific rules
- classify(): tool dispatch, payload inspection for write tools
- wrist_card(): the watch-face contract (headline/detail length limits)
- decide()/load_policy(): shadow vs enforce, thresholds, critical handling
- run_hook(): end-to-end stdin/stdout contract, including stdout purity

The module is pure standard library, so nothing needs mocking beyond the
filesystem for audit-log tests.
"""

import ast
import importlib.util
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import sysconfig
import time

import pytest

import json as _json
import threading
import urllib.error
import urllib.request

import crash_report
import watch_permission_tool as wpt
import watch_relay
import watch_dashboard

import ClaudeRiskClassifier as crc
from ClaudeRiskClassifier import Risk

# serve_forever() checks for shutdown every poll_interval; the default is
# half a second, and shutdown() blocks until that check comes round. With
# fifty-odd relay tests that is ~27 s of the suite spent waiting for a
# server to notice it was told to stop. Nothing observable changes.
_POLL = 0.02


@pytest.fixture(autouse=True)
def _no_leftover_conditions():
    """The relay's condition registry is module-wide, like SITE_RULES: a
    condition left behind by one test would make the next pass for the
    wrong reason. Cleared around every test, once, here — two classes
    used to carry their own copy, one of them rebinding the dict out
    from under the lock that guards it."""
    watch_relay._CONDITIONS.clear()
    yield
    watch_relay._CONDITIONS.clear()


def _serve(server):
    """Run a test relay on a daemon thread; returns the thread. The one
    place the poll interval is set — thirteen call sites each carried
    the lambda, which is how a tuning knob gets missed at one of them."""
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=_POLL),
                              daemon=True)
    thread.start()
    return thread


def _behavior(payload):
    """What Claude Code will actually do with a hook response.

    Accepts the whole response or just its hookSpecificOutput block.
    Returns "allow", "deny", or "escalate" — escalate being the *absence*
    of a decision, which is how the question is left with the human.
    The CLI validates the shape: a bare string is rejected outright, and
    a rejected hook is non-blocking, so the old string form silently did
    nothing at all.
    """
    out = payload.get("hookSpecificOutput", payload)
    decision = out.get("decision")
    return decision.get("behavior") if isinstance(decision, dict) else "escalate"


def _decision_message(payload):
    out = payload.get("hookSpecificOutput", payload)
    decision = out.get("decision")
    return decision.get("message", "") if isinstance(decision, dict) else ""



@pytest.fixture(autouse=True)
def _no_real_self_update(tmp_path, monkeypatch):
    """No test may run `git pull` on the working tree.

    The SessionStart hook fast-forwards a git install on its way past, and
    this repository is one — so without this the suite pulled the very
    checkout it was testing. It also made an unrelated test order-dependent:
    the first test to run wrote the daily stamp, and every test after it
    silently skipped the update. Point the stamp somewhere disposable and
    mark it fresh, so the "asked recently" branch short-circuits before any
    subprocess is reached. Tests that mean to exercise the update override
    this themselves.
    """
    stamp = tmp_path / "last-update"
    stamp.write_text("now", encoding="utf-8")
    # The env var reaches subprocesses; the attribute covers in-process calls
    # made before a subprocess re-imports the module.
    monkeypatch.setenv("TAPPROVAL_UPDATE_STAMP", str(stamp))
    monkeypatch.setattr(watch_relay, "_UPDATE_STAMP", str(stamp))


@pytest.fixture
def settings(tmp_path, monkeypatch):
    """The throwaway settings.json every test already has, as a Path.

    The isolation itself — no ambient wrist-approval settings, and the
    file and audit log pointed at a throwaway — is `_no_ambient_policy`,
    which runs for every test whether it asks or not. This fixture only
    hands the installer tests the path so they can read it back.
    """
    return Path(os.environ["CLAUDE_SETTINGS_PATH"])


@pytest.fixture
def fresh_auth(tmp_path, monkeypatch):
    """A real Auth on a throwaway path, with the legacy-token migration
    pointed at nothing. Two suites used to assemble one with Auth.__new__
    and ten hand-set private fields — every new field on Auth then had to
    be added in both places, and a handler thread crashed when it was
    not. The real initialiser cannot get out of step with itself."""
    monkeypatch.setattr(watch_relay, "TOKEN_FILE", str(tmp_path / "no-token"))
    auth = watch_relay.Auth(path=str(tmp_path / "auth.json"))
    auth.save = lambda: None
    return auth


def _known_watch(auth):
    """The fixture's one paired watch: fixed secrets the tests can type."""
    auth.tunnel_secret = "tunnelsecret"
    auth.bootstrap = "bootstraptoken"
    auth.devices = [{"id": "w1", "token": "devicetoken",
                     "label": "Watch", "issued": 0, "last_seen": 0,
                     "source": "test"}]
    auth.paired_ever = True
    auth.close_window()
    return auth


# The real one, kept before any fixture stubs it: the tests about signing
# in are the tests that must run it.
_REAL_SIGNED_IN = watch_relay.signed_in


def _watch_present(queue):
    """What /health's watch_seen_seconds_ago means to the wrist: seen
    within WATCH_PRESENT_SECONDS. The queue used to carry this as a
    method nothing in production called."""
    seen = queue.watch_seen_seconds_ago()
    return seen is not None and seen <= queue.WATCH_PRESENT_SECONDS


def relay_call(url, token=None, method="GET", body=None):
    """One HTTP call to a test relay: (status, parsed body). An HTTP
    error is an answer here, not an exception."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Tapproval-Token"] = token
    data = json.dumps(body or {}).encode() if method == "POST" else None
    request = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as reply:
            return reply.status, _json.loads(reply.read().decode())
    except urllib.error.HTTPError as error:
        try:
            return error.code, _json.loads(error.read().decode())
        except Exception:
            return error.code, {}



@pytest.fixture(autouse=True)
def _no_real_home_files(tmp_path, monkeypatch):
    """No test may read or write the owner's own Tapproval files.

    Found 2026-09-17: the real crash log held 57 copies of one test's
    "decode failed: /sessions", a test created the real pairing file with
    fresh secrets when it was missing, and the say and relay logs were
    written on every run. Each path is fixed at import, so HOME alone
    would not have redirected them.
    """
    home = tmp_path / "home-files"
    home.mkdir()
    monkeypatch.setattr(crash_report, "CRASH_LOG", str(home / "crashes.jsonl"))
    monkeypatch.setattr(crash_report, "KEY_FILE", str(home / "no-resend-key"))
    crash_report._reset_for_tests()
    monkeypatch.setattr(watch_relay, "AUTH_FILE", str(home / "auth.json"))
    monkeypatch.setattr(watch_relay, "TOKEN_FILE", str(home / "no-token"))
    monkeypatch.setattr(watch_relay, "RELAY_LOG", str(home / "relay.log"))
    monkeypatch.setattr(watch_relay, "SAY_LOG", str(home / "say.log"))
    # And no test may read the owner's own Claude Code transcripts. Routes
    # that list sessions walked ~/.claude/projects — on this machine a
    # 97 MB transcript among them — so a routing test could time out
    # because of what the owner had been working on. A test's world is
    # its tmp_path; one that wants transcripts writes them there.
    projects = home / "projects"
    projects.mkdir()
    monkeypatch.setattr(watch_dashboard, "CLAUDE_PROJECTS", str(projects))
    sessions = home / "sessions"
    sessions.mkdir()
    monkeypatch.setattr(watch_dashboard, "CLAUDE_SESSIONS", str(sessions))
    # And no test asks the real CLI whether it is signed in: /health does
    # that now, so a routing test would otherwise start a subprocess — and
    # one such test asserts that nothing was spawned at all. The tests
    # about signing in put the real function back.
    monkeypatch.setattr(watch_relay, "_SIGNIN", {"at": 0.0, "in": None})
    monkeypatch.setattr(watch_relay, "signed_in", lambda *a, **k: None)


@pytest.fixture(autouse=True)
def _no_real_launch_agent(tmp_path, monkeypatch):
    """No test may ever touch the real LaunchAgents dir or launchctl —
    same isolation rule as CLAUDE_SETTINGS_PATH."""
    monkeypatch.setenv("CLAUDE_LAUNCH_AGENT_PATH",
                       str(tmp_path / "com.tapproval.relay.plist"))
    monkeypatch.setattr(crc, "_launchctl", lambda *args: None)


@pytest.fixture(autouse=True)
def _no_ambient_policy(tmp_path, monkeypatch):
    """Every test starts from the machine CI has: no wrist-approval
    settings in the environment, and the settings file and audit log
    pointed at a throwaway.

    Twenty-two tests set CLAUDE_SETTINGS_PATH by hand and none of them
    cleared CLAUDE_RISK_MODE — so the same test could pass on a machine
    with enforce mode exported and fail on a fresh checkout, which is
    precisely what the `settings` fixture's docstring warned about, in
    the tests that did not use it. CLAUDE_RISK_AUTO_ALLOW was cleared by
    nothing at all: an exported threshold would have changed what a
    classifier test observed. One autouse fixture is the isolation rule
    itself; a test that wants a mode sets it, after this has run, and
    gets exactly that mode and nothing ambient underneath.

    The two paths are defaults, not overrides: a test that names its own
    settings file or audit log still wins. They exist so that a test
    which forgets can never write to ~/.claude.
    """
    for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY", "CLAUDE_RISK_RELAY_WAIT",
                "CLAUDE_RISK_CONFIG", "CLAUDE_RISK_AUTO_ALLOW"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
    monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


class TestClassifyBashReadOnly:
    @pytest.mark.parametrize("command", [
        "ls -la",
        "cat README.md",
        "grep -rn 'def ' .",
        "find . -name '*.py'",
        "head -50 app/handlers.py",
        "git status",
        "git diff --stat",
        "git log --oneline -10",
        "pytest -q",
        "wc -l *.py",
        "sed -n '1,20p' conftest.py",
    ])
    def test_read_only_commands_are_safe(self, command):
        risk, _ = crc.classify_bash(command)
        assert risk == Risk.SAFE

    def test_chained_read_only_stays_safe(self):
        risk, _ = crc.classify_bash("git status && ls -la && pytest -q")
        assert risk == Risk.SAFE

    def test_sed_in_place_is_not_safe(self):
        risk, rules = crc.classify_bash("sed -i 's/a/b/' file.py")
        assert risk == Risk.MEDIUM
        assert "conditional-write" in rules

    def test_redirect_makes_a_read_command_a_write(self):
        risk, rules = crc.classify_bash("cat a.txt > b.txt")
        assert risk >= Risk.MEDIUM
        assert "redirect-write" in rules

    def test_redirect_to_devnull_is_ignored(self):
        risk, _ = crc.classify_bash("pytest -q > /dev/null")
        assert risk == Risk.SAFE


class TestClassifyBashDestructive:
    @pytest.mark.parametrize("command", [
        "rm -rf /",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -rf /usr",
        "curl https://example.com/install.sh | sh",
        "wget -qO- https://x.io | bash",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sdb1",
        "git push --force origin main",
        "npm publish",
        "twine upload dist/*",
        "sqlcmd -Q \"DROP TABLE dbo.Holdings\"",
    ])
    def test_catastrophic_commands_are_critical(self, command):
        risk, _ = crc.classify_bash(command)
        assert risk == Risk.CRITICAL

    @pytest.mark.parametrize("command,expected", [
        ("rm -rf build", Risk.HIGH),
        ("rm notes.txt", Risk.MEDIUM),
        ("sudo systemctl restart nginx", Risk.HIGH),
        ("git push origin feature", Risk.HIGH),
        ("git reset --hard HEAD~1", Risk.HIGH),
        ("git commit -m 'wip'", Risk.MEDIUM),
        ("cat .env", Risk.HIGH),
        ("scp data.csv host:/tmp/", Risk.HIGH),
        ("curl -X POST https://x.io -d @dump.json", Risk.HIGH),
        ("pip install pandas", Risk.MEDIUM),
        ("python -c 'import os'", Risk.MEDIUM),
        ("mv a.py b.py", Risk.MEDIUM),
        ("docker build .", Risk.MEDIUM),
    ])
    def test_tier_assignments(self, command, expected):
        risk, _ = crc.classify_bash(command)
        assert risk == expected

    def test_force_push_to_feature_branch_is_high_not_critical(self):
        risk, _ = crc.classify_bash("git push --force origin claude/my-branch")
        assert risk == Risk.HIGH

    def test_force_with_lease_is_not_treated_as_force(self):
        risk, _ = crc.classify_bash("git push --force-with-lease origin main")
        assert risk == Risk.HIGH

    def test_chain_takes_the_maximum_risk(self):
        risk, _ = crc.classify_bash("ls -la && rm -rf / && echo done")
        assert risk == Risk.CRITICAL

    @pytest.mark.parametrize("command", [
        "git -C /repo push --force origin main",
        "git -c user.name=x push --force origin main",
        "git --git-dir=/repo/.git push --force origin main",
        "git --git-dir /repo/.git push --force origin main",
        "git -C /repo -c core.pager=cat push --force origin main",
    ])
    def test_git_global_flags_do_not_hide_a_protected_force_push(self, command):
        """`-C <dir>` / `-c <k>=<v>` and friends must not smuggle a
        protected force-push past the subcommand parser down to MEDIUM."""
        risk, rules = crc.classify_bash(command)
        assert risk == Risk.CRITICAL
        assert "git-force-push-protected" in rules

    def test_git_global_flag_keeps_read_only_subcommand_safe(self):
        risk, _ = crc.classify_bash("git -C /repo status")
        assert risk == Risk.SAFE

    @pytest.mark.parametrize("command", [
        "echo $(rm -rf /)",
        "x=`mkfs.ext4 /dev/sda`",
        "echo $(git push --force origin main)",
        "echo $(echo $(rm -rf /))",
    ])
    def test_command_substitution_descends_into_the_inner_command(self, command):
        """A destructive command inside `$(…)`/backticks runs for real, so
        its tier must surface — not hide behind the MEDIUM substitution cap."""
        risk, _ = crc.classify_bash(command)
        assert risk == Risk.CRITICAL

    def test_benign_command_substitution_stays_capped_at_medium(self):
        risk, rules = crc.classify_bash("echo $(date)")
        assert risk == Risk.MEDIUM
        assert "cmd-substitution" in rules


class TestSiteRules:
    """Deployment-specific rules. The tool ships knowing nothing about any
    particular infrastructure; you name your own servers in config."""

    @pytest.fixture(autouse=True)
    def _isolate(self):
        """Site rules are module-wide, so reset them around every test."""
        crc.configure_site_rules({})
        yield
        crc.configure_site_rules({})

    def test_no_site_rules_by_default(self):
        assert crc.SITE_RULES == []
        risk, _ = crc.classify_bash("cp out.csv //fileserver-01/data/")
        assert risk < Risk.HIGH

    def test_named_host_in_a_command_is_high(self):
        crc.configure_site_rules({"sensitive_hosts": ["db-prod-01"]})
        risk, rules = crc.classify_bash('sqlcmd -S db-prod-01 -Q "SELECT 1"')
        assert risk == Risk.HIGH
        assert "sensitive-host" in rules

    def test_named_host_in_a_path_is_high(self):
        crc.configure_site_rules({"sensitive_hosts": ["fileserver-01"]})
        risk, rules = crc.classify_path("//fileserver-01/shared/Report.py")
        assert risk == Risk.HIGH
        assert "sensitive-host" in rules

    def test_matches_either_path_separator(self):
        crc.configure_site_rules({"sensitive_hosts": ["fileserver-01"]})
        for path in ("//fileserver-01/x", "\\\\fileserver-01\\x"):
            assert crc.classify_path(path)[0] == Risk.HIGH, path

    def test_matching_is_case_insensitive(self):
        crc.configure_site_rules({"sensitive_hosts": ["db-prod-01"]})
        assert crc.classify_bash("ping DB-PROD-01")[0] == Risk.HIGH

    def test_host_named_in_file_content_is_high(self):
        crc.configure_site_rules({"sensitive_hosts": ["db-prod-01"]})
        result = crc.classify({"tool_name": "Write",
                               "tool_input": {"file_path": "notes.md",
                                              "content": "connect to db-prod-01"}})
        assert result["risk"] == Risk.HIGH
        assert "sensitive-host" in result["rules"]

    def test_hostnames_are_matched_literally_not_as_regex(self):
        """A dotted hostname must not behave as a wildcard pattern."""
        crc.configure_site_rules({"sensitive_hosts": ["db.prod.example"]})
        assert crc.classify_bash("ping db.prod.example")[0] == Risk.HIGH
        assert crc.classify_bash("ping dbXprodYexample")[0] < Risk.HIGH

    def test_blank_and_missing_entries_are_ignored(self):
        assert crc.configure_site_rules({"sensitive_hosts": ["", "  ", None]}) == []
        assert crc.configure_site_rules({}) == []
        assert crc.configure_site_rules({"sensitive_hosts": None}) == []

    def test_load_policy_installs_the_rules(self, tmp_path, monkeypatch):
        config = tmp_path / "policy.json"
        config.write_text(json.dumps({"sensitive_hosts": ["db-prod-01"]}), encoding="utf-8")
        monkeypatch.setenv("CLAUDE_RISK_CONFIG", str(config))
        crc.load_policy()
        assert crc.classify_bash("ping db-prod-01")[0] == Risk.HIGH


class TestClassifyBashSql:
    """SQL is dangerous wherever it runs, independent of site config."""

    def test_sql_mutation_is_high(self):
        risk, rules = crc.classify_bash("sqlcmd -Q \"INSERT INTO dbo.Holdings VALUES (1)\"")
        assert risk == Risk.HIGH
        assert "sql-mutation" in rules


class TestClassifyBashFailClosed:
    def test_unknown_command_is_not_auto_allowed(self):
        risk, rules = crc.classify_bash("some-unknown-binary --do-a-thing")
        assert risk >= Risk.MEDIUM
        assert "unknown-command" in rules

    def test_empty_command_is_not_auto_allowed(self):
        risk, _ = crc.classify_bash("")
        assert risk >= Risk.MEDIUM

    def test_command_substitution_is_not_auto_allowed(self):
        risk, rules = crc.classify_bash("echo $(cat /etc/passwd)")
        assert risk >= Risk.MEDIUM
        assert "cmd-substitution" in rules

    def test_env_assignment_prefix_does_not_hide_the_command(self):
        risk, _ = crc.classify_bash("FOO=bar rm -rf /")
        assert risk == Risk.CRITICAL


class TestClassifyPath:
    @pytest.mark.parametrize("path,expected", [
        ("test_pdsqlconn.py", Risk.LOW),
        ("README.md", Risk.LOW),
        ("app/handlers.py", Risk.MEDIUM),
        ("migrations/002_add_index.sql", Risk.HIGH),
        (".github/workflows/ci.yml", Risk.HIGH),
        ("requirements.txt", Risk.HIGH),
        (".env", Risk.CRITICAL),
        (".git/config", Risk.CRITICAL),
        ("~/.ssh/id_rsa", Risk.CRITICAL),
    ])
    def test_path_tiers(self, path, expected):
        risk, _ = crc.classify_path(path, cwd=os.getcwd())
        assert risk == expected

    def test_write_outside_the_project_is_high(self):
        risk, rules = crc.classify_path("/etc/passwd", cwd="/home/user/project")
        assert risk == Risk.HIGH
        assert "outside-project" in rules

    def test_write_inside_the_project_is_not_flagged_as_outside(self):
        risk, rules = crc.classify_path("/home/user/project/Foo.py", cwd="/home/user/project")
        assert "outside-project" not in rules
        assert risk == Risk.MEDIUM

    def test_missing_path_is_not_auto_allowed(self):
        risk, _ = crc.classify_path(None)
        assert risk >= Risk.MEDIUM


class TestClassifyDispatch:
    def test_read_only_tools_are_safe(self):
        for tool in ("Read", "Glob", "Grep", "TodoWrite"):
            result = crc.classify({"tool_name": tool, "tool_input": {}})
            assert result["risk"] == Risk.SAFE, tool

    def test_unknown_tool_is_not_auto_allowed(self):
        result = crc.classify({"tool_name": "SomeFutureTool", "tool_input": {}})
        assert result["risk"] >= Risk.MEDIUM

    def test_missing_tool_name_is_not_auto_allowed(self):
        assert crc.classify({})["risk"] >= Risk.MEDIUM

    def test_mcp_write_tool_is_high(self):
        result = crc.classify({"tool_name": "mcp__github__create_pull_request",
                               "tool_input": {}})
        assert result["risk"] == Risk.HIGH

    def test_mcp_read_tool_is_medium(self):
        result = crc.classify({"tool_name": "mcp__github__get_file_contents",
                               "tool_input": {}})
        assert result["risk"] == Risk.MEDIUM

    @pytest.mark.parametrize("tool,tier", [
        # The old regex used [^_]+ for the server, so a server whose name
        # carries an underscore never matched and every write on it read
        # as an unknown MCP tool — two tiers below the same write elsewhere.
        ("mcp__ccd_session_mgmt__send_message", Risk.HIGH),
        ("mcp__scheduled_tasks__delete_scheduled_task", Risk.HIGH),
        ("mcp__scheduled_tasks__update_scheduled_task", Risk.HIGH),
        # Two things that regex did that a whole-word split lost, found in
        # review: it matched camelCase names, and it matched a verb as a
        # prefix. Neither may read lower than it did.
        ("mcp__gh__createIssue", Risk.HIGH),
        ("mcp__gh__deleteFile", Risk.HIGH),
        ("mcp__gh__getFileContents", Risk.MEDIUM),
        ("mcp__x__setup_webhook", Risk.HIGH),
        ("mcp__x__runtime_info", Risk.HIGH),
        # The verb is the first word. Judging every word made get_label a
        # write, because "label" is a verb somewhere else.
        ("mcp__github__get_label", Risk.MEDIUM),
        ("mcp__x__list_things", Risk.MEDIUM),
        # Verbs the hand-picked list did not have, that the vocabulary does.
        ("mcp__x__destroy_cluster", Risk.HIGH),
        ("mcp__x__revoke_key", Risk.HIGH),
        # PUBLISH and GRANT beyond the machine are CRITICAL by G3 — but the
        # classifier cannot tell a WordPress from a PDF viewer, so for a
        # server TOOL_REACH does not know the tier is capped at HIGH. Under
        # critical_action: deny, CRITICAL here would refuse an image upload.
        ("mcp__github__deploy_project", Risk.HIGH),
        ("mcp__claude-in-chrome__upload_image", Risk.HIGH),
        # A read that hands over a credential is a credential read (G4);
        # writing or rotating one is CRITICAL, and G4 does not depend on
        # reach, so the cap does not apply.
        ("mcp__x__get_secret", Risk.HIGH),
        ("mcp__vault__read_api_key", Risk.HIGH),
        ("mcp__vault__get_private_key", Risk.HIGH),
        ("mcp__x__create_secret", Risk.CRITICAL),
        ("mcp__x__delete_secret", Risk.CRITICAL),
        ("mcp__cf__rotate_token", Risk.CRITICAL),
    ])
    def test_mcp_tools_are_judged_by_their_verb_not_their_server(self, tool, tier):
        result = crc.classify({"tool_name": tool, "tool_input": {}})
        assert result["risk"] == tier, (tool, result)

    def test_mcp_delete_ranks_the_same_on_every_server(self):
        """One act, one tier — whatever the server is called."""
        tiers = {crc.classify({"tool_name": t, "tool_input": {}})["risk"]
                 for t in ("mcp__github__delete_repository",
                           "mcp__a_b__delete_thing", "mcp__a_b_c__delete_x",
                           "mcp__gh__deleteRepository")}
        assert tiers == {Risk.HIGH}

    def test_every_mcp_verb_lands_at_exactly_the_tier_its_effect_implies(self):
        """Enumerated, not exampled, over all three vocabularies and several
        server-name shapes. Exact, not a floor: a floor could not see a
        deploy quietly becoming CRITICAL. The finding this holds was found
        by exactly one missing example — an underscored server."""
        shapes = ("github", "a_b", "a_b_c", "x-y")
        for word, effect in crc.EFFECT_WORDS.items():
            if "-" in word:
                continue                  # split apart before lookup; not an MCP verb shape
            expected = max(min(crc.derive_risk(effect, crc.Reach.SHARED), Risk.HIGH),
                           Risk.MEDIUM)
            for server in shapes:
                tool = "mcp__%s__%s_something" % (server, word)
                got = crc.classify({"tool_name": tool, "tool_input": {}})["risk"]
                assert got == expected, (tool, got, expected)
        for word in crc.MCP_MUTATE_WORDS | crc.MCP_EXECUTE_WORDS:
            for server in shapes:
                tool = "mcp__%s__%s_something" % (server, word)
                got = crc.classify({"tool_name": tool, "tool_input": {}})["risk"]
                assert got == Risk.HIGH, (tool, got)
        for word in crc.SECRET_WORDS:
            if "-" in word:
                continue
            tool = "mcp__x__get_%s" % word
            got = crc.classify({"tool_name": tool, "tool_input": {}})["risk"]
            assert got == Risk.HIGH, (tool, got)

    def test_a_server_the_reach_table_knows_is_not_capped(self, monkeypatch):
        """The cap is for servers the classifier cannot place. One it can —
        a row in TOOL_REACH, the same table binaries use — gets the tier
        the ontology says."""
        monkeypatch.setitem(crc.TOOL_REACH, "wp", crc.Reach.PUBLIC)
        got = crc.classify({"tool_name": "mcp__wp__publish_post", "tool_input": {}})
        assert got["risk"] == Risk.CRITICAL

    def test_an_mcp_name_with_no_server_is_still_not_auto_allowed(self):
        for tool in ("mcp__", "mcp__weird", "mcp__a__", "mcp____x"):
            assert crc.classify({"tool_name": tool, "tool_input": {}})["risk"] >= Risk.MEDIUM

    def test_write_payload_can_escalate_a_benign_path(self):
        """A .md file is LOW, but a DROP TABLE payload inside it is not."""
        result = crc.classify({
            "tool_name": "Write",
            "tool_input": {"file_path": "notes.md", "content": "DROP TABLE dbo.Holdings;"},
        })
        assert result["risk"] == Risk.CRITICAL
        assert "sql-destructive" in result["rules"]

    def test_write_payload_with_mutation_is_high(self):
        result = crc.classify({
            "tool_name": "Write",
            "tool_input": {"file_path": "notes.md", "content": "DELETE FROM dbo.Holdings"},
        })
        assert result["risk"] == Risk.HIGH

    def test_non_dict_tool_input_does_not_crash(self):
        result = crc.classify({"tool_name": "Bash", "tool_input": "not-a-dict"})
        assert result["risk"] >= Risk.MEDIUM


class TestWristCard:
    """The watch-face contract: it has to be readable in one glance."""

    SAMPLES = [
        ("Bash", {"command": "rm -rf /home/user/project/build"}),
        ("Bash", {"command": "git push --force origin main"}),
        ("Bash", {"command": "x" * 500}),
        ("Bash", {"command": "sqlcmd -S db-prod-01 -Q \"" + "A" * 300 + "\""}),
        ("Write", {"file_path": "//fileserver-01/shared/A Very Long File Name Indeed.py"}),
        ("Edit", {"file_path": "app/handlers.py"}),
        ("mcp__github__create_pull_request", {"title": "y" * 200}),
        ("SomeFutureTool", {"blob": "z" * 200}),
    ]

    @pytest.mark.parametrize("tool,tool_input", SAMPLES)
    def test_headline_and_detail_respect_limits(self, tool, tool_input):
        card = crc.wrist_card(tool, tool_input, Risk.HIGH,
                              headline_chars=40, detail_chars=80)
        assert len(card["headline"]) <= 40
        assert len(card["detail"]) <= 80
        assert card["tier"] == "HIGH"

    @pytest.mark.parametrize("tool,tool_input", SAMPLES)
    def test_headline_is_never_empty(self, tool, tool_input):
        card = crc.wrist_card(tool, tool_input, Risk.MEDIUM)
        assert card["headline"].strip()

    def test_headline_has_no_newlines(self):
        card = crc.wrist_card("Bash", {"command": "line one\nline two\nline three"}, Risk.LOW)
        assert "\n" not in card["headline"]
        assert "\n" not in card["detail"]

    def test_rm_headline_is_human_readable(self):
        card = crc.wrist_card("Bash", {"command": "rm -rf build"}, Risk.HIGH)
        assert card["headline"].startswith("Delete build")

    def test_chained_command_headline_shows_remaining_count(self):
        card = crc.wrist_card("Bash", {"command": "ls && rm -rf build && echo ok"}, Risk.HIGH)
        assert "+2 more" in card["headline"]

    def test_write_headline_uses_the_basename(self):
        card = crc.wrist_card("Write", {"file_path": "/a/very/long/path/to/Report.py"}, Risk.MEDIUM)
        assert card["headline"] == "Write Report.py"

    def test_custom_limits_are_honoured(self):
        card = crc.wrist_card("Bash", {"command": "y" * 200}, Risk.LOW,
                              headline_chars=12, detail_chars=20)
        assert len(card["headline"]) <= 12
        assert len(card["detail"]) <= 20


class TestCardFacts:
    """A card for a tool the builder does not know answers one sentence —
    Claude wants to DO WHAT to WHAT THING — in words, never in JSON."""

    DESIGN = {"method": "finalize_plan",
              "projectId": "80b7c22c-6e00-401b-a786-e261a2fed502",
              "localDir": "./ds-bundle",
              "writes": ["components/**", "tokens/**", "fonts/**",
                         "_vendor/**", "styles.css"],
              "deletes": []}

    def test_headline_is_the_verb_phrase_not_the_tool(self):
        card = crc.wrist_card("DesignSync", self.DESIGN, Risk.MEDIUM)
        assert card["headline"] == "DesignSync · finalize plan"

    def test_facts_name_the_target_without_json(self):
        card = crc.wrist_card("DesignSync", self.DESIGN, Risk.MEDIUM)
        labels = [label for label, _ in card["facts"]]
        assert labels == ["project", "local dir", "writes"]
        assert card["facts"][0][1].startswith("80b7c22c")
        assert card["facts"][2][1] == "5 items"
        for char in "{}\"":
            assert char not in card["detail"]
        assert "project 80b7c22c" in card["detail"]

    def test_the_action_key_is_not_repeated_as_a_fact(self):
        card = crc.wrist_card("DesignSync", self.DESIGN, Risk.MEDIUM)
        assert "method" not in [label for label, _ in card["facts"]]

    def test_mcp_call_reads_as_server_and_action(self):
        card = crc.wrist_card("mcp__github__merge_pull_request",
                              {"owner": "acme", "repo": "platform",
                               "pull_number": 142, "merge_method": "squash"},
                              Risk.HIGH)
        assert card["headline"] == "github · merge pull request"
        assert card["facts"][:3] == [["owner", "acme"], ["repo", "platform"],
                                     ["pull number", "142"]]

    def test_an_action_argument_joins_the_headline(self):
        card = crc.wrist_card("mcp__wordpress__content_authoring",
                              {"action": "posts.create", "site_id": 7,
                               "title": "Launch"}, Risk.HIGH)
        assert card["headline"] == "wordpress · content authoring · posts.create"
        assert ["title", "Launch"] in card["facts"]

    def test_nested_input_collapses_to_counts(self):
        card = crc.wrist_card("SomeFutureTool",
                              {"payload": {"a": 1, "b": 2}, "rows": [1, 2, 3, 4],
                               "flag": True, "empty": None}, Risk.MEDIUM)
        assert card["facts"] == [["payload", "2 fields"], ["rows", "4 items"],
                                 ["flag", "yes"]]

    def test_a_path_keeps_its_tail(self):
        long_path = "/Users/someone/Developer/very/deep/tree/src/api/handlers.py"
        value = crc._fact_value(long_path, 24)
        assert value.startswith("…") and value.endswith("handlers.py")
        assert len(value) <= 24

    def test_short_string_lists_are_spelled_out(self):
        assert crc._fact_value(["a", "b"], 32) == "a, b"
        assert crc._fact_value([], 32) == "none"

    def test_labels_are_words(self):
        assert crc._humanise_key("projectId") == "project"
        assert crc._humanise_key("file_path") == "file"
        assert crc._humanise_key("pull_number") == "pull number"
        assert crc._humanise_key("id") == "id"

    def test_facts_are_never_a_single_hidden_field(self):
        card = crc.wrist_card("mcp__db__run", {"host": "db-prod-01",
                                               "table": "users",
                                               "query": "DELETE FROM users"},
                              Risk.CRITICAL)
        assert ["host", "db-prod-01"] in card["facts"]
        assert ["table", "users"] in card["facts"]

    def test_known_tools_carry_no_facts(self):
        card = crc.wrist_card("Bash", {"command": "ls"}, Risk.SAFE)
        assert "facts" not in card

    def test_facts_pass_through_the_credential_filter(self):
        card = crc.wrist_card("Deploy", {"token": "ghp_" + "a" * 40,
                                         "target": "prod"}, Risk.HIGH)
        assert "ghp_" + "a" * 40 not in card["detail"]
        assert all("ghp_" + "a" * 40 not in v for _, v in card["facts"])


class TestDecide:
    DEFAULT = dict(crc.DEFAULT_POLICY)

    QUIET = dict(crc.DEFAULT_POLICY, auto_allow_at_or_below="LOW")

    @pytest.mark.parametrize("risk,expected", [
        (Risk.SAFE, "allow"),
        (Risk.LOW, "allow"),
        (Risk.MEDIUM, "escalate"),
        (Risk.HIGH, "escalate"),
        (Risk.CRITICAL, "escalate"),
    ])
    def test_default_policy(self, risk, expected):
        """With --quiet on, the boring tiers are handled for you."""
        decision, _ = crc.decide(risk, self.QUIET)
        assert decision == expected

    def test_critical_can_be_configured_to_deny(self):
        policy = dict(self.DEFAULT, critical_action="deny")
        decision, _ = crc.decide(Risk.CRITICAL, policy)
        assert decision == "deny"

    def test_threshold_can_be_raised(self):
        policy = dict(self.DEFAULT, auto_allow_at_or_below="MEDIUM")
        assert crc.decide(Risk.MEDIUM, policy)[0] == "allow"
        assert crc.decide(Risk.HIGH, policy)[0] == "escalate"

    def test_critical_is_never_auto_allowed_even_at_max_threshold(self):
        policy = dict(self.DEFAULT, auto_allow_at_or_below="CRITICAL")
        assert crc.decide(Risk.CRITICAL, policy)[0] != "allow"

    def test_nothing_is_auto_allowed_by_default(self):
        """The classifier labels; it does not decide unless asked to."""
        for risk in (Risk.SAFE, Risk.LOW, Risk.MEDIUM, Risk.CRITICAL):
            assert crc.decide(risk, crc.DEFAULT_POLICY)[0] == "escalate"

    def test_invalid_threshold_fails_closed(self):
        policy = dict(self.DEFAULT, auto_allow_at_or_below="NONSENSE")
        # An unreadable setting must fail closed, never widen what is allowed.
        assert crc.decide(Risk.LOW, policy)[0] == "escalate"
        assert crc.decide(Risk.MEDIUM, policy)[0] == "escalate"


class TestLoadPolicy:
    def test_defaults_to_shadow_mode(self):
        assert crc.load_policy(env={})["mode"] == "shadow"

    def test_env_overrides_mode(self):
        assert crc.load_policy(env={"CLAUDE_RISK_MODE": "enforce"})["mode"] == "enforce"

    def test_config_file_is_merged(self, tmp_path):
        config = tmp_path / "policy.json"
        config.write_text(json.dumps({"auto_allow_at_or_below": "MEDIUM"}), encoding="utf-8")
        policy = crc.load_policy(env={"CLAUDE_RISK_CONFIG": str(config)})
        assert policy["auto_allow_at_or_below"] == "MEDIUM"
        assert policy["mode"] == "shadow"

    def test_broken_config_file_does_not_raise(self, tmp_path, capsys):
        config = tmp_path / "policy.json"
        config.write_text("{not json", encoding="utf-8")
        policy = crc.load_policy(env={"CLAUDE_RISK_CONFIG": str(config)})
        assert policy["mode"] == "shadow"
        assert "bad config" in capsys.readouterr().err


class TestBuildResponse:
    def test_shadow_mode_never_changes_behaviour(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, mode="shadow", auto_allow_at_or_below="LOW",
                      audit_log=str(tmp_path / "a.jsonl"))
        event = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        response, audit, _ = crc.build_response(event, policy)
        assert _behavior(response) == "escalate"
        # ...but the classification is still recorded, which is the point.
        assert audit["decision"] == "allow"
        assert audit["tier"] == "SAFE"
        assert audit["mode"] == "shadow"

    def test_enforce_mode_acts_on_the_classification(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, mode="enforce", auto_allow_at_or_below="LOW",
                      audit_log=str(tmp_path / "a.jsonl"))
        event = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
        response, audit, _ = crc.build_response(event, policy)
        assert _behavior(response) == "allow"
        assert audit["effective"] == "allow"

    def test_response_names_the_hook_event(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "a.jsonl"))
        response, _, _ = crc.build_response({"tool_name": "Read", "tool_input": {}}, policy)
        assert response["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"


class TestAuditLog:
    def test_write_then_read_round_trip(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "sub" / "audit.jsonl"))
        crc.write_audit({"tier": "SAFE", "decision": "allow"}, policy)
        crc.write_audit({"tier": "HIGH", "decision": "escalate"}, policy)
        entries = crc.read_audit(policy)
        assert [e["tier"] for e in entries] == ["SAFE", "HIGH"]

    def test_missing_log_reads_as_empty(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "nope.jsonl"))
        assert crc.read_audit(policy) == []

    def test_corrupt_lines_are_skipped(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        path.write_text('{"tier": "SAFE"}\nnot json\n{"tier": "HIGH"}\n', encoding="utf-8")
        entries = crc.read_audit(dict(crc.DEFAULT_POLICY, audit_log=str(path)))
        assert [e["tier"] for e in entries] == ["SAFE", "HIGH"]


class TestHookContract:
    """End-to-end: the stdin/stdout contract Claude Code actually depends on."""

    def _run(self, payload, env=None):
        environment = dict(os.environ)
        environment.pop("CLAUDE_RISK_MODE", None)
        environment.pop("CLAUDE_RISK_CONFIG", None)
        environment.pop("CLAUDE_RISK_RELAY", None)
        environment.update(env or {})
        return subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__) or ".",
                                          "ClaudeRiskClassifier.py")],
            input=payload, capture_output=True, text=True, env=environment, timeout=30,
        )

    def test_stdout_contains_only_json(self, tmp_path):
        event = {"session_id": "s", "tool_name": "Bash",
                 "tool_input": {"command": "ls -la"}, "cwd": str(tmp_path)}
        result = self._run(json.dumps(event),
                           {"CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl")})
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert parsed["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"

    def test_enforce_mode_allows_a_safe_command(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
        result = self._run(json.dumps(event), {
            "CLAUDE_RISK_MODE": "enforce",
            "CLAUDE_RISK_AUTO_ALLOW": "LOW",
            "CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl"),
        })
        assert _behavior(json.loads(result.stdout)) == "allow"

    def test_enforce_mode_escalates_a_dangerous_command(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}
        result = self._run(json.dumps(event), {
            "CLAUDE_RISK_MODE": "enforce",
            "CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl"),
        })
        assert _behavior(json.loads(result.stdout)) == "escalate"

    @pytest.mark.parametrize("payload", ["", "   ", "not json", "[]", "null", '{"tool_name":'])
    def test_malformed_input_fails_closed_to_the_human(self, payload, tmp_path):
        result = self._run(payload, {"CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl")})
        assert result.returncode == 0
        decision = _behavior(json.loads(result.stdout))
        assert decision == "escalate"

    def test_unwritable_audit_log_still_returns_a_decision(self, tmp_path):
        """An audit-log failure must never take the session down."""
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = self._run(json.dumps(event),
                           {"CLAUDE_RISK_AUDIT_LOG": str(blocker / "audit.jsonl")})
        assert result.returncode == 0
        assert _behavior(json.loads(result.stdout))


class TestInstaller:
    """The installer writes to the user's real Claude Code config, so the
    safety properties matter more than the happy path."""

    def _handlers(self, path):
        data = json.loads(path.read_text(encoding="utf-8"))
        return [h for entry in data.get("hooks", {}).get("PermissionRequest", [])
                for h in entry.get("hooks", [])]

    def test_install_creates_the_file(self, settings, capsys):
        assert crc.run_install() == 0
        capsys.readouterr()
        assert settings.exists()
        commands = [h["command"] for h in self._handlers(settings)]
        assert len(commands) == 1
        assert "ClaudeRiskClassifier.py" in commands[0]

    def test_reboot_survival_installs_and_uninstalls_with_us(
            self, settings, capsys, monkeypatch):
        """A reboot must not orphan the watch: install writes a login
        wake-up for the relay, uninstall takes it out again."""
        agent = crc._launch_agent_path()
        monkeypatch.setattr(crc.sys, "platform", "darwin")
        assert crc.run_install() == 0
        assert os.path.exists(agent)
        xml = open(agent, encoding="utf-8").read()
        assert "com.tapproval.relay" in xml
        assert "--ensure" in xml
        assert "RunAtLoad" in xml
        # A re-run repairs a deleted agent even when settings are current.
        os.remove(agent)
        assert crc.run_install() == 0
        assert os.path.exists(agent)
        assert crc.run_uninstall() == 0
        capsys.readouterr()
        assert not os.path.exists(agent)

    def test_install_uses_the_running_interpreter(self, settings, capsys):
        crc.run_install()
        capsys.readouterr()
        assert sys.executable in self._handlers(settings)[0]["command"]

    def test_install_is_idempotent(self, settings, capsys):
        crc.run_install()
        crc.run_install()
        crc.run_install()
        capsys.readouterr()
        assert len(self._handlers(settings)) == 1

    def test_install_preserves_unrelated_settings(self, settings, capsys):
        settings.write_text(json.dumps({
            "model": "claude-opus-5",
            "env": {"FOO": "bar"},
            "hooks": {
                "PermissionRequest": [
                    {"matcher": "Bash",
                     "hooks": [{"type": "command", "command": "/other/guard.sh"}]}
                ],
                "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}],
            },
        }), encoding="utf-8")
        crc.run_install()
        capsys.readouterr()
        data = json.loads(settings.read_text(encoding="utf-8"))
        assert data["model"] == "claude-opus-5"
        assert data["env"] == {"FOO": "bar"}
        assert data["hooks"]["Stop"][0]["hooks"][0]["command"] == "say done"
        commands = [h["command"] for h in self._handlers(settings)]
        assert "/other/guard.sh" in commands
        assert len(commands) == 2

    def test_install_repoints_a_stale_path(self, settings, capsys):
        settings.write_text(json.dumps({"hooks": {"PermissionRequest": [
            {"matcher": "*", "hooks": [{"type": "command",
                                        "command": "python /old/place/ClaudeRiskClassifier.py"}]}
        ]}}), encoding="utf-8")
        assert crc.run_install() == 0
        capsys.readouterr()
        handlers = self._handlers(settings)
        assert len(handlers) == 1
        assert "/old/place/" not in handlers[0]["command"]

    def test_install_refuses_to_touch_malformed_json(self, settings, capsys):
        settings.write_text("{ this is not json", encoding="utf-8")
        assert crc.run_install() == 1
        assert "Nothing was changed" in capsys.readouterr().out
        assert settings.read_text(encoding="utf-8") == "{ this is not json"

    def test_install_backs_up_before_changing(self, settings, capsys, tmp_path):
        settings.write_text(json.dumps({"model": "keep-me"}), encoding="utf-8")
        crc.run_install()
        capsys.readouterr()
        backups = list(tmp_path.glob("settings.json.bak-*"))
        assert len(backups) == 1
        assert json.loads(backups[0].read_text(encoding="utf-8")) == {"model": "keep-me"}

    def test_uninstall_removes_only_our_entry(self, settings, capsys):
        settings.write_text(json.dumps({"hooks": {"PermissionRequest": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/other/guard.sh"}]}
        ]}}), encoding="utf-8")
        crc.run_install()
        crc.run_uninstall()
        capsys.readouterr()
        commands = [h["command"] for h in self._handlers(settings)]
        assert commands == ["/other/guard.sh"]

    def test_uninstall_leaves_no_empty_scaffolding(self, settings, capsys):
        crc.run_install()
        crc.run_uninstall()
        capsys.readouterr()
        assert json.loads(settings.read_text(encoding="utf-8")) == {}

    def test_uninstall_when_not_installed_is_a_no_op(self, settings, capsys):
        settings.write_text('{"hooks": {"PermissionRequest": []}}')
        assert crc.run_uninstall() == 0
        assert "nothing to remove" in capsys.readouterr().out.lower()
        # A run that changed nothing must leave nothing: the backup exists
        # to undo a write, and this used to drop a .bak on every clean run.
        assert not list(settings.parent.glob("settings.json.bak*"))

    def test_install_uninstall_round_trip_restores_the_file(self, settings, capsys):
        original = {"model": "claude-opus-5",
                    "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "x"}]}]}}
        settings.write_text(json.dumps(original), encoding="utf-8")
        crc.run_install()
        crc.run_uninstall()
        capsys.readouterr()
        assert json.loads(settings.read_text(encoding="utf-8")) == original


class TestStatus:
    def test_reports_installed_and_shadow_mode(self, tmp_path, monkeypatch, capsys):
        # The machine may have wrist approvals switched on globally; this
        # test is about the default, so clear the ambient settings.
        for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY",
                    "CLAUDE_RISK_RELAY_WAIT", "CLAUDE_RISK_CONFIG"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        crc.run_install()
        capsys.readouterr()
        crc.run_status()
        out = capsys.readouterr().out
        assert "Installed     : yes" in out
        assert "shadow" in out

    def test_counts_collected_decisions(self, tmp_path, monkeypatch, capsys):
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        log.write_text('{"ts": "2026-08-14T10:00:00+00:00", "tier": "SAFE"}\n'
                       '{"ts": "2026-08-15T10:00:00+00:00", "tier": "HIGH"}\n', encoding="utf-8")
        crc.run_status()
        out = capsys.readouterr().out
        assert "Decisions     : 2 recorded" in out
        assert "since 2026-08-14" in out


class TestShareFooter:
    """The only place the CLI asks a terminal for anything.

    Its whole design is where it does NOT appear. `--report` is run out of
    curiosity about what the tool bought you — the moment it has just
    proved itself. `--status` is run when something is wrong. Asking at
    the second moment costs more than it earns, so these tests pin the
    absence as hard as the presence.
    """

    def _audit(self, tmp_path, monkeypatch):
        for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY", "CLAUDE_RISK_CONFIG"):
            monkeypatch.delenv(key, raising=False)
        log = tmp_path / "audit.jsonl"
        log.write_text(
            '{"ts": "2026-09-01T10:00:00+00:00", "tier": "SAFE",'
            ' "decision": "allow", "tool": "Read"}\n'
            '{"ts": "2026-09-01T10:01:00+00:00", "tier": "HIGH",'
            ' "decision": "escalate", "tool": "Bash"}\n',
            encoding="utf-8")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))

    def test_it_names_both_numbers_readably(self):
        text = "\n".join(crc.share_footer(1503, 118))
        assert "1,503" in text
        assert "118" in text

    def test_it_carries_the_project_site_and_no_personal_address(self):
        text = "\n".join(crc.share_footer(10, 1))
        assert crc.PROJECT_SITE in text
        # One contact address for the whole project, and this is not the
        # place for it: a footer is not a support channel.
        assert "@" not in text

    def test_it_offers_nothing_in_exchange(self):
        # Attaching a reward to a recommendation measurably shrinks it, and
        # rewarding a review outright breaks the App Store guidelines. The
        # vocabulary of either must never reach this string.
        text = "\n".join(crc.share_footer(10, 1)).lower()
        for bribe in ("free", "discount", "% off", "reward", "coupon", "unlock"):
            assert bribe not in text, bribe

    def test_it_asks_for_one_thing_and_never_for_a_rating(self):
        # An iOS app cannot be reviewed from a desktop browser, so a rating
        # ask in a terminal is a dead end. The terminal gets the share; the
        # wrist gets the rating.
        text = "\n".join(crc.share_footer(10, 1)).lower()
        assert "tell" in text
        for dead_end in ("rate", "review", "star"):
            assert dead_end not in text, dead_end

    def test_report_prints_it(self, tmp_path, monkeypatch, capsys):
        self._audit(tmp_path, monkeypatch)
        assert crc.run_report() == 0
        assert crc.PROJECT_SITE in capsys.readouterr().out

    def test_status_never_prints_it(self, tmp_path, monkeypatch, capsys):
        self._audit(tmp_path, monkeypatch)
        crc.run_status()
        assert crc.PROJECT_SITE not in capsys.readouterr().out

    def test_install_never_prints_it(self, tmp_path, monkeypatch, capsys):
        # Nothing has been earned at install time.
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        crc.run_install()
        assert crc.PROJECT_SITE not in capsys.readouterr().out

    def test_an_empty_audit_log_asks_for_nothing(self, tmp_path, monkeypatch, capsys):
        # No decisions recorded means the tool has not yet done anything for
        # this person. Reciprocity runs one way only.
        for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY", "CLAUDE_RISK_CONFIG"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        assert crc.run_report() == 0
        assert crc.PROJECT_SITE not in capsys.readouterr().out


class TestInstallerCLI:
    def _run(self, args, tmp_path):
        env = dict(os.environ)
        env["CLAUDE_SETTINGS_PATH"] = str(tmp_path / "settings.json")
        env["CLAUDE_RISK_AUDIT_LOG"] = str(tmp_path / "audit.jsonl")
        return subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__) or ".",
                                          "ClaudeRiskClassifier.py")] + args,
            capture_output=True, text=True, env=env, timeout=30,
        )

    def test_install_then_status_then_uninstall(self, tmp_path):
        assert self._run(["--install"], tmp_path).returncode == 0
        status = self._run(["--status"], tmp_path)
        assert "Installed     : yes" in status.stdout
        assert self._run(["--uninstall"], tmp_path).returncode == 0
        assert "Installed     : no" in self._run(["--status"], tmp_path).stdout

    def test_installed_hook_command_actually_runs(self, tmp_path):
        """The command written into settings.json must work as written."""
        import shlex
        self._run(["--install"], tmp_path)
        data = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
        command = data["hooks"]["PermissionRequest"][0]["hooks"][0]["command"]
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})
        env = dict(os.environ, CLAUDE_RISK_AUDIT_LOG=str(tmp_path / "audit.jsonl"))
        # Default behaviour is the subject here, so drop any ambient
        # wrist-approval settings the machine may have switched on.
        for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY",
                    "CLAUDE_RISK_RELAY_WAIT", "CLAUDE_RISK_CONFIG"):
            env.pop(key, None)
        result = subprocess.run(shlex.split(command), input=event,
                                capture_output=True, text=True, env=env, timeout=30)
        assert result.returncode == 0
        decision = _behavior(json.loads(result.stdout))
        assert decision == "escalate"


class TestPipeHandling:
    """`--report | head` and quitting `less` early must not raise."""

    def test_truncated_pipe_exits_cleanly(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text("".join(
            '{"ts": "2026-08-14T10:00:00+00:00", "tier": "SAFE", '
            '"decision": "allow", "tool": "Read", "headline": "x"}\n'
            for _ in range(50)), encoding="utf-8")
        env = dict(os.environ,
                   CLAUDE_RISK_AUDIT_LOG=str(log),
                   CLAUDE_SETTINGS_PATH=str(tmp_path / "settings.json"))
        script = os.path.join(os.path.dirname(__file__) or ".", "ClaudeRiskClassifier.py")
        producer = subprocess.Popen([sys.executable, script, "--report"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        head = subprocess.Popen(["head", "-2"], stdin=producer.stdout,
                                stdout=subprocess.PIPE, text=True)
        producer.stdout.close()
        head.communicate()
        producer.wait(timeout=30)
        assert producer.returncode == 0
        assert b"BrokenPipeError" not in producer.stderr.read()


class TestProjectAttribution:
    """Decisions must be attributable to the project they came from —
    one machine-wide log spans every repository the user works in."""

    def test_project_is_recorded(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "a.jsonl"))
        _, audit, _ = crc.build_response(
            {"tool_name": "Read", "tool_input": {}, "cwd": "/Users/x/Developer/some-repo"},
            policy)
        assert audit["project"] == "some-repo"

    @pytest.mark.parametrize("cwd,expected", [
        ("/Users/x/Developer/some-repo", "some-repo"),
        ("/Users/x/Developer/some-repo/", "some-repo"),
        ("C:\\Users\\x\\Developer\\some-repo", "some-repo"),
        ("/", None),
        ("", None),
        (None, None),
    ])
    def test_project_name_edge_cases(self, cwd, expected):
        assert crc._project_name(cwd) == expected

    def test_only_the_basename_is_logged(self, tmp_path):
        """The log must not carry directory structure."""
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "a.jsonl"))
        _, audit, _ = crc.build_response(
            {"tool_name": "Read", "tool_input": {},
             "cwd": "/Users/x/clients/acme-bank/secret-project"}, policy)
        assert audit["project"] == "secret-project"
        assert "acme-bank" not in json.dumps(audit)

    def test_report_breaks_down_by_project(self, tmp_path, capsys, monkeypatch):
        log = tmp_path / "a.jsonl"
        rows = ([{"ts": "2026-08-21T10:00:00+00:00", "project": "org-repo",
                  "tier": "SAFE", "decision": "allow", "tool": "Read", "headline": "x"}] * 8 +
                [{"ts": "2026-08-21T10:00:00+00:00", "project": "org-repo",
                  "tier": "HIGH", "decision": "escalate", "tool": "Bash", "headline": "y"}] * 2 +
                [{"ts": "2026-08-21T10:00:00+00:00", "project": "personal",
                  "tier": "SAFE", "decision": "allow", "tool": "Read", "headline": "z"}] * 5)
        log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        crc.run_report()
        out = capsys.readouterr().out
        assert "By project" in out
        assert "org-repo" in out and "personal" in out
        assert "80% silenced" in out

    def test_single_project_omits_the_breakdown(self, tmp_path, capsys, monkeypatch):
        log = tmp_path / "a.jsonl"
        log.write_text(json.dumps({"ts": "2026-08-21T10:00:00+00:00", "project": "only-one",
                                   "tier": "SAFE", "decision": "allow", "tool": "Read",
                                   "headline": "x"}) + "\n", encoding="utf-8")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        crc.run_report()
        assert "By project" not in capsys.readouterr().out

    def test_old_entries_without_a_project_do_not_break_the_report(self, tmp_path, capsys, monkeypatch):
        log = tmp_path / "a.jsonl"
        log.write_text(json.dumps({"ts": "2026-08-21T10:00:00+00:00", "tier": "SAFE",
                                   "decision": "allow", "tool": "Read", "headline": "x"}) + "\n",
                       encoding="utf-8")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        assert crc.run_report() == 0


class TestCommandHealthCheck:
    """settings.json can name an interpreter that later disappears. A hook
    that cannot start fails silently, so --status has to catch it."""

    def test_healthy_command_reports_no_problems(self):
        assert crc.check_command(crc._hook_command()) == []

    def test_missing_interpreter_is_reported(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("", encoding="utf-8")
        problems = crc.check_command("/Applications/Gone.app/bin/python3 %s" % script)
        assert any("interpreter no longer exists" in p for p in problems)

    def test_missing_script_is_reported(self):
        problems = crc.check_command("%s /nowhere/ClaudeRiskClassifier.py" % sys.executable)
        assert any("script no longer exists" in p for p in problems)

    def test_bare_interpreter_not_on_path_is_reported(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("", encoding="utf-8")
        problems = crc.check_command("python9nonexistent %s" % script)
        assert any("not on PATH" in p for p in problems)

    def test_quoted_paths_with_spaces_are_handled(self, tmp_path):
        folder = tmp_path / "My Developer"
        folder.mkdir()
        script = folder / "s.py"
        script.write_text("", encoding="utf-8")
        assert crc.check_command("%s '%s'" % (sys.executable, script)) == []

    def test_unparseable_command_is_reported(self):
        assert crc.check_command("'unbalanced") == ["the command in settings.json cannot be parsed"]

    def test_empty_command_is_reported(self):
        assert crc.check_command("") == ["the command in settings.json is empty"]

    def test_status_surfaces_a_broken_install(self, tmp_path, monkeypatch, capsys):
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({"hooks": {"PermissionRequest": [
            {"matcher": "*", "hooks": [{"type": "command",
             "command": "/gone/python3 /gone/ClaudeRiskClassifier.py"}]}]}}), encoding="utf-8")
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(settings))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        crc.run_status()
        out = capsys.readouterr().out
        assert "BROKEN" in out
        assert "Re-run --install" in out

    def test_status_stays_quiet_when_healthy(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        crc.run_install()
        capsys.readouterr()
        crc.run_status()
        assert "BROKEN" not in capsys.readouterr().out


class TestWatchRelayBridge:
    """ask_watch() + watch_relay.py, exercised together over real loopback HTTP.

    The safety property under test: every failure mode of the relay — unset,
    unreachable, timing out, replying nonsense — must collapse to "none" so
    the ordinary terminal prompt appears. Only an explicit human allow/deny
    from the watch may change a decision.
    """

    @pytest.fixture
    def relay(self):

        server, queue = watch_relay.serve(port=0)
        _serve(server)
        url = "http://127.0.0.1:%d" % server.server_address[1]
        yield url, queue
        server.shutdown()
        server.server_close()

    def _watch_is_present(self, queue):
        """Simulate a watch on a wrist: the relay only queues cards for one."""
        queue.pending(from_watch=True)

    def _answer_first_card(self, queue, decision):
        """Background 'human': decide the first card that appears."""
        import time

        def worker():
            for _ in range(200):
                pending = queue.pending()
                if pending:
                    queue.decide(pending[0]["id"], decision)
                    return
                time.sleep(0.01)

        threading.Thread(target=worker, daemon=True).start()

    CARD = {"tier": "HIGH", "headline": "Delete build -r", "detail": "rm -r build"}

    def test_no_relay_configured_is_none_without_network(self):
        policy = dict(crc.DEFAULT_POLICY)
        assert crc.ask_watch(self.CARD, policy) == ("none", None)

    def test_non_http_relay_is_refused(self):
        policy = dict(crc.DEFAULT_POLICY, relay="file:///etc/passwd")
        assert crc.ask_watch(self.CARD, policy) == ("none", None)

    def test_unreachable_relay_fails_closed(self):
        policy = dict(crc.DEFAULT_POLICY, relay="http://127.0.0.1:1", relay_wait=0.5)
        assert crc.ask_watch(self.CARD, policy) == ("none", None)

    def test_watch_allow_comes_back(self, relay):
        url, queue = relay
        self._watch_is_present(queue)
        self._answer_first_card(queue, "allow")
        policy = dict(crc.DEFAULT_POLICY, relay=url, relay_wait=5.0)
        assert crc.ask_watch(self.CARD, policy) == ("allow", None)

    def test_watch_deny_comes_back(self, relay):
        url, queue = relay
        self._watch_is_present(queue)
        self._answer_first_card(queue, "deny")
        policy = dict(crc.DEFAULT_POLICY, relay=url, relay_wait=5.0)
        assert crc.ask_watch(self.CARD, policy) == ("deny", None)

    def test_nobody_answers_means_none(self, relay):
        url, _ = relay
        policy = dict(crc.DEFAULT_POLICY, relay=url, relay_wait=0.2)
        assert crc.ask_watch(self.CARD, policy) == ("none", None)

    def test_relay_rejects_bogus_decisions(self, relay):
        _, queue = relay
        self._watch_is_present(queue)
        assert queue.decide("nope", "allow") is False          # unknown card
        card_ids = []
        threading.Thread(
            target=lambda: card_ids.append(queue.submit(self.CARD, 1.0)),
            daemon=True).start()
        import time
        for _ in range(200):
            if queue.pending():
                break
            time.sleep(0.01)
        live = queue.pending()[0]["id"]
        assert queue.decide(live, "shrug") is False            # invalid verdict
        assert queue.decide(live, "allow") is True

    def test_enforce_hook_applies_the_watch_answer(self, relay, tmp_path, monkeypatch):
        import io
        url, queue = relay
        monkeypatch.setenv("CLAUDE_RISK_MODE", "enforce")
        monkeypatch.setenv("CLAUDE_RISK_RELAY", url)
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)
        self._watch_is_present(queue)
        self._answer_first_card(queue, "allow")

        event = {"tool_name": "Bash", "tool_input": {"command": "rm -r build"}}
        stdout = io.StringIO()
        crc.run_hook(stdin=io.StringIO(json.dumps(event)), stdout=stdout)

        response = json.loads(stdout.getvalue())
        assert _behavior(response) == "allow"
        # An allow carries no message: the checked shape is {"behavior":
        # "allow"} and nothing else. The reason lives in the audit log.
        assert response["hookSpecificOutput"]["decision"] == {"behavior": "allow"}
        entries = crc.read_audit({"audit_log": str(tmp_path / "a.jsonl")})
        assert entries[-1]["watch"] == "allow"
        assert entries[-1]["effective"] == "allow"

    def test_shadow_mode_never_contacts_the_relay(self, tmp_path, monkeypatch):
        import io
        monkeypatch.setenv("CLAUDE_RISK_MODE", "shadow")
        # A relay that cannot exist: if shadow mode tried to reach it the
        # request would stall and fail. It must never be asked at all.
        monkeypatch.setenv("CLAUDE_RISK_RELAY", "http://127.0.0.1:1")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)

        called = []
        monkeypatch.setattr(crc, "ask_watch",
                            lambda *a, **k: called.append(1) or "allow")
        event = {"tool_name": "Bash", "tool_input": {"command": "rm -r build"}}
        stdout = io.StringIO()
        crc.run_hook(stdin=io.StringIO(json.dumps(event)), stdout=stdout)

        assert called == []
        decision = _behavior(json.loads(stdout.getvalue()))
        assert decision == "escalate"


class TestRecapSummary:
    """The lifetime numbers behind the recap screen.

    Today's figures read only what was appended since the last call, because
    the audit log grows for the product's whole lifetime. A lifetime figure
    cannot do that, so this pays for one full pass — and therefore has to
    survive everything a log that size can contain, including a torn last
    line and a file that is not there at all.
    """

    import datetime as _dt
    NOW = _dt.datetime(2026, 9, 4, tzinfo=_dt.timezone.utc).timestamp()

    def _log(self, tmp_path, rows, trailing=""):
        path = tmp_path / "audit.jsonl"
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n" + trailing,
                        encoding="utf-8")
        return str(path)

    def _rows(self, allowed=120, asked=9):
        rows = [{"ts": "2026-08-05T10:00:00+00:00", "tier": "SAFE",
                 "decision": "allow"} for _ in range(allowed)]
        rows += [{"ts": "2026-09-01T10:00:00+00:00", "tier": "CRITICAL",
                  "decision": "escalate", "watch": "deny"} for _ in range(asked)]
        return rows

    def test_it_counts_the_whole_log(self, tmp_path):
        import watch_dashboard as wd
        facts = wd.recap_summary(self._log(tmp_path, self._rows()), self.NOW)
        assert facts["total"] == 129
        assert facts["silenced"] == 120
        assert facts["asked"] == 9
        assert facts["critical"] == 9
        assert facts["answered_on_watch"] == 9
        assert facts["silenced_percent"] == 93

    def test_a_torn_last_line_is_not_a_failure(self, tmp_path):
        # The hook appends while this reads. A half-written line is normal.
        import watch_dashboard as wd
        path = self._log(tmp_path, self._rows(), trailing='{"ts": "2026-09-0')
        assert wd.recap_summary(path, self.NOW)["total"] == 129

    def test_days_span_the_first_entry_to_now_inclusive(self, tmp_path):
        import watch_dashboard as wd
        facts = wd.recap_summary(self._log(tmp_path, self._rows()), self.NOW)
        assert facts["first_day"] == "2026-08-05"
        assert facts["days"] == 31

    def test_time_saved_is_the_documented_estimate(self, tmp_path):
        # Named and conservative on purpose: a number that flatters the tool
        # is worse than no number, and every screen showing it must say
        # "estimate".
        import watch_dashboard as wd
        facts = wd.recap_summary(self._log(tmp_path, self._rows()), self.NOW)
        assert facts["seconds_saved"] == 120 * wd.SECONDS_PER_SILENCED_PROMPT

    def test_a_missing_log_is_zeros_not_an_exception(self, tmp_path):
        import watch_dashboard as wd
        facts = wd.recap_summary(str(tmp_path / "nope.jsonl"), self.NOW)
        assert facts["total"] == 0
        assert facts["silenced_percent"] == 0
        assert facts["days"] == 0

    def test_an_empty_log_does_not_divide_by_zero(self, tmp_path):
        import watch_dashboard as wd
        path = tmp_path / "audit.jsonl"
        path.write_text("", encoding="utf-8")
        assert wd.recap_summary(str(path), self.NOW)["silenced_percent"] == 0

    def test_a_changing_log_is_not_rescanned_on_every_call(self, tmp_path):
        """The one route where a (mtime, size) cache is not enough.

        The hook appends throughout a session, so that key changes
        constantly and every open of the screen would re-read the whole
        file. Nothing rate-limits a GET, so the floor is what bounds the
        work — navigating in and out must not have the relay scanning a
        lifetime of decisions each time.
        """
        import watch_dashboard as wd
        path = self._log(tmp_path, self._rows())
        assert wd.recap_summary(path, self.NOW)["total"] == 129
        # The log grows, as it does during any live session.
        with open(path, "a", encoding="utf-8") as handle:
            for _ in range(50):
                handle.write(json.dumps({"ts": "2026-09-02T10:00:00+00:00",
                                          "tier": "SAFE",
                                          "decision": "allow"}) + "\n")
        within = self.NOW + wd.RECAP_MIN_INTERVAL - 1
        assert wd.recap_summary(path, within)["total"] == 129, "rescanned early"
        after = self.NOW + wd.RECAP_MIN_INTERVAL + 1
        assert wd.recap_summary(path, after)["total"] == 179

    def test_an_unchanged_log_is_served_from_cache(self, tmp_path):
        # The floor bounds the worst case; the stat key still spares the
        # common one, where nothing has been decided since the last look.
        import watch_dashboard as wd
        path = self._log(tmp_path, self._rows())
        first = wd.recap_summary(path, self.NOW)
        later = wd.recap_summary(path, self.NOW + 10 * wd.RECAP_MIN_INTERVAL)
        assert first is later


class TestRelayBonjour:
    def test_advertise_returns_none_without_dnssd(self, monkeypatch):
        """Non-macOS hosts have no dns-sd; the relay must degrade quietly."""
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _: None)
        assert watch_relay.advertise(8977) is None

    def test_advertise_survives_spawn_failure(self, monkeypatch):
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _: "/usr/bin/dns-sd")
        def boom(*a, **k):
            raise OSError("nope")
        monkeypatch.setattr(watch_relay.subprocess, "Popen", boom)
        assert watch_relay.advertise(8977) is None


class TestRelaySessions:
    def test_lists_sessions_newest_first(self, tmp_path, monkeypatch):
        import time as _time
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"aaaa1111": "Terminal",
                                     "bbbb2222": "Terminal"})
        proj = tmp_path / "-Users-x-Developer-MyProject"
        proj.mkdir()
        old = proj / "aaaa1111.jsonl"
        new = proj / "bbbb2222.jsonl"
        old.write_text("{}\n")
        new.write_text("{}\n")
        past = _time.time() - 3600
        import os as _os
        _os.utime(old, (past, past))
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert [s["session_id"] for s in sessions] == ["bbbb2222", "aaaa1111"]
        assert sessions[0]["project"] == "MyProject"
        assert sessions[1]["minutes_ago"] >= 59

    def test_missing_projects_dir_is_empty(self, tmp_path):
        assert watch_relay.recent_sessions(projects_dir=str(tmp_path / "no")) == []


class TestRelayTunnelToken:
    """The tunnel listener must expose ONLY token-prefixed routes, and never
    card injection — that is what makes a public URL safe to hold."""

    @pytest.fixture
    def tokened(self):
        server, queue = watch_relay.serve(port=0, token="s3cret")
        _serve(server)
        yield "http://127.0.0.1:%d" % server.server_address[1], queue
        server.shutdown()
        server.server_close()

    def _get(self, url):
        try:
            with urllib.request.urlopen(url, timeout=5) as reply:
                return reply.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_unprefixed_paths_are_refused(self, tokened):
        base, _ = tokened
        assert self._get(base + "/pending") == 404
        assert self._get(base + "/health") == 404

    def test_every_lan_only_route_is_absent_through_the_tunnel(self, tokened):
        """Derived from ROUTES, not from a list of examples: the flag on
        the route is the ONLY thing that hides it, so a route added with
        lan_only tomorrow is covered the day it is added. A second tuple
        used to say which paths the tunnel hid, and nothing checked that
        it agreed with the table."""
        base, _ = tokened
        hidden = [(m, p) for m, routes in watch_relay.RelayHandler.ROUTES.items()
                  for p, (_, rules) in routes.items() if rules.get("lan_only")]
        assert {"/pair", "/enroll", "/card", "/heartbeat", "/tunnel"} <= {p for _, p in hidden}
        assert all(p.startswith("/admin/") or p in ("/pair", "/enroll", "/card",
                                                     "/heartbeat", "/tunnel")
                   for _, p in hidden)
        for method, path in hidden:
            status, _ = relay_call(base + "/t/s3cret" + path, method=method)
            # 404, the same answer as a path that does not exist — never
            # 403, which would tell a stranger the route is there.
            assert status == 404, (method, path, status)

    def test_token_prefix_alone_is_no_longer_enough(self, tokened):
        """The secret path says WHERE, the device token says WHO. Holding a
        leaked travel URL must not be holding the key: the URL is printed to
        stderr and written to the relay log, so it is not a secret worth
        betting a session on."""
        base, _ = tokened
        assert self._get(base + "/t/s3cret/pending") == 403
        assert self._get(base + "/t/wrong/pending") == 404
        # /health stays anonymous-friendly for liveness, but only under the
        # correct prefix.
        assert self._get(base + "/t/s3cret/health") == 403

    def test_card_injection_refused_through_tunnel(self, tokened):
        base, queue = tokened
        request = urllib.request.Request(
            base + "/t/s3cret/card",
            data=json.dumps({"card": {"tier": "HIGH", "headline": "x",
                                       "detail": "x"}}).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                status = reply.status
        except urllib.error.HTTPError as error:
            status = error.code
        assert status == 404
        assert queue.pending() == []


class TestRelayTunnelDiscovery:
    def test_lan_listener_serves_tunnel_url(self):
        watch_relay.TUNNEL_URL = "https://example.trycloudflare.com/t/tok"
        try:
            server, _ = watch_relay.serve(port=0)
            _serve(server)
            base = "http://127.0.0.1:%d" % server.server_address[1]
            with urllib.request.urlopen(base + "/tunnel", timeout=5) as reply:
                assert json.loads(reply.read())["url"].endswith("/t/tok")
            server.shutdown()
            server.server_close()
        finally:
            watch_relay.TUNNEL_URL = None

    def test_tunnel_url_not_exposed_through_tunnel_listener(self):
        server, _ = watch_relay.serve(port=0, token="tok")
        _serve(server)
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            urllib.request.urlopen(base + "/t/tok/tunnel", timeout=5)
            status = 200
        except urllib.error.HTTPError as error:
            status = error.code
        assert status == 404
        server.shutdown()
        server.server_close()


class TestSelfStartingRelay:
    """--install wires a SessionStart hook so the relay's lifecycle is
    automatic: it exists whenever Claude Code does. No extra hardware, no
    always-on machine, nothing for the user to run."""

    @pytest.fixture(autouse=True)
    def _off_the_machines_ports(self, monkeypatch):
        """Point TUNNEL_PORT at a port nobody holds.

        Since a stop is only proved when BOTH listeners are gone, these
        tests would otherwise consult the developer's own running relay
        and fail on a laptop while passing in CI — the worst direction for
        a test to be wrong in, and a coupling this suite already had one
        of elsewhere.
        """
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(watch_relay, "TUNNEL_PORT", free)

    def test_install_registers_session_start_relay(self, settings, capsys):
        crc.run_install()
        data = json.loads(settings.read_text())
        starters = data["hooks"]["SessionStart"]
        commands = [h["command"] for e in starters for h in e["hooks"]]
        assert any("watch_relay.py" in c and "--ensure" in c for c in commands)

    def test_install_is_idempotent_with_relay(self, settings, capsys):
        crc.run_install()
        first = settings.read_text()
        crc.run_install()
        assert settings.read_text() == first
        assert "Nothing to do" in capsys.readouterr().out

    def test_uninstall_removes_both_hooks(self, settings, capsys):
        crc.run_install()
        crc.run_uninstall()
        data = json.loads(settings.read_text())
        hooks = data.get("hooks", {})
        assert "PermissionRequest" not in hooks
        assert "SessionStart" not in hooks

    def test_ensure_detects_running_relay(self, monkeypatch, capsys):
        server, _ = watch_relay.serve(port=0)
        _serve(server)
        monkeypatch.setattr(watch_relay, "DEFAULT_PORT",
                            server.server_address[1])
        spawned = []
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda *a, **k: spawned.append(a))
        assert watch_relay.ensure_running() == 0
        assert spawned == []
        server.shutdown()
        server.server_close()

    def test_ensure_spawns_when_down_and_says_so_only_once_it_answers(self, monkeypatch, capsys):
        """A spawn that produces nothing is not a start. Until 2026-09-09
        --ensure printed "started in the background" the moment Popen
        returned, over a child that had already died on a held port."""
        monkeypatch.setattr(watch_relay, "DEFAULT_PORT", 1)  # nothing there
        monkeypatch.setattr(watch_relay, "RELAY_START_WAIT", 0.0)
        spawned = []
        class FakeProc:
            pass
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda cmd, **k: spawned.append(cmd) or FakeProc())
        assert watch_relay.ensure_running() == 1
        assert len(spawned) == 1 and "--tunnel" in spawned[0]
        err = capsys.readouterr().err
        assert "did not come up" in err and "started" not in err

    def test_ensure_says_started_when_the_child_actually_serves(self, monkeypatch, capsys):
        started = {}
        def spawn(cmd, **k):
            server, _ = watch_relay.serve(port=0)
            _serve(server)
            started["server"] = server
            monkeypatch.setattr(watch_relay, "DEFAULT_PORT", server.server_address[1])
            return object()
        monkeypatch.setattr(watch_relay, "DEFAULT_PORT", 1)
        monkeypatch.setattr(watch_relay.subprocess, "Popen", spawn)
        try:
            assert watch_relay.ensure_running() == 0
            assert "started in the background" in capsys.readouterr().err
        finally:
            started["server"].shutdown()
            started["server"].server_close()

    def test_ensure_will_not_start_a_second_relay_on_a_held_port(self, monkeypatch, capsys):
        """The 2026-09-09 shape: an older relay that will not die. The
        honest answer is that the old one keeps serving — not a corpse
        on the port and a cheerful line in the log."""
        monkeypatch.setattr(watch_relay, "_probe_relay",
                            lambda timeout=2: {"version": watch_relay.RELAY_VERSION - 1, "pending": 0})
        monkeypatch.setattr(watch_relay, "_stop_relay", lambda deadline=8.0: False)
        monkeypatch.setattr(watch_relay, "_relay_pid", lambda port=None: 4242)
        spawned = []
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda cmd, **k: spawned.append(cmd))
        assert watch_relay.ensure_running(updated=True) == 1
        assert spawned == []
        err = capsys.readouterr().err
        assert "could not stop" in err and "4242" in err and "keeps serving" in err

    def test_stop_asks_by_pid_then_insists_and_reports_the_truth(self, monkeypatch):
        """pkill -f could not see the relay at all; the pid can always be
        signalled. TERM first; KILL when TERM is ignored; and the return
        value is whether the port is actually free, nothing else."""
        sent = []
        monkeypatch.setattr(watch_relay, "_relay_pid", lambda port=None: 4242)
        monkeypatch.setattr(watch_relay.os, "kill", lambda pid, sig: sent.append((pid, sig)))
        monkeypatch.setattr(watch_relay, "_probe_relay", lambda timeout=2: {"version": 2})
        assert watch_relay._stop_relay(deadline=0.0) is False
        assert sent == [(4242, watch_relay.signal.SIGTERM), (4242, watch_relay.signal.SIGKILL)]

    def test_stop_is_content_with_a_relay_that_leaves_when_asked(self, monkeypatch):
        sent = []
        alive = {"up": True}
        monkeypatch.setattr(watch_relay, "_relay_pid", lambda port=None: 4242)
        def kill(pid, sig):
            sent.append(sig)
            alive["up"] = False
        monkeypatch.setattr(watch_relay.os, "kill", kill)
        monkeypatch.setattr(watch_relay, "_probe_relay",
                            lambda timeout=2: {"version": 2} if alive["up"] else None)
        assert watch_relay._stop_relay(deadline=1.0) is True
        assert sent == [watch_relay.signal.SIGTERM], "KILL must not follow a TERM that worked"

    def test_the_relay_is_found_by_the_pid_it_wrote(self, tmp_path, monkeypatch):
        pidfile = tmp_path / "relay.pid"
        pidfile.write_text(str(os.getpid()))
        monkeypatch.setattr(watch_relay, "PID_FILE", str(pidfile))
        assert watch_relay._relay_pid() == os.getpid()
        pidfile.write_text("999999999")                # a pid that is not alive
        monkeypatch.setattr(watch_relay.subprocess, "run",
                            lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""))
        assert watch_relay._relay_pid(port=1) is None, "a stale pidfile is not a relay"


class TestStatusRelayAwareness:
    def test_status_reports_wired_relay(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        crc.run_install()
        capsys.readouterr()
        crc.run_status()
        out = capsys.readouterr().out
        assert "starts itself with every Claude Code session" in out
        assert "Relay         :" in out

    def test_status_flags_missing_relay_hook(self, tmp_path, monkeypatch, capsys):
        settings = tmp_path / "s.json"
        settings.write_text(json.dumps({"hooks": {"PermissionRequest": [
            {"matcher": "*", "hooks": [{"type": "command",
             "command": "python3 /x/ClaudeRiskClassifier.py"}]}]}}),
            encoding="utf-8")
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(settings))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        crc.run_status()
        assert "not wired" in capsys.readouterr().out


class TestWatchSeenAttribution:
    """Only a real watch's polls count as "watch seen" — the CloudKit
    bridge identifies itself and stays out of the diagnostics."""

    def test_bridge_polls_do_not_count_as_watch(self):
        server, queue = watch_relay.serve(port=0)
        _serve(server)
        base = "http://127.0.0.1:%d" % server.server_address[1]

        urllib.request.urlopen(base + "/pending?source=bridge", timeout=5).read()
        assert queue.watch_seen_seconds_ago() is None

        urllib.request.urlopen(base + "/pending", timeout=5).read()
        assert queue.watch_seen_seconds_ago() is not None

        server.shutdown()
        server.server_close()


class TestBonjourTXTAddresses:
    """The relay publishes every address it has in the Bonjour TXT record,
    so the watch never has to resolve the service — resolution is the step
    that silently fails on real hardware."""

    def test_txt_carries_port_always(self):
        txt = watch_relay.advertise_txt(8977)
        assert txt["port"] == "8977"

    def test_txt_never_carries_the_tunnel(self, monkeypatch):
        """The tunnel URL embeds the travel secret; a TXT record would
        hand it to every device on the network. Never broadcast."""
        monkeypatch.setattr(watch_relay, "TUNNEL_URL",
                            "https://x.trycloudflare.com/t/tok")
        txt = watch_relay.advertise_txt(8977)
        assert "tunnel" not in txt
        assert "tok" not in json.dumps(txt)

    def test_lan_ips_never_returns_tailnet_addresses(self, monkeypatch):
        class FakeRun:
            stdout = "100.69.31.42\n"
        monkeypatch.setattr(watch_relay.subprocess, "run",
                            lambda *a, **k: FakeRun())
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _: "/usr/sbin/ipconfig")
        assert watch_relay.lan_ips() == [] or all(
            not ip.startswith("100.") for ip in watch_relay.lan_ips())



def _write_transcript(tmp_path, folder, name, lines):
    """The one way tests write a fake Claude transcript."""
    pdir = tmp_path / folder
    pdir.mkdir(parents=True, exist_ok=True)
    path = pdir / name
    path.write_text(
        "\n".join(line if isinstance(line, str) else json.dumps(line)
                   for line in lines) + "\n",
        encoding="utf-8")
    return path


class TestSessionNames:
    """Claude Code's folder names are lossy — familia-gateway and
    familia/gateway both become "-Users-...-familia-gateway". The transcript
    carries the real cwd, so the watch shows the real project name."""

    def _write(self, tmp_path, folder, name, lines):
        return _write_transcript(tmp_path, folder, name, lines)

    def test_hyphenated_project_keeps_its_full_name(self, tmp_path,
                                                    monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"abc123": "Terminal"})
        self._write(tmp_path, "-Users-dev-Developer-familia-gateway",
                    "abc123.jsonl",
                    [{"cwd": "/Users/dev/Developer/familia-gateway",
                      "message": {"role": "user", "content": "fix the pwa"}}])
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert sessions[0]["project"] == "familia-gateway"
        assert sessions[0]["path"] == "/Users/dev/Developer/familia-gateway"
        assert sessions[0]["opening"] == "fix the pwa"
        assert sessions[0]["turns"] == 1

    def test_falls_back_to_folder_name_without_cwd(self, tmp_path,
                                                   monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"def456": "Terminal"})
        self._write(tmp_path, "-Users-dev-Developer-solo", "def456.jsonl",
                    [{"message": {"role": "assistant", "content": "hi"}}])
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert sessions[0]["project"] == "solo"

    def test_skips_system_injected_openers(self, tmp_path, monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"ghi789": "Terminal"})
        self._write(tmp_path, "-p", "ghi789.jsonl", [
            {"cwd": "/x/proj",
             "message": {"role": "user", "content": "<system-reminder>noise"}},
            {"message": {"role": "user",
                         "content": [{"type": "text", "text": "the real ask"}]}}])
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert sessions[0]["opening"] == "the real ask"

    def test_title_is_how_the_session_began_not_its_newest_message(self, tmp_path,
                                                                    monkeypatch):
        """The phone titles a session once, from its opening ask. Titling
        by the newest message (as this test once demanded) showed the
        wrist a different name for the same session than the phone — seen
        on the wrist 2026-09-03 — so the opening ask is the title, and a
        /rename beats it."""
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"jkl012": "VS Code"})
        monkeypatch.setattr(watch_dashboard, "session_registry", lambda: {})
        self._write(tmp_path, "-p", "jkl012.jsonl", [
            {"cwd": "/x/proj",
             "message": {"role": "user",
                         "content": "fix the pwa startup crash please"}},
            {"message": {"role": "assistant", "content": "done"}},
            {"message": {"role": "user",
                         "content": "compare the glyphs per subject now"}},
            {"message": {"role": "user", "content": "ok"}},
            {"message": {"role": "user",
                         "content": "/simplify → 4 cleanup agents in parallel"}},
            {"message": {"role": "user",
                         "content": "This session is being continued from a "
                                    "previous conversation that ran out"}}])
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert sessions[0]["title"] == "Fix the pwa startup crash please"
        assert sessions[0]["opening"].startswith("fix the pwa")


class TestSessionsLikeTheApp:
    """The watch shows what the Claude app shows: a title, the repository,
    and whether the session is live."""

    def test_live_sessions_ignores_dead_processes(self, tmp_path):
        (tmp_path / "1.json").write_text(json.dumps(
            {"pid": os.getpid(), "sessionId": "alive-1",
             "entrypoint": "claude-vscode"}), encoding="utf-8")
        (tmp_path / "2.json").write_text(json.dumps(
            {"pid": 999999, "sessionId": "dead-1",
             "entrypoint": "claude-desktop"}), encoding="utf-8")
        live = watch_dashboard.live_sessions(sessions_dir=str(tmp_path))
        assert live == {"alive-1": "VS Code"}

    def test_live_sessions_survives_a_missing_directory(self, tmp_path):
        assert watch_dashboard.live_sessions(sessions_dir=str(tmp_path / "no")) == {}

    def test_unattended_sdk_runs_stay_off_the_wrist(self, tmp_path):
        """The phone app never lists headless SDK runs; the wrist mirrors
        the phone, so a live sdk-cli process must not appear either."""
        (tmp_path / "1.json").write_text(json.dumps(
            {"pid": os.getpid(), "sessionId": "robot-1",
             "entrypoint": "sdk-cli"}), encoding="utf-8")
        (tmp_path / "2.json").write_text(json.dumps(
            {"pid": os.getpid(), "sessionId": "human-1",
             "entrypoint": "claude-vscode"}), encoding="utf-8")
        live = watch_dashboard.live_sessions(sessions_dir=str(tmp_path))
        assert live == {"human-1": "VS Code"}

    @pytest.mark.parametrize("url,expected", [
        ("git@github.com:Thoughtful-Steward/pantri.git", "Thoughtful-Steward/pantri"),
        ("https://github.com/marcobelini/wrist-triage.git", "marcobelini/wrist-triage"),
        ("https://github.com/owner/repo", "owner/repo"),
        ("", ""),
    ])
    def test_repo_slug_parses_remotes(self, url, expected, monkeypatch):
        class Out:
            stdout = url
        monkeypatch.setattr(watch_relay.subprocess, "run", lambda *a, **k: Out())
        # Module-wide cache, so reset it like the site rules — this used to
        # reach into the function's mutable default argument, which is the
        # thing that made the cache invisible and unbounded.
        watch_dashboard._REPO_SLUG_CACHE.clear()
        assert watch_dashboard.repo_slug("/some/path") == expected

    @pytest.mark.parametrize("text,expected", [
        ("Pantri app seems unresponsive. /debug and verify", "Pantri app seems unresponsive"),
        ("/simplify do the thing", "Do the thing"),
        ("", ""),
        ("x" * 80, "X" + "x" * 42 + "…"),
    ])
    def test_derive_title(self, text, expected):
        assert watch_dashboard.derive_title(text) == expected


class TestUsageSummary:
    """Token consumption is measured from the transcripts, so the number on
    the wrist is what was actually spent — never an estimate."""

    def _transcript(self, tmp_path, name, entries):
        return _write_transcript(tmp_path, "-Users-x-proj", name, entries)

    def _entry(self, minutes_ago, out_tokens, model="claude-opus-5"):
        import datetime as _dt
        stamp = (_dt.datetime.now(_dt.timezone.utc)
                 - _dt.timedelta(minutes=minutes_ago)).isoformat()
        return {"timestamp": stamp,
                "message": {"role": "assistant", "model": model,
                            "usage": {"input_tokens": 10,
                                      "output_tokens": out_tokens,
                                      "cache_read_input_tokens": 100}}}

    def test_counts_only_the_rolling_window(self, tmp_path):
        self._transcript(tmp_path, "a.jsonl", [
            self._entry(10, 500),      # inside 5h
            self._entry(60, 300),      # inside 5h
            self._entry(60 * 9, 999),  # outside 5h, inside 24h
        ])
        usage = watch_relay.usage_summary(projects_dir=str(tmp_path))
        assert usage["window_output"] == 800
        assert usage["window_messages"] == 2
        assert usage["day_output"] == 1799
        assert usage["day_messages"] == 3

    def test_breaks_down_by_model(self, tmp_path):
        self._transcript(tmp_path, "b.jsonl", [
            self._entry(5, 100, "claude-opus-5"),
            self._entry(5, 400, "claude-fable-5"),
            self._entry(5, 50, "claude-opus-5"),
        ])
        usage = watch_relay.usage_summary(projects_dir=str(tmp_path))
        assert usage["models"]["claude-fable-5"] == 400
        assert usage["models"]["claude-opus-5"] == 150

    def test_empty_directory_reports_zeroes(self, tmp_path):
        usage = watch_relay.usage_summary(projects_dir=str(tmp_path))
        assert usage["window_output"] == 0 and usage["day_messages"] == 0

    def test_unparseable_lines_are_skipped(self, tmp_path):
        pdir = tmp_path / "-p"
        pdir.mkdir()
        (pdir / "c.jsonl").write_text(
            'not json\n{"usage": broken}\n' +
            json.dumps(self._entry(1, 42)) + "\n", encoding="utf-8")
        assert watch_relay.usage_summary(
            projects_dir=str(tmp_path))["window_output"] == 42


class TestWatchToggle:
    """Exporting env vars in one shell did nothing for the sessions that
    matter — real sessions read settings.json. --watch writes it there."""

    def test_watch_writes_env_for_every_session(self, settings, capsys):
        crc.run_install()
        capsys.readouterr()
        crc.run_watch(True)
        data = json.loads(settings.read_text())
        assert data["env"]["CLAUDE_RISK_MODE"] == "enforce"
        assert data["env"]["CLAUDE_RISK_RELAY"].startswith("http://")
        assert float(data["env"]["CLAUDE_RISK_RELAY_WAIT"]) >= 60

    def test_watch_outlives_its_own_wait(self, settings, capsys):
        """The hook's timeout must exceed the wrist wait, or Claude Code
        kills the hook mid-glance and the card vanishes."""
        crc.run_install()
        crc.run_watch(True)
        capsys.readouterr()
        data = json.loads(settings.read_text())
        timeouts = [h.get("timeout")
                    for entry in data["hooks"]["PermissionRequest"]
                    for h in entry["hooks"] if crc._is_our_hook(h)]
        wait = float(data["env"]["CLAUDE_RISK_RELAY_WAIT"])
        assert timeouts and all(t > wait for t in timeouts)

    def test_no_watch_reverts_cleanly(self, settings, capsys):
        crc.run_install()
        crc.run_watch(True)
        crc.run_watch(False)
        capsys.readouterr()
        data = json.loads(settings.read_text())
        assert "CLAUDE_RISK_MODE" not in data.get("env", {})
        assert data["hooks"]["PermissionRequest"]  # hook itself survives

    def test_watch_is_idempotent(self, settings, capsys):
        crc.run_install()
        crc.run_watch(True)
        capsys.readouterr()
        before = settings.read_text()
        crc.run_watch(True)
        assert settings.read_text() == before
        assert "already on" in capsys.readouterr().out

    def test_relay_wait_reads_the_environment(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_RISK_RELAY_WAIT", "42")
        assert crc.load_policy()["relay_wait"] == 42.0

    def test_timeout_is_recorded_for_diagnosis(self, tmp_path, monkeypatch):
        """A card nobody answered must be visible in the audit, not silent."""
        import io
        monkeypatch.setenv("CLAUDE_RISK_MODE", "enforce")
        monkeypatch.setenv("CLAUDE_RISK_RELAY", "http://127.0.0.1:1")
        monkeypatch.setenv("CLAUDE_RISK_RELAY_WAIT", "0.2")
        log = tmp_path / "audit.jsonl"
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(log))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)
        event = {"tool_name": "Bash", "tool_input": {"command": "rm -r build"}}
        crc.run_hook(stdin=io.StringIO(json.dumps(event)), stdout=io.StringIO())
        entry = json.loads(log.read_text().strip().splitlines()[-1])
        assert entry["watch"] == "none"


class TestDescriptionHeadlines:
    """The wrist shows the same words as the phone: Claude's own description
    of the tool call, not the raw command."""

    def test_description_becomes_the_headline(self):
        card = crc.wrist_card(
            "Bash",
            {"command": "cd /x && for p in 1 2 3; do gh pr view $p; done",
             "description": "Check mergeability of every open PR"},
            Risk.MEDIUM, 64, 80)
        assert card["headline"] == "Check mergeability of every open PR"
        assert card["detail"].startswith("cd /x")

    def test_falls_back_to_the_command_without_one(self):
        card = crc.wrist_card("Bash", {"command": "rm -rf build"},
                              Risk.HIGH, 64, 80)
        assert "Delete" in card["headline"]

    def test_long_descriptions_still_fit_the_face(self):
        card = crc.wrist_card(
            "Bash", {"command": "x", "description": "y" * 200},
            Risk.LOW, 64, 80)
        assert len(card["headline"]) <= 64

    def test_blank_description_is_ignored(self):
        card = crc.wrist_card("Bash", {"command": "git push", "description": "   "},
                              Risk.HIGH, 64, 80)
        assert "git push" in card["headline"]

    def test_wrist_window_outlives_nothing_but_is_generous(self):
        assert crc.DEFAULT_POLICY["relay_wait"] >= 60
        assert crc.WATCH_HOOK_TIMEOUT > float(
            crc.WATCH_ENV["CLAUDE_RISK_RELAY_WAIT"])


class TestWatchPresence:
    """Claude Code shows its own prompt concurrently with the hook's wait,
    so queueing costs the user nothing — and a wrist raised a minute after
    the prompt fired must still find the card. Presence is diagnostics,
    never a gate."""

    def test_a_card_queues_even_with_no_watch_yet(self):
        import time as _time
        queue = watch_relay.CardQueue()          # nobody has ever polled
        result = {}

        def submit():
            _, result["decision"], _ = queue.submit(
                {"tier": "HIGH", "headline": "x", "detail": "x"}, wait=10)

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()
        for _ in range(200):
            if queue.pending():
                break
            _time.sleep(0.01)
        cards = queue.pending(from_watch=True)   # the wrist rises late...
        assert cards, "the card must be waiting for a late wrist"
        queue.decide(cards[0]["id"], "allow")    # ...and can still answer
        thread.join(timeout=5)
        assert result["decision"] == "allow"

    def test_inject_worker_matches_submit_arity(self):
        """`_inject`'s worker unpacks submit()'s return; a 2/3-tuple
        mismatch killed the --demo/--card path silently (worker thread
        died after the wait, outcome never printed)."""
        import time as _time
        queue = watch_relay.CardQueue()
        thread = watch_relay._inject(
            queue, {"tier": "HIGH", "headline": "x", "detail": "x"}, wait=10)
        for _ in range(200):
            if queue.pending():
                break
            _time.sleep(0.01)
        cards = queue.pending(from_watch=True)
        assert cards
        queue.decide(cards[0]["id"], "allow")
        thread.join(timeout=5)
        assert not thread.is_alive()      # would still be alive if it raised

    def test_a_recent_poll_counts_as_present(self):
        queue = watch_relay.CardQueue()
        assert not _watch_present(queue)
        queue.pending(from_watch=True)
        assert _watch_present(queue)

    def test_a_stale_poll_does_not(self, monkeypatch):
        import time as _time
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        queue.last_poll = _time.monotonic() - (queue.WATCH_PRESENT_SECONDS + 5)
        assert not _watch_present(queue)


class TestLateDecisions:
    """A late answer must be refused, and refused visibly — a tap that
    silently does nothing is indistinguishable from a broken button."""

    def test_relay_refuses_an_answer_for_a_card_it_no_longer_holds(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        card_id, decision, _ = queue.submit(
            {"tier": "HIGH", "headline": "x", "detail": "x"}, wait=0.1)
        assert decision == "none"                    # nobody answered in time
        assert queue.decide(card_id, "allow") is False   # too late, refused
        assert queue.pending() == []

    def test_an_answer_in_time_is_accepted(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        result = {}

        def submit():
            result["id"], result["decision"], result["answer"] = queue.submit(
                {"tier": "HIGH", "headline": "x", "detail": "x"}, wait=5)

        thread = threading.Thread(target=submit)
        thread.start()
        for _ in range(50):
            pending = queue.pending()
            if pending:
                assert queue.decide(pending[0]["id"], "deny") is True
                break
            time.sleep(0.05)
        thread.join(timeout=6)
        assert result["decision"] == "deny"


class TestWaitsOnlyWhileWatched:
    """The card stays up while the watch is listening and is released the
    moment it isn't — that is what makes a long window safe."""

    def test_a_lowered_wrist_does_not_cost_the_question(self):
        """Once asked, the card stands until answered — a wrist that stops
        polling for a while must never retract it. (The owner's rule, twice.)"""
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        done = threading.Event()

        def submit():
            queue.submit({"tier": "HIGH", "headline": "x", "detail": "x"},
                         wait=600)
            done.set()

        threading.Thread(target=submit, daemon=True).start()
        time.sleep(0.3)
        assert queue.pending(), "card should be up while the watch is present"
        # The watch goes quiet: last poll ages far past the presence window.
        queue.last_poll = time.monotonic() - (queue.WATCH_PRESENT_SECONDS + 60)
        time.sleep(6)
        assert not done.is_set(), "the card must still be waiting"
        assert queue.pending(), "and still visible for the returning wrist"

    def test_keeps_waiting_while_the_watch_keeps_polling(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        done = threading.Event()

        def submit():
            queue.submit({"tier": "HIGH", "headline": "x", "detail": "x"},
                         wait=600)
            done.set()

        threading.Thread(target=submit, daemon=True).start()
        for _ in range(6):          # keep the watch "present" for ~3s
            time.sleep(0.5)
            queue.pending(from_watch=True)
        assert not done.is_set(), "must still be waiting for a listening watch"
        assert queue.pending()


class TestSessionReplies:
    """A reply typed on the wrist is carried into the session the same way
    the terminal would: `claude --resume <id> -p <text>`."""

    def _session(self, tmp_path, name="abc12345.jsonl", cwd="/x/proj"):
        _write_transcript(tmp_path, "-x-proj", name,
                          [{"cwd": cwd,
                            "message": {"role": "user", "content": "hi"}}])

    def test_resolves_a_short_id_to_the_full_one(self, tmp_path):
        self._session(tmp_path)
        session_id, cwd = watch_relay.resolve_session(
            "abc123", projects_dir=str(tmp_path))
        assert session_id == "abc12345"
        assert cwd == "/x/proj"

    def test_unknown_session_is_reported_not_guessed(self, tmp_path):
        assert watch_relay.say_to_session(
            "nope", "hello", projects_dir=str(tmp_path)) == "unknown session"

    def test_empty_text_is_refused(self, tmp_path):
        self._session(tmp_path)
        assert watch_relay.say_to_session(
            "abc123", "   ", projects_dir=str(tmp_path)) == "empty"

    def test_sends_in_the_sessions_own_directory(self, tmp_path, monkeypatch):
        self._session(tmp_path)
        seen = {}
        class FakeProc:
            pass
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda cmd, **kw: seen.update(cmd=cmd, cwd=kw.get("cwd")) or FakeProc())
        assert watch_relay.say_to_session(
            "abc123", "run the tests", projects_dir=str(tmp_path)) == "sent"
        assert seen["cmd"][:2] == ["claude", "--resume"]
        assert seen["cmd"][2] == "abc12345"
        assert seen["cmd"][-3:] == ["-p", "--", "run the tests"]
        assert seen["cwd"] == "/x/proj"

    def _spawned(self, tmp_path, monkeypatch, **kwargs):
        self._session(tmp_path)
        seen = {}
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _: "/usr/bin/claude")
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda cmd, **kw: seen.update(cmd=cmd) or object())
        assert watch_relay.say_to_session(
            "abc123", "run the tests", projects_dir=str(tmp_path),
            **kwargs) == "sent"
        return seen["cmd"]

    def test_a_wrist_reply_is_asked_for_briefly_by_default(self, tmp_path, monkeypatch):
        """Each message is its own `claude` process, so the Concise style
        rides along for that one reply and never touches the desktop
        session it lands in."""
        import json
        cmd = self._spawned(tmp_path, monkeypatch)
        assert "--settings" in cmd
        settings = json.loads(cmd[cmd.index("--settings") + 1])
        assert settings == {"outputStyle": "Concise"}
        # The message itself is still the last thing on the line.
        assert cmd[-3:] == ["-p", "--", "run the tests"]

    def test_the_watch_can_ask_for_full_replies(self, tmp_path, monkeypatch):
        cmd = self._spawned(tmp_path, monkeypatch, brief=False)
        assert "--settings" not in cmd
        # The permission flags ride on every send, brief or not — a prompt
        # raised by a full reply needs the wrist as much as a short one.
        assert cmd[:3] == ["claude", "--resume", "abc12345"]
        assert cmd[-3:] == ["-p", "--", "run the tests"]
        assert "--permission-prompt-tool" in cmd


class TestRecognisedTooling:
    """The classifier's knowledge is the product: recognising a read-only
    invocation is what keeps a wrist quiet. Unknown still escalates."""

    @pytest.mark.parametrize("command", [
        "xcrun simctl list devices",
        "security find-identity -v -p codesigning",
        "plutil -p Info.plist",
        "defaults read com.apple.dock",
        "docker ps -a",
        "docker logs api",
        "kubectl get pods -n prod",
        "gh pr view 123",
        "gh issue list",
        "gh run view 55",
        "gh api /repos/x/y",
        "tailscale ip -4",
        "brew list",
        "pip list",
        "xcodebuild -list",
        "xcodebuild -version",
        "xcodebuild -showsdks",
        "codesign -d --deep --strict app.ipa",
        "sw_vers",
        "system_profiler SPHardwareDataType",
        "flyctl status",
    ])
    def test_read_only_invocations_are_safe(self, command):
        risk, rules = crc.classify_bash(command)
        assert risk == Risk.SAFE, rules

    @pytest.mark.parametrize("command", [
        "docker run -it ubuntu",
        "kubectl delete pod api",
        "gh pr merge 123",
        "gh api -X POST /repos/x/y/issues",
        "gh api -XDELETE /repos/x/y",
        "gh api --method=PUT /repos/x/y/topics",
        # gh flips the default method to POST when a body field is given,
        # and quoting the method must not hide it.
        "gh api graphql -f query='mutation { x }'",
        "gh api repos/x/y/issues -f title=x",
        'gh api -X "DELETE" /repos/x/y/git/refs/heads/main',
        # security's cms/export verbs can sign and dump private keys.
        "security cms -S -N identity -i payload -o signed",
        "security export -k login.keychain -t privKeys -o keys.pem",
        "brew install ffmpeg",
        "defaults write com.apple.dock autohide -bool true",
        "security delete-keychain build.keychain",
        "helm install release .",
        "some-random-binary --go",
        # xcodebuild with NO verb still builds: value-taking selectors
        # describe a build, so they must never look read-only.
        "xcodebuild -project App.xcodeproj -scheme App",
        "xcodebuild -workspace A.xcworkspace -scheme App clean archive",
        "xcodebuild -list build",
        "xcrun xcodebuild -project App.xcodeproj -scheme App",
    ])
    def test_anything_else_still_escalates(self, command):
        risk, _ = crc.classify_bash(command)
        assert risk >= Risk.MEDIUM

    def test_recognition_does_not_forgive_a_dangerous_chain(self):
        risk, rules = crc.classify_bash("gh pr view 1 && rm -rf /")
        assert risk == Risk.CRITICAL

    def test_recognition_does_not_forgive_a_redirect(self):
        risk, _ = crc.classify_bash("docker ps > /etc/hosts")
        assert risk >= Risk.MEDIUM


class TestLabellerByDefault:
    """Measurement showed the deciding half auto-allowed ~5% of prompts
    while carrying all of the misjudgement risk. So it is opt-in now."""

    def test_an_unknown_command_can_never_be_waved_through(self):
        risk, rules = crc.classify_bash("some-tool-nobody-taught-us --force")
        assert "unknown-command" in rules
        assert crc.decide(risk, crc.DEFAULT_POLICY)[0] == "escalate"
        quiet = dict(crc.DEFAULT_POLICY, auto_allow_at_or_below="LOW")
        assert crc.decide(risk, quiet)[0] == "escalate"

    def test_tiers_still_label_the_card(self):
        """The half that earns its keep: risk visible at a glance."""
        assert crc.classify_bash("git push --force origin main")[0] == Risk.CRITICAL
        assert crc.classify_bash("rm -rf build")[0] == Risk.HIGH
        assert crc.classify_bash("gh pr view 1")[0] == Risk.SAFE

    def test_quiet_writes_the_opt_in_for_every_session(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        crc.run_install()
        capsys.readouterr()
        crc.run_quiet(True)
        data = json.loads((tmp_path / "s.json").read_text())
        assert data["env"]["CLAUDE_RISK_AUTO_ALLOW"] == "LOW"
        crc.run_quiet(False)
        data = json.loads((tmp_path / "s.json").read_text())
        assert "CLAUDE_RISK_AUTO_ALLOW" not in data.get("env", {})

    def test_the_environment_can_opt_in(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_RISK_AUTO_ALLOW", "LOW")
        assert crc.load_policy()["auto_allow_at_or_below"] == "LOW"


class TestRelayPairing:
    """The trust model: a local process is trusted because it is already
    inside the machine; everyone else must hold a device key, whichever
    network they arrive from. Being on the same Wi-Fi proves nothing — on a
    café network that is a room full of strangers."""

    def test_loopback_needs_nothing(self):
        assert watch_relay.authorize_request(
            "127.0.0.1", "/say", "", False, "secret")

    def test_strangers_are_refused_everywhere_but_health(self):
        assert not watch_relay.authorize_request(
            "203.0.113.9", "/pending", "", False, "secret")
        assert not watch_relay.authorize_request(
            "203.0.113.9", "/say", "wrong", False, "secret")
        assert watch_relay.authorize_request(
            "203.0.113.9", "/health", "", False, "secret")

    @pytest.mark.parametrize("ip", [
        "192.168.1.50", "10.0.0.5", "172.20.1.1", "169.254.9.9",
        "100.99.1.2", "fe80::1",
    ])
    @pytest.mark.parametrize("path", [
        "/pending", "/sessions", "/thread", "/activity", "/usage",
        "/decision", "/say", "/tunnel",
    ])
    def test_a_private_address_is_not_a_credential(self, ip, path):
        """The café-Wi-Fi hole, closed. Every one of these once answered a
        stranger on the same subnet: transcripts, the session list, and the
        power to answer a prompt or speak into a live session."""
        assert not watch_relay.authorize_request(ip, path, "", False, "secret")

    def test_the_paired_key_opens_everything(self):
        assert watch_relay.authorize_request(
            "192.168.1.50", "/thread", "secret", False, "secret")
        assert watch_relay.authorize_request(
            "100.99.1.2", "/decision", "secret", False, "secret")

    def test_the_tunnel_path_is_an_address_not_a_credential(self):
        """The travel URL is printed to stderr and written to the relay log,
        so it is not a secret worth betting a session on. It says where to
        knock; the device key still says who is knocking."""
        assert not watch_relay.authorize_request(
            "203.0.113.9", "/pending", "", True, "secret", via_tunnel=True)
        assert watch_relay.authorize_request(
            "203.0.113.9", "/pending", "secret", True, "secret", via_tunnel=True)

    def test_loopback_is_not_a_pass_on_the_tunnel_listener(self):
        """cloudflared connects from 127.0.0.1, so on that listener loopback
        means "the internet", not "a local process"."""
        assert not watch_relay.authorize_request(
            "127.0.0.1", "/pending", "", True, "secret", via_tunnel=True)

    def test_no_configured_key_never_admits_strangers(self):
        assert not watch_relay.authorize_request(
            "203.0.113.9", "/pending", "wrong", False, None)

    @pytest.mark.parametrize("ip,local", [
        ("10.0.0.5", True), ("192.168.0.9", True), ("172.16.4.4", True),
        ("172.31.255.1", True), ("172.32.0.1", False), ("100.64.0.1", True),
        ("100.127.9.9", True), ("100.128.0.1", False), ("8.8.8.8", False),
        ("169.254.1.1", True), ("", False),
    ])
    def test_private_address_detection(self, ip, local):
        """Still needed — but only for the Host-header rebinding check, never
        as an authorization decision."""
        assert watch_relay._is_private_address(ip) is local

    def test_the_old_boundary_helper_is_gone(self):
        """Guard against a merge resurrecting the function whose docstring
        called itself "the pairing boundary"."""
        assert not hasattr(watch_relay, "_is_local_source")



class TestParityCheckIsHonestAboutItsScope:
    """`phone_would_auto_allow` answers "would Claude Code itself stay
    silent?". It used to say yes for every non-Bash tool — Write, Edit,
    every mcp__* call — and was safe only because its one caller checks the
    SAFE tier first. That invariant lived in another function."""

    @pytest.mark.parametrize("tool", ["Read", "Glob", "Grep", "NotebookRead"])
    def test_read_tools_are_silent(self, tool):
        assert crc.phone_would_auto_allow(tool, {})

    @pytest.mark.parametrize("tool", [
        "Write", "Edit", "MultiEdit", "NotebookEdit", "mcp__github__create_pr",
        "WebFetch", "Task",
    ])
    def test_everything_else_is_not(self, tool):
        assert not crc.phone_would_auto_allow(tool, {"file_path": "/tmp/x"})


class TestAuditLogRotates:
    """The audit log is the user's own record of what was decided for them,
    so it is rotated rather than trimmed — the README promises they can read
    it, and cutting the middle out of a record is not reading."""

    def test_an_oversized_log_is_moved_aside_not_cut(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        path.write_text("old entry\n" * 500, encoding="utf-8")
        before = path.read_text(encoding="utf-8")
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(path))
        assert crc._roll_audit(str(path), limit=100) is True
        crc.write_audit({"tier": "HIGH"}, policy)
        # Nothing lost: the old entries are one file over.
        assert (tmp_path / "audit.jsonl.1").read_text(encoding="utf-8") == before
        assert "HIGH" in path.read_text(encoding="utf-8")

    def test_a_normal_log_is_untouched(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        path.write_text("entry\n", encoding="utf-8")
        assert crc._roll_audit(str(path)) is False
        assert not (tmp_path / "audit.jsonl.1").exists()


class TestTheWristSaysWhatThePhoneSays:
    """The watch is a second view of the same conversation, so its wording
    is not a design choice — it is a fact about the phone."""

    def _thread(self, tmp_path, lines, limit=14):
        import watch_dashboard
        folder = tmp_path / "-p"
        folder.mkdir(exist_ok=True)
        path = folder / "sess.jsonl"
        with open(path, "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(json.dumps(line) + "\n")
        watch_dashboard._THREAD_STATE.pop(str(path), None)
        return watch_dashboard._parse_thread(str(path), limit)

    def _tool(self, name, description=None):
        use = {"type": "tool_use", "name": name, "input": {}}
        if description:
            use["input"]["description"] = description
        return {"message": {"role": "assistant", "content": [use]}}

    def _said(self, text):
        return {"message": {"role": "assistant", "content": text}}

    def test_several_commands_are_counted_not_listed(self, tmp_path):
        """The phone writes "Ran 4 commands". The wrist used to write
        "Ran a command, ran a command…" and push the actual words off the
        top of a very small screen."""
        turns, _, _ = self._thread(tmp_path, [
            self._said("starting"),
            self._tool("Bash"), self._tool("Bash"),
            self._tool("Bash"), self._tool("Bash"),
            self._said("done"),
        ])
        tools = [t["text"] for t in turns if t["kind"] == "tool"]
        assert tools == ["Ran 4 commands"]

    def test_a_single_command_is_named_by_what_it_was_for(self, tmp_path):
        turns, _, _ = self._thread(tmp_path, [
            self._said("before"),
            self._tool("Bash", "Read the distribution logs"),
            self._said("after"),
        ])
        tools = [t["text"] for t in turns if t["kind"] == "tool"]
        assert tools == ["Ran Read the distribution logs"]

    def test_a_mixed_run_counts_each_kind(self, tmp_path):
        turns, _, _ = self._thread(tmp_path, [
            self._said("x"),
            self._tool("Bash"), self._tool("Bash"), self._tool("Edit"),
            self._said("y"),
        ])
        tools = [t["text"] for t in turns if t["kind"] == "tool"]
        assert tools == ["Ran 2 commands, edited a file"]


class TestAPhantomTaskCannotBeBorn:
    """A running-task count is a claim about the world, so it needs evidence
    from the world. Text that merely LOOKS like a launch is not evidence.

    This is not hypothetical: a test fixture containing the words
    "agentId: deadbeef99" travelled through a real conversation, was read as
    a launch, and — never having existed — could never produce the receipt
    that would retire it. The wrist reported a running task for the rest of
    the day while the phone showed none.
    """

    def test_a_quoted_id_with_nothing_on_disk_is_not_running(self, tmp_path):
        import watch_dashboard
        folder = tmp_path / "-p"
        folder.mkdir()
        path = folder / "sess.jsonl"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"message": {
                "role": "user",
                "content": 'the test fixture says agentId: deadbeef99 (internal)'
            }}) + "\n")
        watch_dashboard._THREAD_STATE.pop(str(path), None)
        _turns, running, _tool = watch_dashboard._parse_thread(str(path), 14)
        assert running == 0

    def test_a_task_with_a_live_output_file_does_count(self, tmp_path, monkeypatch):
        """The guard must not silence real tasks — only invented ones."""
        import watch_dashboard
        session = "sess"
        tasks = tmp_path / "tmp" / "claude-1" / "proj" / session / "tasks"
        tasks.mkdir(parents=True)
        (tasks / "realtask1.output").write_text("still working\n", encoding="utf-8")
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        assert watch_dashboard._task_state(session, "realtask1") == "running"

    def test_a_finished_task_is_terminal(self, tmp_path, monkeypatch):
        import watch_dashboard
        session = "sess"
        tasks = tmp_path / "tmp" / "claude-1" / "proj" / session / "tasks"
        tasks.mkdir(parents=True)
        (tasks / "done1.output").write_text("output\n[exited with code 0]\n",
                                            encoding="utf-8")
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        assert watch_dashboard._task_state(session, "done1") == "done"


class TestLogsDoNotGrowForever:
    """The relay runs for weeks; nothing used to trim what it writes."""

    def test_a_large_log_is_trimmed_to_its_tail(self, tmp_path):
        path = tmp_path / "relay.log"
        path.write_text("x" * 40 + "\n" + ("line\n" * 5000), encoding="utf-8")
        before = path.stat().st_size
        assert watch_relay._rotate_log(str(path), limit=2000) is True
        after = path.read_text(encoding="utf-8")
        assert path.stat().st_size < before
        assert after.startswith("[earlier entries trimmed]")
        # Never start mid-line: a truncated first line reads as corruption.
        assert "\nline\n" in after

    def test_a_small_log_is_left_alone(self, tmp_path):
        path = tmp_path / "relay.log"
        path.write_text("still short\n", encoding="utf-8")
        assert watch_relay._rotate_log(str(path), limit=2000) is False
        assert path.read_text(encoding="utf-8") == "still short\n"

    def test_a_missing_log_is_not_an_error(self, tmp_path):
        assert watch_relay._rotate_log(str(tmp_path / "nope.log")) is False


class TestSecretsDoNotRideAlong:
    """A card carries command text to the wrist and through iCloud, and the
    audit log keeps it on disk. A token pasted into a command should not be
    copied to any of those places."""

    @pytest.mark.parametrize("command,leak", [
        ('curl -H "Authorization: Bearer sk-live-9f8e7d6c5b4a" https://api.x',
         "sk-live-9f8e7d6c5b4a"),
        ("gh auth login --token ghp_ABCDEFGHIJKLMNOPQRSTUVWX",
         "ghp_ABCDEFGHIJKLMNOPQRSTUVWX"),
        ("API_TOKEN=hunter2hunter2 ./deploy.sh", "hunter2hunter2"),
        ("psql --password swordfish99 -h db", "swordfish99"),
    ])
    def test_the_secret_never_reaches_the_card(self, command, leak):
        card = crc.wrist_card("Bash", {"command": command}, Risk.HIGH)
        assert leak not in card["detail"]
        assert leak not in card["headline"]

    def test_the_command_is_still_recognisable(self):
        """Redaction must not turn the card into a riddle — the point of the
        card is that a human can judge it at a glance."""
        card = crc.wrist_card(
            "Bash", {"command": "gh auth login --token ghp_" + "A" * 20},
            Risk.HIGH)
        assert "gh auth login" in card["detail"]

    def test_ordinary_commands_are_untouched(self):
        card = crc.wrist_card("Bash", {"command": "rm -rf build dist"},
                              Risk.HIGH)
        assert card["detail"] == "rm -rf build dist"

    def test_the_audit_log_is_not_world_readable(self, tmp_path):
        """It records what each card showed; on a shared machine the default
        umask leaves that readable by everyone."""
        import os
        path = tmp_path / "audit.jsonl"
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(path))
        crc.write_audit({"tier": "HIGH", "detail": "rm -rf /"}, policy)
        assert path.exists()
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


class TestTheKeyCarriedThroughICloudWorks:
    """A watch reads its key from the owner's private iCloud and presents it
    directly. That key therefore has to BE a key, not only a ticket to ask
    for one — an older build has no idea how to make the exchange, and a
    watch that cannot use what it was given falls back to iCloud forever and
    quietly loses the session list."""

    def _auth(self, tmp_path, monkeypatch):
        monkeypatch.setattr(watch_relay, "TOKEN_FILE", str(tmp_path / "none"))
        return watch_relay.Auth(path=str(tmp_path / "auth.json"))

    def test_the_mirrored_key_opens_the_data_endpoints(self, tmp_path, monkeypatch):
        auth = self._auth(tmp_path, monkeypatch)
        assert auth.matches(auth.bootstrap)

    def test_it_survives_a_reload(self, tmp_path, monkeypatch):
        auth = self._auth(tmp_path, monkeypatch)
        again = watch_relay.Auth(path=auth.path)
        assert again.matches(again.bootstrap)

    def test_rotation_keeps_it_usable(self, tmp_path, monkeypatch):
        auth = self._auth(tmp_path, monkeypatch)
        before = auth.bootstrap
        auth.rotate()
        assert auth.bootstrap != before
        assert not auth.matches(before)      # the old key really is dead
        assert auth.matches(auth.bootstrap)  # the new one works at once

    def test_it_is_still_not_the_tunnel_secret(self, tmp_path, monkeypatch):
        """Two secrets, two jobs — that separation is the whole point."""
        auth = self._auth(tmp_path, monkeypatch)
        assert auth.bootstrap != auth.tunnel_secret


class TestLanSourceIsNotTrusted:
    """The café-Wi-Fi hole, proved closed against a real server.

    The relay binds 0.0.0.0 because the watch reaches it over the LAN, so
    the defence has to be authentication rather than binding. These tests
    speak to a live server while its peer address reads as a LAN address.
    """

    @pytest.fixture
    def lan(self, fresh_auth):
        # Rate-limit counters are module-wide, like site rules: reset them or
        # one test's burst becomes the next test's mysterious 429.
        watch_relay.LIMITS.reset()
        auth = _known_watch(fresh_auth)
        server, queue = watch_relay.serve(port=0, auth=auth)
        # Rewrite the peer address on the server instance: a LAN client with
        # no production test seam, and the Host header still names loopback
        # so the rebinding defence is not what is under test here.
        real = server.get_request

        def spoofed():
            sock, addr = real()
            return sock, ("192.168.1.77", addr[1])

        server.get_request = spoofed
        _serve(server)
        yield "http://127.0.0.1:%d" % server.server_address[1], queue, auth
        server.shutdown()
        server.server_close()

    _call = staticmethod(relay_call)

    @pytest.mark.parametrize("path", [
        "/pending", "/sessions", "/activity", "/usage", "/thread?id=x",
        "/tunnel",
    ])
    def test_reads_are_refused_without_a_key(self, lan, path):
        base, _, _ = lan
        status, _body = self._call(base + path)
        assert status == 403

    @pytest.mark.parametrize("path,body", [
        ("/decision", {"id": "x", "decision": "allow"}),
        ("/say", {"session_id": "x", "text": "hello"}),
    ])
    def test_writes_are_refused_without_a_key(self, lan, path, body):
        base, _, _ = lan
        status, _body = self._call(base + path, method="POST", body=body)
        assert status == 403

    def test_a_valid_key_still_works(self, lan):
        """Hardened, not bricked: the watch's own key opens the same doors."""
        base, _, _ = lan
        assert self._call(base + "/pending", token="devicetoken")[0] == 200
        assert self._call(base + "/sessions", token="devicetoken")[0] == 200

    def test_card_injection_is_local_processes_only(self, lan):
        """A forged card is a fake prompt harvesting a real tap — even a
        correctly-keyed LAN device may not post one."""
        base, queue, _ = lan
        status, _body = self._call(
            base + "/card", token="devicetoken", method="POST",
            body={"card": {"tier": "HIGH", "headline": "x", "detail": "x"},
                  "wait": 0})
        assert status == 403
        assert queue.pending() == []

    def test_heartbeat_is_local_processes_only(self, lan):
        base, _, _ = lan
        status, _body = self._call(base + "/heartbeat", token="devicetoken",
                                   method="POST",
                                   body={"watch_seen_seconds_ago": 1})
        assert status == 403

    def test_admin_is_local_processes_only(self, lan):
        base, _, auth = lan
        status, _body = self._call(base + "/admin/pair-open", method="POST")
        assert status == 403
        assert not auth.window_open()

    def test_the_watch_can_report_its_own_trouble(self, lan):
        """watchOS has no MetricKit and Tapproval has no server, so the one
        channel that exists is this: the watch telling the owner's own Mac,
        over the token it already holds."""
        base, _, _ = lan
        status, body = self._call(
            base + "/diagnostic", token="devicetoken", method="POST",
            body={"kind": "caught", "message": "decode failed: /sessions",
                  "detail": "keyNotFound(status)", "app_version": "1.1",
                  "build": "115"})
        assert status == 200 and body["ok"] is True
        # Honest about what happened to it: recorded is not e-mailed. And
        # "sent" is NOT among the acceptable answers — on 2026-09-10 this
        # very fixture reached the owner's inbox, twice, because a key had
        # been installed and nothing stopped a test run from using it.
        # Not "duplicate" or "rate_limited" either: the crash log and the
        # dedupe state are this test's own, so neither can be left over.
        assert body["reported"] in ("mail_not_configured",
                                    "not_sent_in_tests"), body["reported"]

    def test_a_report_with_nothing_in_it_is_refused(self, lan):
        base, _, _ = lan
        status, body = self._call(base + "/diagnostic", token="devicetoken",
                                  method="POST", body={"kind": "caught"})
        assert status == 400 and "message" in body["error"]

    def test_a_local_process_cannot_file_a_fault_in_the_watchs_name(self, lan):
        """Same rule as /say: a command Claude runs is a local process, and
        loopback is not a credential for speaking as the watch."""
        base, _, _ = lan
        status, _ = self._call(base + "/diagnostic", method="POST",
                               body={"kind": "caught", "message": "x"})
        assert status == 403

    def test_health_tells_a_stranger_nothing_but_alive(self, lan):
        """Liveness is public; a pending count and "is a watch on the wrist
        right now" is a presence oracle."""
        base, _, _ = lan
        status, body = self._call(base + "/health")
        assert status == 200 and body == {"ok": True}
        status, body = self._call(base + "/health", token="devicetoken")
        assert status == 200 and "pending" in body and "version" in body

    def test_health_tells_a_paired_watch_where_the_helper_code_is_from(self, lan, monkeypatch):
        """The receipt behind the version number — see
        TestTheHelperSaysWhereItsCodeIsFrom. Paired callers only: which
        day a machine's software is from is a fact for its owner."""
        monkeypatch.setattr(watch_relay, "_PROVENANCE", ("abc1234", "2026-09-08T10:00:00+02:00"))
        base, _, _ = lan
        _status, body = self._call(base + "/health", token="devicetoken")
        assert body["helper_commit"] == "abc1234"
        assert body["helper_date"] == "2026-09-08T10:00:00+02:00"
        _status, stranger = self._call(base + "/health")
        assert "helper_commit" not in stranger

    def test_pairing_is_shut_once_a_device_is_enrolled(self, lan):
        base, _, _ = lan
        status, body = self._call(base + "/pair")
        assert status == 403 and body.get("error") == "already paired"

    def test_an_open_window_hands_over_the_bootstrap_once_per_address(self, lan):
        base, _, auth = lan
        auth.open_window(60)
        status, body = self._call(base + "/pair")
        assert status == 200 and body["token"] == "bootstraptoken"
        assert self._call(base + "/pair")[0] == 403   # same address, again

    def test_a_burst_shuts_the_window(self, lan):
        """A flood is an attack, not a retry."""
        base, _, auth = lan
        auth.open_window(60)
        for _ in range(8):
            self._call(base + "/pair")
        assert not auth.window_open()

    # -- a machine that has never paired ----------------------------------
    #
    # The door used to be a 10-minute fuse lit when the relay started — and
    # install.sh starts the relay. Install the helper, go and get the watch
    # app from TestFlight, read the tour: the fuse had burnt out, and the
    # first thing a new user saw was "Not paired yet" plus a phrase no
    # README explains. There is nothing behind that door yet to protect.

    def _never_paired(self, auth):
        auth.paired_ever = False
        auth.devices = []
        auth.relight()          # the door a relay start would have lit

    def test_a_never_paired_machine_keeps_the_door_open(self, lan):
        base, _, auth = lan
        self._never_paired(auth)
        assert auth.window_open()
        status, body = self._call(base + "/pair")
        assert status == 200 and body["token"] == "bootstraptoken"

    def test_the_door_stays_open_long_enough_to_install_and_no_longer(self, lan):
        """The fuse: twenty minutes later still open, an hour later shut —
        until the next session start lights it again."""
        base, _, auth = lan
        self._never_paired(auth)
        real = watch_relay.time.time
        try:
            watch_relay.time.time = lambda: real() + 1200.0
            assert auth.window_open()
            assert self._call(base + "/pair")[0] == 200
            watch_relay.time.time = lambda: real() + 3600.0
            assert not auth.window_open()
            assert self._call(base + "/pair")[0] == 403
            auth.relight()
            assert auth.window_open()
        finally:
            watch_relay.time.time = real

    def test_enrolment_shuts_the_open_door_for_good(self, lan):
        """The moment a device is on the other side, it is a door again."""
        base, _, auth = lan
        self._never_paired(auth)
        self._call(base + "/enroll", token="bootstraptoken", method="POST",
                   body={"device_id": "w1", "label": "Watch"})
        assert auth.paired_ever
        assert not auth.window_open()
        status, body = self._call(base + "/pair")
        assert status == 403 and body.get("error") == "already paired"

    def test_a_burst_still_slams_a_never_paired_door(self, lan):
        """A burst shuts the door before the fuse would — and the next
        --ensure reopens it, which is the right trade."""
        base, _, auth = lan
        self._never_paired(auth)
        for _ in range(8):
            self._call(base + "/pair")
        assert not auth.window_open()
        # Refused either way: the rate limiter answers first (429), and
        # the shut door would answer 403 behind it. Both are "no".
        assert self._call(base + "/pair")[0] in (403, 429)
        auth.open_window()                 # what --ensure does at start
        assert auth.window_open()

    def test_enrolment_trades_the_bootstrap_for_a_device_key(self, lan):
        base, _, auth = lan
        status, body = self._call(base + "/enroll", token="bootstraptoken",
                                  method="POST",
                                  body={"device_id": "w2", "label": "Watch 2"})
        assert status == 200
        issued = body["token"]
        assert issued not in ("bootstraptoken", "devicetoken", "tunnelsecret")
        assert self._call(base + "/pending", token=issued)[0] == 200
        # The bootstrap alone opens nothing else.
        assert self._call(base + "/pending", token="bootstraptoken")[0] == 403

    def test_the_three_secrets_are_distinct(self, lan):
        """A future refactor must not quietly merge them again."""
        _base, _queue, auth = lan
        assert len({auth.tunnel_secret, auth.bootstrap,
                    auth.devices[0]["token"]}) == 3


class TestGhostCards:
    """A card whose hook has died is an already-answered question; it must
    leave the wrist immediately, not haunt it for the rest of the wait."""

    def test_dead_caller_retracts_the_card_promptly(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        alive = {"value": True}
        result = {}

        def submit():
            started = time.monotonic()
            _, result["decision"], _ = queue.submit(
                {"tier": "HIGH", "headline": "x", "detail": "x"}, wait=600,
                caller_alive=lambda: alive["value"])
            result["elapsed"] = time.monotonic() - started

        thread = threading.Thread(target=submit)
        thread.start()
        time.sleep(0.3)
        assert queue.pending(), "card should be up while the hook lives"
        alive["value"] = False                    # the hook was killed
        thread.join(timeout=10)
        assert result["decision"] == "none"
        assert result["elapsed"] < 7
        assert queue.pending() == []              # retracted, not haunting

    def test_a_live_caller_keeps_waiting(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        done = threading.Event()

        def submit():
            queue.submit({"tier": "HIGH", "headline": "x", "detail": "x"},
                         wait=600, caller_alive=lambda: True)
            done.set()

        threading.Thread(target=submit, daemon=True).start()
        for _ in range(4):
            time.sleep(0.5)
            queue.pending(from_watch=True)
        assert not done.is_set()
        assert queue.pending()


class TestThreadForTheWatch:
    """The thread view is a live surface: tool runs are typed, markdown
    noise is stripped, and freshness says whether Claude is working."""

    def _transcript(self, tmp_path):
        return _write_transcript(tmp_path, "-p", "livethread1.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "fix the **bug**"}},
            {"message": {"role": "assistant",
                         "content": [{"type": "tool_use", "name": "Bash"}]}},
            {"message": {"role": "assistant",
                         "content": [{"type": "text",
                                      "text": "Done — see `main.py`"}]}},
        ])

    def test_tool_turns_are_typed_and_text_is_cleaned(self, tmp_path):
        self._transcript(tmp_path)
        turns = watch_dashboard.session_thread("livethread1",
                                           projects_dir=str(tmp_path))
        kinds = [(t["kind"], t["text"]) for t in turns]
        assert ("tool", "Ran a command") in kinds        # the phone's words
        assert ("text", "fix the bug") in kinds          # ** stripped
        assert ("text", "Done — see main.py") in kinds   # backticks stripped


class TestASendIntoALiveSessionAsksFirst:
    """A wrist send runs ``claude --resume -p`` — a second process on the
    session. When a process already holds the session open, that second
    one appends turns the first never reads. The relay knows the live
    ones (``claude agents --json``) and says "live" instead of forking;
    ``force`` is the wrist's "send anyway"."""

    def test_the_live_list_is_the_session_registry(self, tmp_path):
        # The same files the session list is built from: a registry entry
        # whose pid is alive and whose entrypoint is not an SDK run.
        _write_transcript(tmp_path, "sessions", "1.json", [
            {"sessionId": "abc", "pid": os.getpid(), "entrypoint": "claude-desktop"}])
        _write_transcript(tmp_path, "sessions", "2.json", [
            {"sessionId": "gone", "pid": 999999999, "entrypoint": "claude-desktop"}])
        live = watch_relay.session_registry(str(tmp_path / "sessions"))
        assert watch_relay.say_guard("abc", live=live) == "live"
        assert watch_relay.say_guard("gone", live=live) is None

    def test_an_unreadable_registry_blocks_nothing(self, tmp_path):
        live = watch_relay.session_registry(str(tmp_path / "nowhere"))
        assert live == {}
        assert watch_relay.say_guard("abc", live=live) is None

    def test_live_stops_and_force_goes_through(self):
        live = {"abc": {"name": "x", "status": "idle", "pid": 1}}
        assert watch_relay.say_guard("abc", live=live) == "live"
        assert watch_relay.say_guard("abc", force=True, live=live) is None
        assert watch_relay.say_guard("other", live=live) is None

    def test_a_headless_turn_is_named_in_the_thread(self, tmp_path):
        _write_transcript(tmp_path, "-p", "fork1.jsonl", [
            {"cwd": "/x", "entrypoint": "claude-desktop",
             "message": {"role": "user", "content": "from the desk"}},
            {"cwd": "/x", "entrypoint": "sdk-cli",
             "message": {"role": "user", "content": "from the wrist"}},
        ])
        turns = watch_dashboard.session_thread("fork1", projects_dir=str(tmp_path))
        origins = {t["text"]: t.get("origin") for t in turns}
        assert origins == {"from the desk": None, "from the wrist": "headless"}


class TestCodeBlocksForTheWatch:
    """The phone shows code in a box; the wrist showed "[code]". A watch
    that can draw the box now gets the code alongside the flattened text,
    never instead of it, so an older watch keeps reading."""

    def test_a_fence_becomes_a_code_block_between_text_blocks(self):
        md = "Run this:\n\n```python\nx = 1\nprint(x)\n```\n\nthen **stop**."
        assert watch_dashboard.blocks(md) == [
            {"kind": "text", "text": "Run this:"},
            {"kind": "code", "lang": "python", "text": "x = 1\nprint(x)"},
            {"kind": "text", "text": "then **stop**."},   # marks kept for the watch to render
        ]
        assert watch_dashboard.plain_text(md) == "Run this:\n\n[code]\n\nthen stop."

    def test_no_fence_means_no_blocks(self):
        assert watch_dashboard.blocks("just **prose** here") == []
        assert watch_dashboard.blocks("") == []

    def test_a_markdown_fence_is_prose_and_a_nested_fence_is_content(self):
        md = "````markdown\n# T\n```\ninner\n```\n````"
        assert watch_dashboard.blocks(md) == [{"kind": "text", "text": "T\ninner"}]

    def test_an_unclosed_fence_is_still_code(self):
        assert watch_dashboard.blocks("```sh\nls -la") == [
            {"kind": "code", "lang": "sh", "text": "ls -la"}]

    def test_the_thread_carries_blocks_only_where_there_is_code(self, tmp_path):
        _write_transcript(tmp_path, "-p", "blocks1.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "```\nmine\n```"}},
            {"message": {"role": "assistant",
                         "content": [{"type": "text", "text": "See:\n```swift\nlet a = 1\n```"}]}},
            {"message": {"role": "assistant",
                         "content": [{"type": "text", "text": "plain reply"}]}},
        ])
        turns = watch_dashboard.session_thread("blocks1", projects_dir=str(tmp_path))
        by_text = {t["text"]: t for t in turns}
        assert by_text["See:\n[code]"]["blocks"] == [
            {"kind": "text", "text": "See:"},
            {"kind": "code", "lang": "swift", "text": "let a = 1"}]
        assert "blocks" not in by_text["plain reply"]
        assert "blocks" not in by_text["[code]"]      # the user's own bubble stays flat


class TestPlainTextForTheWatch:
    """Claude writes Markdown; a 40mm screen shows plain lines. Structure
    survives (one line per item), markers do not — and prose wrapped in a
    ```markdown fence is flattened like everything else."""

    @pytest.mark.parametrize("md,expected", [
        ("## Heading\nbody", "Heading\nbody"),
        ("- one\n- two", "• one\n• two"),
        ("* star\n+ plus", "• star\n• plus"),
        ("1. first\n2. second", "1. first\n2. second"),
        ("see [PR #12](https://x/y/12) now", "see PR #12 now"),
        ("![diagram](img.png) caption", "diagram caption"),
        ("**bold** and *em* and _em2_ and `code`", "bold and em and em2 and code"),
        ("> quoted", "quoted"),
        ("a\n\n---\n\nb", "a\n\nb"),
        ("| Name | State |\n|------|-------|\n| a | ok |", "Name · State\na · ok"),
        ("<b>tag</b> text", "tag text"),
        ("escaped \\* star", "escaped * star"),
        ("~~gone~~ kept", "gone kept"),
    ])
    def test_markers_go_structure_stays(self, md, expected):
        assert watch_dashboard.plain_text(md) == expected

    def test_markdown_fence_is_prose_in_disguise(self):
        md = "```markdown\n# Title\n- item\n```"
        assert watch_dashboard.plain_text(md) == "Title\n• item"

    def test_four_backtick_markdown_fence_is_prose_too(self):
        """Claude uses ````markdown when the content itself holds ```."""
        md = "````markdown\n# PKT-003 — bygget\n## Runde 2\n````"
        assert watch_dashboard.plain_text(md) == "PKT-003 — bygget\nRunde 2"

    def test_code_fence_becomes_one_marker(self):
        """Code renders as a box on the phone; the wrist shows one [code]
        marker per block instead of verbatim lines."""
        md = "```python\n# a comment\nx = 1\n```"
        assert watch_dashboard.plain_text(md) == "[code]"

    def test_identifiers_with_double_underscores_survive(self):
        assert watch_dashboard.plain_text("ran mcp__github__merge_pull_request") == \
            "ran mcp__github__merge_pull_request"

    def test_empty_and_none(self):
        assert watch_dashboard.plain_text("") == ""
        assert watch_dashboard.plain_text(None) == ""

    def test_thread_turns_and_titles_are_flattened(self, tmp_path):
        _write_transcript(tmp_path, "-p", "mdthread1.jsonl", [
            {"cwd": "/x", "message": {"role": "user",
                                       "content": "## Fix the **checkout**"}},
            {"message": {"role": "assistant",
                         "content": [{"type": "text",
                                      "text": "Done:\n- [PR #9](https://x/9)\n- tests green"}]}},
        ])
        turns = watch_dashboard.session_thread("mdthread1", projects_dir=str(tmp_path))
        assert turns[0]["text"] == "Fix the checkout"
        assert turns[1]["text"] == "Done:\n• PR #9\n• tests green"
        _, opening, _ = watch_dashboard.session_meta(
            str(tmp_path / "-p" / "mdthread1.jsonl"))
        assert opening == "Fix the checkout"


class TestTheMoreListIsWhatThisMachineCanAnswer:
    """The watch's More list used to be a fixed set typed into the app,
    which is how /verify and /debug sat there for weeks answering
    "Unknown command". The relay now lists what the machine actually
    has — user, project and plugin skills and commands — described in
    each file's own words, plus the two read-only built-ins."""

    def _machine(self, tmp_path):
        home = tmp_path / "home"
        (home / ".claude" / "skills" / "debug").mkdir(parents=True)
        (home / ".claude" / "skills" / "debug" / "SKILL.md").write_text(
            "---\nname: debug\ndescription: \"Digs into why the last thing failed.\"\n---\n# Debug\n")
        (home / ".claude" / "commands").mkdir()
        (home / ".claude" / "commands" / "standup.md").write_text("Write today's standup from the log.\n")
        plugin = tmp_path / "plugins" / "eng" / "skills" / "incident"
        plugin.mkdir(parents=True)
        (plugin / "SKILL.md").write_text("---\ndescription: Runs an incident.\n---\n")
        (home / ".claude" / "plugins").mkdir()
        (home / ".claude" / "plugins" / "installed_plugins.json").write_text(json.dumps(
            {"version": 2, "plugins": {"eng@x": [{"installPath": str(tmp_path / "plugins" / "eng")}]}}))
        project = tmp_path / "proj"
        (project / ".claude" / "skills" / "deploy").mkdir(parents=True)
        (project / ".claude" / "skills" / "deploy" / "SKILL.md").write_text("---\ndescription: Ships it.\n---\n")
        return str(home), str(project)

    def test_every_source_is_listed_in_its_own_words(self, tmp_path):
        home, project = self._machine(tmp_path)
        rows = {r["name"]: r for r in watch_relay.known_skills(project, home=home, now=1.0)}
        assert rows["/debug"] == {"name": "/debug", "description": "Digs into why the last thing failed.", "source": "user"}
        assert rows["/standup"]["description"] == "Write today's standup from the log."
        assert rows["/incident"]["source"] == "plugin"
        assert rows["/deploy"]["source"] == "project"
        assert rows["/code-review"]["source"] == "builtin" and rows["/security-review"]["source"] == "builtin"
        assert "/verify" not in rows                        # never existed; never listed

    def test_a_project_without_its_own_skills_still_gets_the_users(self, tmp_path):
        home, _ = self._machine(tmp_path)
        names = [r["name"] for r in watch_relay.known_skills(str(tmp_path / "elsewhere"), home=home, now=2.0)]
        assert "/debug" in names and "/deploy" not in names

    def test_the_route_answers_a_paired_watch_and_nobody_else(self, fresh_auth):
        server, _queue = watch_relay.serve(port=0, auth=_known_watch(fresh_auth))
        _serve(server)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            status, body = relay_call(base + "/skills", token="devicetoken")
            assert status == 200
            assert any(r["name"] == "/code-review" for r in body["skills"])
            assert all(r["name"].startswith("/") and "description" in r for r in body["skills"])
        finally:
            server.shutdown()
            server.server_close()


class TestSlashCommandsReachTheWrist:
    """A slash command sent from the watch is answered by the CLI itself,
    not by Claude: /recap runs zero model turns and writes its output as
    a system line. The phone paints that red with a warning triangle;
    the watch dropped it with every other "<"-prefixed line, so Recap
    looked like it did nothing. Measured 2026-09-08 on Claude Code 2.1.260."""

    def test_a_local_command_shows_its_echo_and_its_output(self, tmp_path):
        _write_transcript(tmp_path, "-p", "recap1.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "Fix the checkout"}},
            {"message": {"role": "user", "content": "<command-name>/recap</command-name>"
                                                   "<command-message>recap</command-message>"
                                                   "<command-args></command-args>"}},
            {"type": "system", "subtype": "local_command", "level": "info",
             "content": "<local-command-stdout>Goal: fix checkout. Now: the race. Next: wait for the job.</local-command-stdout>"},
        ])
        turns = watch_dashboard.session_thread("recap1", projects_dir=str(tmp_path))
        kinds = [(t["role"], t.get("kind"), t["text"]) for t in turns]
        assert ("user", "text", "/recap") in kinds
        assert ("system", "notice", "Goal: fix checkout. Now: the race. Next: wait for the job.") in kinds

    def test_a_recap_arrives_whole_with_its_lines(self, tmp_path):
        """The fixture above is 58 characters, which is why nobody saw
        that a real /recap — several paragraphs — was flattened to one
        line and cut at 200 with no marker before it left the Mac. On the
        wrist, the tap that opens a collapsed bubble then revealed the
        same 200 characters, so it read as the command's own answer."""
        recap = ("Goal: get Tapproval onto the App Store.\n"
                 "\n"
                 "Today: build 117 went to every TestFlight group, the purchase "
                 "error wording was fixed, and Apple's rejection under 2.1(b) was "
                 "traced to the Paid Apps Agreement rather than the code.\n"
                 "\n"
                 "Next: confirm the agreement is active, rename the rejected "
                 "version to 1.1, attach a build that carries the fix, buy the "
                 "unlock once in sandbox on a real wrist, and resubmit.\n"
                 "\n"
                 "Blocked: nothing store-side until the agreement shows active.")
        assert len(recap) > 200, "the case the old cap would have cut"
        _write_transcript(tmp_path, "-p", "recap3.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "status?"}},
            {"message": {"role": "user", "content": "<command-name>/recap</command-name>"
                                                   "<command-message>recap</command-message>"
                                                   "<command-args></command-args>"}},
            {"type": "system", "subtype": "local_command", "level": "info",
             "content": "<local-command-stdout>%s</local-command-stdout>" % recap},
        ])
        turns = watch_dashboard.session_thread("recap3", projects_dir=str(tmp_path))
        notice = [t["text"] for t in turns if t.get("kind") == "notice"][0]
        assert notice.endswith("until the agreement shows active."), (
            "cut short: %r" % notice[-60:])
        assert "…" not in notice, "nothing this size should be marked as cut"
        assert notice.count("\n") >= 3, (
            "a recap has paragraphs; flattening them to one line is its own "
            "kind of truncation: %r" % notice[:120])

    def test_only_something_enormous_is_cut_and_it_says_so(self):
        huge = {"type": "system", "subtype": "local_command",
                "content": "<local-command-stdout>%s</local-command-stdout>"
                           % ("word " * 5000)}
        said = watch_dashboard._system_text(huge)
        assert len(said) <= 12002 and said.endswith(" …"), (len(said), said[-10:])

    def test_an_unknown_command_is_a_notice_not_silence(self, tmp_path):
        _write_transcript(tmp_path, "-p", "recap2.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "hello"}},
            {"message": {"role": "user", "content": "<command-name>/verify</command-name><command-args></command-args>"}},
            {"type": "system", "subtype": "local_command", "level": "info",
             "content": "<local-command-stderr>Unknown command: /verify</local-command-stderr>"},
        ])
        turns = watch_dashboard.session_thread("recap2", projects_dir=str(tmp_path))
        assert [t["text"] for t in turns if t.get("kind") == "notice"] == ["Unknown command: /verify"]

    def test_a_system_error_is_a_notice_and_info_chatter_is_not(self, tmp_path):
        _write_transcript(tmp_path, "-p", "recap3.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "hello"}},
            {"type": "system", "level": "info", "content": "Context left until auto-compact: 12%"},
            {"type": "system", "level": "error", "content": "API rate limit reached"},
        ])
        turns = watch_dashboard.session_thread("recap3", projects_dir=str(tmp_path))
        assert [t["text"] for t in turns if t.get("kind") == "notice"] == ["API rate limit reached"]

    def test_claudes_nothing_to_add_after_a_local_command_is_not_a_reply(self, tmp_path):
        """Measured on a live session, 2026-09-08: the wrist's /recap was
        answered by the CLI, then Claude's turn said "No response
        requested." — which the watch showed as a reply bubble under a
        recap that had already arrived. Not a turn."""
        _write_transcript(tmp_path, "-p", "recap4.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "hello"}},
            {"message": {"role": "user", "content": "<command-name>/recap</command-name>"}},
            {"type": "system", "subtype": "local_command", "level": "info",
             "content": "<local-command-stdout>Goal: ship. Next: merge.</local-command-stdout>"},
            {"message": {"role": "assistant", "content": [{"type": "text", "text": "No response requested."}]}},
            {"message": {"role": "assistant", "content": [{"type": "text", "text": "A real reply."}]}},
        ])
        turns = watch_dashboard.session_thread("recap4", projects_dir=str(tmp_path))
        texts = [t["text"] for t in turns if t["role"] == "assistant"]
        assert texts == ["A real reply."]

    def test_the_args_ride_with_the_command(self):
        assert watch_dashboard._command_sent(
            "<command-name>/loop</command-name><command-args>5m /x</command-args>") == "/loop 5m /x"
        assert watch_dashboard._command_sent("plain words") is None


class TestFenceNesting:
    """Four-backtick fences exist to contain ``` lines — an inner fence
    must not flip the state (the motivating case for the {3,} widening)."""

    def test_inner_fence_stays_inside_the_outer(self):
        text = "before\n````markdown\ninner prose\n```\nstill inside\n````\nafter"
        flat = watch_dashboard.plain_text(text)
        # prose fences still flatten their content; the inner ``` does not
        # close the outer four-tick block
        assert "still inside" in flat
        assert "after" in flat

    def test_code_blocks_become_one_marker(self):
        """A code block is a box on the phone; on the wrist it is one
        [code] marker — never verbatim soup, never more than one marker
        per block."""
        text = "before\n````\ncode line\n```\nmore code\n````\ntail"
        flat = watch_dashboard.plain_text(text)
        assert "more code" not in flat
        assert flat.count("[code]") == 1
        assert "tail" in flat


@pytest.fixture
def live_relay():
    """One live relay on a random loopback port, watch already present.

    Shared by every hook-through-relay test so the env handling and the
    server teardown cannot drift apart between copies."""
    queue = watch_relay.CardQueue()
    server, _ = watch_relay.serve("127.0.0.1", 0, queue=queue)
    _serve(server)
    queue.pending(from_watch=True)
    yield server.server_address[1], queue
    server.shutdown()
    server.server_close()


class TestQuestionCards:
    """AskUserQuestion renders as the question with the phone's exact
    option labels — and a wrist answer travels back as the one hook
    channel that can carry words: a deny whose reason is the answer."""

    EVENT_INPUT = {"questions": [{
        "question": "Lige/ulige uger findes allerede — hvordan udvides?",
        "header": "Uger",
        "options": [
            {"label": "Samme knap på alle rækker", "description": "x"},
            {"label": "Del hele ugen i to", "description": "y"},
            {"label": "Kun \"skifter hver anden uge\"", "description": "z"},
        ],
        "multiSelect": False,
    }]}

    def test_card_carries_question_and_exact_labels(self):
        card = crc.wrist_card("AskUserQuestion", self.EVENT_INPUT,
                              Risk.MEDIUM, 64, 80)
        assert card["kind"] == "question"
        assert card["headline"].startswith("Lige/ulige uger findes allerede")
        assert card["options"] == [
            "Samme knap på alle rækker",
            "Del hele ugen i to",
            'Kun "skifter hver anden uge"',
        ]

    def test_malformed_questions_fail_soft(self):
        card = crc.wrist_card("AskUserQuestion", {"questions": "junk"},
                              Risk.MEDIUM, 64, 80)
        assert card["headline"] == "Claude has a question"
        assert "options" not in card

    def test_answer_travels_back_as_the_deny_reason(self, live_relay,
                                                    tmp_path, monkeypatch):
        import io
        import time as _time
        port, queue = live_relay

        def answer_first_card():
            for _ in range(60):
                cards = queue.pending()
                if cards:
                    queue.decide(cards[0]["id"], "answer",
                                 answer="Del hele ugen i to")
                    return
                _time.sleep(0.05)

        threading.Thread(target=answer_first_card, daemon=True).start()
        monkeypatch.setenv("CLAUDE_RISK_MODE", "enforce")
        monkeypatch.setenv("CLAUDE_RISK_RELAY", "http://127.0.0.1:%d" % port)
        monkeypatch.setenv("CLAUDE_RISK_RELAY_WAIT", "10")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH",
                           str(tmp_path / "user-settings.json"))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)
        monkeypatch.delenv("CLAUDE_RISK_AUTO_ALLOW", raising=False)
        out = io.StringIO()
        crc.run_hook(stdin=io.StringIO(json.dumps(
            {"tool_name": "AskUserQuestion",
             "tool_input": self.EVENT_INPUT})), stdout=out)
        result = json.loads(out.getvalue())["hookSpecificOutput"]
        assert _behavior(result) == "deny"
        assert "Del hele ugen i to" in _decision_message(result)
        assert "answered from their watch" in _decision_message(result)


class TestPhoneVocabulary:
    """The watch thread speaks the phone app's language: tool bursts
    become one phrase, and running background tasks are counted."""

    def test_consecutive_tools_become_one_phrase(self, tmp_path):
        lines = [{"cwd": "/x", "message": {"role": "user", "content": "go"}}]
        for name in ("Bash", "Bash", "Edit", "Grep"):
            lines.append({"message": {"role": "assistant",
                          "content": [{"type": "tool_use", "name": name}]}})
        lines.append({"message": {"role": "assistant",
                      "content": [{"type": "text", "text": "done"}]}})
        _write_transcript(tmp_path, "-p", "phrase01.jsonl", lines)
        turns = watch_dashboard.session_thread("phrase01",
                                           projects_dir=str(tmp_path))
        tool_turns = [t for t in turns if t["kind"] == "tool"]
        assert len(tool_turns) == 1
        assert tool_turns[0]["text"] == (
            "Ran 2 commands, edited a file, searched the code")

    def test_a_receipted_task_stops_counting(self, tmp_path, monkeypatch):
        """Launches minus receipts is the candidate set — and every
        candidate still has to be found on disk before it counts.

        This test used to assert the opposite, and its own fixture proved
        why that was wrong: the fake id it invented travelled through a real
        conversation, was read as a launch there, and reported a running
        task on the wrist for the rest of the day while the phone showed
        none. A task nobody can find is not a task.
        """
        import watch_dashboard
        lines = [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "user", "content":
             "Command running in background with ID: abc123."}},
            {"message": {"role": "user", "content":
             "Command running in background with ID: stillgoing1."}},
            {"message": {"role": "user", "content":
             "<task-notification><task-id>abc123</task-id>done"}},
        ]
        _write_transcript(tmp_path, "-p", "tasks01.jsonl", lines)
        path = watch_relay._find_transcript("tasks01",
                                            projects_dir=str(tmp_path))
        # Give the unreceipted one an output file, the way a real task has.
        session = os.path.splitext(os.path.basename(path))[0]
        tasks = tmp_path / "tmp" / "claude-1" / "proj" / session / "tasks"
        tasks.mkdir(parents=True)
        (tasks / "stillgoing1.output").write_text("working\n", encoding="utf-8")
        monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
        watch_dashboard._THREAD_STATE.pop(path, None)
        _, running, _ = watch_relay._parse_thread(path, 14)
        assert running == 1     # abc123 receipted; stillgoing1 found on disk


class TestEveryPress:
    """Every press the watch can make, mock-verified end to end through
    the hook: allow, deny, an option answer, and the phone's third
    button — always for this session, which must auto-answer the next
    identical ask without touching the wrist."""

    def _hook(self, port, tmp_path, command="rm -r build",
              description=None):
        import io
        import os as _os
        env_backup = dict(_os.environ)
        _os.environ.update({
            "CLAUDE_RISK_MODE": "enforce",
            "CLAUDE_RISK_RELAY": "http://127.0.0.1:%d" % port,
            "CLAUDE_RISK_RELAY_WAIT": "10",
            "CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl"),
            "CLAUDE_SETTINGS_PATH": str(tmp_path / "user-settings.json"),
        })
        _os.environ.pop("CLAUDE_RISK_CONFIG", None)
        _os.environ.pop("CLAUDE_RISK_AUTO_ALLOW", None)
        try:
            out = io.StringIO()
            tool_input = {"command": command}
            if description:
                tool_input["description"] = description
            # Real prompts that offer "don't ask again" carry permission
            # suggestions — the always-flow tests need the offer to exist.
            crc.run_hook(stdin=io.StringIO(json.dumps(
                {"tool_name": "Bash", "session_id": "sess-1",
                 "tool_input": tool_input,
                 "permission_suggestions": [
                     {"type": "rule", "rule": "Bash(%s)" % command}]})),
                stdout=out)
            return json.loads(out.getvalue())["hookSpecificOutput"]
        finally:
            _os.environ.clear()
            _os.environ.update(env_backup)

    def _press(self, queue, decision, answer=None):
        import time as _time

        def worker():
            for _ in range(100):
                cards = queue.pending(from_watch=True)
                if cards:
                    queue.decide(cards[0]["id"], decision, answer=answer)
                    return
                _time.sleep(0.05)

        threading.Thread(target=worker, daemon=True).start()

    def test_allow_press(self, live_relay, tmp_path):
        port, queue = live_relay
        self._press(queue, "allow")
        result = self._hook(port, tmp_path)
        assert _behavior(result) == "allow"
        assert result["decision"] == {"behavior": "allow"}

    def test_deny_press(self, live_relay, tmp_path):
        port, queue = live_relay
        self._press(queue, "deny")
        result = self._hook(port, tmp_path)
        assert _behavior(result) == "deny"
        assert "watch" in _decision_message(result).lower()

    def test_always_press_then_silence(self, live_relay, tmp_path):
        port, queue = live_relay
        self._press(queue, "always")
        first = self._hook(port, tmp_path)
        assert _behavior(first) == "allow"
        # The identical ask again: NO press this time — the relay must
        # answer instantly from the session grant, no card queued.
        second = self._hook(port, tmp_path)
        assert _behavior(second) == "allow"
        assert queue.pending() == []

    def test_always_does_not_leak_across_commands(self, live_relay, tmp_path):
        port, queue = live_relay
        self._press(queue, "always")
        assert _behavior(self._hook(port, tmp_path)) == "allow"
        # A DIFFERENT command from the same session must still ask.
        result = self._hook(port, tmp_path, command="git push --force origin main")
        assert _behavior(result) == "escalate"

    def test_always_keys_on_the_command_not_the_headline(self, live_relay,
                                                         tmp_path):
        """Claude authors the description, and two different commands can
        share one. The grant must replay only for the identical command."""
        port, queue = live_relay
        self._press(queue, "always")
        first = self._hook(port, tmp_path, command="rm -r build",
                           description="Clean build artifacts")
        assert _behavior(first) == "allow"
        # Same headline, different command: a human must see it.
        self._press(queue, "deny")
        second = self._hook(port, tmp_path, command="rm -r src",
                            description="Clean build artifacts")
        assert _behavior(second) == "deny"

    def test_critical_is_never_replayed(self, live_relay, tmp_path):
        """The human tap may land on any tier — its echo may not.
        CLAUDE.md: CRITICAL must never be auto-allowed."""
        port, queue = live_relay
        command = "git push --force origin main && rm -rf / --no-preserve-root"
        self._press(queue, "always")
        first = self._hook(port, tmp_path, command=command)
        assert _behavior(first) == "allow"      # the tap itself is human
        # The identical CRITICAL ask again: no silent replay allowed.
        self._press(queue, "deny")
        second = self._hook(port, tmp_path, command=command)
        assert _behavior(second) == "deny"


class TestRunningToolChip:
    """The phone's grey "Running" chip, derived honestly: a tool_use with
    no tool_result after it is the command running right now."""

    def test_unfinished_tool_is_running(self, tmp_path):
        lines = [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": "sleep 99",
                           "description": "Long build step"}}]}},
        ]
        _write_transcript(tmp_path, "-p", "runtool1.jsonl", lines)
        path = watch_relay._find_transcript("runtool1",
                                            projects_dir=str(tmp_path))
        _, _, running_tool = watch_relay._parse_thread(path, 14)
        assert running_tool == "Long build step"

    def test_finished_tool_is_not(self, tmp_path):
        lines = [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash",
                 "input": {"description": "Quick check"}}]}},
            {"message": {"role": "user", "content": [
                {"type": "tool_result", "content": "ok"}]}},
        ]
        _write_transcript(tmp_path, "-p", "runtool2.jsonl", lines)
        path = watch_relay._find_transcript("runtool2",
                                            projects_dir=str(tmp_path))
        _, _, running_tool = watch_relay._parse_thread(path, 14)
        assert running_tool is None


class TestPromptParity:
    """The phone is the reference: the wrist cards exactly what the phone
    prompts on — never the classes Claude Code answers silently."""

    def _hook(self, port, tmp_path, command, cwd=None):
        import io
        import os as _os
        backup = dict(_os.environ)
        _os.environ.update({
            "CLAUDE_RISK_MODE": "enforce",
            "CLAUDE_RISK_RELAY": "http://127.0.0.1:%d" % port,
            "CLAUDE_RISK_RELAY_WAIT": "5",
            "CLAUDE_RISK_AUDIT_LOG": str(tmp_path / "a.jsonl"),
            "CLAUDE_SETTINGS_PATH": str(tmp_path / "user-settings.json"),
        })
        _os.environ.pop("CLAUDE_RISK_CONFIG", None)
        _os.environ.pop("CLAUDE_RISK_AUTO_ALLOW", None)
        try:
            out = io.StringIO()
            event = {"tool_name": "Bash", "tool_input": {"command": command}}
            if cwd:
                event["cwd"] = cwd
            crc.run_hook(stdin=io.StringIO(json.dumps(event)), stdout=out)
            return json.loads(out.getvalue())["hookSpecificOutput"]
        finally:
            _os.environ.clear()
            _os.environ.update(backup)

    def test_read_only_never_reaches_the_wrist(self, live_relay, tmp_path):
        """gh pr view shows no phone prompt — so no card, instantly."""
        import time as _time
        port, queue = live_relay
        started = _time.monotonic()
        result = self._hook(port, tmp_path, "gh pr view 12")
        assert _behavior(result) == "escalate"
        assert _time.monotonic() - started < 2, "must not wait on the relay"
        assert queue.pending() == []

    def test_the_users_own_allow_rule_is_honored(self, live_relay, tmp_path):
        import time as _time
        port, queue = live_relay
        project = tmp_path / "proj" / ".claude"
        project.mkdir(parents=True)
        (project / "settings.json").write_text(json.dumps(
            {"permissions": {"allow": ["Bash(npm run build *)"]}}))
        started = _time.monotonic()
        result = self._hook(port, tmp_path, "npm run build --prod",
                            cwd=str(tmp_path / "proj"))
        assert _behavior(result) == "escalate"
        assert _time.monotonic() - started < 2
        assert queue.pending() == []

    def test_a_real_prompt_still_cards(self, live_relay, tmp_path):
        import time as _time
        port, queue = live_relay
        seen = {}

        def watcher():
            for _ in range(100):
                cards = queue.pending(from_watch=True)
                if cards:
                    seen["card"] = cards[0]["headline"]
                    queue.decide(cards[0]["id"], "allow")
                    return
                _time.sleep(0.05)

        threading.Thread(target=watcher, daemon=True).start()
        result = self._hook(port, tmp_path, "rm -rf build")
        assert _behavior(result) == "allow"
        assert "card" in seen

    @pytest.mark.parametrize("pattern,command,hit", [
        ("Bash(git log *)", "git log --oneline", True),
        ("Bash(git log *)", "git log", True),
        ("Bash(git log *)", "git logs-evil", False),
        ("Bash(npm test)", "npm test", True),
        ("Bash(npm test)", "npm test --force", False),
        ("Bash(gh pr*)", "gh prune", True),
        ("WebFetch", "", True),
        # The colon form is what Claude Code's own /permissions UI writes.
        ("Bash(git commit:*)", "git commit -m x", True),
        ("Bash(git commit:*)", "git commit", True),
        ("Bash(npm run test:*)", "npm run test:unit", True),
        ("Bash(git commit:*)", "git commitx", False),
    ])
    def test_pattern_forms(self, pattern, command, hit, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH",
                           str(tmp_path / "s.json"))
        (tmp_path / "s.json").write_text(json.dumps(
            {"permissions": {"allow": [pattern]}}))
        tool = "WebFetch" if pattern == "WebFetch" else "Bash"
        assert crc.matches_user_allowlist(
            tool, {"command": command}) is hit

    @pytest.mark.parametrize("kind", ["deny", "ask"])
    def test_deny_and_ask_veto_the_allowlist(self, kind, tmp_path,
                                             monkeypatch):
        """Claude Code's precedence: a deny or ask rule beats allow, so
        the phone WOULD prompt (or block) — parity must not skip it."""
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        (tmp_path / "s.json").write_text(json.dumps(
            {"permissions": {"allow": ["Bash(git push *)"],
                             kind: ["Bash(git push --force *)"]}}))
        assert crc.matches_user_allowlist(
            "Bash", {"command": "git push origin main"}) is True
        assert crc.matches_user_allowlist(
            "Bash", {"command": "git push --force origin main"}) is False

    def test_a_list_shaped_settings_file_fails_soft(self, tmp_path,
                                                    monkeypatch):
        """A settings file whose top level is not an object must be
        skipped, never knock the hook into the fallback path."""
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        (tmp_path / "s.json").write_text('["not", "an", "object"]')
        assert crc.matches_user_allowlist(
            "Bash", {"command": "ls"}) is False


class TestCloudHeartbeat:
    """An away watch is seen through the cloud: the bridge reads its
    CloudKit heartbeat and reports the age to /heartbeat, which must count
    as presence — otherwise /health tells the wrist nobody has been seen
    while the watch is answering over iCloud. (Cards queue regardless.)"""

    def test_fresh_heartbeat_counts_as_presence(self, live_relay):
        port, queue = live_relay
        queue.last_poll = None      # no direct watch poll ever
        assert not _watch_present(queue)
        request = urllib.request.Request(
            "http://127.0.0.1:%d/heartbeat" % port,
            data=json.dumps({"watch_seen_seconds_ago": 12}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as reply:
            assert _json.loads(reply.read())["ok"] is True
        assert _watch_present(queue)

    def test_stale_heartbeat_is_ignored(self):
        queue = watch_relay.CardQueue()
        queue.note_watch_indirect(watch_relay.CardQueue.WATCH_PRESENT_SECONDS + 5)
        assert not _watch_present(queue)

    def test_garbage_never_crashes_or_counts(self):
        queue = watch_relay.CardQueue()
        for junk in (None, "soon", -3, {"a": 1}):
            queue.note_watch_indirect(junk)
        assert not _watch_present(queue)

    def test_indirect_never_rewinds_a_direct_poll(self):
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)          # direct poll: now
        direct = queue.last_poll
        queue.note_watch_indirect(60)           # older cloud sighting
        assert queue.last_poll == direct


class TestOnlyActiveSessionsAreListed:
    """The wrist mirrors the phone's session list: sessions with a live
    Claude process — never a graveyard of every transcript on disk."""

    def test_dead_transcripts_are_not_listed(self, tmp_path, monkeypatch):
        import watch_dashboard
        _write_transcript(tmp_path, "-p", "livesess1.jsonl",
                          [{"cwd": "/x/a",
                            "message": {"role": "user", "content": "go"}}])
        _write_transcript(tmp_path, "-p", "deadsess1.jsonl",
                          [{"cwd": "/x/b",
                            "message": {"role": "user", "content": "old"}}])
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"livesess1": "VS Code"})
        sessions = watch_relay.recent_sessions(projects_dir=str(tmp_path))
        assert [s["session_id"] for s in sessions] == ["livesess1"]
        assert sessions[0]["live"] is True


class TestCompoundCommandParity:
    """The bug that reached the wrist as silence: `Bash(grep *)`
    prefix-matched a whole `grep … && sed "$(grep …)"` compound, so the
    wrist skipped a prompt the phone showed. Claude Code judges every
    segment on its own, and command substitution always prompts."""

    def _allow(self, tmp_path, monkeypatch, patterns):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        (tmp_path / "s.json").write_text(json.dumps(
            {"permissions": {"allow": patterns}}))

    def test_the_exact_command_that_slipped(self, tmp_path, monkeypatch):
        self._allow(tmp_path, monkeypatch, ["Bash(grep *)", "Bash(sed *)"])
        command = ('grep -n "def recent_sessions" watch_relay.py && '
                   'sed -n "$(grep -n \'def recent_sessions\' '
                   'watch_relay.py | cut -d: -f1),+55p" watch_relay.py')
        assert crc.matches_user_allowlist(
            "Bash", {"command": command}) is False   # $() always prompts

    def test_every_segment_needs_its_own_rule(self, tmp_path, monkeypatch):
        self._allow(tmp_path, monkeypatch, ["Bash(grep *)"])
        assert crc.matches_user_allowlist(
            "Bash", {"command": "grep -n foo x.py && rm -rf build"}) is False

    def test_fully_covered_compound_still_skips(self, tmp_path, monkeypatch):
        self._allow(tmp_path, monkeypatch, ["Bash(grep *)", "Bash(ls *)"])
        assert crc.matches_user_allowlist(
            "Bash", {"command": "grep -n foo x.py && ls -la"}) is True

    def test_a_deny_on_one_segment_vetoes_the_whole(self, tmp_path,
                                                    monkeypatch):
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "s.json"))
        (tmp_path / "s.json").write_text(json.dumps({"permissions": {
            "allow": ["Bash(git *)"],
            "deny": ["Bash(git push --force *)"]}}))
        assert crc.matches_user_allowlist(
            "Bash", {"command":
                     "git status && git push --force origin main"}) is False


class TestPhoneSilenceMirror:
    """Parity may only skip what Claude Code ITSELF answers silently. Our
    recognition tables are broader (pytest, brew, xcodebuild -list are SAFE
    to us) — those DO prompt on the phone and must card the wrist."""

    @pytest.mark.parametrize("command,silent", [
        ("git status", True),
        ("gh pr view 12", True),
        ("docker ps -a", True),
        ("grep -n foo bar.py", True),
        ("pytest", False),
        ("brew list", False),
        ("xcodebuild -list", False),
        ("kubectl get pods", False),
        ("git status && pytest", False),   # every segment must qualify
    ])
    def test_lead_command_mirror(self, command, silent):
        assert crc.phone_would_auto_allow(
            "Bash", {"command": command}) is silent

    def test_non_bash_read_tools_are_silent(self):
        assert crc.phone_would_auto_allow("Read", {"file_path": "/x"}) is True

    def test_safe_but_phone_prompting_still_cards(self, live_relay,
                                                  tmp_path, monkeypatch):
        """pytest is SAFE in our tables but prompts on the phone — the
        wrist must card it, not skip it as parity."""
        import io
        import time as _time
        port, queue = live_relay

        def press():
            for _ in range(100):
                cards = queue.pending(from_watch=True)
                if cards:
                    queue.decide(cards[0]["id"], "allow")
                    return
                _time.sleep(0.05)

        threading.Thread(target=press, daemon=True).start()
        monkeypatch.setenv("CLAUDE_RISK_MODE", "enforce")
        monkeypatch.setenv("CLAUDE_RISK_RELAY", "http://127.0.0.1:%d" % port)
        monkeypatch.setenv("CLAUDE_RISK_RELAY_WAIT", "10")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH",
                           str(tmp_path / "settings.json"))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)
        monkeypatch.delenv("CLAUDE_RISK_AUTO_ALLOW", raising=False)
        out = io.StringIO()
        crc.run_hook(stdin=io.StringIO(json.dumps(
            {"tool_name": "Bash", "tool_input": {"command": "pytest"}})),
            stdout=out)
        result = json.loads(out.getvalue())["hookSpecificOutput"]
        # An allow is the bare checked shape; the reason is audited,
        # not sent — anything extra risks failing validation again.
        assert result["decision"] == {"behavior": "allow"}


class TestQuestionCardTier:
    def test_question_cards_carry_their_tier(self):
        card = crc.wrist_card("AskUserQuestion",
                              {"questions": [{"question": "x?"}]},
                              Risk.MEDIUM, 64, 80)
        assert card["tier"] == "MEDIUM"


class TestFingerprintPerTool:
    def test_bashoutput_inputs_do_not_share_one_fingerprint(self):
        a = crc._card_fingerprint("BashOutput", {"bash_id": "task-a"})
        b = crc._card_fingerprint("BashOutput", {"bash_id": "task-b"})
        assert a != b

    def test_unknown_tool_detail_names_the_target(self):
        card = crc.wrist_card("mcp__github__delete_repo",
                              {"owner": "x", "repo": "critical-prod"},
                              Risk.HIGH, 64, 80)
        assert "critical-prod" in card["detail"]


class TestEmptyAnswerRefused:
    def test_answer_with_no_words_is_refused(self):
        import time as _time
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        result = {}

        def submit():
            _, result["decision"], _ = queue.submit(
                {"tier": "MEDIUM", "headline": "q", "detail": "q"}, wait=5)

        threading.Thread(target=submit, daemon=True).start()
        for _ in range(200):
            if queue.pending():
                break
            _time.sleep(0.01)
        live = queue.pending()[0]["id"]
        assert queue.decide(live, "answer") is False          # no words
        assert queue.decide(live, "answer", answer="Ja") is True


class TestAnsweredQuestionsCount:
    def test_watch_answer_counts_in_activity(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        log.write_text(json.dumps({
            "ts": "2099-01-01T10:00:00+00:00", "tier": "MEDIUM",
            "decision": "escalate", "watch": "answer",
            "answer": "Ja, uret virker", "headline": "Virker uret?",
        }) + "\n")
        stats = watch_relay.activity_summary(
            audit_log=str(log),
            now=__import__("datetime").datetime(
                2099, 1, 1, 12, tzinfo=__import__("datetime").timezone.utc
            ).timestamp())
        assert stats["answered_on_watch"] == 1


class TestResolvedElsewhere:
    """A prompt answered on the phone or terminal must leave the wrist:
    Claude Code does not reliably kill the hook, so the relay watches the
    session transcript for the tool_result of the very call the card asks
    about."""

    def _card_and_transcript(self, tmp_path, command="rm -r build"):
        fingerprint = crc._card_fingerprint("Bash", {"command": command})
        lines = [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_e2e_1", "name": "Bash",
                 "input": {"command": command}}]}},
        ]
        path = _write_transcript(tmp_path, "-p", "resolvedsess01.jsonl", lines)
        card = {"tier": "HIGH", "headline": "x", "detail": command,
                "tool": "Bash", "session_id": "resolvedsess01",
                "fingerprint": fingerprint}
        return card, path

    def test_a_phone_answer_retracts_the_card(self, tmp_path):
        import time as _time
        card, path = self._card_and_transcript(tmp_path)
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        result = {}

        def submit():
            started = _time.monotonic()
            _, result["decision"], _ = queue.submit(
                card, wait=30,
                resolved_elsewhere=watch_relay._prompt_resolver(
                    card, projects_dir=str(tmp_path)))
            result["elapsed"] = _time.monotonic() - started

        thread = threading.Thread(target=submit, daemon=True)
        thread.start()
        _time.sleep(0.5)
        assert queue.pending(), "card should be up before the phone answers"
        # The phone answers: the session writes the tool_result.
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_e2e_1",
                 "content": "ok"}]}}) + "\n")
        thread.join(timeout=15)
        assert result["decision"] == "none"
        assert result["elapsed"] < 12          # retracted, not expired
        assert queue.pending() == []

    def test_unrelated_results_do_not_retract(self, tmp_path):
        import time as _time
        card, path = self._card_and_transcript(tmp_path)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"message": {"role": "assistant",
                "content": [{"type": "tool_use", "id": "toolu_other",
                             "name": "Bash",
                             "input": {"command": "ls"}}]}}) + "\n")
            handle.write(json.dumps({"message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_other",
                 "content": "ok"}]}}) + "\n")
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        started = _time.monotonic()
        _, decision, _ = queue.submit(
            card, wait=1.5,
            resolved_elsewhere=watch_relay._prompt_resolver(
                card, projects_dir=str(tmp_path)))
        assert decision == "none"
        assert _time.monotonic() - started >= 1.4   # ran to expiry

    def test_a_rewritten_transcript_never_matches_history(self, tmp_path):
        """Compaction rewrites the file smaller. The resolver must go
        dormant past the rewrite — matching an EARLIER identical command's
        old result would retract a live card nobody answered."""
        card, path = self._card_and_transcript(tmp_path)
        resolver = watch_relay._prompt_resolver(
            card, projects_dir=str(tmp_path))
        assert resolver() is False                    # tracks the tail
        # The rewrite: smaller file whose HISTORY holds the same command,
        # already run and answered once before.
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"message": {
                "role": "assistant", "content": [
                    {"type": "tool_use", "id": "toolu_old", "name": "Bash",
                     "input": {"command": "rm -r build"}}]}}) + "\n")
            handle.write(json.dumps({"message": {
                "role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_old",
                     "content": "ok"}]}}) + "\n")
        assert resolver() is False                    # dormant, not fooled
        # A fresh result APPENDED after the rewrite must not match either:
        # its tool_use was consumed by the dormant skip.
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"message": {
                "role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_old",
                     "content": "ok"}]}}) + "\n")
        assert resolver() is False


class TestTaskVerdictsCanRecover:
    """Only an exit marker is forever: a task whose output file was
    momentarily unreadable or long-quiet must be able to count as running
    again — and an exit marker beats a stale mtime."""

    def test_exit_marker_wins_even_when_stale(self, tmp_path, monkeypatch):
        tasks = tmp_path / "claude-1" / "x" / "sess" / "tasks"
        tasks.mkdir(parents=True)
        out = tasks / "tid1.output"
        out.write_text("...\n[exited with code 0]\n")
        os.utime(out, (1, 1))                       # ancient mtime
        import glob as _glob
        monkeypatch.setattr(_glob, "glob",
                            lambda pattern: [str(out)])
        assert watch_dashboard._task_state("sess", "tid1") == "done"

    def test_stale_but_alive_is_unknown_not_done(self, tmp_path, monkeypatch):
        import glob as _glob
        out = tmp_path / "tid2.output"
        out.write_text("still working\n")
        os.utime(out, (1, 1))                       # quiet for years
        monkeypatch.setattr(_glob, "glob", lambda pattern: [str(out)])
        assert watch_dashboard._task_state("sess", "tid2") == "unknown"
        # The task wakes and writes again: the verdict must recover.
        out.write_text("still working\nmore output\n")
        assert watch_dashboard._task_state("sess", "tid2") == "running"


class TestAlwaysMirrorsThePhone:
    """The phone offers "don't ask again" exactly when Claude Code sends
    permission suggestions — the wrist must never offer (or honor) a
    third choice the phone doesn't have."""

    def test_suggestions_set_can_always(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "a.jsonl"))
        _, _, card = crc.build_response(
            {"tool_name": "Bash", "tool_input": {"command": "rm -r build"},
             "permission_suggestions": [{"type": "rule"}]}, policy)
        assert card["can_always"] is True

    def test_no_suggestions_no_always(self, tmp_path):
        policy = dict(crc.DEFAULT_POLICY, audit_log=str(tmp_path / "a.jsonl"))
        _, _, card = crc.build_response(
            {"tool_name": "Bash", "tool_input": {"command": "rm -r build"}},
            policy)
        assert card["can_always"] is False

    def test_relay_never_records_a_grant_the_phone_would_not_offer(self):
        import time as _time
        queue = watch_relay.CardQueue()
        queue.pending(from_watch=True)
        card = {"tier": "HIGH", "headline": "x", "detail": "x",
                "tool": "Bash", "session_id": "s1",
                "fingerprint": "abc123", "can_always": False}

        def press_always():
            for _ in range(100):
                cards = queue.pending()
                if cards:
                    queue.decide(cards[0]["id"], "always")
                    return
                _time.sleep(0.05)

        threading.Thread(target=press_always, daemon=True).start()
        _, decision, _ = queue.submit(dict(card), wait=10)
        assert decision == "allow"        # this once — a human tapped
        # The identical ask again must NOT be answered from a grant.
        started = _time.monotonic()
        _, decision2, _ = queue.submit(dict(card), wait=1.2)
        assert decision2 == "none"
        assert _time.monotonic() - started >= 1.0


class TestHostRebindingDefense:
    """A DNS-rebinding page reaches the loopback relay same-origin unless
    the Host header is validated: the browser puts the ATTACKER's domain
    in Host, which is neither a loopback name nor a bare local IP."""

    def test_loopback_and_local_ip_hosts_pass(self):
        for host in ("127.0.0.1:8977", "localhost:8977", "localhost",
                     "192.168.1.25:8977", "10.0.0.3:8977", "100.100.5.5:8977",
                     "[::1]:8977", "::1"):
            assert watch_relay.host_allowed(host), host

    def test_rebinding_and_foreign_hosts_are_rejected(self):
        for host in ("evil.com:8977", "evil.com", "",
                     "10.evil.com:8977", "127.0.0.1.evil.com",
                     "8.8.8.8:8977", "attacker.local:8977"):
            assert not watch_relay.host_allowed(host), host

    def test_main_listener_refuses_a_foreign_host_end_to_end(self):
        import http.client
        queue = watch_relay.CardQueue()
        server, _ = watch_relay.serve("127.0.0.1", 0, queue=queue)
        _serve(server)
        port = server.server_address[1]
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.putrequest("GET", "/pair", skip_host=True)
            conn.putheader("Host", "evil.com")
            conn.endheaders()
            assert conn.getresponse().status == 403
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            body = json.dumps({"id": "x", "decision": "allow"}).encode()
            conn.putrequest("POST", "/decision", skip_host=True)
            conn.putheader("Host", "evil.com")
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders()
            conn.send(body)
            assert conn.getresponse().status == 403
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/health")
            assert conn.getresponse().status == 200
            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_tunnel_listener_is_exempt(self):
        handler = type("H", (watch_relay.RelayHandler,),
                       {"required_token": "sekret"})
        inst = handler.__new__(handler)
        inst.headers = {"Host": "bird-engines.trycloudflare.com"}
        assert inst._host_ok() is True


class TestFullTextReachesTheWrist:
    """A 2KB cap once cut a real reply mid-sentence on the watch (the
    message was 2549 chars; the cut landed exactly at byte 2048). The
    wrist shows the full text, like the phone."""

    def test_a_long_reply_survives_intact(self, tmp_path):
        tail = "Hæver jeg den til fem minutter, sparer jeg trafikken. SLUT"
        long_text = ("A" * 2500) + " " + tail
        _write_transcript(tmp_path, "-p", "longmsg01.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "text", "text": long_text}]}},
        ])
        path = watch_relay._find_transcript("longmsg01",
                                            projects_dir=str(tmp_path))
        turns, _, _ = watch_relay._parse_thread(path, 14)
        assert turns[-1]["text"].endswith("SLUT")

    def test_the_truly_enormous_is_cut_at_a_word_and_says_so(self, tmp_path):
        enormous = ("ord " * 5000).strip()          # ~20000 chars
        _write_transcript(tmp_path, "-p", "longmsg02.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "text", "text": enormous}]}},
        ])
        path = watch_relay._find_transcript("longmsg02",
                                            projects_dir=str(tmp_path))
        turns, _, _ = watch_relay._parse_thread(path, 14)
        text = turns[-1]["text"]
        assert len(text) <= 12002
        assert text.endswith(" …")
        assert not text[:-2].endswith("or")   # cut at the word boundary


class TestSessionListCarriesTheRing:
    """The list must tell "working now" from "connected but quiet" — the
    activity fields _parse_thread computes for the detail screen ride in
    the sessions payload too, plus the last GitHub fact Claude mentioned."""

    def _session(self, tmp_path, monkeypatch, lines):
        import watch_dashboard
        _write_transcript(tmp_path, "-p", "ringsess01.jsonl", lines)
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"ringsess01": "VS Code"})
        return watch_relay.recent_sessions(projects_dir=str(tmp_path))[0]

    def test_activity_fields_ride_in_the_list(self, tmp_path, monkeypatch):
        session = self._session(tmp_path, monkeypatch, [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": "sleep 99",
                           "description": "Long build step"}}]}},
        ])
        assert session["running_tool"] == "Long build step"
        assert session["running_tasks"] == 0
        assert isinstance(session["active_seconds_ago"], int)
        assert session["active_seconds_ago"] < 60   # just written
        assert session["github"] is None

    def test_the_last_github_fact_rides_along(self, tmp_path, monkeypatch):
        session = self._session(tmp_path, monkeypatch, [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "text", "text": "Opened PR #142 for review."}]}},
            {"message": {"role": "assistant", "content": [
                {"type": "text", "text": "PR #88 merged — done."}]}},
        ])
        assert session["github"] == "PR #88 merged"

    def test_a_bare_pr_mention_is_not_an_event(self, tmp_path, monkeypatch):
        session = self._session(tmp_path, monkeypatch, [
            {"cwd": "/x", "message": {"role": "user", "content": "go"}},
            {"message": {"role": "assistant", "content": [
                {"type": "text",
                 "text": "Take a look at PR #14 when you have time."}]}},
        ])
        assert session["github"] is None

    def test_user_turns_never_produce_facts(self, tmp_path, monkeypatch):
        session = self._session(tmp_path, monkeypatch, [
            {"cwd": "/x", "message": {"role": "user",
                                      "content": "was PR #9 merged?"}},
        ])
        assert session["github"] is None


# ---------------------------------------------------------------------------
# The plugin path
#
# `/plugin install` registers the hooks from the plugin's own manifest and
# writes nothing to settings.json. Nothing here had ever opened a file under
# helper/, which is how the manifest once shipped a 3600-second wait while the
# installer wrote 86400 — the card really did expire after an hour, and the
# tests stayed green.

_ROOT = os.path.dirname(os.path.abspath(crc.__file__))
# helper/ in the product repo; the same files sit at the root of the public
# repo the sync script produces, and this suite runs there too.
HELPER_DIR = (os.path.join(_ROOT, "helper")
              if os.path.isdir(os.path.join(_ROOT, "helper")) else _ROOT)


def _helper_manifest(*parts):
    with open(os.path.join(HELPER_DIR, *parts), encoding="utf-8") as handle:
        return json.load(handle)


class TestTheSyncScriptSaysWhatItDidAndDidNot:
    """`sync-helper.sh` publishes to the public repo. Two of the things it
    said about itself were wrong on 2026-09-17, in the same way: a
    sentence nobody had checked.

    Its version refusal named two files to bump. Four carry the number,
    and someone who followed the message literally left marketplace.json
    behind — the suite caught that one, but only after the message had
    been believed.

    Its personal-identifier gate reads a gitignored file and skipped
    itself when that file was absent, printing nothing. Every machine but
    the owner's is such a machine, so a sync that checked nothing looked
    exactly like a sync that checked everything. The privacy renderer a
    few lines above already announces its own absence; this holds the gate
    to the same standard."""

    # Every file that carries the helper's version. The refusal message is
    # checked against this list, so a fifth carrier added here fails until
    # the message names it too.
    CARRIERS = (
        "ClaudeRiskClassifier.py",
        "WatchApp/Tapproval/RelayModel.swift",
        "helper/.claude-plugin/plugin.json",
        "helper/.claude-plugin/marketplace.json",
    )

    def _script(self):
        """Absent in the public layout: sync-helper.sh is what publishes to
        that repo, not something it ships. The sync runs this suite in the
        layout it produces, and caught the first version of these tests
        failing there — which is the whole reason that step exists."""
        path = os.path.join(_ROOT, "sync-helper.sh")
        if not os.path.isfile(path):
            pytest.skip("no sync script in this layout")
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def _gate(self, script):
        """The identifier gate, from its filename to the fi that ends it."""
        gate = script[script.index('FORBIDDEN="'):]
        return gate[:gate.index("\n  fi")]

    def test_every_carrier_really_holds_the_version(self):
        """The list is only worth checking a message against if it is
        itself true."""
        for rel in self.CARRIERS:
            path = os.path.join(_ROOT, rel)
            if not os.path.isfile(path):
                pytest.skip("not the product layout: %s" % rel)
            with open(path, encoding="utf-8") as handle:
                assert crc.__version__ in handle.read(), (
                    "%s does not carry %s" % (rel, crc.__version__))

    def _refusal(self, script):
        """The version refusal alone, not the whole script.

        Scoped deliberately: every one of these paths also appears in a
        `cp` line further up, so a search of the file passes whether or
        not the message says anything. The first version of this test did
        exactly that and would have let the old message through."""
        start = script.index("the helper's sources changed")
        return script[start:script.index("exit 1", start)]

    def test_the_version_refusal_names_every_file_that_carries_it(self):
        refusal = self._refusal(self._script())
        missing = [rel for rel in self.CARRIERS if rel not in refusal]
        assert not missing, (
            "sync-helper.sh tells the operator which files to bump and does "
            "not name: %s. A message that names some of them is how "
            "marketplace.json was left behind." % (missing,))

    def test_the_script_refuses_to_publish_a_version_backwards(self):
        """The gate above asks only whether the number changed. It cannot
        see a number that changed downwards, and on 2026-09-17 the public
        repo really was a version ahead of the product repo's main, so a
        sync from main would have published 1.1.6 over 1.1.7 in silence."""
        script = self._script()
        assert "sort -V" in script, (
            "nothing compares the two versions by order, so a downgrade "
            "reads the same as an upgrade")
        assert "older than the one already there" in script

    @pytest.mark.parametrize("local,published,refuses", [
        ("1.1.6", "1.1.7", True),    # the live case on 2026-09-17
        ("1.1.7", "1.1.6", False),   # the ordinary one
        ("1.1.6", "1.1.6", False),   # unchanged: the other gate's business
        ("1.1.9", "1.1.10", True),   # 10 > 9, which a string compare denies
        ("1.2.0", "1.1.99", False),
    ])
    def test_the_comparison_orders_versions_as_numbers_not_text(
            self, local, published, refuses):
        """Run the script's own condition. Sorting these as strings puts
        1.1.10 before 1.1.9, which would wave through exactly the case the
        gate exists for."""
        condition = (
            '[ "$1" != "$2" ] && '
            '[ "$(printf \'%s\\n%s\\n\' "$1" "$2" | sort -V | head -1)" = "$1" ]')
        done = subprocess.run(["bash", "-c", condition, "bash", local, published])
        assert (done.returncode == 0) is refuses, (
            "%s over %s: expected refuses=%s" % (local, published, refuses))

    def test_the_identifier_gate_says_so_when_it_does_not_run(self):
        """The else is the whole point: without it the gate is silent
        exactly when it is inert."""
        gate = self._gate(self._script())
        assert "else" in gate, "the identifier gate has no else: it skips in silence"
        assert [line for line in gate.splitlines()
                if ">&2" in line and "did NOT run" in line], (
            "the skip must say on stderr that it did not run")

    def test_the_refusal_is_read_apart_from_the_cp_lines_above_it(self):
        """Prove the scoping matters: the whole file mentions every
        carrier even when the message names none of them."""
        script = self._script()
        assert all(rel in script for rel in self.CARRIERS)
        refusal = self._refusal(script)
        assert len(refusal) < len(script) / 2, (
            "the refusal should be a few lines, not most of the script")

    def test_the_guard_catches_a_gate_that_skips_in_silence(self):
        """Prove it can fail, against the gate as it stood while inert."""
        was = ('FORBIDDEN=".private/forbidden-strings.txt"\n'
               '  if [ -f "$FORBIDDEN" ]; then\n'
               '    echo "a personal identifier is in a file bound for the '
               'public repo" >&2\n'
               '    exit 1\n'
               '  fi\n')
        gate = was[:was.index("\n  fi")]
        assert "else" not in gate


class TestPluginManifest:
    """Shipped configuration, held to the module's own constants."""

    def test_hook_carries_the_env_the_installer_would_write(self):
        env, _timeout = crc._manifest_hook(_helper_manifest("hooks", "hooks.json"))
        assert env == crc.WATCH_ENV

    def test_hook_timeout_outlives_the_wrist_wait(self):
        _env, timeout = crc._manifest_hook(_helper_manifest("hooks", "hooks.json"))
        assert timeout == crc.WATCH_HOOK_TIMEOUT

    def test_session_start_starts_the_relay(self):
        wiring = _helper_manifest("hooks", "hooks.json")
        commands = [handler.get("command", "")
                    for entry in wiring["hooks"]["SessionStart"]
                    for handler in entry["hooks"]]
        assert any("watch_relay.py" in c and "--ensure" in c for c in commands)

    def test_plugin_version_matches_the_module(self):
        assert _helper_manifest(
            ".claude-plugin", "plugin.json")["version"] == crc.__version__

    def test_marketplace_lists_the_plugin_it_ships(self):
        market = _helper_manifest(".claude-plugin", "marketplace.json")
        plugin = _helper_manifest(".claude-plugin", "plugin.json")
        assert len(market["plugins"]) == 1
        entry = market["plugins"][0]
        assert entry["name"] == plugin["name"] == crc.PLUGIN_NAME
        # plugin.json wins at install time and a mismatched entry version is
        # silently ignored, so the two must not be allowed to drift.
        assert entry["version"] == plugin["version"]


class TestPluginInstall:
    """A plugin user has no hook in settings.json.

    Every command that read only settings.json told them they were not
    installed while the hook ran happily underneath — the confident wrong
    answer this tool exists to prevent.
    """

    @pytest.fixture
    def plugin(self, tmp_path, monkeypatch):
        root = tmp_path / "cache" / "tapproval" / "tapproval-helper" / "1.1.0"
        (root / ".claude-plugin").mkdir(parents=True)
        (root / "hooks").mkdir()
        for parts in ((".claude-plugin", "plugin.json"), ("hooks", "hooks.json")):
            (root.joinpath(*parts)).write_text(
                json.dumps(_helper_manifest(*parts)), encoding="utf-8")
        # The registry Claude Code actually keeps; installPath is authoritative.
        (tmp_path / "installed_plugins.json").write_text(json.dumps({
            "version": 2,
            "plugins": {"tapproval-helper@tapproval": [
                {"scope": "user", "installPath": str(root), "version": "1.1.0"},
            ]},
        }), encoding="utf-8")
        monkeypatch.setenv("CLAUDE_PLUGINS_DIR", str(tmp_path))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        for key in ("CLAUDE_RISK_MODE", "CLAUDE_RISK_RELAY",
                    "CLAUDE_RISK_RELAY_WAIT", "CLAUDE_RISK_CONFIG"):
            monkeypatch.delenv(key, raising=False)
        return root

    def test_found_through_the_registry(self, plugin):
        found = crc._plugin_install()
        assert found is not None
        assert found["root"] == str(plugin)
        assert found["env"]["CLAUDE_RISK_MODE"] == "enforce"
        assert found["relay"] is True

    def test_status_reports_the_plugin_and_its_real_mode(self, plugin, capsys):
        assert crc.run_status() == 0
        out = capsys.readouterr().out
        assert "Installed     : yes — as a Claude Code plugin" in out
        assert "Mode          : enforce" in out
        assert "Relay hook    : starts itself" in out
        assert "the plugin adds no login item" in out

    def test_status_says_no_when_nothing_is_installed(self, tmp_path, monkeypatch,
                                                      capsys):
        monkeypatch.setenv("CLAUDE_PLUGINS_DIR", str(tmp_path / "empty"))
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        assert crc.run_status() == 0
        assert "Installed     : no" in capsys.readouterr().out

    def test_no_watch_refuses_rather_than_claiming_success(self, plugin, capsys):
        settings = os.environ["CLAUDE_SETTINGS_PATH"]
        assert crc.run_watch(False) == 1
        out = capsys.readouterr().out
        assert "/plugin disable" in out
        assert "OFF" not in out
        assert not os.path.exists(settings)

    def test_watch_says_it_is_already_on(self, plugin, capsys):
        assert crc.run_watch(True) == 0
        assert "already on" in capsys.readouterr().out

    def test_uninstall_refuses_rather_than_removing_nothing(self, plugin, capsys):
        assert crc.run_uninstall() == 1
        out = capsys.readouterr().out
        assert "/plugin uninstall" in out
        assert "nothing to remove" not in out

    def test_quiet_still_works_because_the_manifest_leaves_it_alone(
            self, plugin, capsys):
        """The inline assignments override only what they name; anything
        else still reaches the hook from settings.json."""
        assert "CLAUDE_RISK_AUTO_ALLOW" not in crc.WATCH_ENV
        assert crc.run_quiet(True) == 0
        capsys.readouterr()
        data = json.loads(
            open(os.environ["CLAUDE_SETTINGS_PATH"], encoding="utf-8").read())
        assert data["env"]["CLAUDE_RISK_AUTO_ALLOW"] == "LOW"


class TestHookCommandAssignments:
    """check_command() shlex-split the command and took the first word for
    the interpreter, so a plugin-shaped command reported
    'CLAUDE_RISK_MODE=enforce is not on PATH'."""

    def test_reads_past_inline_assignments(self):
        command = "CLAUDE_RISK_MODE=enforce %s %s" % (
            crc._quote_path(sys.executable),
            crc._quote_path(os.path.abspath(crc.__file__)))
        assert crc.check_command(command) == []

    def test_assignments_with_nothing_to_run_are_a_problem(self):
        assert crc.check_command("CLAUDE_RISK_MODE=enforce") == [
            "that command sets variables but never runs anything"]

    def test_splitter_stops_at_the_first_real_word(self):
        env, rest = crc._split_assignments(["A=1", "B=2", "python3", "C=3"])
        assert env == {"A": "1", "B": "2"}
        assert rest == ["python3", "C=3"]


class TestPermissionDecisionShape:
    """The exact JSON Claude Code accepts — the whole product rides on it.

    The CLI validates the decision and says so in its own words:

        PermissionRequest decision must be {"behavior": "allow"} or
        {"behavior": "deny", "message": "..."}

    Until 1.1.1 this hook emitted a bare string. That fails validation,
    and a failed hook is NON-BLOCKING — the permission flow proceeds as
    if nothing had answered. So every wrist approval was discarded while
    the audit log recorded a perfectly good "allow", on every machine,
    for every card, in silence. Nothing else in this suite catches that:
    the tests all asked what we *meant*, never what we *emit*.
    """

    def test_allow_is_the_bare_checked_object(self):
        assert crc._permission_output("allow") == {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }

    def test_deny_carries_its_message(self):
        out = crc._permission_output("deny", "because")
        assert out["decision"] == {"behavior": "deny", "message": "because"}

    def test_escalation_sends_no_decision_at_all(self):
        """Saying nothing is what leaves the question with the human."""
        assert crc._permission_output("escalate") == {
            "hookEventName": "PermissionRequest"}
        assert "decision" not in crc._permission_output("escalate")

    def test_the_fallback_escalates_by_saying_nothing(self):
        assert crc.ESCALATE_FALLBACK["hookSpecificOutput"] == {
            "hookEventName": "PermissionRequest"}

    def test_decision_is_never_a_bare_string(self):
        """The regression itself, stated as a rule."""
        for behavior in ("allow", "deny", "escalate", "anything-else"):
            decision = crc._permission_output(behavior, "m").get("decision")
            assert not isinstance(decision, str)

    @pytest.mark.parametrize("verdict,expected", [
        ("allow", {"behavior": "allow"}),
        ("deny", None),          # message differs; shape checked below
    ])
    def test_a_watch_answer_reaches_stdout_in_that_shape(
            self, verdict, expected, tmp_path, monkeypatch):
        import io
        monkeypatch.setenv("CLAUDE_RISK_MODE", "enforce")
        # A relay address is what makes the hook consult the wrist at all.
        # Leaving it to the ambient environment passed here and failed on
        # CI, because this machine exports it and a clean one does not.
        monkeypatch.setenv("CLAUDE_RISK_RELAY", "http://127.0.0.1:8977")
        monkeypatch.setenv("CLAUDE_RISK_AUDIT_LOG", str(tmp_path / "a.jsonl"))
        monkeypatch.delenv("CLAUDE_RISK_CONFIG", raising=False)
        monkeypatch.delenv("CLAUDE_RISK_AUTO_ALLOW", raising=False)
        monkeypatch.setattr(crc, "ask_watch", lambda *a, **k: (verdict, None))
        out = io.StringIO()
        crc.run_hook(stdin=io.StringIO(json.dumps(
            {"tool_name": "Bash", "cwd": str(tmp_path),
             "tool_input": {"command": "rm -rf %s/x" % tmp_path}})), stdout=out)
        decision = json.loads(out.getvalue())["hookSpecificOutput"]["decision"]
        assert isinstance(decision, dict)
        assert decision["behavior"] == verdict
        if expected:
            assert decision == expected


class TestSubagentCardsRetract:
    """A card raised inside a subagent must leave the wrist when answered.

    Claude Code writes a subagent's tool calls to its own transcript —
    `<project>/<session-id>/subagents/agent-*.jsonl` — not to the session
    file. The resolver used to watch only the session file, so it never
    saw the originating tool_use, no result could ever match it, and the
    card sat on the wrist until the 24-hour wait expired. Found live with
    six such cards stacked up from one session.
    """

    TOOL, TOOL_INPUT = "Bash", {"command": "rm -rf /tmp/subagent-target"}

    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setattr(watch_relay, "RESOLVER_RESCAN_SECONDS", 0.0)
        sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        project = tmp_path / "-Users-someone-Developer-Demo"
        project.mkdir()
        (project / (sid + ".jsonl")).write_text(
            json.dumps({"type": "user", "message": {"content": "hi"}}) + "\n",
            encoding="utf-8")
        card = {"session_id": sid, "tool": self.TOOL,
                "fingerprint": crc._card_fingerprint(self.TOOL, self.TOOL_INPUT)}
        check = watch_relay._prompt_resolver(card, projects_dir=str(tmp_path))
        return check, project / sid / "subagents"

    def _write(self, path, *blocks):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            for block in blocks:
                handle.write(json.dumps(
                    {"type": "assistant", "isSidechain": True,
                     "message": {"content": [block]}}) + "\n")

    def test_a_subagent_card_is_retracted_when_answered_elsewhere(
            self, tmp_path, monkeypatch):
        check, subagents = self._setup(tmp_path, monkeypatch)
        assert check() is False
        agent = subagents / "agent-deadbeef.jsonl"
        self._write(agent, {"type": "tool_use", "id": "toolu_SUB",
                            "name": self.TOOL, "input": self.TOOL_INPUT})
        assert check() is False, "asked but unanswered must not retract"
        self._write(agent, {"type": "tool_result",
                            "tool_use_id": "toolu_SUB", "content": "ok"})
        assert check() is True

    def test_a_subagent_starting_after_the_card_is_still_watched(
            self, tmp_path, monkeypatch):
        """The subagent that raises the card does not exist when the card
        is posted, which is why the directory is rescanned."""
        check, subagents = self._setup(tmp_path, monkeypatch)
        assert not subagents.exists()
        check()
        agent = subagents / "agent-later.jsonl"
        self._write(agent, {"type": "tool_use", "id": "toolu_LATE",
                            "name": self.TOOL, "input": self.TOOL_INPUT},
                    {"type": "tool_result", "tool_use_id": "toolu_LATE",
                     "content": "done"})
        assert check() is True

    def test_another_subagents_answer_does_not_retract_this_card(
            self, tmp_path, monkeypatch):
        """Several subagents run at once; only a matching call counts."""
        check, subagents = self._setup(tmp_path, monkeypatch)
        other = subagents / "agent-other.jsonl"
        self._write(other, {"type": "tool_use", "id": "toolu_OTHER",
                            "name": self.TOOL,
                            "input": {"command": "echo something else"}},
                    {"type": "tool_result", "tool_use_id": "toolu_OTHER",
                     "content": "ok"})
        assert check() is False


class TestAnsweredElsewhereDespiteExtraFields:
    """Claude Code gives the hook fields it never writes to the transcript.

    Seen 2026-09-17: two DesignSync prompts answered on the phone at 08:24
    were still on the wrist at 12:40. The hook's copy of the input carried
    consent fields the transcript's tool_use does not, so the whole-input
    fingerprint could never match and nothing retracted the cards.
    """

    TOOL = "DesignSync"
    RECORDED = {"method": "create_project", "name": "HOV – Ugerytmen forslag"}
    HOOK_SAW = dict(RECORDED, consentBitShown="none", consentAskCanReachUser="no")

    def _check(self, tmp_path, hook_input=None, digests=True):
        sid = "028d9dce-1dd1-4a2a-a64b-36164180af42"
        project = tmp_path / "-Users-someone-Developer-Demo"
        project.mkdir()
        transcript = project / (sid + ".jsonl")
        transcript.write_text("", encoding="utf-8")
        seen = hook_input or self.HOOK_SAW
        card = {"session_id": sid, "tool": self.TOOL,
                "fingerprint": crc._card_fingerprint(self.TOOL, seen)}
        if digests:
            card["input_digests"] = crc._input_digests(self.TOOL, seen)
        return watch_relay._prompt_resolver(card, projects_dir=str(tmp_path)), transcript

    def _append(self, transcript, recorded, use_id="toolu_DS"):
        with open(transcript, "a", encoding="utf-8") as handle:
            for block in ({"type": "tool_use", "id": use_id, "name": self.TOOL,
                           "input": recorded},
                          {"type": "tool_result", "tool_use_id": use_id,
                           "content": "ok"}):
                handle.write(json.dumps({"type": "assistant",
                                         "message": {"content": [block]}}) + "\n")

    def test_the_fingerprints_really_differ(self):
        """The premise, so this class cannot pass for the wrong reason."""
        assert (crc._card_fingerprint(self.TOOL, self.HOOK_SAW)
                != crc._card_fingerprint(self.TOOL, self.RECORDED))

    def test_a_card_is_retracted_when_the_transcript_recorded_less(self, tmp_path):
        check, transcript = self._check(tmp_path)
        assert check() is False
        self._append(transcript, self.RECORDED)
        assert check() is True

    def test_a_card_from_an_older_hook_without_digests_still_matches_exactly(self, tmp_path):
        check, transcript = self._check(tmp_path, hook_input=self.RECORDED, digests=False)
        check()
        self._append(transcript, self.RECORDED)
        assert check() is True

    def test_a_different_value_is_a_different_call(self, tmp_path):
        check, transcript = self._check(tmp_path)
        check()
        self._append(transcript, dict(self.RECORDED, name="Another project"))
        assert check() is False

    def test_a_key_the_hook_never_saw_is_a_different_call(self, tmp_path):
        check, transcript = self._check(tmp_path)
        check()
        self._append(transcript, dict(self.RECORDED, extra="x"))
        assert check() is False

    def test_an_empty_recorded_input_matches_nothing(self, tmp_path):
        check, transcript = self._check(tmp_path)
        check()
        self._append(transcript, {})
        assert check() is False

    def test_the_hook_puts_digests_on_every_card(self):
        event = {"tool_name": self.TOOL, "tool_input": self.HOOK_SAW,
                 "session_id": "s", "cwd": "/tmp"}
        _, _, card = crc.build_response(event, dict(crc.DEFAULT_POLICY))
        assert card["input_digests"] == crc._input_digests(self.TOOL, self.HOOK_SAW)
        assert set(card["input_digests"]) == set(self.HOOK_SAW)


class TestASignedOutMacSaysSo:
    """2026-09-18: the CLI's OAuth session expired with no refresh token,
    so every wrist send died with "Failed to authenticate: OAuth session
    expired and could not be refreshed" — which reached the watch looking
    like Claude's own reply, in a thread, under a working pulse. Nothing
    anywhere said the Mac needed signing in."""

    @pytest.fixture(autouse=True)
    def _fresh(self, monkeypatch):
        # Put the real function back: the suite-wide fixture stubs it so no
        # other test asks the CLI anything.
        monkeypatch.setattr(watch_relay, "signed_in", _REAL_SIGNED_IN)
        monkeypatch.setattr(watch_relay, "_SIGNIN", {"at": 0.0, "in": None})
        watch_relay.clear_condition("signin")
        yield
        watch_relay.clear_condition("signin")

    @staticmethod
    def _answer(code, out):
        import subprocess as sp
        return lambda: sp.CompletedProcess(["claude"], code, out, "")

    def test_signed_in_is_true_and_clears_the_condition(self):
        watch_relay.note_condition("signin", "stale")
        assert watch_relay.signed_in(runner=self._answer(0, '{"loggedIn": true}')) is True
        assert "signin" not in [c["key"] for c in watch_relay.conditions()]

    def test_signed_out_is_reported_where_every_fault_is_reported(self):
        assert watch_relay.signed_in(runner=self._answer(0, '{"loggedIn": false}')) is False
        said = [c for c in watch_relay.conditions() if c["key"] == "signin"]
        assert said, "the wrist learns of this on Check connection or not at all"
        assert "claude auth login" in said[0]["detail"], "say the fix, not the fault"

    @pytest.mark.parametrize("code,out", [(1, ""), (0, "not json at all")])
    def test_an_answer_that_cannot_be_read_is_not_a_refusal(self, code, out):
        """None, never False: this must not become a reason a send fails."""
        assert watch_relay.signed_in(runner=self._answer(code, out)) is None
        assert "signin" not in [c["key"] for c in watch_relay.conditions()]

    def test_the_answer_is_cached(self):
        calls = []
        def once():
            import subprocess as sp
            calls.append(1)
            return sp.CompletedProcess(["claude"], 0, '{"loggedIn": true}', "")
        watch_relay.signed_in(runner=once)
        watch_relay.signed_in(runner=once)
        assert len(calls) == 1, "a subprocess per health poll is a subprocess too many"

    def test_a_send_refuses_in_words_rather_than_spawning(self, tmp_path, monkeypatch):
        """Spawning anyway is what put the CLI's error in the transcript."""
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/bin/claude")
        monkeypatch.setattr(watch_relay, "signed_in", lambda *a, **k: False)
        spawned = []
        monkeypatch.setattr(watch_relay, "_spawn_detached",
                            lambda *a, **k: spawned.append(a) or "")
        session = tmp_path / "-Users-x-Developer-acme"
        session.mkdir()
        (session / "abc12345.jsonl").write_text(json.dumps(
            {"type": "user", "cwd": str(tmp_path),
             "message": {"role": "user", "content": "hi"}}) + "\n", encoding="utf-8")
        assert watch_relay.say_to_session("abc12345", "run the tests",
                                          projects_dir=str(tmp_path)) == "signed out"
        assert spawned == [], "nothing may be spawned into a signed-out CLI"

    def test_the_clis_own_error_is_a_notice_not_a_reply(self, tmp_path):
        sid = "cccccccc-1111-2222-3333-666666666666"
        project = tmp_path / "-Users-someone-Developer-Demo"
        project.mkdir()
        path = project / (sid + ".jsonl")
        path.write_text(json.dumps({
            "type": "assistant", "timestamp": "2026-09-18T16:00:00Z",
            "message": {"role": "assistant", "content": [
                {"type": "text",
                 "text": "Failed to authenticate: OAuth session expired and "
                         "could not be refreshed"}]}}) + "\n", encoding="utf-8")
        turns, _, _ = watch_dashboard._parse_thread(str(path), watch_dashboard.THREAD_TURN_LIMIT)
        assert len(turns) == 1
        assert turns[0]["role"] == "system" and turns[0]["kind"] == "notice"
        assert "signed out" in turns[0]["text"] and "claude auth login" in turns[0]["text"]


class TestPicturesReachTheWrist:
    """A screenshot pasted into Claude Code is an image part, and every
    screen here used to drop it: a turn that was only a picture arrived
    empty, which reads as the watch having lost the message (2026-09-18).
    """

    PART = {"type": "image",
            "source": {"type": "base64", "media_type": "image/png",
                       "data": base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()}}

    @pytest.fixture(autouse=True)
    def _empty_cache(self):
        watch_dashboard._IMAGES.clear()
        yield
        watch_dashboard._IMAGES.clear()

    def test_a_picture_is_remembered_and_served_back(self):
        ref = watch_dashboard.remember_image(self.PART)
        assert ref and len(ref) == 16
        assert watch_dashboard.image_bytes(ref) == ("image/png", b"\x89PNG\r\n\x1a\nfake")

    def test_the_same_picture_twice_is_one_entry(self):
        first = watch_dashboard.remember_image(self.PART)
        assert watch_dashboard.remember_image(self.PART) == first
        assert len(watch_dashboard._IMAGES) == 1

    @pytest.mark.parametrize("part", [
        {"type": "image", "source": {"type": "url", "url": "http://x/y.png"}},
        {"type": "image", "source": {"type": "base64", "media_type": "text/html", "data": "eA=="}},
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": 7}},
        {"type": "image"},
    ])
    def test_what_is_not_a_picture_is_refused(self, part):
        assert watch_dashboard.remember_image(part) is None

    def test_an_unknown_reference_is_simply_missing(self):
        assert watch_dashboard.image_bytes("deadbeefdeadbeef") is None
        assert watch_dashboard.image_bytes(None) is None

    def test_the_cache_is_bounded_by_count(self, monkeypatch):
        monkeypatch.setattr(watch_dashboard, "IMAGE_CACHE_MAX", 3)
        for n in range(6):
            watch_dashboard.remember_image(
                {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": base64.b64encode(b"x" * (n + 1)).decode()}})
        assert len(watch_dashboard._IMAGES) == 3, "a long session of screenshots must not grow forever"

    def test_a_picture_too_large_to_send_is_not_kept(self, monkeypatch):
        monkeypatch.setattr(watch_dashboard, "IMAGE_MAX_BYTES", 8)
        assert watch_dashboard.remember_image(
            {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": "A" * 64}}) is None

    def test_a_turn_that_is_only_a_picture_still_says_something(self, tmp_path):
        sid = "aaaaaaaa-1111-2222-3333-444444444444"
        project = tmp_path / "-Users-someone-Developer-Demo"
        project.mkdir()
        path = project / (sid + ".jsonl")
        path.write_text(json.dumps({
            "type": "user", "timestamp": "2026-09-18T12:00:00Z",
            "message": {"role": "user", "content": [self.PART]}}) + "\n",
            encoding="utf-8")
        turns, _, _ = watch_dashboard._parse_thread(str(path), watch_dashboard.THREAD_TURN_LIMIT)
        assert len(turns) == 1, turns
        assert turns[0]["text"] == "[image]"
        assert turns[0]["images"] == [watch_dashboard.remember_image(self.PART)]


class TestTheImageRouteIsNotOpenToTheRoom:
    """The pictures are the user's own screens. Loopback is not a person:
    /image needs a device key, exactly like /say and /thread's siblings."""

    def test_the_route_demands_a_key(self):
        rules = watch_relay.RelayHandler.ROUTES["GET"]["/image"][1]
        assert rules.get("token") is True

    def test_an_unknown_reference_is_a_404_not_an_error(self, tmp_path, monkeypatch):
        watch_dashboard._IMAGES.clear()
        auth = _known_watch(watch_relay.Auth(path=str(tmp_path / "auth.json")))
        auth.save = lambda: None
        server, _ = watch_relay.serve(port=0, auth=auth)
        _serve(server)
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            status, _ = relay_call(base + "/image?ref=nothing", token="devicetoken")
            assert status == 404
        finally:
            server.shutdown()
            server.server_close()


class TestTunnelBinaryLookup:
    """The travel tunnel must survive being started by launchd.

    A login item gets a bare PATH — no /opt/homebrew/bin, no
    /usr/local/bin. The relay is started that way after every reboot, so
    looking only on PATH found nothing, printed "cloudflared not
    installed" (which was false), and left the away-from-home route off
    until somebody restarted the relay from a shell. Nobody would notice
    until they were away from home with a watch that could not connect.
    """

    def test_found_on_path(self, monkeypatch, tmp_path):
        fake = tmp_path / "cloudflared"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        assert watch_relay._cloudflared() == str(fake)

    def test_found_where_homebrew_puts_it_when_path_is_bare(
            self, monkeypatch, tmp_path):
        fake = tmp_path / "cloudflared"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", "/nonexistent")
        monkeypatch.setattr(watch_relay, "_TUNNEL_PATHS", (str(fake),))
        assert watch_relay._cloudflared() == str(fake)

    def test_none_when_genuinely_absent(self, monkeypatch):
        monkeypatch.setenv("PATH", "/nonexistent")
        monkeypatch.setattr(watch_relay, "_TUNNEL_PATHS",
                            ("/nonexistent/cloudflared",))
        assert watch_relay._cloudflared() is None


class TestHelperKeepsItselfCurrent:
    """A stale helper is not a cosmetic problem.

    The version before 1.1.1 discarded every wrist approval in silence, so
    an update that never arrives is the failure this guards against. The
    SessionStart hook already runs on every session; it now kicks off a
    fast-forward of a git install at most once a day, in a detached
    process, so it is never in the way of a session.
    """

    def _spawns(self, monkeypatch):
        spawned = []
        monkeypatch.setattr(watch_relay, "_spawn_detached",
                            lambda argv, log: spawned.append(argv) or None)
        return spawned

    def test_a_plugin_install_is_never_rewritten(self, tmp_path, monkeypatch):
        """Claude Code owns a plugin's files and manages its own updates."""
        wr = watch_relay
        spawned = self._spawns(monkeypatch)
        monkeypatch.setattr(wr, "__file__", str(tmp_path / "watch_relay.py"))
        monkeypatch.setattr(wr, "_UPDATE_STAMP", str(tmp_path / "stamp"))
        wr._self_update()                      # no .git beside it
        assert spawned == []

    def test_it_asks_at_most_once_a_day(self, tmp_path, monkeypatch):
        wr = watch_relay
        spawned = self._spawns(monkeypatch)
        (tmp_path / ".git").mkdir()
        stamp = tmp_path / "stamp"
        stamp.write_text("recent", encoding="utf-8")
        monkeypatch.setattr(wr, "__file__", str(tmp_path / "watch_relay.py"))
        monkeypatch.setattr(wr, "_UPDATE_STAMP", str(stamp))
        wr._self_update()
        assert spawned == [], "a fresh stamp must skip the update entirely"

    def test_a_failure_never_blocks_the_session(self, tmp_path, monkeypatch):
        """No git, no network, a dirty clone — start what is already there."""
        wr = watch_relay
        monkeypatch.setattr(wr, "__file__", str(tmp_path / "watch_relay.py"))

        def boom(*_a, **_k):
            raise OSError("git is not installed")
        monkeypatch.setattr(wr.subprocess, "run", boom)
        assert wr._pull_update() is False


    def test_it_never_raises_whatever_git_does(self, tmp_path, monkeypatch):
        """This runs on the blocking path of a SessionStart hook. An
        exception here takes down the session — a far worse outcome than
        a missed update — so the guard catches everything, not a chosen
        list. A narrow except is how this promise was first broken: a
        test that stubbed subprocess.Popen made subprocess.run raise
        TypeError, which sailed straight through."""
        wr = watch_relay
        monkeypatch.setattr(wr, "__file__", str(tmp_path / "watch_relay.py"))
        for blow_up in (TypeError("no __enter__"), AttributeError("nope"),
                        ValueError("odd"), RuntimeError("worse")):
            def raiser(*_a, _e=blow_up, **_k):
                raise _e
            monkeypatch.setattr(wr.subprocess, "run", raiser)
            assert wr._pull_update() is False


class TestInstallTranscript:
    """What the installer says must be what it did.

    As two calls, install.sh's transcript promised "shadow mode — work
    normally for a week" and, three lines later, "Wrist approvals are ON".
    A first-time user reading that has no way to know which one is true.
    """

    def test_install_with_watch_does_not_promise_shadow_mode(
            self, settings, capsys):
        assert crc.main(["--install", "--watch"]) == 0
        out = capsys.readouterr().out
        assert "Wrist approvals are ON" in out
        assert "shadow mode" not in out
        assert "work normally for a week" not in out

    def test_install_alone_still_explains_shadow_mode(self, settings, capsys):
        """The plain --install path is unchanged: it IS shadow mode."""
        assert crc.main(["--install"]) == 0
        assert "shadow mode" in capsys.readouterr().out

    def test_install_with_watch_actually_enables_it(self, settings):
        crc.main(["--install", "--watch"])
        data = json.loads(settings.read_text(encoding="utf-8"))
        assert data["env"]["CLAUDE_RISK_MODE"] == "enforce"

    def test_the_wait_is_a_duration_a_person_would_say(self, settings, capsys):
        crc.main(["--install", "--watch"])
        out = capsys.readouterr().out
        assert "24 hours" in out
        # Held to the sentence, not the whole transcript. The transcript
        # also prints a backup filename stamped with the clock, and at
        # 14:40:54 on 2026-09-16 that stamp contained "1440" — CI went red
        # on a pull request that had not touched this code, and would have
        # gone red at 14:40 on any day.
        line = next(row for row in out.splitlines() if "24 hours" in row)
        assert "1440" not in line

    @pytest.mark.parametrize("seconds,expected", [
        (60, "1 minute"), (300, "5 minutes"), (3600, "1 hour"),
        (86400, "24 hours"), (5400, "90 minutes"), (0, "1 minute"),
    ])
    def test_human_duration(self, seconds, expected):
        assert crc._human_duration(seconds) == expected


class TestTheHelperSaysWhereItsCodeIsFrom:
    """A version number is a claim the code makes about itself; the
    checkout's commit and date are the receipt. On 2026-09-08 a helper
    four days behind the repository reported the same v1.1.1 the app
    expected, and nothing on the wrist could have said otherwise."""

    def _repo(self, tmp_path):
        import subprocess
        root = tmp_path / "helper"
        root.mkdir()
        (root / "watch_relay.py").write_text("# me\n")
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@x", "PATH": os.environ["PATH"], "HOME": str(tmp_path)}
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "one"]):
            subprocess.run(["git", "-C", str(root)] + args, check=True, env=env, capture_output=True)
        return str(root)

    def test_a_git_checkout_names_its_commit_and_day(self, tmp_path):
        commit, date = watch_relay.helper_provenance(self._repo(tmp_path))
        assert re.fullmatch(r"[0-9a-f]{7,}", commit)
        assert re.match(r"\d{4}-\d{2}-\d{2}T", date), date

    def test_an_install_without_a_checkout_says_nothing_rather_than_guessing(self, tmp_path):
        plain = tmp_path / "plugin"
        plain.mkdir()
        assert watch_relay.helper_provenance(str(plain)) == (None, None)

    def test_main_reads_the_receipt_before_serving(self):
        """/health answers from what main() read at startup; a request
        must never be the thing that runs git."""
        with open(watch_relay.__file__, encoding="utf-8") as handle:
            source = handle.read()
        body = source.split("def main(", 1)[1]
        assert body.index("helper_provenance()") < body.index("serve(args.host")
        health = source.split("def _get_health", 1)[1].split("def _get_projects", 1)[0]
        assert "helper_provenance(" not in health



class TestWhatWeKnowAboutTheTranscript:
    """watch_dashboard reads a file another product writes, in a format
    with no version number and no promise. Each shape it leans on is named
    in UPSTREAM_SHAPES with the date it was last seen here — because when
    one changes upstream the wrist quietly loses something, which is how
    "No response requested." became a reply bubble and how a /recap once
    showed nothing at all."""

    @staticmethod
    def _source_outside_the_table():
        """The module's source with the table itself cut out. The first
        version of this check read the whole file, so every entry proved
        its own existence and the guard could never fail — a confident
        statement nobody had seen be false (#38)."""
        with open(watch_dashboard.__file__, encoding="utf-8") as handle:
            source = handle.read()
        start = source.index("UPSTREAM_SHAPES = {")
        end = source.index("\ndef shape(", start)
        return source[:start] + source[end:]

    def test_every_shape_named_is_one_the_code_actually_reads(self):
        """A table that outlives its readers is documentation, not a
        registry. An entry earns its place two ways: something calls
        shape() for it, or the string appears in a reader — the tag
        regexes spell theirs out, which is where a regex has to say it.
        Anything else is a shape nobody reads, and no test upstream will
        ever tell us it changed."""
        source = self._source_outside_the_table()
        orphans = [name for name, (value, _m, _s) in watch_dashboard.UPSTREAM_SHAPES.items()
                   if 'shape("%s")' % name not in source and value not in source]
        assert not orphans, ("named in UPSTREAM_SHAPES and read nowhere: %s"
                             % ", ".join(orphans))

    def test_each_shape_carries_a_day_somebody_saw_it(self):
        import datetime
        today = datetime.date.today()
        for name, (_value, meaning, seen) in watch_dashboard.UPSTREAM_SHAPES.items():
            day = datetime.date.fromisoformat(seen)          # raises if not a date
            assert day <= today, "%s claims to have been seen in the future" % name
            assert meaning.endswith("."), "%s: say what it means, in a sentence" % name

    def test_the_readers_go_through_the_table(self):
        """A reader that spells an upstream string out again is the drift
        this table exists to stop."""
        with open(watch_dashboard.__file__, encoding="utf-8") as handle:
            source = handle.read()
        for name in ("system.subtype.local_command", "text.nothing_to_add",
                     "part.tool_result"):
            assert 'shape("%s")' % name in source, name

    def test_a_system_line_we_have_no_reading_for_is_said_once(self, capsys):
        watch_dashboard._UNKNOWN_SUBTYPES.clear()
        assert watch_dashboard.note_unknown_subtype("compact_boundary") is True
        assert watch_dashboard.note_unknown_subtype("compact_boundary") is False
        said = capsys.readouterr().err
        assert said.count("compact_boundary") == 1
        assert "does not read" in said

    def test_nothing_is_said_about_a_line_with_no_subtype(self, capsys):
        watch_dashboard._UNKNOWN_SUBTYPES.clear()
        assert watch_dashboard.note_unknown_subtype(None) is False
        assert capsys.readouterr().err == ""

    def test_a_transcript_carrying_an_unfamiliar_line_says_so(self, tmp_path, capsys):
        """End to end: the notice comes from reading a real transcript, not
        from calling the reporter by hand."""
        watch_dashboard._UNKNOWN_SUBTYPES.clear()
        _write_transcript(tmp_path, "-p", "shapes.jsonl", [
            {"cwd": "/x", "message": {"role": "user", "content": "hello"}},
            {"type": "system", "subtype": "a_shape_from_the_future",
             "content": "something new"},
        ])
        watch_dashboard.session_thread("shapes", projects_dir=str(tmp_path))
        assert "a_shape_from_the_future" in capsys.readouterr().err


class TestTheHelperReportsItsOwnCrashes:
    """Pantri shipped to TestFlight with only the push half of this and the
    owner sent crash reports for weeks that reached nobody — the absence of
    reports looks exactly like the absence of crashes. So: written down
    first, shown on the wrist second, e-mailed third, and every failure in
    the chain says which."""

    @pytest.fixture(autouse=True)
    def _fresh(self):
        crash_report._reset_for_tests()
        yield
        crash_report._reset_for_tests()

    SETTINGS = ("key", "to@example.org", "from@example.org")

    class _Post:
        """A stand-in for Resend that records what it was handed."""
        def __init__(self, status=200):
            self.status, self.calls = status, []

        def __call__(self, request, timeout=None):
            self.calls.append(json.loads(request.data.decode("utf-8")))
            outer = self

            class Reply:
                status = outer.status
                def __enter__(self_inner): return self_inner
                def __exit__(self_inner, *a): return False
            return Reply()

    def test_the_same_crash_from_the_same_place_is_one_report(self):
        a = crash_report.fingerprint("ValueError: boom",
                                     '  File "relay.py", line 9, in serve')
        b = crash_report.fingerprint("ValueError: boom",
                                     '  File "relay.py", line 9, in serve')
        c = crash_report.fingerprint("ValueError: boom",
                                     '  File "other.py", line 3, in advertise')
        assert a == b and a != c

    def test_it_is_written_down_before_anything_is_sent(self, tmp_path):
        """The file is the record; e-mail is only the push. A crash with no
        network, or one that kills the process first, must still be findable."""
        log = tmp_path / "crashes.jsonl"
        reason, _ = crash_report.report("ValueError: boom", 'File "a.py", line 1',
                                        path=str(log),
                                        settings=(None, None, None))
        assert reason == "mail_not_configured"
        written = json.loads(log.read_text().strip())
        assert written["message"] == "ValueError: boom"
        assert written["source"] == "process" and written["at"]
        assert oct(os.stat(log).st_mode & 0o777) == "0o600"

    def test_a_machine_with_no_key_says_so_rather_than_pretending(self, tmp_path):
        reason, _ = crash_report.report("boom", "stack", path=str(tmp_path / "c"),
                                        settings=(None, "to@x", "from@x"))
        assert reason == "mail_not_configured"

    def test_a_configured_machine_sends_one_and_counts_the_rest(self, tmp_path):
        post = self._Post()
        log = str(tmp_path / "c")
        first, _ = crash_report.report("ValueError: boom", 'File "a.py", line 1',
                                       helper="1.1.3", path=log,
                                       settings=self.SETTINGS, opener=post)
        again, _ = crash_report.report("ValueError: boom", 'File "a.py", line 1',
                                       helper="1.1.3", path=log,
                                       settings=self.SETTINGS, opener=post)
        assert (first, again) == ("sent", "duplicate")
        assert len(post.calls) == 1, "the second identical crash is counted, not sent"
        sent = post.calls[0]
        assert sent["to"] == ["to@example.org"] and sent["from"] == "from@example.org"
        assert "Tapproval helper 1.1.3" in sent["subject"] and "boom" in sent["subject"]
        assert 'File "a.py"' in sent["text"], "the stack is the whole point"
        # Both crashes are on disk even though one e-mail went.
        assert len(log_lines(log)) == 2

    def test_a_crash_loop_cannot_send_a_thousand_e_mails(self, tmp_path):
        post = self._Post()
        reasons = [crash_report.report("boom %d" % i, "File \"a.py\", line %d" % i,
                                       path=str(tmp_path / "c"),
                                       settings=self.SETTINGS, opener=post)[0]
                   for i in range(crash_report.MAX_SENDS_PER_WINDOW + 3)]
        assert reasons.count("sent") == crash_report.MAX_SENDS_PER_WINDOW
        assert reasons[-1] == "rate_limited"

    def test_a_refused_send_is_loud_rather_than_silent(self, tmp_path, capsys):
        """Resend refuses any from-address on a domain it has not verified,
        and a swallowed refusal looks exactly like "no crashes" — the state
        Pantri sat in with all three secrets correctly set."""
        def angry(request, timeout=None):
            raise urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
        reason, _ = crash_report.report("boom", "stack", path=str(tmp_path / "c"),
                                        settings=self.SETTINGS, opener=angry)
        assert reason == "send_failed"
        assert "send failed" in capsys.readouterr().err

    def test_the_reporter_never_raises_into_a_crash(self, tmp_path):
        """A reporter that throws inside the crash path destroys the evidence
        it exists to preserve — so anything the send does, however unlikely,
        comes back as a reason."""
        def explode(request, timeout=None):
            raise RecursionError("something absurd, deep in urllib")
        reason, entry = crash_report.report("boom", "stack", path=str(tmp_path / "c"),
                                            settings=self.SETTINGS, opener=explode)
        assert reason == "send_failed"
        assert entry["message"] == "boom", "and the crash is still recorded"

    def test_it_does_not_swallow_the_owner_pressing_ctrl_c(self, tmp_path):
        """The one thing it must NOT catch. `except Exception` is deliberate:
        a reporter that eats KeyboardInterrupt makes a hung send unkillable,
        which is a worse failure than a lost report."""
        def interrupted(request, timeout=None):
            raise KeyboardInterrupt
        with pytest.raises(KeyboardInterrupt):
            crash_report.report("boom", "stack", path=str(tmp_path / "c"),
                                settings=self.SETTINGS, opener=interrupted)
        assert log_lines(str(tmp_path / "c")), "written down before the send"

    def test_an_unwritable_log_is_reported_not_thrown(self, tmp_path, capsys):
        reason, _ = crash_report.report("boom", "stack",
                                        path=str(tmp_path / "no" / "such" / "c"),
                                        settings=(None, None, None))
        assert reason == "mail_not_configured"
        assert "could not write" in capsys.readouterr().err

    def test_the_key_is_stored_where_only_its_owner_can_read_it(self, tmp_path):
        target = tmp_path / "keys" / "resend-key"
        said = crash_report.install_key("re_abc123\n", path=str(target))
        assert "stored" in said and "re_abc123" not in said, "never echo the key"
        assert target.read_text().strip() == "re_abc123"
        assert oct(os.stat(target).st_mode & 0o777) == "0o600"

    def test_the_request_carries_a_user_agent(self):
        """Cloudflare fronts Resend and refuses urllib's default agent with
        a bare 403 and "error code: 1010" — nothing from Resend at all. So
        no key of any kind could send from here, and the failure looked
        exactly like a rejected key. Found 2026-09-10 against a live key,
        which then answered 401 restricted_api_key: through Cloudflare, and
        the right answer for a send-only key."""
        seen = {}
        class Reply:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        def opener(request, timeout=None):
            seen["headers"] = {k.lower(): v for k, v in request.header_items()}
            return Reply()
        crash_report.send({"at": "now", "message": "m", "stack": "s",
                           "source": "test", "helper": "h"}, 1, 0,
                          settings=("re_k", "to@x", "from@x"), opener=opener)
        assert seen["headers"].get("User-agent".lower()), (
            "without a User-Agent Cloudflare answers 403 before Resend sees it")

    def test_a_refusal_carries_the_servers_own_words(self):
        """The selftest promised "the message above from Resend says why"
        and printed "HTTP Error 403: Forbidden" — a number and no reason,
        which sends the reader looking for an explanation never written."""
        class Refusal(urllib.error.HTTPError):
            def __init__(self):
                urllib.error.HTTPError.__init__(
                    self, "https://api.resend.com/emails", 401, "Unauthorized",
                    {}, None)
            def read(self):
                return b'{"statusCode":401,"name":"restricted_api_key"}'
        said = crash_report._why(Refusal())
        assert "401" in said and "restricted_api_key" in said, said

    def test_a_refusal_with_no_body_still_reads_as_an_error(self):
        said = crash_report._why(OSError("connection reset"))
        assert "connection reset" in said

    def test_a_pipe_is_read_and_a_person_is_asked(self):
        """Two ways in, because the clipboard is not always where the key
        is. Piped, it is read. On a terminal it is asked for — the old
        behaviour there was sys.stdin.read() against a tty: no prompt, no
        cursor, waiting for a Ctrl-D nobody had been told about, which
        looks exactly like a hang."""
        class Pipe:
            @staticmethod
            def isatty(): return False
            @staticmethod
            def read(): return "re_from_a_pipe\n"
        assert crash_report.key_from_stdin(Pipe()) == "re_from_a_pipe\n"

        class Terminal:
            @staticmethod
            def isatty(): return True
            @staticmethod
            def read(): raise AssertionError("a terminal must be asked, not read")
        asked = []
        def ask(prompt):
            asked.append(prompt)
            return "re_typed_by_hand"
        assert crash_report.key_from_stdin(Terminal(), ask=ask) == "re_typed_by_hand"
        assert asked and "press return" in asked[0], asked

    def test_the_typed_key_is_never_echoed(self):
        """It is asked for through getpass, so it does not reach the
        scrollback of a shared terminal or a screen recording."""
        import ast
        source = open(crash_report.__file__, encoding="utf-8").read()
        func = next(node for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "key_from_stdin")
        used = {ast.dump(n) for n in ast.walk(func) if isinstance(n, ast.Attribute)}
        assert any("getpass" in u for u in used), (
            "the terminal path must not echo the key — use getpass")
        calls_input = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                          and n.func.id == "input" for n in ast.walk(func))
        assert not calls_input, "input() would echo it"

    def test_a_real_key_is_not_refused_for_its_capital_letter(self, tmp_path):
        """2026-09-10: the owner pasted a key beginning "Re_" and this
        refused it, insisting keys begin with "re_" — a validator turning
        away the exact thing it exists to accept, and saying the form it
        had just been handed. The prefix is here to catch a URL or a
        command pasted by mistake, not to police capitalisation."""
        target = tmp_path / "resend-key"
        said = crash_report.install_key("Re_BiYMaoUu_Ag8NP1", path=str(target))
        assert "stored" in said, said
        assert target.read_text().strip() == "Re_BiYMaoUu_Ag8NP1", (
            "the key is stored exactly as given — case included")

    @pytest.mark.parametrize("pasted, stored", [
        ('"re_quoted"', "re_quoted"),
        ("'re_quoted'", "re_quoted"),
        ("RESEND_API_KEY=re_from_a_dotenv", "re_from_a_dotenv"),
        ("export RESEND_API_KEY='re_from_a_shell_line'", "re_from_a_shell_line"),
        ("  re_with_space\n", "re_with_space"),
    ])
    def test_a_key_arrives_wearing_whatever_it_was_copied_from(
            self, tmp_path, pasted, stored):
        """Copying out of a dashboard, a .env or a shell export brings
        decoration along. None of that is the person making a mistake, and
        a key stored with its quotes still attached fails later, at Resend,
        where the reason is much harder to see."""
        target = tmp_path / "resend-key"
        assert "stored" in crash_report.install_key(pasted, path=str(target))
        assert target.read_text().strip() == stored

    def test_the_refusal_describes_what_arrived_without_printing_it(self, tmp_path):
        target = tmp_path / "resend-key"
        said = crash_report.install_key("re_a_real_looking_key", path=str(target))
        assert "stored" in said
        said = crash_report.install_key("https://resend.com/api-keys", path=str(target))
        assert "27 characters" in said and "'htt'" in said, said

    def test_something_that_is_not_a_key_is_refused_before_it_is_written(self, tmp_path):
        target = tmp_path / "resend-key"
        said = crash_report.install_key("https://resend.com/api-keys", path=str(target))
        assert "does not look like" in said
        assert not target.exists()
        assert "nothing on the clipboard" in crash_report.install_key("  ", path=str(target))

    def test_the_selftest_says_which_piece_is_missing(self, tmp_path):
        code, said = crash_report.selftest(settings=(None, "to@x", None),
                                           path=str(tmp_path / "c"))
        assert code == 1
        assert "a key" in said and "CRASH_REPORT_FROM" in said
        assert "on disk either way" in said

    def test_the_selftest_names_the_inbox_when_it_works(self, tmp_path):
        class Post:
            status = 200
            def __call__(self, request, timeout=None): return self
            def __enter__(self): return self
            def __exit__(self, *a): return False
        code, said = crash_report.selftest(
            settings=("key", "to@example.org", "from@example.org"),
            opener=Post(), path=str(tmp_path / "c"))
        assert code == 0 and "to@example.org" in said

    def test_the_key_is_read_from_a_file_outside_the_repository(self, tmp_path, monkeypatch):
        monkeypatch.delenv(crash_report.KEY_ENV, raising=False)
        assert crash_report.api_key(str(tmp_path / "absent")) is None
        key = tmp_path / "resend-key"
        key.write_text("re_secret\n")
        assert crash_report.api_key(str(key)) == "re_secret"

    def test_a_test_run_never_sends_real_mail(self, tmp_path, monkeypatch):
        """The owner got a crash report about a watch build that had not
        crashed. It was this suite's own fixture: a test posts to
        /diagnostic, the handler calls report() for real, and once a key
        existed the reporter did what it is for.

        The guard is about the process, not the caller. Injecting settings
        fixes the tests you thought of, and this was not one of them.
        """
        key = tmp_path / "resend-key"
        key.write_text("re_a_real_looking_key\n")
        monkeypatch.setattr(crash_report, "KEY_FILE", str(key))
        # No opener: without the guard this would reach api.resend.com.
        reason = crash_report.send(
            {"at": "now", "message": "m", "stack": "s",
             "source": "test", "helper": "h"}, 1, 0)
        assert reason == "not_sent_in_tests", reason

    def test_an_injected_opener_still_exercises_the_send_path(self, tmp_path):
        """The guard must not make the send path untestable — an opener is
        a test saying which door to use, and that stays allowed."""
        class Post:
            status = 200
            def __call__(self, request, timeout=None): return self
            def __enter__(self): return self
            def __exit__(self, *a): return False
        assert crash_report.send(
            {"at": "now", "message": "m", "stack": "s",
             "source": "test", "helper": "h"}, 1, 0,
            settings=("re_k", "to@x", "from@x"), opener=Post()) == "sent"

    def test_the_guard_reads_the_process_not_a_flag(self):
        assert crash_report.running_under_test(env={}, modules={"pytest": object()})
        assert crash_report.running_under_test(
            env={"PYTEST_CURRENT_TEST": "x"}, modules={})
        assert not crash_report.running_under_test(env={}, modules={})

    def test_a_sibling_apps_key_does_not_configure_this_one(self, tmp_path, monkeypatch):
        """Found on 2026-09-10, and the reason these names carry a prefix.

        `RESEND_API_KEY` is what every app that speaks to Resend calls its
        key, so a machine with one exported for other work was silently
        configuring this helper. On a stranger's computer that meant their
        crash — traceback and paths included — posted to Resend under their
        own account and addressed, by default, to the author. Resend
        refuses it, their account having verified no such domain, but the
        POST has already left. "Nothing reaches us" has to hold on a
        machine nobody configured.
        """
        monkeypatch.delenv(crash_report.KEY_ENV, raising=False)
        monkeypatch.setenv("RESEND_API_KEY", "re_someone_elses_key")
        assert crash_report.api_key(str(tmp_path / "absent")) is None

    def test_a_sibling_apps_inbox_does_not_redirect_this_one(self, tmp_path, monkeypatch):
        """The same collision on the addresses, which is how a `--test`
        could have reported success while sending through another app's
        account to another app's mailbox."""
        monkeypatch.setenv("CRASH_REPORT_TO", "someone-else@example.org")
        monkeypatch.setenv("CRASH_REPORT_FROM", "someone-else@send.example.org")
        _key, to, sender = crash_report.mail_settings(
            key_path=str(tmp_path / "absent"))
        assert to == crash_report.DEFAULT_TO
        assert sender == crash_report.DEFAULT_FROM

    def test_the_prefixed_names_still_configure_it(self, tmp_path, monkeypatch):
        """Overriding is allowed — it just has to be this app you mean."""
        monkeypatch.setenv(crash_report.TO_ENV, "mine@example.org")
        monkeypatch.setenv(crash_report.FROM_ENV, "mine@send.example.org")
        _key, to, sender = crash_report.mail_settings(
            key_path=str(tmp_path / "absent"))
        assert (to, sender) == ("mine@example.org", "mine@send.example.org")

    def test_the_key_file_beats_the_environment(self, tmp_path, monkeypatch):
        """`--install-key` writes the file, so the file has to win: a paste
        that appears to work and is then ignored by a variable exported
        months ago is the worst of both."""
        monkeypatch.setenv(crash_report.KEY_ENV, "re_from_the_environment")
        key = tmp_path / "resend-key"
        key.write_text("re_from_the_file\n")
        assert crash_report.api_key(str(key)) == "re_from_the_file"
        assert crash_report.key_and_source(str(key))[1] == "the key file"
        key.unlink()
        found, source = crash_report.key_and_source(str(key))
        assert found == "re_from_the_environment"
        assert source == "$" + crash_report.KEY_ENV

    def test_the_selftest_names_the_route_and_never_the_key(self, tmp_path):
        """A result that does not say where it went is not proof."""
        class Post:
            status = 200
            def __call__(self, request, timeout=None): return self
            def __enter__(self): return self
            def __exit__(self, *a): return False
        code, said = crash_report.selftest(
            settings=("re_never_print_me", "to@example.org", "from@example.org"),
            opener=Post(), path=str(tmp_path / "c"))
        assert code == 0
        assert "to@example.org" in said and "from@example.org" in said
        assert "re_never_print_me" not in said, "never echo the key"

    def test_no_key_lives_in_a_tracked_file(self):
        """A public clone records and shows crashes and sends nothing. That
        is only true while no key is committed."""
        for rel in _tracked_files(_ROOT):
            if not rel.endswith((".py", ".sh", ".json", ".md")):
                continue
            with open(os.path.join(_ROOT, rel), encoding="utf-8", errors="ignore") as handle:
                assert "re_" + "live_" not in handle.read(), rel

    def test_a_dead_thread_reaches_the_wrist(self, tmp_path, monkeypatch):
        """The crash worth catching: a thread dies, the relay keeps
        answering, and nothing looks wrong until something you needed did
        not happen. After it there is still a wrist to tell."""
        import threading
        monkeypatch.setattr(crash_report, "CRASH_LOG", str(tmp_path / "c"))
        monkeypatch.setattr(crash_report, "KEY_FILE", str(tmp_path / "no-key"))
        monkeypatch.delenv(crash_report.KEY_ENV, raising=False)
        chained = []
        monkeypatch.setattr(threading, "excepthook", lambda args: chained.append(args))
        assert watch_relay.install_crash_reporting() is True
        try:
            def angry():
                raise ValueError("the advertiser died")
            worker = threading.Thread(target=angry)
            worker.start()
            worker.join()
            keys = [c["key"] for c in watch_relay.conditions()]
            assert "crash" in keys, "the wrist must be told a thread died"
            said = [c["detail"] for c in watch_relay.conditions() if c["key"] == "crash"][0]
            assert "did not expect" in said and "restarting Claude Code" in said
            assert chained, "the hook that was already there must still run"
            assert json.loads(open(str(tmp_path / "c")).read().strip())["source"] == "thread"
        finally:
            watch_relay.clear_condition("crash")

    def test_main_installs_it_before_serving(self):
        with open(watch_relay.__file__, encoding="utf-8") as handle:
            body = handle.read().split("def main(", 1)[1]
        assert body.index("install_crash_reporting()") < body.index("serve(args.host")


def log_lines(path):
    with open(path, encoding="utf-8") as handle:
        return [line for line in handle if line.strip()]


class TestTheWristAnswersAHeadlessSend:
    """Every quick send runs `claude --resume -p`, and a headless run never
    fires the PermissionRequest hook — the hook belongs to the interactive
    terminal. Until 2026-09-09 a wrist instruction that needed a yes
    stopped at the first risky command and said nothing about why.
    Claude Code's --permission-prompt-tool hands the question to an MCP
    tool instead; this is that tool."""

    class _Fake:
        """Enough of the classifier to answer, without a relay. `decide`
        is the real one: the point of these tests is that the headless
        path obeys the same policy as the hook, so stubbing it would be
        testing the stub."""
        def __init__(self, verdict, relay="http://127.0.0.1:8977", risk=None):
            self.verdict, self.relay = verdict, relay
            self.risk = risk if risk is not None else crc.Risk.HIGH
            self.asked, self.policy_extra = [], {}
            self.asked_the_watch = False

        Risk = crc.Risk
        decide = staticmethod(crc.decide)

        def load_policy(self):
            policy = {"relay": self.relay, "relay_wait": 6.0}
            policy.update(self.policy_extra)
            return policy

        def classify(self, event):
            self.asked.append(event)
            return {"risk": self.risk, "project": "acme"}

        def wrist_card(self, tool, tool_input, risk):
            return {"headline": tool, "tier": risk.name}

        def ask_watch(self, card, policy, project=None):
            self.asked_the_watch = True
            return self.verdict, None

    def test_the_threshold_the_hook_obeys_is_obeyed_here_too(self):
        """A wrist asked about every `ls` stops reading the cards. With a
        raised threshold the harmless ones are answered here, exactly as
        the hook answers them at the keyboard — and CRITICAL never is."""
        fake = self._Fake("deny", risk=crc.Risk.SAFE)  # the wrist would say no
        fake.policy_extra = {"auto_allow_at_or_below": "LOW"}
        out = wpt.decide("Bash", {"command": "ls"}, crc=fake)
        assert out["behavior"] == "allow", "a SAFE call under the threshold never travels"
        assert fake.asked_the_watch is False

    def test_critical_still_reaches_the_wrist_whatever_the_threshold(self):
        fake = self._Fake("allow", risk=crc.Risk.CRITICAL)
        fake.policy_extra = {"auto_allow_at_or_below": "CRITICAL"}
        out = wpt.decide("Bash", {"command": "git push --force origin main"}, crc=fake)
        assert fake.asked_the_watch is True
        assert out["behavior"] == "allow"

    def test_a_yes_on_the_wrist_lets_the_command_run(self):
        fake = self._Fake("allow")
        out = wpt.decide("Bash", {"command": "npm test"}, crc=fake)
        assert out == {"behavior": "allow", "updatedInput": {"command": "npm test"}}
        assert fake.asked[0]["tool_name"] == "Bash"

    def test_a_no_on_the_wrist_is_a_no(self):
        out = wpt.decide("Bash", {"command": "rm -rf build"}, crc=self._Fake("deny"))
        assert out["behavior"] == "deny" and "watch" in out["message"]

    def test_silence_denies_and_says_why(self):
        """The hook may answer "none" and let the ordinary prompt appear,
        because someone is at the terminal. Here nobody is: the run came
        from a wrist. There is no second surface, so silence is a denial
        that explains itself rather than a hang."""
        out = wpt.decide("Bash", {"command": "npm test"}, crc=self._Fake("none"))
        assert out["behavior"] == "deny"
        assert "did not answer" in out["message"] and "Nothing was run" in out["message"]

    def test_no_relay_configured_is_said_in_words(self):
        out = wpt.decide("Bash", {"command": "ls"}, crc=self._Fake("allow", relay=""))
        assert out["behavior"] == "deny" and "no relay address" in out["message"]

    def test_a_classifier_that_throws_still_answers(self):
        class Angry:
            def load_policy(self): raise RuntimeError("boom")
        out = wpt.decide("Bash", {"command": "ls"}, crc=Angry())
        assert out["behavior"] == "deny" and "boom" in out["message"]

    def test_it_speaks_the_handshake_claude_code_expects(self):
        hello = wpt.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert hello["result"]["protocolVersion"] == wpt.PROTOCOL
        assert hello["result"]["capabilities"] == {"tools": {}}
        listed = wpt.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in listed["result"]["tools"]]
        assert names == ["approve"]

    def test_a_notification_is_answered_with_silence(self):
        assert wpt.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_an_unknown_tool_is_an_error_not_an_allow(self):
        reply = wpt.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "something_else", "arguments": {}}})
        assert "error" in reply and "result" not in reply

    def test_the_decision_rides_as_json_in_a_text_block(self):
        reply = wpt.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "approve", "arguments": {
                                "tool_name": "Bash", "input": {"command": "ls"}}}},
                           crc=self._Fake("allow"))
        block = reply["result"]["content"][0]
        assert block["type"] == "text"
        assert json.loads(block["text"])["behavior"] == "allow"

    def test_it_holds_a_real_conversation_over_a_real_pipe(self, tmp_path):
        """The functions above are not the contract; the pipe is. This
        starts the file the way Claude Code starts it and speaks JSON-RPC
        down stdin, with no relay configured so the answer is a refusal in
        words rather than a wait."""
        import subprocess
        env = dict(os.environ, CLAUDE_RISK_RELAY="", CLAUDE_RISK_CONFIG=str(tmp_path / "none.json"))
        talk = "\n".join(json.dumps(m) for m in [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "approve", "arguments": {"tool_name": "Bash",
                                                 "input": {"command": "ls"}}}}])
        done = subprocess.run(
            [sys.executable, os.path.join(_ROOT, "watch_permission_tool.py")],
            input=talk + "\n", capture_output=True, text=True, timeout=30, env=env)
        replies = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
        assert [r["id"] for r in replies] == [1, 2, 3], done.stderr
        assert replies[0]["result"]["serverInfo"]["name"] == "tapproval"
        decision = json.loads(replies[2]["result"]["content"][0]["text"])
        assert decision["behavior"] == "deny"

    def test_a_send_carries_the_wrist_as_its_permission_surface(self, tmp_path, monkeypatch):
        seen = {}
        monkeypatch.setattr(watch_relay, "resolve_session", lambda p, d=None: ("s1", str(tmp_path)))
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/bin/claude")
        monkeypatch.setattr(watch_relay, "_spawn_detached",
                            lambda command, log, cwd=None: seen.update(command=command))
        watch_relay.say_to_session("s1", "what changed?")
        command = seen["command"]
        assert "--permission-prompt-tool" in command
        assert command[command.index("--permission-prompt-tool") + 1] == "mcp__tapproval__approve"
        config = json.loads(command[command.index("--mcp-config") + 1])
        assert config["mcpServers"]["tapproval"]["args"] == [watch_relay.PERMISSION_TOOL]

    def test_a_wrist_run_is_told_it_ends_with_its_reply(self, tmp_path, monkeypatch):
        """On 2026-09-08 a message from the watch — "create a TestFlight
        build" — archived build 111, began the upload, wrote "I'll report
        when it lands", and was killed the moment that reply was written.
        The run believed it had a background. It did not. Now it is told."""
        seen = {}
        monkeypatch.setattr(watch_relay, "resolve_session", lambda p, d=None: ("s1", str(tmp_path)))
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/bin/claude")
        monkeypatch.setattr(watch_relay, "_spawn_detached",
                            lambda command, log, cwd=None: seen.update(command=command))
        watch_relay.say_to_session("s1", "ship a build")
        command = seen["command"]
        rule = command[command.index("--append-system-prompt") + 1]
        assert "ends the moment you reply" in rule
        for word in ("builds", "deploys", "uploads"):
            assert word in rule, "the rule must name the work it forbids"
        assert "session at the keyboard" in rule, "and where that work belongs instead"
        # The rule precedes the message: a flag after -p would be read as
        # part of what the user said.
        assert command.index("--append-system-prompt") < command.index("-p")

    def test_a_relay_without_its_neighbour_still_sends(self, monkeypatch):
        """An install that updated the relay but not the file beside it
        must keep sending messages, not fail every send on a missing
        file."""
        assert watch_relay._permission_tool_flags("/nowhere/absent.py") == []


class TestALostTunnelIsNotALostRelay:
    """2026-09-11, 23:58, from the crash reporter's first real e-mail.

    A relay started while the previous one was still shutting down. The
    main listener bound; the tunnel listener hit "Address already in use";
    the OSError left main() and killed a process whose primary socket was
    already serving. The away route is the fallback, not the product.
    """

    def test_a_busy_tunnel_port_does_not_kill_the_relay(self, monkeypatch, fresh_auth):
        import socket
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        busy = holder.getsockname()[1]
        monkeypatch.setattr(watch_relay, "TUNNEL_PORT", busy)
        watch_relay.clear_condition("tunnel")
        try:
            got = watch_relay._start_tunnel(watch_relay.CardQueue(), fresh_auth)
        finally:
            holder.close()
        assert got is None, "a busy tunnel port must not raise"
        keys = [c["key"] for c in watch_relay.conditions()]
        assert "tunnel" in keys, "and it must not be silent either"
        said = [c["detail"] for c in watch_relay.conditions()
                if c["key"] == "tunnel"][0]
        assert "away" in said.lower() and "unaffected" in said.lower(), said
        watch_relay.clear_condition("tunnel")

    def test_a_stop_is_not_proved_by_one_of_two_ports(self, monkeypatch):
        """The trigger. --ensure watched the main port only, saw it free,
        and started a replacement into a tunnel port still held."""
        import socket
        holder = socket.socket()
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(1)
        busy = holder.getsockname()[1]
        monkeypatch.setattr(watch_relay, "TUNNEL_PORT", busy)
        monkeypatch.setattr(watch_relay, "_probe_relay", lambda timeout=2: None)
        try:
            assert watch_relay._relay_is_down() is False, (
                "the main port being free is not the whole answer"
            )
        finally:
            holder.close()
        assert watch_relay._relay_is_down() is True

    def test_a_port_nobody_holds_reads_as_free(self):
        import socket
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
        probe.close()
        assert watch_relay._port_in_use(free) is False


class TestAWatchThatSpeaksDanish:
    """The wrist is Danish, and so is much of what gets typed on it.

    Found by review on 2026-09-11 against the real compiler rather than by
    reading. ``json.dumps`` at its default writes a \\u escape for any
    non-ASCII character, and AppleScript has no such escape: it does not
    mangle the text, it refuses to compile. Every session started from the
    wrist containing a Danish letter, an emoji or one of the smart quotes
    iOS substitutes as you type lost the Terminal route for the whole life
    of the feature — and nobody noticed, because the .command fallback
    uses the unescaped string and quietly worked.

    Compiled with osacompile, never osascript: running it would ask
    Terminal for an automation consent a test cannot give, and hang.
    """

    @staticmethod
    def _compiles(text, ensure_ascii=False):
        """(ok, what it said) for the AppleScript the relay would build."""
        import shlex as _shlex
        script = "cd %s && claude -- %s" % (_shlex.quote("/tmp/p"),
                                         _shlex.quote(text))
        apple = ('tell application "Terminal"\n'
                 "  activate\n"
                 "  do script %s\n"
                 "end tell" % json.dumps(script, ensure_ascii=ensure_ascii))
        with tempfile.TemporaryDirectory() as scratch:
            done = subprocess.run(["osacompile", "-o", os.path.join(scratch, "t.scpt"),
                                   "-e", apple],
                                  capture_output=True, text=True, timeout=30)
        return done.returncode == 0, ((done.stderr or "") + (done.stdout or "")).strip()

    @pytest.mark.parametrize("text", [
        "ordinary ascii",
        "k\u00f8r testene",                       # Danish
        "ship it \U0001f680",                     # emoji
        "fix the \u201csmart\u201d quotes",        # what iOS types for you
    ])
    def test_what_the_relay_builds_compiles(self, text):
        if sys.platform != "darwin" or not shutil.which("osacompile"):
            pytest.skip("osacompile only exists on macOS")
        ok, said = self._compiles(text)
        assert ok, said

    def test_the_old_escaping_is_what_broke_it(self):
        """Prove the bug, not just the fix. Without this the test above
        would pass on a version that was never broken in the first place."""
        if sys.platform != "darwin" or not shutil.which("osacompile"):
            pytest.skip("osacompile only exists on macOS")
        ok, said = self._compiles("k\u00f8r testene", ensure_ascii=True)
        assert not ok and "-2741" in said, said
        assert self._compiles("ordinary ascii", ensure_ascii=True)[0], (
            "ASCII was always fine; the fault is the escape, not the quoting")

    def test_the_relay_does_not_use_the_default(self):
        """Walked as syntax, not as text.

        The first version searched start_session's source for
        "ensure_ascii=False" and passed with the fix removed, because the
        comment explaining the fix says the same words. A check a comment
        can satisfy is not a check.
        """
        with open(watch_relay.__file__, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        func = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "start_session")
        dumps = [node for node in ast.walk(func)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and node.func.attr == "dumps"]
        assert dumps, "start_session no longer builds the AppleScript here"
        for call in dumps:
            kwargs = {kw.arg: kw.value for kw in call.keywords}
            assert "ensure_ascii" in kwargs, (
                "json.dumps at its default writes a \\u escape AppleScript "
                "cannot read — a Danish word becomes a compilation error")
            assert getattr(kwargs["ensure_ascii"], "value", None) is False


class TestNewSessionFromTheWatch:
    """Starting a real Claude Code session from the wrist.

    Not `claude -p`: a headless session never fires the PermissionRequest
    hook, so it would be the one session that could not ask the watch
    anything. The relay opens a Terminal window instead. Every failure
    must come back as words the watch can show.
    """

    def _projects(self, tmp_path):
        """A fake ~/.claude/projects with two sessions in two directories."""
        root = tmp_path / "projects"
        for slug, cwd, age in (("-Users-x-Developer-acme", tmp_path / "acme", 60),
                               ("-Users-x-Developer-pantri", tmp_path / "pantri", 3600)):
            (root / slug).mkdir(parents=True)
            cwd.mkdir()
            f = root / slug / ("s-%s.jsonl" % slug[-5:])
            f.write_text(json.dumps({"type": "user", "cwd": str(cwd),
                                     "message": {"role": "user", "content": "hi"}}) + "\n",
                         encoding="utf-8")
            os.utime(f, (time.time() - age, time.time() - age))
        return str(root)

    def test_known_projects_are_recent_directories_newest_first(self, tmp_path, monkeypatch):
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})   # nothing live
        rows = watch_relay.known_projects(projects_dir=self._projects(tmp_path))
        assert [r["name"] for r in rows] == ["acme", "pantri"]
        assert all(os.path.isdir(r["path"]) for r in rows)

    def test_known_projects_drop_directories_that_no_longer_exist(self, tmp_path, monkeypatch):
        import shutil
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        root = self._projects(tmp_path)
        shutil.rmtree(tmp_path / "pantri")
        assert [r["name"] for r in watch_relay.known_projects(projects_dir=root)] == ["acme"]

    def test_refuses_anything_but_a_mac(self, tmp_path):
        assert watch_relay.start_session("/x", "go", platform="linux") == "new sessions need a Mac"

    def test_refuses_an_empty_message(self):
        assert watch_relay.start_session("/x", "   ", platform="darwin") == "empty"

    def test_refuses_a_directory_claude_code_has_never_worked_in(self, tmp_path, monkeypatch):
        """The watch never types a path, and the relay never opens a
        terminal somewhere it has not already seen Claude Code run."""
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        root = self._projects(tmp_path)
        assert watch_relay.start_session(str(tmp_path / "elsewhere"), "go",
                                         projects_dir=root, platform="darwin") == "unknown project"

    def test_says_when_claude_is_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: None)
        root = self._projects(tmp_path)
        assert watch_relay.start_session(str(tmp_path / "acme"), "go",
                                         projects_dir=root, platform="darwin") == "claude not on PATH"

    def test_a_terminal_that_will_not_open_is_reported_in_words(self, tmp_path, monkeypatch):
        """No one logged in at the screen is the usual reason; the watch
        must be able to say so rather than spin."""
        import subprocess as sp
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/local/bin/claude")
        monkeypatch.setattr(watch_relay.subprocess, "run", lambda *a, **k: sp.CompletedProcess(
            a[0], 1, "", "execution error: Not authorized to send Apple events to Terminal. (-1743)"))
        root = self._projects(tmp_path)
        status = watch_relay.start_session(str(tmp_path / "acme"), "go",
                                           projects_dir=root, platform="darwin")
        assert status.startswith("could not open Terminal: ")
        assert "Not authorized" in status
        assert ".command" in status, "the fallback must say it was tried too"

    def test_a_terminal_that_ignores_apple_events_gets_a_command_file_instead(self, tmp_path, monkeypatch):
        """Measured on the release Mac, 2026-09-08: osascript hung until
        its timeout on every tap, because the automation consent a
        background relay cannot ask for was never given. `open` on a
        .command file needs no consent."""
        import subprocess as sp
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/local/bin/claude")
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "osascript":
                raise sp.TimeoutExpired(cmd, kw.get("timeout"))
            return sp.CompletedProcess(cmd, 0, "", "")
        monkeypatch.setattr(watch_relay.subprocess, "run", fake_run)
        root = self._projects(tmp_path)
        status = watch_relay.start_session(str(tmp_path / "acme"), "Fix CI; it's red",
                                           projects_dir=root, platform="darwin")
        assert status == "started"
        assert [c[0] for c in calls] == ["osascript", "open"]
        command_file = calls[1][1]
        assert command_file.endswith(".command")
        assert oct(os.stat(command_file).st_mode & 0o777) == "0o700"
        with open(command_file) as handle:
            lines = handle.read().splitlines()
        os.unlink(command_file)
        assert lines[0] == "#!/bin/bash"
        assert lines[1] == 'rm -f -- "$0"', "the file must remove itself, not pile up in tmp"
        import shlex
        assert lines[2] == "cd %s && claude -- %s" % (
            shlex.quote(str(tmp_path / "acme")), shlex.quote("Fix CI; it's red"))

    def test_success_opens_terminal_in_that_directory_with_that_message(self, tmp_path, monkeypatch):
        import subprocess as sp
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/local/bin/claude")
        seen = {}
        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            return sp.CompletedProcess(cmd, 0, "", "")
        monkeypatch.setattr(watch_relay.subprocess, "run", fake_run)
        root = self._projects(tmp_path)
        status = watch_relay.start_session(str(tmp_path / "acme"), "Fix CI; it's red",
                                           projects_dir=root, platform="darwin")
        assert status == "started"
        assert seen["cmd"][0] == "osascript"
        script = seen["cmd"][-1]
        assert 'tell application "Terminal"' in script and "do script" in script
        # The shell line is a JSON string literal inside the AppleScript;
        # decode it and check both cwd and message are shell-quoted, so a
        # message with quotes or semicolons cannot escape into the shell.
        import shlex
        shell_line = json.loads(script.split("do script ", 1)[1].split("\n")[0])
        assert shell_line == "cd %s && claude -- %s" % (
            shlex.quote(str(tmp_path / "acme")), shlex.quote("Fix CI; it's red"))

    def test_a_message_that_looks_like_a_flag_stays_a_message(self, tmp_path, monkeypatch):
        """shlex.quote stops the shell; only "--" stops claude. Checked
        against claude 2.1.260 on 2026-09-17: `claude -p --version` prints
        the version, `claude -p -- --version` sends the words."""
        import subprocess as sp
        import shlex
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _n: "/usr/local/bin/claude")
        seen = {}
        monkeypatch.setattr(watch_relay.subprocess, "run",
                            lambda cmd, **kw: seen.update(cmd=cmd) or sp.CompletedProcess(cmd, 0, "", ""))
        root = self._projects(tmp_path)
        text = "--dangerously-skip-permissions"
        assert watch_relay.start_session(str(tmp_path / "acme"), text,
                                         projects_dir=root, platform="darwin") == "started"
        shell_line = json.loads(seen["cmd"][-1].split("do script ", 1)[1].split("\n")[0])
        words = shlex.split(shell_line)
        assert words[words.index("claude") + 1:] == ["--", text]

    def test_projects_and_new_are_ordinary_data_routes(self, tmp_path, monkeypatch):
        """/projects needs the same key as every other data route, and /new
        answers a refusal as JSON the watch can show — never a 500."""
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {})
        watch_relay.LIMITS.reset()
        server, _ = watch_relay.serve(port=0)
        _serve(server)
        base = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            # 15 s, not 3: both routes scan ~/.claude/projects, which on a
            # machine with a few dozen projects takes two or three seconds
            # by itself, and this test is about routing, not speed.
            with urllib.request.urlopen(base + "/projects", timeout=15) as r:
                assert "projects" in json.loads(r.read())
            req = urllib.request.Request(base + "/new", method="POST",
                                         data=json.dumps({"path": "/nowhere", "text": "go"}).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                body = json.loads(r.read())
            assert body["ok"] is False and body["status"] in ("unknown project", "new sessions need a Mac")
        finally:
            server.shutdown()
            server.server_close()


class TestRelayRoutes:
    """Every route through the dispatcher, from loopback — which the relay
    trusts, so these hold what each route DOES rather than who may call it
    (TestLanSourceIsNotTrusted holds that). The rules that used to sit inline in
    two long handlers now live in one table; a route added without a rule
    is the failure this class is here to catch."""

    @pytest.fixture
    def relay(self, fresh_auth):
        watch_relay.LIMITS.reset()
        auth = _known_watch(fresh_auth)
        auth.devices = []
        server, queue = watch_relay.serve(port=0, auth=auth)
        _serve(server)
        yield "http://127.0.0.1:%d" % server.server_address[1], queue, auth
        server.shutdown()
        server.server_close()

    _call = staticmethod(relay_call)

    def test_every_route_in_the_table_has_a_handler(self):
        handler = watch_relay.RelayHandler
        for method, routes in handler.ROUTES.items():
            for path, (name, rules) in routes.items():
                assert callable(getattr(handler, name)), (method, path)
                assert set(rules) <= {"auth", "lan_only", "local", "admin", "token"}, path

    def test_the_two_pairing_routes_are_the_only_ones_without_auth(self):
        open_routes = {(m, p) for m, routes in watch_relay.RelayHandler.ROUTES.items()
                       for p, (_, rules) in routes.items() if not rules.get("auth", True)}
        assert open_routes == {("GET", "/pair"), ("POST", "/enroll")}

    def test_what_reaches_the_machine_is_local_only(self):
        post = watch_relay.RelayHandler.ROUTES["POST"]
        for path in ("/card", "/heartbeat", "/admin/pair-open", "/admin/rotate", "/admin/pair-reset"):
            assert post[path][1].get("local"), path

    @pytest.mark.parametrize("method,path", [("GET", "/nope"), ("POST", "/nope"),
                                             ("GET", "/say"), ("POST", "/pending")])
    def test_an_unknown_route_or_the_wrong_method_is_not_found(self, relay, method, path):
        base, _, _ = relay
        assert self._call(base + path, method=method)[0] == 404

    def test_health_says_more_to_a_credentialed_caller(self, relay):
        base, _, _ = relay
        status, body = self._call(base + "/health")
        assert status == 200 and body["ok"] is True
        # loopback is credentialed: the details come with it
        assert "version" in body and "pending" in body

    def test_the_read_routes_answer_with_their_shapes(self, relay, monkeypatch):
        monkeypatch.setattr(watch_relay, "known_projects", lambda: [{"name": "x"}])
        monkeypatch.setattr(watch_relay, "recent_sessions", lambda: [])
        monkeypatch.setattr(watch_relay, "activity_summary", lambda: {"total": 0})
        monkeypatch.setattr(watch_relay, "usage_summary", lambda: {"input": 0})
        base, _, _ = relay
        assert self._call(base + "/projects")[1] == {"projects": [{"name": "x"}]}
        assert self._call(base + "/sessions")[1] == {"sessions": []}
        assert self._call(base + "/activity")[1] == {"total": 0}
        assert self._call(base + "/usage")[1] == {"input": 0}

    @staticmethod
    def _raw(url, headers, body=b"{}"):
        """A POST with exactly these headers — nothing added."""
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                return reply.status
        except urllib.error.HTTPError as error:
            return error.code

    # What a web page open on this Mac can send to 127.0.0.1 with no CORS
    # preflight. Measured on 2026-09-17: each of these, before the check,
    # revoked every paired device and opened the pairing window.
    BROWSER_SHAPES = [
        ({"Origin": "https://evil.example", "Content-Type": "text/plain"}, 403),
        ({"Origin": "null", "Content-Type": "application/json"}, 403),
        ({"Sec-Fetch-Site": "cross-site", "Content-Type": "text/plain"}, 403),
        ({"Sec-Fetch-Site": "same-site", "Content-Type": "application/json"}, 403),
        ({"Content-Type": "text/plain"}, 415),
        ({"Content-Type": "application/x-www-form-urlencoded"}, 415),
        ({}, 415),
    ]

    @pytest.mark.parametrize("headers,status", BROWSER_SHAPES)
    def test_a_web_page_cannot_administer_the_relay(self, relay, monkeypatch, headers, status):
        base, _, auth = relay
        revoked = []
        monkeypatch.setattr(auth, "revoke_all", lambda: revoked.append(1))
        assert self._raw(base + "/admin/pair-reset", headers) == status
        assert revoked == [], "the action must not happen at all"

    @pytest.mark.parametrize("headers,status", BROWSER_SHAPES)
    def test_a_web_page_cannot_forge_a_card(self, relay, headers, status):
        base, queue, _ = relay
        body = json.dumps({"card": {"headline": "Approve Xcode update"}}).encode()
        assert self._raw(base + "/card", headers, body) == status
        assert queue.pending() == []

    def test_a_native_client_is_still_served(self, relay, monkeypatch):
        """Prove the guard can pass as well as fail: the headers the hook,
        the bridge and the watch actually send."""
        base, _, auth = relay
        revoked = []
        monkeypatch.setattr(auth, "revoke_all", lambda: revoked.append(1))
        assert self._raw(base + "/admin/pair-reset",
                         {"Content-Type": "application/json; charset=utf-8"}) == 200
        assert revoked == [1]
        assert self._raw(base + "/admin/pair-reset",
                         {"Content-Type": "application/json",
                          "Sec-Fetch-Site": "none"}) == 200

    def test_a_web_page_cannot_read_either(self, relay):
        base, _, _ = relay
        request = urllib.request.Request(base + "/pending",
                                         headers={"Sec-Fetch-Site": "cross-site"})
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        assert caught.value.code == 403

    def test_an_unknown_thread_is_empty_not_an_error(self, relay):
        base, _, _ = relay
        status, body = self._call(base + "/thread?id=nope")
        assert status == 200
        assert body == {"turns": [], "running_tasks": 0, "running_tool": None,
                        "modified_seconds_ago": None}

    def test_the_tunnel_route_hands_over_the_away_addresses(self, relay, monkeypatch):
        monkeypatch.setattr(watch_relay, "TUNNEL_URL", "https://t.example")
        base, _, _ = relay
        status, body = self._call(base + "/tunnel")
        assert status == 200 and body["url"] == "https://t.example"

    def test_a_malformed_card_is_refused_before_anything_waits(self, relay):
        base, _, _ = relay
        status, body = self._call(base + "/card", method="POST", body={"nope": 1})
        assert status == 400 and "card" in body["error"]

    def test_a_malformed_decision_is_refused(self, relay):
        base, _, auth = relay
        key = auth.bootstrap
        assert self._call(base + "/decision", token=key, method="POST", body={"id": 5})[0] == 400
        assert self._call(base + "/decision", token=key, method="POST",
                          body={"id": "x", "decision": "maybe"})[0] == 400

    def test_a_decision_for_a_card_nobody_asked_is_not_accepted(self, relay):
        base, _, auth = relay
        status, body = self._call(base + "/decision", token=auth.bootstrap, method="POST",
                                  body={"id": "ghost", "decision": "allow"})
        assert status == 200 and body == {"ok": False}

    def test_loopback_alone_cannot_answer_a_card(self, relay):
        # A command Claude runs is a local process too. Reading and posting
        # cards stay free on loopback; answering and speaking need a key.
        base, _, auth = relay
        assert self._call(base + "/decision", method="POST",
                          body={"id": "ghost", "decision": "allow"})[0] == 403
        assert self._call(base + "/say", method="POST",
                          body={"session_id": "x", "text": "hi"})[0] == 403
        assert self._call(base + "/decision", token="not-a-key", method="POST",
                          body={"id": "ghost", "decision": "allow"})[0] == 403
        # The bootstrap secret (the 0600 file, which the Mac bridge reads)
        # and a device token both open the door.
        assert self._call(base + "/decision", token=auth.bootstrap, method="POST",
                          body={"id": "ghost", "decision": "allow"})[0] == 200
        device = auth.issue_device("watch-1")
        assert self._call(base + "/decision", token=device, method="POST",
                          body={"id": "ghost", "decision": "allow"})[0] == 200
        # Posting a card from loopback still needs nothing (400: bad body,
        # which means it got past the door).
        assert self._call(base + "/card", method="POST", body={"nope": 1})[0] == 400

    def test_the_heartbeat_records_the_watchs_presence(self, relay):
        base, queue, _ = relay
        status, body = self._call(base + "/heartbeat", method="POST",
                                  body={"watch_seen_seconds_ago": 3})
        assert status == 200 and body == {"ok": True}
        assert queue.watch_seen_seconds_ago() is not None

    def test_a_new_session_with_no_words_is_refused_in_words(self, relay):
        base, _, _ = relay
        status, body = self._call(base + "/new", method="POST", body={"path": "/x", "text": " "})
        assert status == 200 and body == {"ok": False, "status": "empty"}

    def test_the_second_send_in_the_same_moment_waits_its_turn(self, relay):
        base, _, _ = relay
        gate = watch_relay.LIMITS.gate("say", 1)
        assert gate.acquire(blocking=False)
        try:
            status, body = self._call(base + "/say", token=relay[2].bootstrap, method="POST",
                                      body={"session_id": "x", "text": "hi"})
        finally:
            gate.release()
        assert status == 429 and "already" in body["error"]

    def test_administration_from_this_machine_opens_the_pairing_window(self, relay):
        base, _, auth = relay
        status, body = self._call(base + "/admin/pair-open", method="POST")
        assert status == 200 and body["ok"] is True and body["seconds"] > 0
        assert auth._window_until > 0

    def test_a_rotation_answers_in_one_word(self, relay, monkeypatch):
        monkeypatch.setattr(watch_relay, "_rotate_tunnel_prefix", lambda secret: None)
        base, _, _ = relay
        status, body = self._call(base + "/admin/rotate", method="POST")
        assert status == 200 and body == {"ok": True, "rotated": True}


class TestStatusFacts:
    """--status as facts, not lines: the same truths the printout tells,
    reachable without parsing it."""

    def test_a_fresh_machine_reports_nothing_installed(self, tmp_path, monkeypatch):
        import ClaudeRiskClassifier as crc
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setattr(crc, "_plugin_install", lambda: None)
        monkeypatch.setattr(crc, "_relay_health", lambda: None)
        monkeypatch.setattr(crc, "read_audit", lambda policy: [])
        facts = crc.status_facts()
        assert facts["handlers"] == [] and facts["plugin_only"] is False
        assert facts["relay_wired"] is False and facts["relay_health"] is None
        assert facts["entries"] == []

    def test_a_plugin_install_reports_its_own_mode(self, tmp_path, monkeypatch):
        import ClaudeRiskClassifier as crc
        monkeypatch.setenv("CLAUDE_SETTINGS_PATH", str(tmp_path / "settings.json"))
        monkeypatch.setattr(crc, "_plugin_install", lambda: {
            "root": "/plugins/tapproval", "env": {"CLAUDE_RISK_MODE": "enforce"}, "relay": True})
        monkeypatch.setattr(crc, "_relay_health", lambda: {"watch_seen_seconds_ago": 4})
        monkeypatch.setattr(crc, "read_audit", lambda policy: [])
        facts = crc.status_facts()
        assert facts["plugin_only"] is True
        assert facts["mode"] == "enforce"
        assert facts["relay_wired"] is True
        assert facts["relay_health"]["watch_seen_seconds_ago"] == 4


class TestInstallerHelpers:
    """The installer's three moves, each on its own: point our hook at a
    command (idempotently), take our hooks out and nobody else's, and
    strip the env we injected."""

    def test_sync_adds_our_hook_with_the_matcher_when_absent(self):
        import ClaudeRiskClassifier as crc
        entries = []
        assert crc._sync_hook(entries, "/x/ClaudeRiskClassifier.py", "*", "ClaudeRiskClassifier.py")
        assert entries == [{"matcher": "*", "hooks": [
            {"type": "command", "command": "/x/ClaudeRiskClassifier.py", "timeout": 10}]}]

    def test_sync_is_a_no_op_when_already_right(self):
        import ClaudeRiskClassifier as crc
        entries = [{"hooks": [{"type": "command", "command": "/x/ClaudeRiskClassifier.py"}]}]
        assert not crc._sync_hook(entries, "/x/ClaudeRiskClassifier.py", "*", "ClaudeRiskClassifier.py")
        assert len(entries) == 1

    def test_sync_repoints_a_stale_copy_in_place(self):
        import ClaudeRiskClassifier as crc
        entries = [{"hooks": [{"type": "command", "command": "/old/ClaudeRiskClassifier.py"},
                              {"type": "command", "command": "/theirs/other.py"}]}]
        assert crc._sync_hook(entries, "/new/ClaudeRiskClassifier.py", "*", "ClaudeRiskClassifier.py")
        assert entries[0]["hooks"][0]["command"] == "/new/ClaudeRiskClassifier.py"
        assert entries[0]["hooks"][1]["command"] == "/theirs/other.py"
        assert len(entries) == 1

    def test_removal_keeps_everyone_elses_hooks_and_counts_ours(self):
        import ClaudeRiskClassifier as crc
        hooks = {"PermissionRequest": [{"matcher": "*", "hooks": [
                     {"type": "command", "command": "python3 /x/ClaudeRiskClassifier.py"},
                     {"type": "command", "command": "/theirs/lint.sh"}]}],
                 "SessionStart": [{"hooks": [
                     {"type": "command", "command": "python3 /x/watch_relay.py --ensure"}]}]}
        removed = crc._remove_our_hooks(hooks)
        assert removed == 2
        assert hooks == {"PermissionRequest": [{"matcher": "*", "hooks": [
            {"type": "command", "command": "/theirs/lint.sh"}]}]}

    def test_only_our_env_keys_are_stripped(self):
        import ClaudeRiskClassifier as crc
        data = {"env": {"CLAUDE_RISK_MODE": "enforce", "CLAUDE_RISK_RELAY": "x", "EDITOR": "vim"}}
        crc._strip_our_env(data)
        assert data == {"env": {"EDITOR": "vim"}}
        data = {"env": {"CLAUDE_RISK_MODE": "enforce"}}
        crc._strip_our_env(data)
        assert data == {}


class TestReportFacts:
    """The report's numbers without the report's prose."""

    def _entries(self):
        return [
            {"tier": "SAFE", "decision": "allow", "tool": "Bash", "project": "a"},
            {"tier": "SAFE", "decision": "allow", "tool": "Bash", "project": "a"},
            {"tier": "HIGH", "decision": "escalate", "tool": "Bash", "project": "b", "headline": "rm -rf build"},
            {"tier": "CRITICAL", "decision": "deny", "tool": "Bash", "project": "b", "headline": "git push --force"},
        ]

    def test_escalations_and_denies_both_count_as_interruptions(self):
        import ClaudeRiskClassifier as crc
        f = crc.report_facts(self._entries())
        assert (f["total"], f["escalated"], f["saved"]) == (4, 2, 2)
        assert f["tiers"]["SAFE"] == 2 and f["tiers"]["CRITICAL"] == 1

    def test_projects_are_split_with_their_silenced_share(self):
        import ClaudeRiskClassifier as crc
        f = crc.report_facts(self._entries())
        assert f["by_project"] == [("a", 2, 0, 100.0), ("b", 2, 2, 0.0)]

    def test_only_auto_allowed_tools_make_the_top_list(self):
        import ClaudeRiskClassifier as crc
        f = crc.report_facts(self._entries())
        assert f["by_tool"] == [("Bash", 2)]
        assert [e["headline"] for e in f["escalations"]] == ["rm -rf build", "git push --force"]

    def test_an_empty_log_is_all_zeros(self):
        import ClaudeRiskClassifier as crc
        f = crc.report_facts([])
        assert f["total"] == 0 and f["escalated"] == 0 and f["by_project"] == []


class TestMergeToolRuns:
    """Consecutive tool turns read as one phrase, the way the phone words
    them; a spoken turn ends the run."""

    def test_one_described_call_is_named_by_its_purpose(self):
        import watch_dashboard as wd
        turns = [{"kind": "tool", "text": "Bash", "desc": "the tests", "at": "t1"}]
        merged = wd._merge_tool_runs(turns)
        assert merged == [{"role": "assistant", "kind": "tool", "at": "t1", "text": "Ran the tests"}]

    def test_several_calls_collapse_into_counts_and_keep_order(self):
        import watch_dashboard as wd
        turns = [{"kind": "tool", "text": "Bash", "desc": "", "at": "1"},
                 {"kind": "tool", "text": "Bash", "desc": "", "at": "2"},
                 {"kind": "tool", "text": "Edit", "desc": "", "at": "3"},
                 {"kind": "text", "role": "assistant", "text": "Done.", "at": "4"},
                 {"kind": "tool", "text": "Read", "desc": "", "at": "5"}]
        merged = wd._merge_tool_runs(turns)
        assert [m["kind"] for m in merged] == ["tool", "text", "tool"]
        assert merged[0]["at"] == "3" and "Bash" not in merged[0]["text"]
        assert merged[1]["text"] == "Done."

    def test_no_tools_means_the_turns_come_back_as_they_were(self):
        import watch_dashboard as wd
        turns = [{"kind": "text", "role": "user", "text": "hi", "at": "1"}]
        assert wd._merge_tool_runs(turns) == turns


class TestSessionRegistry:
    """What the wrist shows must be what the phone shows: the sessions
    Remote Control lists, under the names the person gave them."""

    def _registry(self, tmp_path, entries):
        for n, entry in enumerate(entries):
            (tmp_path / ("%d.json" % n)).write_text(json.dumps(
                dict({"pid": os.getpid(), "entrypoint": "cli"}, **entry)), encoding="utf-8")

    def test_bridge_and_rename_are_read_from_the_registry(self, tmp_path):
        self._registry(tmp_path, [
            {"sessionId": "phone-1", "bridgeSessionId": "session_x", "name": "acme-3f", "nameSource": "derived"},
            {"sessionId": "local-1", "name": "Billing fix", "nameSource": "user"}])
        reg = watch_relay.session_registry(sessions_dir=str(tmp_path))
        assert reg["phone-1"]["bridged"] is True and reg["phone-1"]["name"] == ""
        assert reg["local-1"]["bridged"] is False and reg["local-1"]["name"] == "Billing fix"

    def test_the_list_mirrors_the_phone_when_the_phone_has_sessions(self, tmp_path, monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"phone-1": "Terminal", "local-1": "Terminal"})
        monkeypatch.setattr(watch_dashboard, "session_registry", lambda: {
            "phone-1": {"status": "Terminal", "bridged": True, "name": ""},
            "local-1": {"status": "Terminal", "bridged": False, "name": ""}})
        for sid in ("phone-1", "local-1"):
            _write_transcript(tmp_path, "-p", sid + ".jsonl",
                              [{"cwd": "/x/proj", "message": {"role": "user", "content": "start " + sid}}])
        ids = [s["session_id"] for s in watch_relay.recent_sessions(projects_dir=str(tmp_path))]
        assert ids == ["phone-1"]

    def test_without_remote_control_every_live_session_shows(self, tmp_path, monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions",
                            lambda: {"a-1": "Terminal", "b-1": "Terminal"})
        monkeypatch.setattr(watch_dashboard, "session_registry", lambda: {
            "a-1": {"status": "Terminal", "bridged": False, "name": ""},
            "b-1": {"status": "Terminal", "bridged": False, "name": ""}})
        for sid in ("a-1", "b-1"):
            _write_transcript(tmp_path, "-p", sid + ".jsonl",
                              [{"cwd": "/x/proj", "message": {"role": "user", "content": "start " + sid}}])
        assert len(watch_relay.recent_sessions(projects_dir=str(tmp_path))) == 2

    def test_a_renamed_session_carries_its_name(self, tmp_path, monkeypatch):
        import watch_dashboard
        monkeypatch.setattr(watch_dashboard, "live_sessions", lambda: {"r-1": "Terminal"})
        monkeypatch.setattr(watch_dashboard, "session_registry", lambda: {
            "r-1": {"status": "Terminal", "bridged": False, "name": "Billing fix"}})
        _write_transcript(tmp_path, "-p", "r-1.jsonl",
                          [{"cwd": "/x/proj", "message": {"role": "user", "content": "fix the invoice totals"}}])
        assert watch_relay.recent_sessions(projects_dir=str(tmp_path))[0]["title"] == "Billing fix"


class TestFirstPairingIsAWindow:
    """A machine that has never paired opens its door for half an hour at
    every relay start and session start — not until someone walks in."""

    def test_open_right_after_start_and_shut_half_an_hour_later(self, fresh_auth, monkeypatch):
        auth = fresh_auth
        assert not auth.paired_ever and auth.window_open()
        now = time.time()
        monkeypatch.setattr(watch_relay.time, "time",
                            lambda: now + watch_relay.PAIR_FIRST_WINDOW_SECONDS + 1)
        assert not auth.window_open()
        assert auth.claim_window("192.168.1.9") is None

    def test_the_window_a_relay_start_lights_is_the_first_window(self, fresh_auth):
        """main() used to call open_window() with its default — the
        ten-minute --pair fuse — on a never-paired relay, cutting the half
        hour Auth() had just lit to a third. relight() is the operation
        that means 'first contact', and a no-op once anything has paired."""
        auth = fresh_auth
        auth.paired_ever = False
        before = time.time()
        until = auth.relight()
        assert until - before >= watch_relay.PAIR_FIRST_WINDOW_SECONDS - 5
        assert until - before > watch_relay.PAIR_WINDOW_SECONDS

    def test_a_session_start_relights_it(self, fresh_auth, monkeypatch):
        auth = fresh_auth
        now = time.time()
        monkeypatch.setattr(watch_relay.time, "time",
                            lambda: now + watch_relay.PAIR_FIRST_WINDOW_SECONDS + 1)
        assert not auth.window_open()
        auth.relight()
        assert auth.window_open()
        assert auth.claim_window("192.168.1.9") == auth.bootstrap

    def test_the_first_watch_shuts_the_door_and_a_session_start_no_longer_opens_it(self, fresh_auth):
        auth = fresh_auth
        assert auth.window_open()
        auth.issue_device("w1", source="lan")
        assert auth.paired_ever and not auth.window_open()
        auth.relight()
        assert not auth.window_open()

    def test_ensure_relights_only_a_never_paired_relay(self, monkeypatch):
        calls = []
        monkeypatch.setattr(watch_relay, "_self_update", lambda: None)
        monkeypatch.setattr(watch_relay, "_admin_call", lambda path: calls.append(path))
        health = {"version": watch_relay.RELAY_VERSION, "pending": 0, "paired_ever": False}
        monkeypatch.setattr(watch_relay, "_probe_relay", lambda: health)
        assert watch_relay.ensure_running() == 0
        assert calls == ["/admin/pair-relight"]
        health["paired_ever"] = True
        assert watch_relay.ensure_running() == 0
        assert calls == ["/admin/pair-relight"]


class TestTheUpdateLeavesTheBlockingPath:
    """The SessionStart hook never waits on git: when an update is due it
    spawns the pull and returns; the pull replaces the relay itself."""

    def test_a_due_update_is_spawned_not_run(self, tmp_path, monkeypatch):
        stamp = tmp_path / "stamp"
        stamp.write_text("0", encoding="utf-8")
        os.utime(stamp, (0, 0))
        monkeypatch.setattr(watch_relay, "_UPDATE_STAMP", str(stamp))
        monkeypatch.setattr(os.path, "isdir", lambda p: True)
        spawned = []
        monkeypatch.setattr(watch_relay, "_spawn_detached",
                            lambda argv, log: spawned.append(argv) or None)
        def no_git(*a, **k):
            raise AssertionError("git ran on the blocking path")
        monkeypatch.setattr(watch_relay.subprocess, "run", no_git)
        watch_relay._self_update()
        assert spawned and spawned[0][-1] == "--update"

    def test_the_detached_half_replaces_the_relay_only_if_the_code_moved(self, monkeypatch):
        ensured = []
        monkeypatch.setattr(watch_relay, "ensure_running",
                            lambda updated=None: ensured.append(updated) or 0)
        monkeypatch.setattr(watch_relay, "_pull_update", lambda: False)
        assert watch_relay.main(["--update"]) == 0
        assert ensured == []
        monkeypatch.setattr(watch_relay, "_pull_update", lambda: True)
        assert watch_relay.main(["--update"]) == 0
        assert ensured == [True]


class TestNoPersonalIdentityInTrackedFiles:
    """CLAUDE.md rules 5 and 6 are a promise, and this is the check.

    The forbidden strings are themselves personal, so they cannot live in
    a tracked file: the list is read from .private/forbidden-strings.txt
    (gitignored) or the TAPPROVAL_FORBIDDEN_FILE environment variable, one
    string per line, and the test skips where neither exists — a public
    checkout has no personal data to protect and no list to protect it
    with."""

    def _forbidden(self):
        root = _ROOT
        path = os.environ.get("TAPPROVAL_FORBIDDEN_FILE") or os.path.join(
            root, ".private", "forbidden-strings.txt")
        if not os.path.isfile(path):
            pytest.skip("no forbidden-strings list on this machine")
        with open(path, encoding="utf-8") as handle:
            words = [w.strip() for w in handle if w.strip() and not w.startswith("#")]
        return root, words

    def test_tracked_files_carry_none_of_them(self):
        root, words = self._forbidden()
        offenders = []
        for rel in _tracked_files(root):
            if rel.startswith("design/"):
                continue
            try:
                with open(os.path.join(root, rel), "rb") as handle:
                    text = handle.read().decode("utf-8", "ignore").lower()
            except OSError:
                continue
            for word in words:
                if word.lower() in text:
                    offenders.append("%s: %s" % (rel, word))
        assert not offenders, "\n".join(offenders)


def _tracked_files(root):
    """Every path git tracks under ``root``, NUL-separated so a space in a
    name cannot split it, and checked so a missing git fails the test
    rather than emptying it. Files deleted but not yet staged are
    skipped. Two tests walk the tree; this is the one walk."""
    listed = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                            capture_output=True, check=True).stdout
    names = [rel for rel in listed.decode("utf-8", "replace").split("\0")
             if rel and os.path.exists(os.path.join(root, rel))]
    assert names, "git ls-files returned nothing — not a checkout?"
    return names


class TestTheHookStaysFast:
    """The hook runs in a fresh interpreter on every tool call, before the
    call. Measured 2026-09-08 on the release Mac: 19 ms to import, 15 µs
    to classify. These ceilings are ten and twenty times that — not to
    catch a micro-regression (nothing this coarse can) but the
    accidental network call, directory walk or sleep that would put a
    visible pause in front of every command."""

    CORPUS = ["ls -la", "git status", "rm -rf build", "npm test", "cat ~/.ssh/id_rsa",
              "curl -X POST https://api.example.com/v1 -d @x", "git push --force origin main",
              "python3 -m pytest -q", "find . -name '*.pyc' -delete", "docker compose up -d",
              "gh pr merge 5", "echo hi > /etc/hosts", "aws s3 rm s3://bucket --recursive",
              "sed -i 's/a/b/' file.txt", "kubectl delete ns prod"] * 20

    def test_classifying_three_hundred_commands_is_quick(self):
        import time
        for command in self.CORPUS[:15]:                       # warm caches
            crc.classify({"tool_name": "Bash", "tool_input": {"command": command}})
        started = time.perf_counter()
        for command in self.CORPUS:
            crc.classify({"tool_name": "Bash", "tool_input": {"command": command}})
        per_call = (time.perf_counter() - started) / len(self.CORPUS)
        assert per_call < 300e-6, "classify() now averages %.0f µs" % (per_call * 1e6)

    def test_importing_the_hook_is_quick(self):
        import importlib
        import time
        started = time.perf_counter()
        importlib.reload(crc)
        took = time.perf_counter() - started
        assert took < 0.2, "importing ClaudeRiskClassifier took %.0f ms" % (took * 1e3)


def _ci_files(*names):
    """The release machinery's files, or a skip.

    sync-helper.sh runs this suite in the layout it publishes, and the
    public repo gets the hook and the tests but none of the release
    tooling — no workflow, no ci-local.sh, no ci-runner.sh. Read blindly,
    fourteen tests turned that absence into fourteen failures and stopped
    a sync that was not broken.
    """
    root = os.path.dirname(os.path.abspath(__file__))
    out = []
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            pytest.skip("%s is not in this layout (the public repo)" % name)
        with open(path, encoding="utf-8") as handle:
            out.append(handle.read())
    return out


class TestTheLocalFallbackRunsWhatCiRuns:
    """`ci-local.sh` is the proof when GitHub will not run the workflow.

    On 2026-09-17 every job failed in three seconds with no steps at all —
    GitHub had stopped starting them over billing — which looks exactly
    like a broken tree and is not one. The fallback exists for that day,
    and a fallback that quietly checks less than CI is worse than none: it
    would report green over a matrix entry or a locale nobody ran.

    The two files are deliberately not generated from one another (a
    workflow that sources a shell script is harder to read than either),
    so this holds the pieces that matter equal.
    """

    @staticmethod
    def _files():
        return _ci_files(".github/workflows/tests.yml", "ci-local.sh")

    def test_every_interpreter_in_the_matrix_is_run_locally(self):
        workflow, local = self._files()
        matrix = re.search(r'python:\s*\[([^\]]+)\]', workflow).group(1)
        versions = re.findall(r'"([\d.]+)"', matrix)
        assert versions, "the matrix should name interpreters"
        loop = re.search(r'for version in ([^;]+); do', local).group(1).split()
        assert loop == versions, (loop, versions)

    def test_the_same_scripts_are_shellchecked(self):
        workflow, local = self._files()
        def targets(text):
            line = re.search(r'^\s*(?:- run: )?shellcheck (install\.sh[^\n]+)',
                             text, re.MULTILINE).group(1)
            # ci-local.sh checks itself too; CI has no such file to check.
            return sorted(set(line.split()) - {"ci-local.sh"})
        assert targets(local) == targets(workflow)

    def test_ruff_is_run_with_the_same_rules(self):
        workflow, local = self._files()
        def flags(text):
            return re.search(r'ruff check ([^\n]+)', text).group(1).strip()
        assert flags(local) == flags(workflow)

    @pytest.mark.parametrize("fragment", [
        "-destination 'generic/platform=watchOS'",      # the device compile
        "-only-testing:TapprovalTests",                 # the second pass
        "-testLanguage en -testRegion DK",              # in the release Mac's locale
        "CODE_SIGNING_ALLOWED=NO",
    ])
    def test_the_watch_job_runs_the_same_xcodebuild(self, fragment):
        workflow, local = self._files()
        assert fragment in workflow, "the workflow changed; update ci-local.sh too"
        assert fragment in local, fragment

    def test_the_dependency_refusal_is_checked_in_both(self):
        workflow, local = self._files()
        for name in ("requirements.txt", "pyproject.toml"):
            assert name in workflow and name in local, name


class TestCiCanBeMovedToThisMacAndBack:
    """Where CI runs is one repository variable, and coming back is
    deleting it.

    The fallback earns its keep only if the return trip is certain: a
    switch that has to be reverted in a commit is a switch nobody makes on
    the bad day, and a default that points at a Mac in someone's house is a
    repository a stranger cannot build. So the checks are: GitHub is the
    default everywhere, exactly one of the two paths can run, and the
    script that flips it names the same variable this file reads.
    """

    @staticmethod
    def _files():
        return _ci_files(".github/workflows/tests.yml", "ci-runner.sh", "ci-local.sh")

    def test_unset_means_github(self):
        """A fresh clone, and the repository after ./ci-runner.sh github,
        have no CI_RUNNER at all. Every hosted job must run in that state."""
        workflow, _, _ = self._files()
        # Only the jobs: block — "on: push:" is indented the same way.
        jobs = re.findall(r"^  (\w[\w-]*):\n((?:    .*\n|\n)*)",
                          workflow.split("\njobs:\n", 1)[1], re.MULTILINE)
        assert len(jobs) >= 4, [name for name, _ in jobs]
        for name, body in jobs:
            guard = re.search(r"if: vars\.CI_RUNNER (==|!=) 'self-hosted'", body)
            assert guard, "%s has no CI_RUNNER guard; it would run on both" % name
            runs_on = re.search(r"runs-on: (.+)", body).group(1)
            if name == "mini":
                assert guard.group(1) == "==" and "self-hosted" in runs_on
            else:
                assert guard.group(1) == "!=", name
                assert "self-hosted" not in runs_on, (
                    "%s would point at a machine in someone's house" % name)

    def test_exactly_one_path_runs_in_either_setting(self):
        workflow, _, _ = self._files()
        guards = re.findall(r"if: vars\.CI_RUNNER (==|!=) 'self-hosted'", workflow)
        for setting in ("self-hosted", ""):
            running = [g for g in guards
                       if (g == "==") == (setting == "self-hosted")]
            assert running, "nothing runs when CI_RUNNER=%r" % setting

    def test_the_mac_job_runs_the_same_checks(self):
        """Not a smaller set: the Mac job runs ci-local.sh, which
        TestTheLocalFallbackRunsWhatCiRuns holds equal to the hosted jobs."""
        workflow, _, _ = self._files()
        mini = workflow.split("  mini:", 1)[1].split("\n  pytest:", 1)[0]
        assert "./ci-local.sh" in mini
        assert "actions/checkout" in mini

    def test_the_switch_script_and_the_workflow_agree(self):
        workflow, switch, _ = self._files()
        assert "CI_RUNNER" in switch and "CI_RUNNER" in workflow
        # The labels the workflow selects on must be the labels the runner
        # registers with, or the job queues for a machine that never answers.
        wanted = re.search(r"runs-on: \[([^\]]+)\]", workflow).group(1)
        labels = re.search(r'LABELS="([^"]+)"', switch).group(1).split(",")
        assert sorted(x.strip() for x in wanted.split(",")) == sorted(labels)

    def test_going_back_deletes_rather_than_sets(self):
        _, switch, _ = self._files()
        github = switch.split("  github)", 1)[1].split(";;", 1)[0]
        assert "gh variable delete CI_RUNNER" in github
        assert "variable set" not in github, (
            "going back must clear the variable, not set another value")

    def test_it_refuses_to_point_at_a_mac_that_is_not_listening(self):
        _, switch, _ = self._files()
        mini = switch.split("\n  mini)", 1)[1].split(";;", 1)[0]
        assert "runner_state" in mini, (
            "switching to a runner nobody registered queues every job forever")


class TestTheDocumentsDoNotRestateTheBuildNumber:
    """WatchApp/BUILD_NUMBER is the one place the current build lives;
    deploy-testflight.sh rewrites and commits it. Five documents once
    said "reads 108" a day after it read 109 — two of them in the same
    sentence that named the file as the authority. Prose may cite a
    build in its history ("build 106 retired"); it may not restate what
    that file currently holds, because that sentence is stale the next
    time the script runs and nothing tells anyone."""

    # The shapes the five documents used: "It reads 108", "as build 108",
    # "build 108 is on TestFlight / on every tester's watch", "is at 108".
    # History may name a build ("build 106 retired", "shipped build 108
    # with it") — those are dated facts, not claims about now.
    RESTATES = re.compile(
        r"\b(reads|is at|as build|is build|current build is|newest build is|latest build is)\s+1\d\d\b"
        r"|\bbuild\s+1\d\d\b[^\n.]{0,50}\b(is on TestFlight|is on every|is live|is current|is the newest|is the latest)",
        re.I)

    def test_no_tracked_document_restates_the_current_build(self):
        offenders = []
        for rel in _tracked_files(_ROOT):
            if not rel.endswith(".md"):
                continue
            with open(os.path.join(_ROOT, rel), encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    if self.RESTATES.search(line):
                        offenders.append("%s:%d: %s" % (rel, number, line.strip()[:80]))
        assert not offenders, "these restate WatchApp/BUILD_NUMBER in prose:\n" + "\n".join(offenders)

    @pytest.mark.parametrize("sentence", [
        "as part of shipping it. It reads 108.",
        "**1.1 has shipped to TestFlight as build 108** — the growth",
        "on TestFlight as build 108 since",
        "| nothing — build 108 is on every tester's watch now | owner |",
        "`BUILD_NUMBER` reads 108 — the script commits the bump",
        "`WatchApp/BUILD_NUMBER` reads 108 — that file, not this list, is the",
    ])
    def test_the_guard_catches_every_sentence_the_documents_actually_used(self, sentence):
        """Replayed against the lines the tidy removed. A guard that
        matched two of six was the first version of this test."""
        assert self.RESTATES.search(sentence), sentence

    @pytest.mark.parametrize("sentence", [
        "retired build 106: 200",
        "after it had shipped build 108 with it. The likeliest reason",
        "Done: 108 on 2026-09-04 (the 1.1 code), 109 on 2026-09-07",
    ])
    def test_history_is_allowed_to_name_a_build(self, sentence):
        assert not self.RESTATES.search(sentence), sentence


class TestTheReportingItselfIsChecked:
    """Issue #38's other half: three of its cases were checks that could
    not fail — TEST BUILD SUCCEEDED with no test action in the scheme, a CI
    list read from a stale commit, a watcher whose regex could not match
    its own success. "A confident statement nobody has seen be false is not
    a check."

    Pieces one and two of that issue added reporting. These two hold the
    reporting to the same standard it was built to enforce, over the whole
    source rather than over chosen examples — the shape
    test_the_ontology_obeys_its_own_guardrails already uses.
    """

    # Every condition the relay can record. Adding a note_condition() with
    # a key that is not here fails the first test below, which is the
    # moment to also give it a test that fires it — the entries here are
    # exercised by a test that fires them, not merely declared.
    VOCABULARY = {"bonjour", "crash", "helper", "signin", "tunnel", "update"}

    @staticmethod
    def _module_source(name):
        with open(os.path.join(_ROOT, name), encoding="utf-8") as handle:
            return ast.parse(handle.read())

    @staticmethod
    def _note_keys(tree):
        """Every literal key passed to note_condition() in this module."""
        keys = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "note_condition"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)):
                keys.add(node.args[0].value)
        return keys

    def test_every_condition_the_code_can_report_has_a_test_that_fires_it(self):
        """A reporting path nobody has seen fire is not a reporting path.

        The vocabulary above is the list the sibling class exercises one by
        one. A new note_condition() lands here first, before it can be
        believed."""
        found = self._note_keys(self._module_source("watch_relay.py"))
        assert found == self.VOCABULARY, (
            "condition keys in the code and keys with a test disagree: "
            "only in code %s, only in the test %s"
            % (sorted(found - self.VOCABULARY),
               sorted(self.VOCABULARY - found)))

    def test_a_function_that_reports_one_failure_reports_all_of_them(self):
        """The regression this cannot allow: a second `return None` added
        to a function that already knows its failures matter.

        advertise() had exactly that shape before — one path logged, one
        returned in silence — and the silent one was the case that actually
        happens on a machine without dns-sd. Scoped to functions that
        already call note_condition, so ordinary "no match found" helpers
        are not dragged in: returning None is not a fault, but reporting
        one failure and not its neighbour is."""
        tree = self._module_source("watch_relay.py")
        silent = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not self._note_keys(node):
                continue                       # not a reporting function
            silent += ["%s:%d" % (node.name, line)
                       for line in _unreported_none_returns(node)]
        assert not silent, (
            "these return None with nothing said on the way out, in a "
            "function that reports its other failures: %s" % silent)


def _unreported_none_returns(func):
    """Lines in `func` returning None with no note_condition before them.

    "Before" means earlier in the same block, or earlier in any block
    enclosing it — a note ahead of the `if` counts for a return inside it.
    """
    parents = {}
    for node in ast.walk(func):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def notes(node):
        return any(isinstance(sub, ast.Call)
                   and isinstance(sub.func, ast.Name)
                   and sub.func.id == "note_condition"
                   for sub in ast.walk(node))

    def announced(stmt):
        node = stmt
        while node in parents:
            parent = parents[node]
            for field in ("body", "orelse", "finalbody"):
                block = getattr(parent, field, None)
                if isinstance(block, list) and node in block:
                    if any(notes(earlier) for earlier in block[:block.index(node)]):
                        return True
            node = parent
        return False

    lines = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Return):
            continue
        if node.value is not None and not (isinstance(node.value, ast.Constant)
                                           and node.value.value is None):
            continue
        if not announced(node):
            lines.append(node.lineno)
    return lines



class TestSilentFailuresStayLoud:
    """#94 and #95, the two cases #38 deferred: an announcer that dies
    after startup, and an update held back by a pending card. Each used
    to be reported nowhere a person looks."""

    class _Alive:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    class _Dead:
        def poll(self):
            return 143                     # what SIGTERM leaves behind

        def terminate(self):
            pass                           # already gone; _republish may still ask

    def _advertiser(self, monkeypatch, first, *replacements):
        """A real _Advertiser whose announcer is ``first`` and whose later
        spawns — restarts and republishes alike — hand out ``replacements``
        in order (None = could not start). Built by the constructor, with
        its two seams stubbed — not by __new__ and three hand-set fields,
        which is the shape the fresh_auth fixture was written to end."""
        monkeypatch.setattr(watch_relay, "advertise_txt", lambda _port: {})
        queue = [first, *replacements]
        monkeypatch.setattr(watch_relay, "advertise",
                            lambda port, txt=None: queue.pop(0) if queue else None)
        return watch_relay._Advertiser(8977)

    def test_the_proof_holds_against_the_real_advertise(self, monkeypatch, capsys):
        """The first cut of this passed only in the stub: the real
        advertise() withdrew the condition itself on every successful
        exec, so a dns-sd that died fifty milliseconds later was noted,
        cleared and "restarted" every tick and /health never saw it. Run
        the real function, with only the spawn faked."""
        spawned = [self._Dead(), self._Alive()]
        monkeypatch.setattr(watch_relay.shutil, "which", lambda name: "/usr/bin/dns-sd")
        monkeypatch.setattr(watch_relay.subprocess, "Popen", lambda *a, **k: spawned.pop(0))
        monkeypatch.setattr(watch_relay, "advertise_txt", lambda _port: {})
        adv = watch_relay._Advertiser(8977)
        assert watch_relay.conditions() == []                  # startup: fine
        assert adv.check_once() == "restarted"
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]   # still standing
        assert adv.check_once() == "fine"
        assert watch_relay.conditions() == []                  # proven, withdrawn

    def test_an_announcer_that_exits_is_said_restarted_and_only_then_cleared(self, monkeypatch, capsys):
        """dns-sd ran with both pipes to DEVNULL and nothing polled it;
        when it died the relay believed it was announced. And a restart
        is not a recovery: the condition is withdrawn only once the
        replacement is still alive at the next look."""
        adv = self._advertiser(monkeypatch, self._Dead(), self._Alive())
        assert adv.check_once() == "restarted"
        assert "announcement stopped" in capsys.readouterr().err
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]   # not yet
        assert adv.check_once() == "fine"
        assert watch_relay.conditions() == []                               # now
        assert "announcing again" in capsys.readouterr().err

    def test_an_announcer_that_keeps_dying_is_given_up_on_and_said_so(self, monkeypatch):
        """Restart forever is a fork bomb with good intentions. After
        MAX_RESTARTS in a row the relay stops and leaves a sentence that
        says what is true; the watchdog thread then has nothing to do."""
        deaths = [self._Dead() for _ in range(watch_relay._Advertiser.MAX_RESTARTS)]
        adv = self._advertiser(monkeypatch, self._Dead(), *deaths)
        for _ in range(watch_relay._Advertiser.MAX_RESTARTS):
            assert adv.check_once() == "restarted"
        assert adv.check_once() == "down"
        detail = watch_relay.conditions()[0]["detail"]
        assert "keeps stopping" in detail and "by hand" in detail
        assert adv.process is None
        assert adv.check_once() == "none"              # nothing left to watch

    def test_an_announcer_that_cannot_be_restarted_stays_reported(self, monkeypatch):
        adv = self._advertiser(monkeypatch, self._Dead())      # no replacement at all
        # advertise() reports its own reason on that path; stand in for it.
        monkeypatch.setattr(watch_relay, "advertise",
                            lambda port, txt=None: watch_relay.note_condition("bonjour", "no dns-sd") or None)
        assert adv.check_once() == "down"
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]
        assert adv.check_once() == "none"

    def test_a_deliberate_republish_is_not_a_death(self, monkeypatch, capsys):
        """The one false alarm that kept this out of #92: _republish
        terminates the announcer on purpose when the tunnel URL arrives.
        The swap happens under the watchdog's lock, so it never sees the
        process it would have blamed."""
        old = self._Alive()
        adv = self._advertiser(monkeypatch, old, self._Alive())
        monkeypatch.setattr(watch_relay, "TUNNEL_URL", "https://x.trycloudflare.com/t/tok")
        monkeypatch.setattr(watch_relay.time, "sleep", lambda seconds: None)
        adv._republish()
        assert old.terminated
        assert adv.process is not old                          # the replacement, not the corpse
        assert adv.check_once() == "fine"
        assert watch_relay.conditions() == []
        assert "stopped" not in capsys.readouterr().err

    def test_a_republish_after_unproven_restarts_does_not_inherit_their_count(self, monkeypatch):
        """Three unproven restarts, then the tunnel comes up and
        _republish installs a fresh announcer. One later death must not
        be the fourth in a row — but the condition from the restarts
        stands until the republished process has lived a tick."""
        dead = [self._Dead() for _ in range(2)]
        adv = self._advertiser(monkeypatch, self._Dead(), *dead, self._Alive(), self._Alive())
        assert adv.check_once() == "restarted"
        assert adv.check_once() == "restarted"                 # two unproven
        monkeypatch.setattr(watch_relay, "TUNNEL_URL", "https://x.trycloudflare.com/t/tok")
        monkeypatch.setattr(watch_relay.time, "sleep", lambda seconds: None)
        adv._republish()                                        # installs an _Alive
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]   # not yet proven
        assert adv.check_once() == "fine"
        assert watch_relay.conditions() == []
        assert adv._restarts == 0

    def test_a_deferred_update_is_recorded_on_the_relay_and_reaches_health(self, fresh_auth):
        """The launcher used to say 'update deferred' on stderr, in a log
        on a Mac nobody is looking at, and the machine ran yesterday's
        rules. The relay now records it about itself; /health carries it.
        The sentence says only what stays true after the card is answered."""
        server, _queue = watch_relay.serve(port=0, auth=_known_watch(fresh_auth))
        _serve(server)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            status, body = relay_call(base + "/admin/update-deferred", method="POST")
            assert (status, body) == (200, {"ok": True})
            _status, body = relay_call(base + "/health", token="devicetoken")
            assert [c["key"] for c in body["conditions"]] == ["update"]
            assert "pending" not in body["conditions"][0]["detail"]
        finally:
            server.shutdown()
            server.server_close()

    def test_an_admin_path_the_handler_does_not_know_is_a_404(self, fresh_auth, monkeypatch):
        """The chain used to end in `else: rotate`, so a route added to
        ROUTES without a handler branch rotated the key and opened the
        pairing window. Add such a route; it must answer 404, and the
        key must be what it was."""
        monkeypatch.setitem(watch_relay.RelayHandler.ROUTES["POST"], "/admin/nope",
                            ("_post_admin", dict(local=True, admin=True, lan_only=True)))
        auth = _known_watch(fresh_auth)
        server, _queue = watch_relay.serve(port=0, auth=auth)
        _serve(server)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            status, body = relay_call(base + "/admin/nope", method="POST")
            assert (status, body.get("error")) == (404, "unknown admin route")
            assert not auth.window_open()                       # no fall-through to rotate
        finally:
            server.shutdown()
            server.server_close()

    def test_ensure_running_tells_the_relay_it_is_being_held_back(self, monkeypatch):
        calls = []
        stopped = []
        monkeypatch.setattr(watch_relay, "_self_update", lambda: None)
        monkeypatch.setattr(watch_relay, "_admin_call",
                            lambda path, timeout=5: calls.append((path, timeout)) or {"ok": True})
        monkeypatch.setattr(watch_relay, "_stop_relay", lambda: stopped.append(True))
        health = {"version": watch_relay.RELAY_VERSION - 1, "pending": 2, "paired_ever": True}
        monkeypatch.setattr(watch_relay, "_probe_relay", lambda: health)
        assert watch_relay.ensure_running() == 0
        assert calls == [("/admin/update-deferred", 2)]     # the probe's bound, not the default 5
        assert stopped == []                            # a relay holding a card is holding an approval

class TestConditionsAreSaidOutLoud:
    """Issue #38: the relay knew several things were wrong and reported them
    only to a log file on a Mac nobody is looking at. These hold that each
    one now reaches /health, and so the wrist."""

    def test_a_condition_is_recorded_and_withdrawn(self):
        watch_relay.note_condition("tunnel", "off")
        assert watch_relay.conditions() == [{"key": "tunnel", "detail": "off"}]
        watch_relay.clear_condition("tunnel")
        assert watch_relay.conditions() == []

    def test_withdrawing_something_that_was_never_wrong_is_harmless(self):
        watch_relay.clear_condition("never-happened")
        assert watch_relay.conditions() == []

    def test_the_same_complaint_is_printed_once(self, capsys):
        """A warning that repeats on every retry teaches the reader to skip
        warnings — which is how a real one goes unread."""
        watch_relay.note_condition("tunnel", "off")
        watch_relay.note_condition("tunnel", "off")
        assert capsys.readouterr().err.count("off") == 1
        # A changed detail is news again.
        watch_relay.note_condition("tunnel", "off, differently")
        assert "off, differently" in capsys.readouterr().err

    def test_bonjour_with_no_tool_at_all_is_no_longer_silent(self, monkeypatch):
        """The exact hole: advertise() returned None with no log line, and
        its caller prints only on success, so "the watch cannot find this
        computer" was reported nowhere."""
        monkeypatch.setattr(watch_relay.shutil, "which", lambda _name: None)
        assert watch_relay.advertise(8977) is None
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]

    def test_a_successful_start_withdraws_the_complaint(self, monkeypatch):
        """At startup the announcer is withdrawn on exec — there is no
        earlier process whose death is being recovered from. advertise()
        itself no longer clears anything: a process that exec'd is not
        one that works, and the watchdog's proof depends on the clear
        being the caller's decision."""
        watch_relay.note_condition("bonjour", "stale complaint")
        monkeypatch.setattr(watch_relay.shutil, "which",
                            lambda name: "/usr/bin/dns-sd")
        # advertise_txt reaches for the LAN address through subprocess, and
        # a stubbed Popen would break that on the way past.
        monkeypatch.setattr(watch_relay, "advertise_txt", lambda _port: {})
        monkeypatch.setattr(watch_relay.subprocess, "Popen",
                            lambda *a, **k: "a running dns-sd")
        assert watch_relay.advertise(8977) is not None
        assert [c["key"] for c in watch_relay.conditions()] == ["bonjour"]   # not advertise's call
        watch_relay._Advertiser(8977)
        assert watch_relay.conditions() == []

    def test_a_missing_tunnel_binary_is_a_condition(self, monkeypatch):
        monkeypatch.setattr(watch_relay, "_cloudflared", lambda: None)
        assert watch_relay.start_tunnel(8978, "tok") is None
        detail = watch_relay.conditions()[0]["detail"]
        assert "cloudflared" in detail

    def test_a_stranger_is_not_told_what_is_weak_about_this_machine(
            self, fresh_auth):
        """The list names where this computer is soft — not announcing, no
        way in from away. That is the machine's business, not a passer-by's,
        so it rides the same credential as the rest of the detail."""
        watch_relay.LIMITS.reset()
        watch_relay.note_condition("bonjour", "not announcing")
        server, _queue = watch_relay.serve(port=0, auth=_known_watch(fresh_auth))
        real = server.get_request

        def spoofed():
            sock, addr = real()
            return sock, ("192.168.1.77", addr[1])

        server.get_request = spoofed
        _serve(server)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            _status, body = relay_call(base + "/health")
            assert body == {"ok": True}
            _status, body = relay_call(base + "/health", token="devicetoken")
            assert body["conditions"] == [{"key": "bonjour",
                                           "detail": "not announcing"}]
        finally:
            server.shutdown()
            server.server_close()

    def test_a_relay_that_cannot_see_the_helper_says_so(self, monkeypatch):
        """The third key, and the one that was unreachable: it lived inline
        in main(), so nothing could fire it. It is also the explanation for
        the watch showing the helper version as "unknown"."""
        monkeypatch.setattr(watch_relay, "HELPER_VERSION", "unknown")
        assert watch_relay.check_helper_is_visible() is False
        assert [c["key"] for c in watch_relay.conditions()] == ["helper"]

    def test_a_relay_that_can_see_the_helper_withdraws_the_complaint(
            self, monkeypatch):
        watch_relay.note_condition("helper", "stale complaint")
        monkeypatch.setattr(watch_relay, "HELPER_VERSION", "1.1.1")
        assert watch_relay.check_helper_is_visible() is True
        assert watch_relay.conditions() == []

    def test_health_carries_conditions_to_a_credentialed_caller(self, fresh_auth):
        watch_relay.note_condition("bonjour", "not announcing")
        server, _queue = watch_relay.serve(port=0, auth=_known_watch(fresh_auth))
        _serve(server)
        try:
            base = "http://127.0.0.1:%d" % server.server_address[1]
            _status, body = relay_call(base + "/health")
            assert body["conditions"] == [{"key": "bonjour",
                                           "detail": "not announcing"}]
        finally:
            server.shutdown()
            server.server_close()


def test_the_watch_names_the_helper_version_this_repository_ships():
    """The watch warns when the helper on the computer is behind it, and it
    can only do that against a version it was told to expect. That constant
    lives in Swift, `__version__` lives here, and nothing would notice them
    drifting apart: the row would simply stop firing, or fire forever. The
    same trap Version.xcconfig fell into when it said 1.1 and every build
    shipped 1.0."""
    swift = os.path.join(_ROOT, "WatchApp", "Tapproval", "RelayModel.swift")
    if not os.path.isfile(swift):
        pytest.skip("no watch app in this layout")
    with open(swift, encoding="utf-8") as handle:
        found = re.search(r'static let expected = "([^"]+)"', handle.read())
    assert found, "HelperVersion.expected is gone from RelayModel.swift"
    assert found.group(1) == crc.__version__, (
        "the watch expects helper %s, this repository ships %s"
        % (found.group(1), crc.__version__))


def test_the_two_ci_workflows_share_their_test_steps():
    """helper/.github/workflows/tests.yml is copied verbatim into the public
    repo. Its Python steps must be the private workflow's, or the public
    repo tests something else than what shipped."""
    private = os.path.join(_ROOT, ".github", "workflows", "tests.yml")
    public = os.path.join(HELPER_DIR, ".github", "workflows", "tests.yml")
    if not os.path.isfile(private):
        pytest.skip("no private workflow in this layout")
    def python_steps(path):
        """The pytest job, without the line that says where it runs.

        It used to be "every line before shellcheck", which also covered
        the header and any job declared above pytest — so adding the
        CI_RUNNER switch (ci-runner.sh) made the two files differ in a way
        that says nothing about what the public repo tests. The matrix and
        the steps are what must match; the runner is deliberately private.
        """
        lines = open(path, encoding="utf-8").read().split("\n")
        start = lines.index("  pytest:")
        rest = lines[start + 1:]
        end = next((i for i, line in enumerate(rest)
                    if line.startswith("  ") and not line.startswith("   ")), len(rest))
        return [line for line in rest[:end]
                if "vars.CI_RUNNER" not in line and "runs-on:" not in line]
    assert python_steps(private) == python_steps(public)


class TestTheEffectOntology:
    """Risk derived from what a command does, not from which binary does it.

    Fourteen tables in the classifier answer "what does this verb do", every
    one keyed on a binary's name — which is how `flyctl apps destroy myapp`
    read SAFE, and SAFE is auto-allowed under `--quiet`. These hold the
    derivation, the guardrails it must obey, and the commands that were
    wrong before it existed.
    """

    E, RE, U = crc.Effect, crc.Reach, crc.Undo

    # --- the guardrails, over the whole table rather than per example -----

    def test_the_ontology_obeys_its_own_guardrails(self):
        """G1-G4 hold for every combination, not for chosen examples. A rule
        added tomorrow that contradicts one from last month fails here."""
        for effect in self.E:
            for reach in self.RE:
                for undo in self.U:
                    for secret in (False, True):
                        tier = crc.derive_risk(effect, reach, undo, secret=secret)
                        where = (effect.name, reach.name, undo.name, secret)
                        if secret:                                    # G4
                            assert tier >= crc.Risk.HIGH, where
                        if effect == self.E.DESTROY and reach > self.RE.SCRATCH:
                            assert tier >= crc.Risk.HIGH, where       # G2
                        if effect in (self.E.GRANT, self.E.PUBLISH):
                            assert tier >= crc.Risk.HIGH, where       # G3
                            if reach >= self.RE.SYSTEM:
                                assert tier == crc.Risk.CRITICAL, where
                        if (undo == self.U.IRREVERSIBLE
                                and reach >= self.RE.SHARED
                                and effect >= self.E.DESTROY):        # G1
                            assert tier == crc.Risk.CRITICAL, where

    def test_observing_is_safe_unless_the_resource_is_a_credential(self):
        """Looking is what an agent does all day; looking at a secret is not."""
        for reach in self.RE:
            assert crc.derive_risk(self.E.OBSERVE, reach) == crc.Risk.SAFE
            assert crc.derive_risk(self.E.OBSERVE, reach, secret=True) >= crc.Risk.HIGH

    def test_a_command_naming_no_effect_yields_no_opinion(self):
        """G5: absence of a fact is not a licence. The ontology returns None
        and the ordinary rules decide — it may never invent a SAFE."""
        for command in ("ls -la", "git status", "docker ps", "kubectl get pods",
                        "gh pr view 123", "defaults read com.apple.dock",
                        "sort -d notes.txt", "docker logs web"):
            assert crc._ontology_risk(command) is None, command

    def test_it_can_only_raise(self):
        """Wired ahead of every recognition table, and bump() takes the
        maximum — so adding it cannot make the classifier more permissive.
        Whatever the ontology says, the shipped tier is at least that."""
        for command in ("flyctl apps destroy myapp --yes", "terraform destroy",
                        "kubectl delete namespace production", "ls -la",
                        "rm -rf build/", "git status"):
            named = crc._ontology_risk(command)
            shipped, _ = crc.classify_bash(command)
            assert shipped >= (named[1] if named else crc.Risk.SAFE), command

    # --- the commands that were wrong -------------------------------------

    @pytest.mark.parametrize("command,floor", [
        # Read verb recognised, the word after it never read.
        ("flyctl apps destroy myapp --yes", crc.Risk.CRITICAL),
        ("kubectl delete namespace production", crc.Risk.CRITICAL),
        ("terraform destroy -auto-approve", crc.Risk.CRITICAL),
        ("aws s3 rm s3://prod-bucket --recursive", crc.Risk.CRITICAL),
        ("aws s3 sync . s3://prod --delete", crc.Risk.CRITICAL),
        ("vercel deploy --prod", crc.Risk.CRITICAL),
        ("rclone sync /empty remote:backups", crc.Risk.HIGH),
        # A subcommand on the git read list, with the flags unexamined.
        ("git branch -D main", crc.Risk.HIGH),
        ("git remote set-url origin https://evil.example/r.git", crc.Risk.MEDIUM),
        ("git config --global alias.x '!rm -rf ~'", crc.Risk.CRITICAL),
        # find is a read-only command; -delete is not a read.
        ("find / -name '*.log' -delete", crc.Risk.CRITICAL),
        # Reads that hand over a live credential.
        ("gh auth token", crc.Risk.HIGH),
        ("kubectl get secret db -o yaml", crc.Risk.HIGH),
        ("cat ~/.kube/config", crc.Risk.HIGH),
        ("cat ~/.npmrc", crc.Risk.HIGH),
        # The same word, joined to its neighbours the way AWS, GCP and
        # curl actually spell it — in a flag, a NAME=value, an environment
        # variable. Whole-token matching missed every one.
        ("aws secretsmanager get-secret-value --secret-id prod", crc.Risk.HIGH),
        ("printenv AWS_SECRET_ACCESS_KEY", crc.Risk.HIGH),
        ("echo $GITHUB_TOKEN", crc.Risk.HIGH),
        ("curl -H 'x-api-key=abc' https://api.example/", crc.Risk.HIGH),
        ("gcloud secrets versions access latest --secret=db", crc.Risk.HIGH),
        ("vault kv get -field=api_key secret/prod", crc.Risk.HIGH),
    ])
    def test_every_command_that_used_to_read_safe(self, command, floor):
        risk, rules = crc.classify_bash(command)
        assert risk >= floor, "%s -> %s (%s)" % (command, risk.name, rules)
        assert risk > crc.Risk.LOW, "--quiet would auto-allow %s" % command

    @pytest.mark.parametrize("command", [
        "ls -la", "git status", "git log --oneline", "docker ps",
        "kubectl get pods", "gh pr view 123", "defaults read com.apple.dock",
        "docker logs web", "sort -d notes.txt", "git config --list",
        "git config --get remote.origin.url", "git config user.email",
        # A word that names a credential inside a FILENAME is not one:
        # design tokens and a docs page about passwords are ordinary reads.
        "cat design/tokens.md", "ls tokens/", "cat docs/passwords.md",
    ])
    def test_the_ordinary_reads_are_still_safe(self, command):
        """The cost of a false positive here is a card the user learns to
        tap through, which is how a wrist app stops working."""
        assert crc.classify_bash(command)[0] == crc.Risk.SAFE, command

    @pytest.mark.parametrize("command", [
        # A credential word inside an ordinary NAME — a test file, a branch,
        # a namespace, a compose service, an npm script — is not a
        # credential. Review found the first cut of the joiner split made
        # every one of these a HIGH card.
        "python -m pytest test_token_refresh.py",
        "cat token-bucket.js", "head token_bucket.py",
        "kubectl get pods -n token-service",
        "git log --oneline release-token-fix",
        "git checkout -b fix-token-expiry",
        "npm run build:tokens",
        "docker compose up -d secret-manager",
        "mkdir design-tokens", "cat password-reset.md",
    ])
    def test_a_credential_word_inside_a_name_is_not_a_credential(self, command):
        risk, rules = crc.classify_bash(command)
        assert risk < crc.Risk.HIGH, (command, risk.name, rules)

    def test_a_credential_store_is_a_secret_path(self):
        """The paths SECRET_PATH did not name, each holding a live token."""
        for path in ("~/.kube/config", "~/.npmrc", "~/.pypirc",
                     "~/.docker/config.json", "~/.config/gh/hosts.yml"):
            assert crc.SECRET_PATH.search(path), path


class TestStandardLibraryOnly:
    """Hard constraint 1, held by something that has been seen to fail.

    CI's guard for this was `test ! -f requirements.txt` — which is not
    what the rule says. The rule is about what the code imports, and a
    `import requests` added to the relay passes that check every time. In
    practice the suite caught it anyway, because CI installs only pytest
    and this file imports every module; but that is an accident of how
    the imports at the top of this file happen to be written, not a
    check, and it lasts exactly as long as somebody remembers to add the
    next module to them.

    This walks the source instead, and it takes **every** .py at the top
    of the repository rather than a list. That is the actual defect the
    2026-09-09 audit found twice: a guard that names its files by hand
    does not cover the file added tomorrow. `crash_report.py` and
    `watch_permission_tool.py` shipped on 2026-09-09 and joined neither
    the lint list nor any import check.

    WatchApp/asc is deliberately excluded: the release tooling runs on
    one machine, in a virtual environment, and genuinely uses PyJWT and
    cryptography. The constraint is about code that runs on a stranger's
    computer.
    """

    #: pytest is the one third-party import allowed, and only here: the
    #: test suite is not what a user's interpreter is asked to run.
    ALLOWED_THIRD_PARTY = {"test_claude_risk_classifier.py": {"pytest"}}

    @staticmethod
    def _root_modules():
        """Every .py at the top of the repository, discovered not listed."""
        found = sorted(name for name in os.listdir(_ROOT)
                       if name.endswith(".py"))
        # If this ever comes back short, the discovery broke, not the repo.
        assert len(found) >= 5, found
        return found

    @staticmethod
    def _imported_names(source):
        """Top-level package of every import anywhere in the module.

        Includes imports inside functions and `try:` blocks — several
        modules import urllib lazily, and a third-party import hidden in
        a rarely-taken branch is the one that would survive review.
        """
        names = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:      # relative: our own package, by definition
                    continue
                if node.module:
                    names.add(node.module.split(".")[0])
        return names

    @staticmethod
    def _is_standard_library(name):
        """True for a module that ships with the interpreter itself.

        `sys.stdlib_module_names` would say this in one line, and does
        not exist before 3.10 — and 3.9 is in the matrix precisely
        because macOS still ships it. So resolve the module and ask where
        it lives: builtin, frozen, or under the interpreter's own stdlib
        directory. Anything from site-packages fails, which is the case
        this exists to catch.
        """
        if name in sys.builtin_module_names:
            return True
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            return False
        if spec is None:
            return False
        origin = spec.origin or ""
        if origin in ("built-in", "frozen"):
            return True
        stdlib = sysconfig.get_paths()["stdlib"]
        return (os.path.commonpath([os.path.abspath(origin), stdlib]) == stdlib
                and "site-packages" not in origin)

    def test_every_module_at_the_root_imports_only_the_standard_library(self):
        ours = {name[:-3] for name in self._root_modules()}
        for module in self._root_modules():
            with open(os.path.join(_ROOT, module), encoding="utf-8") as handle:
                imported = self._imported_names(handle.read())
            allowed = ours | self.ALLOWED_THIRD_PARTY.get(module, set())
            for name in sorted(imported - allowed):
                assert self._is_standard_library(name), (
                    "%s imports %r, which is not in the standard library. "
                    "Hooks run under whatever python3 is on the user's "
                    "PATH; see CLAUDE.md, hard constraint 1." % (module, name))

    def test_the_guard_can_fail(self):
        """Issue #38: prove it, do not assert it.

        The check above passes today. It would also pass today if it were
        written wrongly, so this hands it a module that must fail.
        """
        assert not self._is_standard_library("pytest"), (
            "pytest resolved as standard library — the check cannot fail, "
            "which means it is not a check")
        imported = self._imported_names("import os\nimport requests\n")
        assert imported == {"os", "requests"}
        assert self._is_standard_library("os")

    def test_an_import_hidden_in_a_branch_is_still_seen(self):
        """The shape that would otherwise slip through review."""
        source = ("def send():\n"
                  "    try:\n"
                  "        import requests\n"
                  "    except ImportError:\n"
                  "        from urllib import request\n")
        assert self._imported_names(source) == {"requests", "urllib"}
