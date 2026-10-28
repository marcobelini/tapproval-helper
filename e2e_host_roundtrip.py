#!/usr/bin/env python3
"""Install, approve and uninstall through the real hook, on whatever
computer this runs on: macOS, Linux or Windows.

What a user's computer does, end to end, with everything kept in a
throwaway home:

1. ``ClaudeRiskClassifier.py --install --no-bridge`` writes the hooks into
   a settings file that already holds someone else's hook and setting.
2. A relay of this run's own answers on free ports.
3. The PermissionRequest command, read back from that settings file and
   from the plugin's ``hooks.json``, is run the way Claude Code runs it on
   this host: ``sh -c`` on macOS and Linux; Git Bash, and PowerShell where
   Git Bash is missing, on Windows; or with no shell when it is written in
   exec form. A recorded prompt goes in on stdin.
4. The card reaches the relay, the relay is answered as a watch would,
   and the hook's stdout must carry the decision object Claude Code
   accepts. One run is left unanswered and must carry no decision at all.
5. ``--uninstall`` must leave the settings file as it was.

Nothing here reaches the live relay: the plugin's command names port 8977,
which is rewritten to this run's port before it is run, and the run stops
if the rewrite did not happen. Standard library only, Python 3.9.

    python3 e2e_host_roundtrip.py            # every way this host can run it
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
WINDOWS = os.name == "nt"
LIVE_RELAY = "http://127.0.0.1:8977"
FAILURES = []


def say(line):
    print(line, flush=True)


def check(ok, what):
    say(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        FAILURES.append(what)
    return ok


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def isolated_env(home):
    """This process's environment, without the session's own relay, with
    every path the installer and the relay write pointed into ``home``."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_RISK_")}
    env.update({
        "HOME": home, "USERPROFILE": home,
        "CLAUDE_SETTINGS_PATH": os.path.join(home, ".claude", "settings.json"),
        "CLAUDE_LAUNCH_AGENT_PATH": os.path.join(home, "launch-agent.plist"),
        "CODEX_HOME": os.path.join(home, "no-codex"),
        "TAPPROVAL_BRIDGE_DIR": os.path.join(home, "bridge"),
        "TAPPROVAL_BRIDGE_LEGACY_DIR": os.path.join(home, "bridge-legacy"),
        "TAPPROVAL_BRIDGE_AGENT_PATH": os.path.join(home, "bridge-agent.plist"),
        "TAPPROVAL_RELAY_START": os.path.join(home, "relay-start.json"),
        "PYTHONIOENCODING": env.get("PYTHONIOENCODING", ""),
    })
    if not env["PYTHONIOENCODING"]:
        del env["PYTHONIOENCODING"]
    return env


def git_bash():
    """Git for Windows' bash, never System32's WSL launcher of that name."""
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        candidate = os.path.join(base, "Git", "bin", "bash.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def runners(hook):
    """(name, argv) for every way Claude Code may run this hook here."""
    if hook.get("args"):
        return [("exec", [hook["command"]] + list(hook["args"]))]
    command = hook["command"]
    if not WINDOWS:
        return [("sh", ["sh", "-c", command])]
    found = []
    bash = git_bash()
    if bash:
        found.append(("git-bash", [bash, "-c", command]))
    found.append(("powershell", ["powershell.exe", "-NoProfile", "-NonInteractive",
                                 "-Command", command]))
    return found


def get(url, token):
    request = urllib.request.Request(url, headers={"X-Tapproval-Token": token})
    with urllib.request.urlopen(request, timeout=5) as reply:
        return json.loads(reply.read().decode("utf-8"))


def decide(base, token, card_id, decision):
    body = json.dumps({"id": card_id, "decision": decision}).encode("utf-8")
    request = urllib.request.Request(
        base + "/decision", data=body,
        headers={"Content-Type": "application/json", "X-Tapproval-Token": token})
    with urllib.request.urlopen(request, timeout=5) as reply:
        return json.loads(reply.read().decode("utf-8"))


def wait_for_card(base, token, needle, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        for card in get(base + "/pending", token).get("cards") or []:
            if needle in json.dumps(card):
                return card
        time.sleep(0.3)
    return None


def decision_of(stdout):
    """The decision object in a hook's stdout, None for no decision, or
    the text itself when stdout is not the JSON Claude Code would parse."""
    text = stdout.strip()
    if not text:
        return None
    try:
        output = json.loads(text)
    except ValueError:
        return text
    return (output.get("hookSpecificOutput") or {}).get("decision")


def one_card(name, argv, env, base, token, home, answer, wait):
    needle = "tapproval-e2e-%s-%s-%d" % (name, answer or "none", int(time.time() * 1000))
    event = {"hook_event_name": "PermissionRequest", "session_id": "e2e-" + name,
             "cwd": home, "tool_name": "Bash",
             "tool_input": {"command": "rm -rf build/" + needle,
                            "description": "Clear a build folder"}}
    hook_env = dict(env, CLAUDE_RISK_MODE="enforce", CLAUDE_RISK_RELAY=base,
                    CLAUDE_RISK_RELAY_WAIT=str(wait),
                    CLAUDE_RISK_AUTH_FILE=os.path.join(home, ".tapproval", "data", "auth.json"),
                    CLAUDE_RISK_AUDIT_LOG=os.path.join(home, "audit.jsonl"),
                    CLAUDE_PLUGIN_ROOT=ROOT)
    hook = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=hook_env, cwd=home)
    hook.stdin.write(json.dumps(event).encode("utf-8"))
    hook.stdin.close()
    hook.stdin = None  # communicate() on 3.9 flushes a stdin it still holds
    card = None
    if answer:
        card = wait_for_card(base, token, needle)
        if check(card is not None, "%s: the card reached the relay" % name):
            decide(base, token, card["id"], answer)
    try:
        out, err = hook.communicate(timeout=wait + 30)
    except subprocess.TimeoutExpired:
        hook.kill()
        out, err = hook.communicate()
    got = decision_of(out.decode("utf-8", "replace"))
    if answer:
        ok = isinstance(got, dict) and got.get("behavior") == answer
        check(ok, "%s: a wrist %s comes back as {\"behavior\": \"%s\"}" % (name, answer, answer))
    else:
        ok = got is None
        check(ok, "%s: no answer leaves no decision, so the terminal asks" % name)
    if not ok:
        say("        stdout: %r" % out[:300])
        say("        stderr: %r" % err.decode("utf-8", "replace")[-600:])


def plugin_hook(base):
    """The plugin's PermissionRequest hook, aimed at this run's relay."""
    # helper/hooks here; hooks/ at the root of the public repo.
    path = next(p for p in (os.path.join(ROOT, "helper", "hooks", "hooks.json"),
                            os.path.join(ROOT, "hooks", "hooks.json"))
                if os.path.isfile(p))
    with open(path, encoding="utf-8") as handle:
        hooks = json.load(handle)["hooks"]["PermissionRequest"][0]["hooks"][0]
    hook = dict(hooks)
    for key in ("command", "args"):
        if key not in hook:
            continue
        text = json.dumps(hook[key])
        if "8977" in text:
            text = text.replace(LIVE_RELAY, base)
            if "8977" in text:
                raise SystemExit("the plugin hook names port 8977 in a form this run "
                                 "cannot redirect; refusing to reach the live relay")
        text = text.replace("${CLAUDE_PLUGIN_ROOT}", ROOT.replace("\\", "/"))
        text = text.replace("CLAUDE_RISK_RELAY_WAIT=86400", "CLAUDE_RISK_RELAY_WAIT=20")
        hook[key] = json.loads(text)
    return hook


def installed_hook(settings_path):
    with open(settings_path, encoding="utf-8") as handle:
        settings = json.load(handle)
    for group in settings.get("hooks", {}).get("PermissionRequest", []):
        for hook in group.get("hooks", []):
            if "ClaudeRiskClassifier" in json.dumps(hook):
                return hook
    return None


def main():
    say("host: %s, Python %s" % (sys.platform, sys.version.split()[0]))
    home = tempfile.mkdtemp(prefix="tapproval-e2e-")
    env = isolated_env(home)
    settings_path = env["CLAUDE_SETTINGS_PATH"]
    os.makedirs(os.path.dirname(settings_path))
    before = {"env": {"SOMEONE_ELSES": "kept"},
              "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                  {"type": "command", "command": "echo someone-elses-hook"}]}]}}
    with open(settings_path, "w", encoding="utf-8") as handle:
        json.dump(before, handle)

    relay = None
    try:
        say("install")
        done = subprocess.run([sys.executable, os.path.join(ROOT, "ClaudeRiskClassifier.py"),
                               "--install", "--no-bridge"],
                              env=env, cwd=home, capture_output=True, timeout=120)
        check(done.returncode == 0, "--install exits 0")
        if done.returncode:
            say(done.stdout.decode("utf-8", "replace")[-800:])
            say(done.stderr.decode("utf-8", "replace")[-800:])
        hook = installed_hook(settings_path)
        check(hook is not None, "--install wrote a PermissionRequest hook")

        say("relay")
        port = free_port()
        base = "http://127.0.0.1:%d" % port
        relay = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "watch_relay.py"), "--port", str(port),
             "--tls-port", str(free_port()), "--tunnel-port", str(free_port()),
             "--no-bonjour"],
            env=env, cwd=home, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline, up = time.time() + 30, False
        while time.time() < deadline and not up:
            try:
                urllib.request.urlopen(base + "/health", timeout=2).read()
                up = True
            except OSError:
                time.sleep(0.3)
        if not check(up, "the relay answers /health"):
            relay.kill()
            say(relay.communicate()[0].decode("utf-8", "replace")[-1500:])
            relay = None
            raise SystemExit(1)
        with open(os.path.join(home, ".tapproval", "data", "auth.json"), encoding="utf-8") as handle:
            token = json.load(handle)["bootstrap"]

        sources = [("installed", hook)] if hook else []
        sources.append(("plugin", plugin_hook(base)))
        for source, entry in sources:
            for shell, argv in runners(entry):
                name = "%s/%s" % (source, shell)
                say(name)
                one_card(name, argv, env, base, token, home, "allow", 20)
                one_card(name, argv, env, base, token, home, "deny", 20)
        if hook:
            name, argv = runners(hook)[0]
            one_card("installed/%s" % name, argv, env, base, token, home, None, 2)

        say("uninstall")
        done = subprocess.run([sys.executable, os.path.join(ROOT, "ClaudeRiskClassifier.py"),
                               "--uninstall"],
                              env=env, cwd=home, capture_output=True, timeout=120)
        check(done.returncode == 0, "--uninstall exits 0")
        with open(settings_path, encoding="utf-8") as handle:
            after = json.load(handle)
        check(installed_hook(settings_path) is None, "--uninstall removed our hook")
        check(after.get("env", {}).get("SOMEONE_ELSES") == "kept"
              and after.get("hooks", {}).get("PreToolUse") == before["hooks"]["PreToolUse"],
              "someone else's hook and setting survive install and uninstall")
    finally:
        if relay is not None:
            relay.terminate()
            try:
                relay.wait(timeout=10)
            except subprocess.TimeoutExpired:
                relay.kill()
        shutil.rmtree(home, ignore_errors=True)

    if FAILURES:
        say("\n%d failed on %s:" % (len(FAILURES), sys.platform))
        for what in FAILURES:
            say("  - " + what)
        return 1
    say("\nall passed on %s" % sys.platform)
    return 0


if __name__ == "__main__":
    sys.exit(main())
