#!/usr/bin/env python3
"""Install Tapproval Base the way each agent installs it, in throwaway
homes, and check what each install leaves behind.

Arms:

A  The Claude Code plugin, through Claude Code's own CLI:
   ``claude plugin validate --strict``, ``marketplace add``, ``install``.
   The hooks Claude Code recorded then run as Claude Code runs them: a
   wrist allow and deny come back as decision objects, an unanswered card
   leaves no decision, and SessionStart finds the relay already up and
   starts nothing. ``claude plugin uninstall`` leaves no hook.
C  The terminal install, with Codex present: ``--install --watch
   --no-bridge`` wires both agents. Our own reading of Codex's hook trust
   must agree with Codex's (its app-server's ``hooks/list``) before and
   after the trust click, simulated the way Codex records it. The Codex
   hook runs Codex's path and never makes a wrist card of its own.
   ``--uninstall`` leaves neither agent wired.

B  The Codex plugin, through Codex's own CLI: ``codex plugin marketplace
   add`` and ``add``. Codex keeps only the plugin's small folder; its two
   hooks are untrusted until the click, then trusted. A real ``codex exec``
   session start fetches the helper into ~/.tapproval and starts the relay,
   and says once that it is set up (offering Claude Code only where Claude
   Code is here); the next start is quick and quiet. A question runs
   Codex's path. A helper release keeps the plugin trusted; a change to the
   plugin's own folder does not. ``--uninstall`` takes the plugin out.
D  Both plugins in one home, then the terminal install over them: the Codex
   setup writes nothing into Claude Code, and a Codex question is answered
   once, though two routes are installed.

Each arm also runs once more with a deliberate fault (``--negative``, on
by default), and passes only if its check catches that fault: a check
nobody has seen fail is not a check.

Nothing here reaches the live relay, launchd, the bridge or the real
home. Each arm gets its own temp home and a throwaway copy of the public
tree (``sync-helper.sh --layout-into``, or this folder in the public
repo), in which the live port 8977 is rewritten to this run's own port
and the relay's spawn loses Bonjour and the tunnel; the run stops if a
rewrite did not take. The bridge is off by its own OFF marker, as
``--no-bridge`` leaves it, and launchd is out of reach through
CLAUDE_LAUNCH_AGENT_PATH and TAPPROVAL_BRIDGE_AGENT_PATH. The agents run
with a clean environment, not this process's. The real home's Claude
Code settings, Codex hooks and config, and LaunchAgents are fingerprinted
before and after, and must not change. Standard library only, Python 3.9.

    python3 e2e_plugin_install.py               # every arm whose CLI is here
    python3 e2e_plugin_install.py --arm A
    python3 e2e_plugin_install.py --require     # a missing CLI fails (CI)
    python3 e2e_plugin_install.py --no-negative
"""
import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from e2e_host_roundtrip import (  # noqa: E402  (the shared round-trip helpers)
    decide, decision_of, free_port, get, runners, wait_for_card)

WINDOWS = os.name == "nt"
PLUGIN = "tapproval-helper@tapproval"
CODEX_APP_BINARIES = (
    "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",
    "/Applications/ChatGPT.app/Contents/Resources/codex",
)
# What a user's own computer keeps in its environment, and nothing of
# this session's: no CLAUDE_*, no CODEX_*, no relay of ours.
KEEP = {"PATH", "SYSTEMROOT", "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR",
        "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "SHELL", "USER",
        "LOGNAME", "USERNAME", "ProgramFiles", "ProgramFiles(x86)",
        "ProgramW6432", "PROGRAMDATA", "ProgramData", "NUMBER_OF_PROCESSORS"}
UNANSWERED_WAIT = 8      # seconds the hook waits for a card nobody answers


class Arm:
    """One arm's checks, kept apart so a negative run can be judged by
    which of its checks failed."""

    def __init__(self, name, quiet=False):
        self.name, self.quiet, self.failed = name, quiet, []

    def say(self, line):
        if not self.quiet:
            print(line, flush=True)

    def check(self, ok, what):
        self.say(("  ok    " if ok else "  FAIL  ") + what)
        if not ok:
            self.failed.append(what)
        return ok

    def stop(self, what):
        self.check(False, what)
        raise ArmStopped(what)


class ArmStopped(Exception):
    pass


# --- the tree, aimed away from the live relay ---------------------------------

def public_tree(dest):
    """The tree the public repository ships, copied into ``dest``."""
    if os.path.isdir(os.path.join(ROOT, ".claude-plugin")):      # the public repo
        shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".pytest_cache", "*.pyc"))
        return
    done = subprocess.run(["bash", os.path.join(ROOT, "sync-helper.sh"),
                           "--layout-into=" + dest], capture_output=True, text=True)
    if done.returncode:
        raise SystemExit("sync-helper.sh --layout-into failed:\n" + done.stderr)


def aim(tree, port, tls_port, tunnel_port, sabotage=None):
    """Point every place the tree names the live relay at this run's own,
    and take Bonjour and the tunnel off the relay a session start could
    spawn. Each rewrite must match exactly as often as expected, or the
    run stops."""
    rewrites = [
        ("ClaudeRiskClassifier.py", "RELAY_PORT = 8977\n", "RELAY_PORT = %d\n" % port),
        ("watch_relay.py", "DEFAULT_PORT = 8977 ", "DEFAULT_PORT = %d " % port),
        ("watch_relay.py", '"--host", "0.0.0.0", "--tunnel"]',
         '"--no-bonjour", "--tls-port", "%d", "--tunnel-port", "%d"]' % (tls_port, tunnel_port)),
        # The PermissionRequest hook and the archive ask both name the relay.
        (os.path.join("hooks", "hooks.json"), "http://127.0.0.1:8977",
         "http://127.0.0.1:%d" % port, 2),
        (os.path.join("hooks", "hooks.json"), "CLAUDE_RISK_RELAY_WAIT=86400",
         "CLAUDE_RISK_RELAY_WAIT=%d" % UNANSWERED_WAIT, 2),
    ]
    plugin_script = os.path.join("codex-plugin", "tapproval.py")
    if os.path.isfile(os.path.join(tree, plugin_script)):
        rewrites += [
            (plugin_script, '"http://127.0.0.1:8977"', '"http://127.0.0.1:%d"' % port),
            (plugin_script, '"CLAUDE_RISK_RELAY_WAIT": "86400"',
             '"CLAUDE_RISK_RELAY_WAIT": "%d"' % UNANSWERED_WAIT),
            # The helper it fetches is this tree, never GitHub's.
            (plugin_script, 'REPO = "https://github.com/marcobelini/tapproval-helper.git"',
             "REPO = %r" % tree.replace("\\", "/")),
        ]
    if sabotage:
        rewrites += sabotage
    for rewrite in rewrites:
        name, old, new = rewrite[:3]
        times = rewrite[3] if len(rewrite) > 3 else 1
        path = os.path.join(tree, name)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if text.count(old) != times:
            raise SystemExit("cannot aim %s away from the live relay: %r is there %d times, "
                             "not %d" % (name, old, text.count(old), times))
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text.replace(old, new))
    for name in (os.path.join("hooks", "hooks.json"), os.path.join("codex-plugin", "tapproval.py")):
        try:
            with open(os.path.join(tree, name), encoding="utf-8") as handle:
                text = handle.read()
        except FileNotFoundError:
            continue
        if "8977" in text or "github.com" in text.split("REPO =", 1)[-1].split("\n", 1)[0]:
            raise SystemExit("%s still names the live relay or GitHub; refusing to run" % name)
    # The Codex plugin fetches the helper from this tree with git, as a
    # user's fetches it from GitHub: a repository with a main branch.
    subprocess.run(["git", "init", "-q", tree], check=True)
    subprocess.run(["git", "-C", tree, "checkout", "-q", "-B", "main"], check=True)
    commit(tree, "the tree under test")


def commit(tree, message):
    subprocess.run(["git", "-C", tree, "add", "-A"], check=True)
    subprocess.run(["git", "-C", tree, "-c", "user.name=e2e", "-c",
                    "user.email=e2e@example.invalid", "commit", "-q", "--allow-empty",
                    "-m", message], check=True)


# --- a home of its own ---------------------------------------------------------

def make_home(root, codex=False):
    home = os.path.join(root, "home")
    os.makedirs(os.path.join(home, "bridge"))
    # As --install --no-bridge leaves it: no bridge is installed or launched,
    # so no login item can be registered from here.
    with open(os.path.join(home, "bridge", "OFF"), "w", encoding="utf-8") as handle:
        handle.write("off for e2e_plugin_install.py\n")
    if codex:
        os.makedirs(os.path.join(home, ".codex"))
    return home


def clean_env(home):
    env = {k: v for k, v in os.environ.items() if k in KEEP}
    env.update({
        "HOME": home, "USERPROFILE": home,
        "APPDATA": os.path.join(home, "AppData", "Roaming"),
        "LOCALAPPDATA": os.path.join(home, "AppData", "Local"),
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "CLAUDE_LAUNCH_AGENT_PATH": os.path.join(home, "launch-agent.plist"),
        "TAPPROVAL_BRIDGE_DIR": os.path.join(home, "bridge"),
        "TAPPROVAL_BRIDGE_LEGACY_DIR": os.path.join(home, "bridge-legacy"),
        "TAPPROVAL_BRIDGE_AGENT_PATH": os.path.join(home, "bridge-agent.plist"),
        "TAPPROVAL_RELAY_START": os.path.join(home, "relay-start.json"),
        "TAPPROVAL_RELEASES_URL": "",
    })
    return env


def real_home_fingerprint():
    """What this run must never change on the computer it runs on."""
    home = os.path.expanduser("~")
    codex = os.path.expanduser(os.environ.get("CODEX_HOME") or "~/.codex")
    places = [os.path.join(home, ".claude", "settings.json"),
              os.path.join(home, ".claude", "plugins", "installed_plugins.json"),
              os.path.join(codex, "hooks.json"), os.path.join(codex, "config.toml"),
              os.path.join(home, ".tapproval", "data", "relay-start.json")]
    seen = {}
    for path in places:
        try:
            with open(path, "rb") as handle:
                seen[path] = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            seen[path] = None
    agents = os.path.join(home, "Library", "LaunchAgents")
    seen[agents] = sorted(os.listdir(agents)) if os.path.isdir(agents) else None
    return seen


# --- the agents' own programs --------------------------------------------------

def find_claude():
    return os.environ.get("TAPPROVAL_E2E_CLAUDE") or shutil.which("claude")


def find_codex():
    found = os.environ.get("TAPPROVAL_E2E_CODEX") or shutil.which("codex")
    if found:
        return found
    for path in CODEX_APP_BINARIES:
        if os.access(path, os.X_OK):
            return path
    return None


def run(argv, env, cwd, timeout=180):
    done = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, timeout=timeout)
    return (done.returncode, done.stdout.decode("utf-8", "replace"),
            done.stderr.decode("utf-8", "replace"))


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    try:
        return json.loads(text)
    except ValueError:
        return None


class AppServer:
    """Codex's own app-server on stdio, for the questions only Codex can
    answer: which hooks it found, and whether it trusts them."""

    def __init__(self, codex, env, cwd):
        self.process = subprocess.Popen([codex, "app-server"], env=env, cwd=cwd,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL)
        self.lines = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0
        self.call("initialize", {"clientInfo": {"name": "tapproval-e2e", "version": "0"}})
        self._send({"jsonrpc": "2.0", "method": "initialized"})

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)

    def _send(self, message):
        self.process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.process.stdin.flush()

    def call(self, method, params, timeout=60):
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                message = json.loads(self.lines.get(timeout=max(0.1, deadline - time.time())))
            except (queue.Empty, ValueError):
                continue
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise RuntimeError("%s: %s" % (method, message["error"]))
                return message.get("result")
        raise RuntimeError("%s: no answer in %ds" % (method, timeout))

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


def codex_hooks(codex, env, cwd):
    """Codex's own list of the hooks it found for ``cwd``."""
    server = AppServer(codex, env, cwd)
    try:
        result = server.call("hooks/list", {"cwds": [cwd]})
    finally:
        server.close()
    hooks = []
    for entry in result.get("data") or []:
        hooks.extend(entry.get("hooks") or [])
    return hooks


def trust_as_codex_does(codex_home, hooks):
    """Record trust for ``hooks`` the way Codex's review screen does: one
    [hooks.state."<key>"] table per hook, holding the hash Codex reported
    (two hashes for a plugin's hook, the second over its files)."""
    lines = []
    for hook in hooks:
        current = hook["currentHash"]
        lines.append('\n[hooks.state."%s"]' % hook["key"].replace("\\", "\\\\"))
        if "/" in current.split(":", 1)[-1]:
            definition, content = current.split("/", 1)
            lines.append('trusted_hash = "%s"' % definition)
            lines.append('trusted_content_hash = "%s"' % content)
        else:
            lines.append('trusted_hash = "%s"' % current)
    with open(os.path.join(codex_home, "config.toml"), "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# --- the relay of this run -----------------------------------------------------

def start_relay(tree, home, env, port, tls_port, tunnel_port):
    relay = subprocess.Popen(
        [sys.executable, os.path.join(tree, "watch_relay.py"), "--port", str(port),
         "--tls-port", str(tls_port), "--tunnel-port", str(tunnel_port), "--no-bonjour"],
        env=env, cwd=home, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base + "/health", timeout=2).read()
            with open(os.path.join(home, ".tapproval", "data", "auth.json"), encoding="utf-8") as h:
                return relay, base, json.load(h)["bootstrap"]
        except (OSError, ValueError, KeyError):
            time.sleep(0.3)
    relay.kill()
    raise SystemExit("the relay did not answer /health:\n"
                     + relay.communicate()[0].decode("utf-8", "replace")[-1500:])


def stop_relay(relay):
    if relay is None:
        return
    relay.terminate()
    try:
        relay.wait(timeout=10)
    except subprocess.TimeoutExpired:
        relay.kill()


def pending_has(base, token, needle):
    return any(needle in json.dumps(card)
               for card in get(base + "/pending", token).get("cards") or [])


def ask(arm, label, argv, env, cwd, base, token, answer):
    """One PermissionRequest through a hook command, answered on the
    'wrist' as ``answer`` says (None: nobody answers)."""
    needle = "tapproval-e2e-%s-%d" % (re.sub(r"\W", "-", label), int(time.time() * 1000))
    event = {"hook_event_name": "PermissionRequest", "session_id": "e2e-" + needle,
             "cwd": cwd, "tool_name": "Bash",
             "tool_input": {"command": "rm -rf build/" + needle,
                            "description": "Clear a build folder"}}
    hook = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, cwd=cwd)
    hook.stdin.write(json.dumps(event).encode("utf-8"))
    hook.stdin.close()
    hook.stdin = None
    if answer:
        card = wait_for_card(base, token, needle)
        if arm.check(card is not None, "%s: the card reached this run's relay" % label):
            decide(base, token, card["id"], answer)
    try:
        out, err = hook.communicate(timeout=UNANSWERED_WAIT + 40)
    except subprocess.TimeoutExpired:
        hook.kill()
        out, err = hook.communicate()
    got = decision_of(out.decode("utf-8", "replace"))
    if answer:
        ok = isinstance(got, dict) and got.get("behavior") == answer
        arm.check(ok, '%s: a wrist %s comes back as {"behavior": "%s"}' % (label, answer, answer))
    else:
        ok = got is None
        arm.check(ok, "%s: an unanswered card leaves no decision, so the agent asks" % label)
    if not ok:
        arm.say("        stdout: %r" % out[:300])
        arm.say("        stderr: %r" % err.decode("utf-8", "replace")[-600:])


def our_hooks(hooks_by_event, event):
    found = []
    for group in hooks_by_event.get(event) or []:
        for hook in group.get("hooks") or []:
            if "ClaudeRiskClassifier" in json.dumps(hook) or "watch_relay" in json.dumps(hook):
                found.append(hook)
    return found


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


# --- arm A: the Claude Code plugin ---------------------------------------------

def arm_a(arm, sabotage=None):
    claude = find_claude()
    work = tempfile.mkdtemp(prefix="tapproval-e2e-A-")
    relay = None
    try:
        home = make_home(work)
        env = clean_env(home)
        tree = os.path.join(work, "tree")
        public_tree(tree)
        port, tls_port, tunnel_port = free_port(), free_port(), free_port()
        aim(tree, port, tls_port, tunnel_port, sabotage)

        arm.say("validate, add the marketplace, install")
        code, out, err = run([claude, "plugin", "validate", tree, "--strict"], env, home)
        arm.check(code == 0, "claude plugin validate --strict passes")
        if code:
            arm.say("        " + (out + err)[-800:])
        code, out, err = run([claude, "plugin", "marketplace", "add", tree, "--json"], env, home)
        arm.check(code == 0 and (last_json(out) or {}).get("outcome") == "ok",
                  "claude plugin marketplace add takes the tree")
        code, out, err = run([claude, "plugin", "install", PLUGIN, "--json"], env, home)
        if not arm.check(code == 0 and (last_json(out) or {}).get("outcome") == "ok",
                         "claude plugin install installs " + PLUGIN):
            arm.stop("install: " + (out + err)[-600:])

        registry = read_json(os.path.join(home, ".claude", "plugins", "installed_plugins.json"), {})
        entries = (registry.get("plugins") or {}).get(PLUGIN) or []
        root = entries[0].get("installPath") if entries else None
        if not arm.check(bool(root) and os.path.isdir(root),
                         "Claude Code recorded the install and its folder"):
            arm.stop("no install folder")
        installed = read_json(os.path.join(root, "hooks", "hooks.json"), {})
        shipped = read_json(os.path.join(tree, "hooks", "hooks.json"), {})
        arm.check(installed == shipped, "the installed hooks are the ones the tree ships")
        hooks = installed.get("hooks") or {}

        relay, base, token = start_relay(tree, home, env, port, tls_port, tunnel_port)
        # As Claude Code runs a plugin's hook: its folder in the environment.
        hook_env = dict(env, CLAUDE_PLUGIN_ROOT=root, CLAUDE_PLUGIN_DATA=os.path.join(home, "data"))
        asking = our_hooks(hooks, "PermissionRequest")
        arm.check(len(asking) == 1, "exactly one PermissionRequest hook")
        for hook in asking[:1]:
            for shell, argv in runners(hook):
                label = "plugin/" + shell
                ask(arm, label, argv, hook_env, home, base, token, "allow")
                ask(arm, label, argv, hook_env, home, base, token, "deny")
                ask(arm, label, argv, hook_env, home, base, token, None)

        starting = our_hooks(hooks, "SessionStart")
        arm.check(len(starting) == 1, "exactly one SessionStart hook")
        settings = os.path.join(home, ".claude", "settings.json")
        before = read_json(settings)
        pid_file = os.path.join(home, ".tapproval", "data", "relay.pid")
        pid_before = read_json(pid_file)
        for hook in starting[:1]:
            shell, argv = runners(hook)[0]
            done = subprocess.run(argv, env=hook_env, cwd=home, capture_output=True, timeout=120)
            said = done.stderr.decode("utf-8", "replace")
            arm.check(done.returncode == 0, "SessionStart exits 0")
            arm.check("already running" in said,
                      "SessionStart finds this run's relay and starts no other")
            if "already running" not in said:
                arm.say("        stderr: %r" % said[-600:])
        arm.check(read_json(settings) == before,
                  "SessionStart leaves Claude Code's settings as the plugin install left them")
        arm.check(read_json(pid_file) == pid_before, "no second relay was started")

        arm.say("uninstall")
        code, out, err = run([claude, "plugin", "uninstall", PLUGIN, "--json"], env, home)
        arm.check(code == 0, "claude plugin uninstall exits 0")
        registry = read_json(os.path.join(home, ".claude", "plugins", "installed_plugins.json"), {})
        arm.check(not (registry.get("plugins") or {}).get(PLUGIN),
                  "Claude Code no longer lists the plugin")
        enabled = (read_json(settings, {}) or {}).get("enabledPlugins") or {}
        arm.check(not enabled.get(PLUGIN), "the plugin is not enabled anywhere")
        arm.check(not our_hooks((read_json(settings, {}) or {}).get("hooks") or {},
                                "PermissionRequest"),
                  "no Tapproval hook is left in Claude Code's settings")
    except ArmStopped:
        pass
    finally:
        stop_relay(relay)
        shutil.rmtree(work, ignore_errors=True)


def codex_question(arm, commands, env, home, base, token):
    """One Codex PermissionRequest through every hook command Codex would
    run for it. Returns the audit lines it left."""
    needle = "tapproval-e2e-codex-%d" % int(time.time() * 1000)
    event = {"hook_event_name": "PermissionRequest", "session_id": "e2e-codex",
             "turn_id": "e2e-turn", "cwd": home, "tool_name": "Bash",
             "tool_input": {"command": "rm -rf build/" + needle}}
    quiet = True
    for argv in commands:
        hook_run = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env, cwd=home)
        try:
            out, err = hook_run.communicate(json.dumps(event).encode("utf-8"),
                                            timeout=UNANSWERED_WAIT + 20)
        except subprocess.TimeoutExpired:
            hook_run.kill()
            out, err = hook_run.communicate()
        if hook_run.returncode != 0 or decision_of(out.decode("utf-8", "replace")) is not None:
            quiet = False
            arm.say("        stdout: %r  stderr: %r" % (out[:200], err[-400:]))
    arm.check(not pending_has(base, token, needle),
              "a Codex prompt makes no wrist card of its own")
    arm.check(quiet, "the Codex hook leaves the decision with Codex")
    lines = []
    try:
        with open(os.path.join(home, ".claude", "risk-audit.jsonl"), encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if needle in line]
    except (OSError, ValueError):
        pass
    arm.check(bool(lines) and lines[-1].get("mode") == "enforce"
              and str(lines[-1].get("watch", "")).startswith("native"),
              "it ran Codex's path, in enforce mode, through this run's relay")
    return lines


# --- arm C: the terminal install, with Codex present ---------------------------

def our_reading_of_trust(tree, env, home):
    code, out, err = run([sys.executable, "-c",
                          "import sys; sys.path.insert(0, sys.argv[1]); "
                          "import ClaudeRiskClassifier as c; print(c.codex_hook_trusted())",
                          tree], env, home, timeout=60)
    return out.strip() if code == 0 else "error: " + err[-300:]


def arm_c(arm, sabotage=None):
    codex = find_codex()
    work = tempfile.mkdtemp(prefix="tapproval-e2e-C-")
    relay = None
    try:
        home = make_home(work, codex=True)
        env = clean_env(home)
        codex_home = os.path.join(home, ".codex")
        tree = os.path.join(work, "tree")
        public_tree(tree)
        port, tls_port, tunnel_port = free_port(), free_port(), free_port()
        aim(tree, port, tls_port, tunnel_port)

        arm.say("install from the terminal")
        code, out, err = run([sys.executable, os.path.join(tree, "ClaudeRiskClassifier.py"),
                              "--install", "--watch", "--no-bridge"], env, home)
        if not arm.check(code == 0, "--install --watch exits 0"):
            arm.stop("install: " + (out + err)[-800:])
        arm.check("Claude Code or Codex session" in out,
                  "the installer says both agents are wired")

        settings_path = os.path.join(home, ".claude", "settings.json")
        settings = read_json(settings_path, {})
        claude_hooks = our_hooks(settings.get("hooks") or {}, "PermissionRequest")
        arm.check(len(claude_hooks) == 1, "Claude Code: exactly one PermissionRequest hook")
        relay_url = (settings.get("env") or {}).get("CLAUDE_RISK_RELAY", "")
        arm.check(relay_url == "http://127.0.0.1:%d" % port,
                  "--watch points Claude Code at this run's relay, not 8977")

        hooks_path = os.path.join(codex_home, "hooks.json")
        if sabotage:
            sabotage(hooks_path)
        codex_config = read_json(hooks_path, {}).get("hooks") or {}
        codex_asking = our_hooks(codex_config, "PermissionRequest")
        arm.check(len(codex_asking) == 1, "Codex: exactly one PermissionRequest hook")
        arm.check(bool(codex_asking) and "--agent codex" in codex_asking[0].get("command", ""),
                  "Codex's hook runs the Codex path (--agent codex)")
        arm.check(len(our_hooks(codex_config, "SessionStart")) == 1,
                  "Codex: exactly one SessionStart hook")

        arm.say("trust, as Codex sees it and as we read it")
        listed = [h for h in codex_hooks(codex, env, home)
                  if h.get("source") != "plugin" and ("ClaudeRiskClassifier" in h.get("command", "")
                                                      or "watch_relay" in h.get("command", ""))]
        arm.check(len(listed) == 2, "Codex itself lists our two hooks")
        arm.check(all(h.get("trustStatus") == "untrusted" for h in listed),
                  "Codex calls them untrusted before the click")
        arm.check(our_reading_of_trust(tree, env, home) == "False",
                  "we call the hook untrusted too, so the watch can say so")
        trust_as_codex_does(codex_home, listed)
        listed = [h for h in codex_hooks(codex, env, home)
                  if h.get("key") in {x["key"] for x in listed}]
        arm.check(len(listed) == 2 and all(h.get("trustStatus") == "trusted" for h in listed),
                  "after the click Codex calls them trusted")
        arm.check(our_reading_of_trust(tree, env, home) == "True",
                  "and so do we: our hash is Codex's")

        relay, base, token = start_relay(tree, home, env, port, tls_port, tunnel_port)
        # Claude Code gives its hooks the env its settings hold.
        claude_env = dict(env, **{k: str(v) for k, v in (settings.get("env") or {}).items()})
        for hook in claude_hooks[:1]:
            shell, argv = runners(hook)[0]
            label = "installed/claude/" + shell
            ask(arm, label, argv, claude_env, home, base, token, "allow")
            ask(arm, label, argv, claude_env, home, base, token, "deny")

        # Codex gives its hooks its own environment: nothing from Claude
        # Code's settings, which the hook reads for itself.
        for hook in codex_asking[:1]:
            codex_question(arm, [runners(hook)[0][1]], env, home, base, token)

        arm.say("uninstall")
        code, out, err = run([sys.executable, os.path.join(tree, "ClaudeRiskClassifier.py"),
                              "--uninstall"], env, home)
        arm.check(code == 0, "--uninstall exits 0")
        arm.check(not our_hooks((read_json(settings_path, {}) or {}).get("hooks") or {},
                                "PermissionRequest"),
                  "Claude Code: no Tapproval hook left")
        left = (read_json(hooks_path, {}) or {}).get("hooks") or {}
        arm.check(not our_hooks(left, "PermissionRequest") and not our_hooks(left, "SessionStart"),
                  "Codex: no Tapproval hook left")
    except ArmStopped:
        pass
    finally:
        stop_relay(relay)
        shutil.rmtree(work, ignore_errors=True)


# --- arm B: the Codex plugin ----------------------------------------------------

def install_codex_plugin(arm, codex, env, home, tree):
    code, out, err = run([codex, "plugin", "marketplace", "add", tree, "--json"], env, home)
    arm.check(code == 0 and (last_json(out) or {}).get("marketplaceName") == "tapproval",
              "codex plugin marketplace add takes the tree as the tapproval marketplace")
    code, out, err = run([codex, "plugin", "add", PLUGIN, "--json"], env, home)
    result = last_json(out) or {}
    if not arm.check(code == 0 and result.get("pluginId") == PLUGIN,
                     "codex plugin add installs " + PLUGIN):
        arm.stop("codex plugin add: " + (out + err)[-600:])
    return result.get("installedPath") or ""


def plugin_hooks(codex, env, home):
    return [h for h in codex_hooks(codex, env, home) if h.get("pluginId") == PLUGIN]


def by_event(hooks, name):
    return [h for h in hooks if h.get("eventName") == name]


def start_session_as_codex(command, env, home):
    """The plugin's SessionStart command, as Codex resolved it, run as Codex
    runs it. (stdout JSON or None, seconds it took, stderr)."""
    event = {"hook_event_name": "SessionStart", "session_id": "e2e-start",
             "cwd": home, "source": "startup"}
    began = time.time()
    done = subprocess.run(runners({"command": command})[0][1], input=json.dumps(event).encode(),
                          capture_output=True, env=env, cwd=home, timeout=200)
    return (last_json(done.stdout.decode("utf-8", "replace")), time.time() - began,
            done.stderr.decode("utf-8", "replace"))


def relay_from_pid_file(home):
    try:
        with open(os.path.join(home, ".tapproval", "data", "relay.pid"), encoding="utf-8") as h:
            return int(h.read().strip().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def stop_pid(pid):
    if not pid:
        return
    try:
        if WINDOWS:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        else:
            import signal
            os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def arm_b(arm, sabotage=None):
    codex = find_codex()
    work = tempfile.mkdtemp(prefix="tapproval-e2e-B-")
    pid = None
    try:
        home = make_home(work, codex=True)
        env = clean_env(home)
        # As a user's own terminal has it: codex on PATH, for the uninstall.
        env["PATH"] = os.path.dirname(codex) + os.pathsep + env.get("PATH", "")
        codex_home = os.path.join(home, ".codex")
        tree = os.path.join(work, "tree")
        public_tree(tree)
        port, tls_port, tunnel_port = free_port(), free_port(), free_port()
        aim(tree, port, tls_port, tunnel_port, sabotage)

        arm.say("add the marketplace, install the plugin")
        folder = install_codex_plugin(arm, codex, env, home, tree)
        arm.check(os.path.isfile(os.path.join(folder, "tapproval.py"))
                  and not os.path.exists(os.path.join(folder, "ClaudeRiskClassifier.py")),
                  "Codex keeps only the plugin's own small folder")

        arm.say("trust, as Codex sees it and as we read it")
        listed = plugin_hooks(codex, env, home)
        arm.check(len(by_event(listed, "sessionStart")) == 1
                  and len(by_event(listed, "permissionRequest")) == 1 and len(listed) == 2,
                  "Codex lists the plugin's two hooks, and no others of ours")
        arm.check(all(h.get("trustStatus") == "untrusted" for h in listed),
                  "Codex calls them untrusted before the click")
        tree_helper = tree
        arm.check(our_reading_of_trust(tree_helper, env, home) == "False",
                  "we call the plugin untrusted too, so the watch can say so")
        trust_as_codex_does(codex_home, listed)
        listed = plugin_hooks(codex, env, home)
        arm.check(len(listed) == 2 and all(h.get("trustStatus") == "trusted" for h in listed),
                  "one click: Codex calls both trusted")
        arm.check(our_reading_of_trust(tree_helper, env, home) == "True",
                  "and so do we")

        arm.say("the first session start, by Codex itself")
        code, out, err = run([codex, "exec", "--skip-git-repo-check", "say hello"],
                             env, home, timeout=240)
        helper = os.path.join(home, ".tapproval", "ClaudeRiskClassifier.py")
        arm.check(os.path.isfile(helper) and os.path.isdir(os.path.join(home, ".tapproval", ".git")),
                  "Codex's session start fetched the helper into ~/.tapproval, as a checkout")
        base = "http://127.0.0.1:%d" % port
        up = False
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/health", timeout=2).read()
                up = True
                break
            except OSError:
                time.sleep(0.5)
        arm.check(up, "and started the relay, on this run's port")
        pid = relay_from_pid_file(home)
        arm.check(os.path.exists(os.path.join(home, ".tapproval", "data", "codex-plugin-welcomed")),
                  "and said once that Base is set up")
        arm.check(not os.path.exists(os.path.join(codex_home, "hooks.json")),
                  "the plugin needs nothing in Codex's hooks.json")
        arm.check(not os.path.exists(os.path.join(home, ".claude", "settings.json")),
                  "and writes nothing into Claude Code")
        token = read_json(os.path.join(home, ".tapproval", "data", "auth.json"), {}).get("bootstrap")

        arm.say("the next session start, and a question")
        start = by_event(listed, "sessionStart")[0]["command"]
        said, seconds, err = start_session_as_codex(start, env, home)
        arm.check(said == {}, "a later session start says nothing more")
        arm.check(seconds < 15, "and takes %.1f s, under 15" % seconds)
        ask_command = by_event(listed, "permissionRequest")[0]["command"]
        if token:
            codex_question(arm, [runners({"command": ask_command})[0][1]], env, home, base, token)
        else:
            arm.check(False, "the relay's key is there to ask with")

        arm.say("updates")
        with open(os.path.join(tree, "README.md"), "a", encoding="utf-8") as handle:
            handle.write("\nA helper release.\n")
        commit(tree, "a helper release")
        run([codex, "plugin", "add", PLUGIN, "--json"], env, home)
        arm.check(all(h.get("trustStatus") == "trusted" for h in plugin_hooks(codex, env, home)),
                  "a helper release leaves the plugin trusted: no new click")
        with open(os.path.join(tree, "codex-plugin", "tapproval.py"), "a", encoding="utf-8") as h:
            h.write("# a change to the plugin's own folder\n")
        commit(tree, "a plugin change")
        run([codex, "plugin", "add", PLUGIN, "--json"], env, home)
        arm.check(all(h.get("trustStatus") == "modified" for h in plugin_hooks(codex, env, home)),
                  "a change to the plugin's own folder does ask again, which is why it is rare")

        arm.say("uninstall")
        code, out, err = run([sys.executable, helper, "--uninstall"], env, home)
        arm.check("Removed the Codex plugin." in out, "--uninstall takes the Codex plugin out")
        arm.check(not plugin_hooks(codex, env, home), "Codex lists no Tapproval hook after")
    except ArmStopped:
        pass
    finally:
        stop_pid(pid or relay_from_pid_file(os.path.join(work, "home")))
        shutil.rmtree(work, ignore_errors=True)


# --- arm D: both plugins, then the terminal install over them --------------------

def arm_d(arm, sabotage=None):
    codex, claude = find_codex(), find_claude()
    work = tempfile.mkdtemp(prefix="tapproval-e2e-D-")
    pid = None
    try:
        home = make_home(work, codex=True)
        env = clean_env(home)
        env["PATH"] = os.path.dirname(codex) + os.pathsep + env.get("PATH", "")
        codex_home = os.path.join(home, ".codex")
        tree = os.path.join(work, "tree")
        public_tree(tree)
        port, tls_port, tunnel_port = free_port(), free_port(), free_port()
        aim(tree, port, tls_port, tunnel_port, sabotage)

        arm.say("both plugins")
        code, out, err = run([claude, "plugin", "marketplace", "add", tree, "--json"], env, home)
        code, out, err = run([claude, "plugin", "install", PLUGIN, "--json"], env, home)
        arm.check(code == 0, "Claude Code's plugin installs")
        install_codex_plugin(arm, codex, env, home, tree)
        listed = plugin_hooks(codex, env, home)
        trust_as_codex_does(codex_home, listed)
        settings = os.path.join(home, ".claude", "settings.json")
        before = read_json(settings, {})
        said, seconds, err = start_session_as_codex(
            by_event(listed, "sessionStart")[0]["command"], env, home)
        message = (said or {}).get("systemMessage") or ""
        arm.check("set up for Codex" in message, "the Codex start says Base is set up")
        arm.check("Claude Code too" not in message,
                  "and offers nothing for Claude Code, which has Base already")
        arm.check(read_json(settings, {}) == before,
                  "the Codex setup leaves Claude Code's settings as they were")
        pid = relay_from_pid_file(home)
        base = "http://127.0.0.1:%d" % port
        token = read_json(os.path.join(home, ".tapproval", "data", "auth.json"), {}).get("bootstrap")

        arm.say("the terminal install over both")
        helper = os.path.join(home, ".tapproval", "ClaudeRiskClassifier.py")
        code, out, err = run([sys.executable, helper, "--install", "--watch", "--no-bridge"],
                             env, home)
        arm.check(code == 0, "--install over the plugins exits 0")
        terminal = [h for h in codex_hooks(codex, env, home)
                    if h.get("source") != "plugin" and "--agent codex" in h.get("command", "")]
        trust_as_codex_does(codex_home, terminal)
        asking = [runners({"command": h["command"]})[0][1]
                  for h in by_event(plugin_hooks(codex, env, home), "permissionRequest") + terminal]
        arm.check(len(asking) == 2, "Codex now has two Tapproval question hooks to run")
        if token:
            lines = codex_question(arm, asking, env, home, base, token)
            arm.check(len(lines) == 1, "a Codex question is answered once, not twice (%d)" % len(lines))
    except ArmStopped:
        pass
    finally:
        stop_pid(pid or relay_from_pid_file(os.path.join(work, "home")))
        shutil.rmtree(work, ignore_errors=True)


# --- the deliberate faults -----------------------------------------------------

def _drop_agent_flag(hooks_path):
    with open(hooks_path, encoding="utf-8") as handle:
        text = handle.read()
    with open(hooks_path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(" --agent codex", ""))


# (arm, fault, the check that must catch it)
NEGATIVES = {
    "A": ([(os.path.join("hooks", "hooks.json"), "CLAUDE_RISK_MODE=enforce ", "", 2)],
          'plugin/%s: a wrist allow comes back as {"behavior": "allow"}'),
    # Without --agent codex the hook takes Claude Code's path, which finds
    # no Claude settings in Codex's environment and quietly does nothing:
    # Codex's prompts would never reach the wrist.
    "C": (_drop_agent_flag, "it ran Codex's path, in enforce mode, through this run's relay"),
    # The plugin's script without the watch switched on: Codex's questions
    # would stay on the computer.
    "B": ([(os.path.join("codex-plugin", "tapproval.py"), '"CLAUDE_RISK_MODE": "enforce"',
            '"CLAUDE_RISK_MODE": "shadow"')],
          "it ran Codex's path, in enforce mode, through this run's relay"),
    # The plugin's hook that does not stand down beside a trusted terminal
    # hook: every Codex question mirrored twice.
    "D": ([(os.path.join("codex-plugin", "tapproval.py"),
            'tail = ["--from-codex-plugin"] if knows_the_plugin() else []', "tail = []")],
          "a Codex question is answered once, not twice (2)"),
}
ARMS = {"A": (arm_a, lambda: find_claude(), "claude"),
        "B": (arm_b, lambda: find_codex(), "codex"),
        "C": (arm_c, lambda: find_codex(), "codex"),
        "D": (arm_d, lambda: find_codex() and find_claude(), "codex and claude")}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--arm", action="append", choices=sorted(ARMS))
    parser.add_argument("--require", action="store_true",
                        help="fail, rather than skip, an arm whose agent CLI is missing")
    parser.add_argument("--no-negative", action="store_true",
                        help="skip the runs with a deliberate fault")
    args = parser.parse_args()
    print("host: %s, Python %s" % (sys.platform, sys.version.split()[0]), flush=True)
    before = real_home_fingerprint()
    failures, skipped = [], []
    for key in args.arm or sorted(ARMS):
        function, finder, program = ARMS[key]
        if not finder():
            if args.require:
                failures.append("%s: no %s CLI on this computer" % (key, program))
            else:
                skipped.append("%s (no %s CLI)" % (key, program))
            continue
        print("\narm %s" % key, flush=True)
        arm = Arm(key)
        function(arm)
        failures += ["%s: %s" % (key, what) for what in arm.failed]
        if args.no_negative:
            continue
        fault, catcher = NEGATIVES[key]
        print("arm %s, with a deliberate fault" % key, flush=True)
        negative = Arm(key + "-negative", quiet=True)
        function(negative, sabotage=fault)
        sh = "git-bash" if WINDOWS else "sh"
        caught = catcher.replace("%s", sh) if "%s" in catcher else catcher
        if caught in negative.failed:
            print("  ok    the fault was caught: " + caught, flush=True)
        else:
            print("  FAIL  the fault went unseen; expected to fail: " + caught, flush=True)
            failures.append("%s: its check did not catch a deliberate fault" % key)
    after = real_home_fingerprint()
    changed = [path for path in before if before[path] != after[path]]
    if changed:
        failures.append("the real home changed: " + ", ".join(changed))
    for what in skipped:
        print("\nSKIPPED " + what, flush=True)
    if failures:
        print("\n%d failed on %s:" % (len(failures), sys.platform))
        for what in failures:
            print("  - " + what)
        return 1
    print("\nall passed on %s" % sys.platform)
    return 0


if __name__ == "__main__":
    sys.exit(main())
