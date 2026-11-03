"""Opt-in Desktop stdio connection to the phone's shared Codex owner.

Desktop initialization and approvals pass through unchanged. Its startup
defaults and app-tool binding travel with its own thread requests instead
of creating another process that competes for the thread's writer lock.
"""
from __future__ import annotations

import copy
import json
import math
import os
import plistlib
import re
import select
import shlex
import stat
import subprocess
import sys
import threading
from pathlib import Path

import tapproval_host as host


def codex_home():
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex").resolve()


def _private_directory(path):
    info = path.lstat()
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0)


def desktop_sockets():
    """Only live, same-user endpoints explicitly created by this adapter."""
    if host.native_windows():
        return []
    root = codex_home() / "tapproval-desktop"
    found = []
    try:
        if not _private_directory(root):
            return []
        for folder in sorted(root.glob("s-*"))[:32]:
            try:
                if not _private_directory(folder):
                    continue
                record = folder / "owner.json"
                info = record.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077 or info.st_size > 1024):
                    continue
                owner = json.loads(record.read_text())
                if (not isinstance(owner, dict) or type(owner.get("pid")) is not int
                        or not 0 < owner["pid"] < 2 ** 31
                        or owner.get("home") != str(codex_home())):
                    continue
                os.kill(owner["pid"], 0)
                lease = folder / "live.lock"
                info = lease.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_mode & 0o077):
                    continue
                descriptor = os.open(lease, os.O_RDWR)
                try:
                    if host.try_lock(descriptor):
                        host.unlock(descriptor)
                        continue  # A dead wrapper must not expose an orphan server.
                finally:
                    os.close(descriptor)
                path = folder / "rpc.sock"
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    # Codex can shorten a Unix endpoint with an alias into
                    # its own private socket directory. Validate that target,
                    # not merely an arbitrary symlink in our registry.
                    target = path.resolve(strict=True)
                    if info.st_uid != os.getuid() or not _private_directory(target.parent):
                        continue
                    info = target.lstat()
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
                    found.append(str(path))
            except (OSError, ValueError, TypeError):
                continue
    except OSError:
        pass
    return found


def server_sockets():
    default = str(codex_home() / "app-server-control" / "app-server-control.sock")
    return desktop_sockets() + [default]


def bridge_args(args):
    """Intercept only ordinary app-server starts; preserve all other CLI uses."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-c", "--config", "--enable", "--disable"):
            index += 2
        elif arg.startswith(("--config=", "--enable=", "--disable=")):
            index += 1
        else:
            break
    if index >= len(args) or args[index] != "app-server":
        return False
    tail = args[index + 1:]
    if tail and not tail[0].startswith("-"):
        return False
    for offset, arg in enumerate(tail):
        if arg in ("--print-startup-config", "--startup-sign-out", "--help", "-h"):
            return False
        if arg == "--listen" and (offset + 1 == len(tail) or tail[offset + 1] != "stdio://"):
            return False
        if arg.startswith("--listen=") and arg != "--listen=stdio://":
            return False
    return True


def _config_key(key):
    """Dotted CLI keys, including quoted plugin names, without a TOML dependency."""
    parts = []
    while key:
        match = re.match(r'''(?:"(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_@/-]+)(?=\.|$)''', key)
        if not match:
            raise ValueError("Codex shared connection cannot translate a Desktop config key")
        part = match[0]
        parts.append(json.loads(part) if part.startswith('"') else part.strip("'"))
        key = key[len(part):]
        if key:
            key = key[1:]
            if not key:
                raise ValueError("Codex shared connection cannot translate a Desktop config key")
    if not parts:
        raise ValueError("Codex shared connection cannot translate a Desktop config key")
    return parts


def _config_value(text):
    # Desktop currently supplies booleans. Also retain ordinary JSON/TOML
    # scalar/array overrides; refuse richer TOML instead of silently losing
    # a setting or starting a private server behind the phone's back.
    if text.startswith("'") and text.endswith("'") and "'" not in text[1:-1]:
        return text[1:-1]
    try:
        value = json.loads(text)
    except ValueError as error:
        raise ValueError("Codex shared connection cannot translate a Desktop config value") from error
    def valid(item):
        if isinstance(item, list):
            return all(valid(part) for part in item)
        return (isinstance(item, (str, bool, int)) or
                isinstance(item, float) and math.isfinite(item))
    if not valid(value):
        raise ValueError("Codex shared connection cannot translate a Desktop config value")
    return value


def shared_overrides(args, env):
    """Translate Desktop CLI defaults into native per-thread JSON config.

    A managed server cannot inherit Desktop's pipe environment. Carry only
    the app's existing tool-runtime variables with the enabled app-tools
    server; do not copy arbitrary environment values or global config.
    """
    config = {}
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg in ("app-server", "--analytics-default-enabled", "--stdio", "--listen=stdio://"):
            continue
        if arg == "--listen" and index < len(args) and args[index] == "stdio://":
            index += 1
            continue
        if arg in ("-c", "--config", "--enable", "--disable"):
            if index >= len(args):
                raise ValueError("Codex shared connection is missing a Desktop option value")
            value = args[index]
            index += 1
            value = ("features." + value + "=" + ("true" if arg == "--enable" else "false")
                     if arg in ("--enable", "--disable") else value)
        elif arg.startswith(("--config=", "--enable=", "--disable=")):
            option, value = arg.split("=", 1)
            if option != "--config":
                value = "features." + value + "=" + ("true" if option == "--enable" else "false")
        else:
            raise ValueError("Codex shared connection cannot apply this Desktop startup option")
        if "=" not in value:
            raise ValueError("Codex shared connection is missing a Desktop config value")
        key, value = value.split("=", 1)
        parts = _config_key(key.strip())
        current = config
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            if not isinstance(current, dict):
                raise ValueError("Codex shared connection has conflicting Desktop config keys")
        current[parts[-1]] = _config_value(value.strip())
    bindings = {key: env[key] for key in (
        "CODEX_APP_TOOLS_PIPE_PATH", "CODEX_MCP_NODE_PATH", "CODEX_BROWSER_USE_NODE_PATH",
        "CODEX_ELECTRON_RESOURCES_PATH", "CODEX_CLI_PATH") if env.get(key)}
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        raise ValueError("Codex shared connection has invalid Desktop plugin defaults")
    servers = [config.get("mcp_servers", {})]
    servers += [plugin.get("mcp_servers", {}) for plugin in plugins.values()
                if isinstance(plugin, dict)]
    for entries in servers:
        server = entries.get("codex_app") if isinstance(entries, dict) else None
        if isinstance(server, dict) and server.get("enabled") is True:
            existing = server.setdefault("env", {})
            if not isinstance(existing, dict):
                raise ValueError("Codex shared connection has invalid Desktop app-tool bindings")
            existing.update(bindings)
    return config


def thread_request(message, overrides):
    """Defaults on this Desktop connection, with explicit request settings winning."""
    if not overrides or message.get("method") not in ("thread/start", "thread/resume", "thread/fork"):
        return message
    params = message.get("params")
    if (not isinstance(params, dict) or
            params.get("config") is not None and not isinstance(params["config"], dict)):
        raise ValueError("Invalid Desktop thread configuration on shared connection")
    def merge(low, high):
        result = copy.deepcopy(low)
        for key, value in high.items():
            result[key] = (merge(result[key], value)
                           if isinstance(result.get(key), dict) and isinstance(value, dict)
                           else copy.deepcopy(value))
        return result
    return dict(message, params=dict(params, config=merge(overrides, params.get("config") or {})))


def proxy_stdio(path, overrides=None):
    """One shared owner, preserving framing and the connection's thread defaults."""
    from codex_approvals import LocalWebSocket
    limit = 16 * 1024 * 1024
    wire = LocalWebSocket(path, max_message=limit)
    done = threading.Event()
    failed = threading.Event()
    def read():
        try:
            while not done.is_set():
                message = wire.receive()
                sys.stdout.buffer.write(json.dumps(message, ensure_ascii=False).encode() + b"\n")
                sys.stdout.buffer.flush()
        except (OSError, EOFError, ValueError):
            if not done.is_set():
                failed.set()
            done.set()
    reader = threading.Thread(target=read, name="desktop-stdio", daemon=True)
    reader.start()
    buffered = b""
    try:
        while not done.is_set():
            if not select.select([sys.stdin], [], [], .25)[0]:
                continue
            chunk = os.read(sys.stdin.fileno(), 65536)
            if not chunk:
                return 1 if buffered.strip() else 0
            buffered += chunk
            while b"\n" in buffered:
                line, buffered = buffered.split(b"\n", 1)
                if len(line) > limit:
                    raise ValueError("oversized Desktop message")
                if line.strip():
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise ValueError("expected Desktop JSON-RPC object")
                    wire.send(thread_request(message, overrides))
            if len(buffered) > limit:
                raise ValueError("oversized Desktop message")
        return 1 if failed.is_set() else 0
    finally:
        done.set()
        wire.close()
        reader.join(timeout=2)


def run(cli, args):
    """Join the phone's owner; never spawn a competing Desktop app-server."""
    cli = str(Path(cli).resolve(strict=True))
    env = dict(os.environ)
    # Child tools must resolve the real CLI rather than recurse into the adapter.
    env.pop("TAPPROVAL_CODEX_REAL_CLI", None)
    env["CODEX_CLI_PATH"] = cli
    env["CODEX_APP_RUNTIME_CLI_PATH"] = cli
    if not bridge_args(args):
        return subprocess.call([cli, *args], env=env)
    if host.native_windows():
        raise ValueError("The Desktop socket adapter currently requires a POSIX host")
    overrides = shared_overrides(args, env)
    from codex_talk import _shared_client, shared_socket
    client = _shared_client(binary=cli)
    client.close()
    # Disconnecting the Desktop closes only its client, never the shared
    # server or a phone/watch turn. No writer ownership needs transferring.
    return proxy_stdio(shared_socket(), overrides=overrides)


def prepare_launcher(cli, app):
    """Prepare reviewable files only. Never quit or launch the active app."""
    if not host.is_mac():
        raise ValueError("The prepared Desktop launcher currently requires macOS")
    cli, app = Path(cli).resolve(strict=True), Path(app).resolve(strict=True)
    if not cli.is_file() or not (app / "Contents/Info.plist").is_file():
        raise ValueError("Select the installed CLI executable and Desktop application")
    root = Path.home() / ".tapproval/data/codex-desktop-launcher"
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not _private_directory(root):
        raise ValueError("Desktop launcher directory must be private and owned by this user")
    module = str(Path(__file__).resolve())
    wrapper, launcher = root / "codex", root / "Launch Codex.command"
    common = "%s %s" % (shlex.quote(sys.executable), shlex.quote(module))
    contents = {
        wrapper: ('#!/bin/sh\nexport TAPPROVAL_CODEX_REAL_CLI=%s\nexec %s "$@"\n'
                  % (shlex.quote(str(cli)), common)),
        launcher: ("#!/bin/sh\nexport CODEX_CLI_PATH=%s\nexport TAPPROVAL_CODEX_REAL_CLI=%s\n"
                   "exec %s --launch %s\n") % (
                       shlex.quote(str(wrapper)), shlex.quote(str(cli)), common, shlex.quote(str(app))),
    }
    for path, text in contents.items():
        if path.is_symlink():
            raise ValueError("Refusing a symlinked Desktop launcher")
        with path.open("w") as output:
            os.chmod(path, 0o700)
            output.write(text)
    return launcher


def launch(app, cli):
    app = Path(app).resolve(strict=True)
    with (app / "Contents/Info.plist").open("rb") as source:
        executable = app / "Contents/MacOS" / plistlib.load(source)["CFBundleExecutable"]
    running = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, check=True)
    if any(line.strip() == str(executable) for line in running.stdout.splitlines()):
        print("Quit Codex, then run this launcher again. No app was stopped.", file=sys.stderr)
        return 2
    wrapper = str(Path.home() / ".tapproval/data/codex-desktop-launcher/codex")
    args = ["open", "--env", "CODEX_CLI_PATH=" + wrapper,
            "--env", "TAPPROVAL_CODEX_REAL_CLI=" + cli]
    if os.environ.get("CODEX_HOME"):
        args += ["--env", "CODEX_HOME=" + os.environ["CODEX_HOME"]]
    return subprocess.call(args + ["-a", str(app)])


def main():
    cli = os.environ.get("TAPPROVAL_CODEX_REAL_CLI")
    if not cli:
        print("Set TAPPROVAL_CODEX_REAL_CLI to the installed Codex executable.", file=sys.stderr)
        return 2
    try:
        if sys.argv[1:2] == ["--prepare-launcher"] and len(sys.argv) == 3:
            print(prepare_launcher(cli, sys.argv[2]))
            return 0
        if sys.argv[1:2] == ["--launch"] and len(sys.argv) == 3:
            return launch(sys.argv[2], cli)
        return run(cli, sys.argv[1:])
    except (OSError, ValueError) as error:
        print("Tapproval Desktop adapter: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
