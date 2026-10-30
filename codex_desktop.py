"""Opt-in Desktop CLI adapter: one native server, stdio proxy and private socket.

The Desktop client still owns initialization, turns and approval decisions.
Only its transport changes. No daemon, permission or pairing settings change.
"""
from __future__ import annotations

import json
import os
import plistlib
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
    return not any(arg in ("--print-startup-config", "--startup-sign-out", "--help",
                           "-h", "--stdio", "--listen") or arg.startswith("--listen=")
                   for arg in tail)


def proxy_stdio(path):
    """Translate framing only; all RPC ownership stays with the native server."""
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
                    wire.send(message)
            if len(buffered) > limit:
                raise ValueError("oversized Desktop message")
        return 1 if failed.is_set() else 0
    finally:
        done.set()
        wire.close()
        reader.join(timeout=2)


def run(cli, args):
    """Keep the original config arguments on the server, never on a new thread."""
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
    root = codex_home() / "tapproval-desktop"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not _private_directory(root):
        raise ValueError("Desktop adapter directory must be private and owned by this user")
    folder = Path(tempfile.mkdtemp(prefix="s-", dir=str(root)))
    path = folder / "rpc.sock"
    server = descriptor = None
    previous = {}
    try:
        descriptor = os.open(folder / "live.lock", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        if not host.try_lock(descriptor):
            raise ValueError("Desktop adapter lifecycle lock is already held")
        if len(os.fsencode(path)) > 100:
            raise ValueError("Codex home is too long for a private Unix socket")
        server = subprocess.Popen([cli, *args, "--listen", "unix://" + str(path)],
                                  env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL)
        def stop(_signum, _frame):
            raise KeyboardInterrupt
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        deadline = time.monotonic() + 10
        while not path.exists():
            if server.poll() is not None:
                return server.returncode or 1
            if time.monotonic() >= deadline:
                raise TimeoutError("Desktop app-server did not open its private socket")
            time.sleep(.025)
        record = folder / "owner.json"
        with record.open("x") as output:
            os.chmod(record, 0o600)
            json.dump({"pid": server.pid, "home": str(codex_home())}, output)
        return proxy_stdio(str(path))
    except KeyboardInterrupt:
        return 130
    finally:
        # These are children created here, never a shared daemon or other chat.
        for child in (server,):
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for number, handler in previous.items():
            signal.signal(number, handler)
        if descriptor is not None:
            os.close(descriptor)
        for name in ("owner.json", "rpc.sock", "live.lock"):
            try:
                (folder / name).unlink()
            except FileNotFoundError:
                pass
        folder.rmdir()


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
        wrapper: '#!/bin/sh\nexec %s "$@"\n' % common,
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
