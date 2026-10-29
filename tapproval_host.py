"""What the helper does differently on macOS, Linux and Windows, in one
place (owner, 2026-10-28: the helper runs on every host).

Each function is one thing the helper needs from the computer it runs on,
with a branch per host. The callers never ask which host this is; a test
walks the sources and fails on a host check anywhere else, because the
checks used to be scattered over six files and Windows was missed by all
of them: `--ensure` never started a relay there, its lock import failing
silently into "another session is starting the helper".

The POSIX branch of every function is the code it replaced, moved, not
changed. Standard library only, Python 3.9, nothing at import and no process
module loaded until a function needs it: the hook imports this on every
prompt (TestTheHookStaysFast). The host is read at each call, never cached,
so a test can stand in for another one by setting ``sys.platform``.
"""
import os
import signal
import sys


def is_windows():
    return sys.platform == "win32"


def is_mac():
    return sys.platform == "darwin"


def native_windows():
    """What this interpreter can do, as opposed to which host a test stands
    in for: a suite that sets ``sys.platform`` to "darwin" on a Windows
    runner still has no fcntl, and its signal 0 still interrupts the
    console. Locks, signals, processes and sockets go by this; which
    command or file the helper writes goes by `is_windows()`/`is_mac()`."""
    return os.name == "nt"


# ---- locks -------------------------------------------------------------------

def try_lock(descriptor):
    """Take an exclusive lock on an open file without waiting. True when
    taken, False when someone else holds it; any other failure raises
    OSError. A crash releases it: the operating system drops it with the
    process, on every host."""
    if native_windows():
        import msvcrt
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as error:
            # EACCES, or EDEADLOCK (36) once its own retries ran out.
            if error.errno in (13, 36):
                return False
            raise
    import errno
    import fcntl
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EAGAIN):
            return False
        raise


def lock(descriptor):
    """Take an exclusive lock, waiting for it. Never raises on contention."""
    if native_windows():
        import msvcrt
        import time
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            try:
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                return
            except OSError as error:
                # LK_LOCK gives up after ten one-second tries; anything but
                # contention is a real failure, never a reason to spin.
                if error.errno not in (13, 36):
                    raise
                time.sleep(0.1)
    import fcntl
    fcntl.flock(descriptor, fcntl.LOCK_EX)


def unlock(descriptor):
    """Let a lock go. Never raises."""
    try:
        if native_windows():
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass


# ---- processes ---------------------------------------------------------------

_STILL_ACTIVE = 259
_QUERY_LIMITED = 0x1000
_ACCESS_DENIED = 5


def _windows_process_state(pid):
    """True running, False gone, None exists but is not ours to ask."""
    import ctypes
    # Its own handle on kernel32, typed: a HANDLE is pointer-sized, and the
    # error code is read where ctypes kept it, not after other calls ran.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    handle = kernel.OpenProcess(_QUERY_LIMITED, False, int(pid))
    if not handle:
        return None if ctypes.get_last_error() == _ACCESS_DENIED else False
    try:
        code = ctypes.c_ulong()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            return None
        return code.value == _STILL_ACTIVE
    finally:
        kernel.CloseHandle(handle)


def pid_alive(pid):
    """True when ``pid`` runs and this user may signal it. Never raises.

    Not ``os.kill(pid, 0)`` on Windows: there signal 0 is CTRL_C_EVENT,
    which interrupts every process on the console instead of asking."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if native_windows():
        try:
            return _windows_process_state(pid) is True
        except (OSError, AttributeError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def pid_exists(pid):
    """True while ``pid`` names a process, whoever owns it. Never raises."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if native_windows():
        try:
            return _windows_process_state(pid) is not False
        except (OSError, AttributeError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def reap(pid):
    """Collect a finished child of ours, so it is not left a zombie. POSIX
    only; Windows keeps no zombies. Never raises."""
    if native_windows():
        return
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass


def stop(pid, hard=False):
    """Ask ``pid`` to stop (TERM), or make it (KILL). True when the signal
    was delivered. On Windows both end the process: there is no TERM a
    console-less process can catch. Never raises."""
    signum = signal.SIGTERM
    if hard:
        signum = getattr(signal, "SIGKILL", signal.SIGTERM)
    try:
        os.kill(int(pid), signum)
        return True
    except (OSError, ValueError, TypeError):
        return False


# Windows: a new process group with no console, and out of the job Claude
# Code's process tree runs in, so the relay outlives the session that
# started it. Breaking away is refused inside a job that forbids it, so the
# spawn is retried without it.
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def popen_detached(command, **kwargs):
    """``subprocess.Popen`` for a child that outlives this process: its own
    session on POSIX, its own process group and no console on Windows.
    Raises what Popen raises."""
    import subprocess
    if not native_windows():
        return subprocess.Popen(command, start_new_session=True, **kwargs)
    flags = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    try:
        return subprocess.Popen(command, creationflags=flags | _CREATE_BREAKAWAY_FROM_JOB,
                                **kwargs)
    except OSError:
        return subprocess.Popen(command, creationflags=flags, **kwargs)


def current_user():
    """This user's id as the process list writes it: the uid on POSIX, the
    account name on Windows. None when it cannot be told."""
    if native_windows():
        name = os.environ.get("USERNAME")
        domain = os.environ.get("USERDOMAIN")
        if not name:
            return None
        return ("%s\\%s" % (domain, name)) if domain else name
    return str(os.getuid())


def _windows_processes():
    """(pid, owner, command) from CIM: the owner only where Windows tells a
    normal user, which is its own processes. Never raises."""
    import subprocess
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-CimInstance Win32_Process | ForEach-Object {"
        " $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner;"
        " $u = if ($o.User) { if ($o.Domain) { \"$($o.Domain)\\$($o.User)\" } else { $o.User } } else { '' };"
        " \"{0}`t{1}`t{2}\" -f $_.ProcessId, $u, $_.CommandLine }")
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                              "-Command", script], capture_output=True, text=True,
                             timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3 and parts[0].strip().isdigit() and parts[2].strip():
            found.append((int(parts[0]), parts[1].strip() or None, parts[2].strip()))
    return found


def processes():
    """(pid, owner, command) of every process this user can see. The owner
    is comparable with `current_user()`. Never raises; [] when the list
    cannot be read."""
    import subprocess
    if native_windows():
        return _windows_processes()
    try:
        out = subprocess.run(["ps", "-axo", "pid=,uid=,command="], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            found.append((int(parts[0]), parts[1], parts[2]))
    return found


def command_of(pid):
    """The command line ``pid`` runs, or "" when it cannot be read."""
    import subprocess
    if native_windows():
        return next((command for found, _, command in _windows_processes()
                     if found == int(pid)), "")
    try:
        return subprocess.run(["ps", "-o", "command=", "-p", str(int(pid))],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def pids_running(needle):
    """Pids of this user's processes whose command line contains
    ``needle``, as ``pgrep -f`` finds them. Never raises."""
    import subprocess
    if not native_windows():
        try:
            out = subprocess.run(["pgrep", "-f", needle], capture_output=True,
                                 text=True, timeout=5).stdout
            return [int(word) for word in out.split() if word.isdigit()]
        except (OSError, subprocess.SubprocessError):
            return []
    me = current_user()
    return [pid for pid, owner, command in _windows_processes()
            if needle in command and (owner is None or owner == me)]


def _windows_listeners():
    """{port: pid} for every TCP listener on this machine, IPv4 and IPv6,
    from Windows' own table (GetExtendedTcpTable): no process to start and
    no console to wait on. None when the table cannot be read."""
    import ctypes
    import socket
    import struct
    try:
        table_of = ctypes.windll.iphlpapi.GetExtendedTcpTable
    except (AttributeError, OSError):
        return None
    found = {}
    # (family, row size, offset of the local port, offset of the pid) for
    # MIB_TCPROW_OWNER_PID and MIB_TCP6ROW_OWNER_PID; 3 asks for listeners.
    for family, size, port_at, pid_at in ((2, 24, 8, 20), (23, 56, 20, 52)):
        needed = ctypes.c_ulong(0)
        table_of(None, ctypes.byref(needed), False, family, 3, 0)
        for _ in range(3):
            buffer = ctypes.create_string_buffer(needed.value + 4096)
            needed = ctypes.c_ulong(len(buffer))
            status = table_of(buffer, ctypes.byref(needed), False, family, 3, 0)
            if status != 122:                    # ERROR_INSUFFICIENT_BUFFER: grew
                break
        if status != 0:
            return None
        raw = buffer.raw
        for row in range(struct.unpack_from("<I", raw, 0)[0]):
            base = 4 + row * size
            port = socket.ntohs(struct.unpack_from("<I", raw, base + port_at)[0] & 0xFFFF)
            found.setdefault(port, struct.unpack_from("<I", raw, base + pid_at)[0])
    return found


def listener_pid(port):
    """The pid listening on this machine's TCP ``port``, or None."""
    import subprocess
    if native_windows():
        try:
            table = _windows_listeners()
        except (OSError, ValueError):
            table = None
        if table is not None:
            return table.get(int(port))
        try:
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                                 text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        for line in out.splitlines():
            parts = line.split()
            if (len(parts) >= 5 and parts[3].upper() == "LISTENING"
                    and parts[1].rsplit(":", 1)[-1] == str(port) and parts[4].isdigit()):
                return int(parts[4])
        return None
    try:
        done = subprocess.run(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN", "-t"],
                              capture_output=True, text=True, timeout=5)
        first = done.stdout.split()
        return int(first[0]) if first else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


# ---- listening sockets -------------------------------------------------------

def claim_port_alone(server):
    """Before a socketserver binds: no second listener may share its port.

    POSIX's SO_REUSEADDR, which socketserver sets, only lets a restarted
    relay take its port back from TIME_WAIT. Windows' lets a second live
    server bind the same port beside the first, so two relays both
    "started" and a port race never failed (2026-10-28). There the port is
    claimed exclusively instead."""
    if not native_windows():
        return
    import socket
    server.allow_reuse_address = False
    server.socket.setsockopt(socket.SOL_SOCKET,
                             getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)


def something_listens(port, host="127.0.0.1", timeout=1.0):
    """True while something listens on ``port``. Unknown counts as yes:
    this answers "may I bind?", and a maybe is a no.

    Windows does not refuse a connection to a closed loopback port at
    once: it retries the handshake for about two seconds, so a one-second
    try timed out and every free port read as taken; --ensure then never
    started a relay there (2026-10-28). There the listener table is read
    instead, and asked longer when it cannot be."""
    import socket
    if native_windows():
        try:
            table = _windows_listeners()
        except (OSError, ValueError):
            table = None
        if table is not None:
            return int(port) in table
        timeout = max(timeout, 3.0)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except socket.timeout:
        return True                     # the maybe: something is there, slowly
    except OSError:
        return False                    # refused: nothing is listening


def unix_sockets():
    """True where this Python can open a Unix socket. Windows' cannot, so
    a session's inbox and Codex's app socket are out of reach there and
    the helper takes the road it takes for a closed session."""
    import socket
    return hasattr(socket, "AF_UNIX")


# ---- files only their owner may read -----------------------------------------

def _windows_security():
    """advapi32 and kernel32, typed for the calls below."""
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    advapi.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, pointer(wintypes.HANDLE))
    advapi.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, pointer(wintypes.DWORD))
    advapi.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, pointer(ctypes.c_void_p))
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, pointer(ctypes.c_void_p), ctypes.c_void_p)
    advapi.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p, pointer(wintypes.BOOL), pointer(ctypes.c_void_p), pointer(wintypes.BOOL))
    advapi.SetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p)
    advapi.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, pointer(ctypes.c_void_p))
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, pointer(ctypes.c_void_p),
        pointer(wintypes.DWORD))
    return ctypes, wintypes, advapi, kernel


_DACL = 0x00000004                  # DACL_SECURITY_INFORMATION
_PROTECTED_DACL = 0x80000000        # PROTECTED_DACL_SECURITY_INFORMATION
_FILE_OBJECT = 1                    # SE_FILE_OBJECT


def _windows_user_sid():
    """This process's user, as an SDDL SID string ("S-1-5-21-…"), or None."""
    ctypes, wintypes, advapi, kernel = _windows_security()
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        return None
    try:
        size = wintypes.DWORD(0)
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))   # TokenUser
        buffer = ctypes.create_string_buffer(max(size.value, 1))
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]     # TOKEN_USER.User.Sid
        text = ctypes.c_void_p()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            return None
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def _windows_set_dacl(path, sddl):
    """Replace ``path``'s access list with the one ``sddl`` spells, cut
    from its parent's. True when Windows took it."""
    ctypes, wintypes, advapi, kernel = _windows_security()
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        return False
    try:
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                ctypes.byref(dacl), ctypes.byref(defaulted)):
            return False
        return advapi.SetNamedSecurityInfoW(path, _FILE_OBJECT, _DACL | _PROTECTED_DACL,
                                            None, None, dacl, None) == 0
    finally:
        kernel.LocalFree(descriptor)


def _windows_dacl(path):
    """``path``'s access list in SDDL ("D:P(A;;FA;;;S-1-5-…)"), or None."""
    ctypes, wintypes, advapi, kernel = _windows_security()
    descriptor = ctypes.c_void_p()
    if advapi.GetNamedSecurityInfoW(path, _FILE_OBJECT, _DACL, None, None, None, None,
                                    ctypes.byref(descriptor)) != 0:
        return None
    try:
        text, length = ctypes.c_void_p(), wintypes.DWORD()
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, _DACL, ctypes.byref(text), ctypes.byref(length)):
            return None
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.LocalFree(descriptor)


def _windows_sid_spellings(sid):
    """Every way an access list read back may write ``sid``: itself, and
    the alias Windows swaps in for a well-known account ("LA" for the
    built-in Administrator, which is who GitHub's runners are)."""
    ctypes, wintypes, advapi, kernel = _windows_security()
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:(A;;FA;;;%s)" % sid, 1, ctypes.byref(descriptor), None):
        return {sid}
    try:
        text, length = ctypes.c_void_p(), wintypes.DWORD()
        if not advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor, 1, _DACL, ctypes.byref(text), ctypes.byref(length)):
            return {sid}
        try:
            spelled = ctypes.wstring_at(text).rstrip(")").rsplit(";", 1)[-1]
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.LocalFree(descriptor)
    return {sid, spelled}


def restrict_to_owner(path, folder=False):
    """On Windows, make ``path`` readable by this user alone: nothing
    inherited, one grant (a folder's passes to what is made inside it).
    Its callers already chmod 0600/0700, which is the whole of it on POSIX
    and does nothing for anyone else on Windows. Windows' own calls, no
    process: the hook makes its audit log through here. True when done or
    not needed; never raises."""
    if not native_windows():
        return True
    try:
        sid = _windows_user_sid()
        if not sid:
            return False
        return _windows_set_dacl(str(path), "D:P(A;%s;FA;;;%s)"
                                 % ("OICI" if folder else "", sid))
    except (OSError, AttributeError, ValueError):
        return False


def owner_only(path):
    """True when nobody but this user may read ``path``: mode 0600/0700 on
    POSIX, nothing inherited and every grant this user's on Windows. None
    when it cannot be told."""
    if not native_windows():
        try:
            return os.stat(path).st_mode & 0o077 == 0
        except OSError:
            return None
    import re
    try:
        sid, sddl = _windows_user_sid(), _windows_dacl(str(path))
    except (OSError, AttributeError, ValueError):
        return None
    if not sid or not sddl or not sddl.startswith("D:"):
        return None
    flags = sddl[2:].split("(", 1)[0]
    aces = [ace.split(";") for ace in re.findall(r"\(([^)]*)\)", sddl)]
    grants = [ace for ace in aces if ace and ace[0] == "A"]
    try:
        mine = _windows_sid_spellings(sid)
    except (OSError, AttributeError, ValueError):
        mine = {sid}
    return ("P" in flags and bool(grants)
            and all(len(ace) >= 6 and ace[5] in mine and "ID" not in ace[1] for ace in grants))


# ---- the person at this computer ---------------------------------------------

def has_screen():
    """True where a window can be shown to someone sitting here: always on
    Windows and macOS sessions, and on Linux only with a display."""
    if native_windows() or is_mac():
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _which(name):
    import shutil
    return shutil.which(name)


def ask_person(title, text, allow, deny, seconds):
    """Ask whoever sits at this Linux or Windows computer a yes-or-no on its
    screen. (True, how) only when they chose ``allow``; (False, why)
    otherwise: they said no, did not answer within ``seconds``, or there is
    no screen or no way to show one. Fails closed; never raises. macOS asks
    through osascript in the relay, unchanged."""
    import subprocess
    if not has_screen():
        return False, "no screen to ask on"
    try:
        if native_windows():
            # WScript.Shell's Popup is the one built-in dialog that gives up
            # by itself. 4 = Yes and No, 48 = a warning, 256 = No is the
            # default; 6 is Yes. The words go in by the environment, never
            # into the script's text.
            script = ("$s = New-Object -ComObject WScript.Shell; "
                      "exit $s.Popup($env:TAPPROVAL_ASK_TEXT, %d, $env:TAPPROVAL_ASK_TITLE, 308)"
                      % int(seconds))
            env = dict(os.environ, TAPPROVAL_ASK_TEXT="%s\n\nYes: %s.  No: %s."
                       % (text, allow, deny), TAPPROVAL_ASK_TITLE=title)
            done = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                                   "-Command", script], env=env, capture_output=True,
                                  timeout=seconds + 15)
            if done.returncode == 6:
                return True, "allowed on this computer"
            return False, "not answered" if done.returncode == -1 else "not allowed"
        if _which("zenity"):
            done = subprocess.run(["zenity", "--question", "--title", title, "--text", text,
                                   "--ok-label", allow, "--cancel-label", deny,
                                   "--default-cancel", "--timeout", str(int(seconds))],
                                  capture_output=True, timeout=seconds + 15)
            if done.returncode == 0:
                return True, "allowed on this computer"
            return False, "not answered" if done.returncode == 5 else "not allowed"
        if _which("kdialog"):
            done = subprocess.run(["kdialog", "--title", title, "--yes-label", allow,
                                   "--no-label", deny, "--warningyesno", text],
                                  capture_output=True, timeout=seconds)
            if done.returncode == 0:
                return True, "allowed on this computer"
            return False, "not allowed"
        return False, "no dialog program (zenity or kdialog) to ask with"
    except subprocess.TimeoutExpired:
        return False, "not answered"
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)


# ---- signing in at login -----------------------------------------------------

def login_file_path():
    """Where a file that wakes the relay at every login lives, on hosts
    that have no launchd: XDG autostart on Linux, the Startup folder on
    Windows (neither needs an administrator). None on macOS, whose login
    job is launchd's."""
    if is_mac():
        return None
    if is_windows():
        base = os.environ.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs",
                            "Startup", "Tapproval relay.cmd")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "autostart", "tapproval-relay.desktop")


def login_file_text(python, relay):
    """The login file's contents, running ``relay --ensure`` once: it starts
    the relay if none answers and exits, as the Mac's job does."""
    if is_windows():
        quiet = os.path.join(os.path.dirname(python), "pythonw.exe")
        if os.path.exists(quiet):
            python = quiet                       # no console window at login
        return '@echo off\r\nstart "" "%s" "%s" --ensure\r\n' % (python, relay)
    def quoted(word):
        # The Desktop Entry spec's quoting: double quotes, with \\ \" \` \$.
        for char in '\\"`$':
            word = word.replace(char, "\\" + char)
        return '"%s"' % word
    return ("[Desktop Entry]\nType=Application\nName=Tapproval relay\n"
            "Comment=Lets your watch reach this computer after a restart\n"
            "Exec=%s %s --ensure\nTerminal=false\nNoDisplay=true\n"
            "X-GNOME-Autostart-enabled=true\n" % (quoted(python), quoted(relay)))


# ---- a terminal window -------------------------------------------------------

def powershell_literal(text):
    """``text`` as a PowerShell single-quoted string. PowerShell also closes
    such a string on the typographic single quotes, so each is doubled."""
    text = str(text)
    for quote in "'‘’‚‛":
        text = text.replace(quote, quote * 2)
    return "'%s'" % text


_TERMINALS = (                              # (program, what goes before the command)
    ("gnome-terminal", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("kitty", []),
    ("alacritty", ["-e"]),
    # Debian's alternative last but one: its -e takes one word on some
    # terminals, and the named ones above are asked for by their own rule.
    ("x-terminal-emulator", ["-e"]),
    ("xterm", ["-e"]),
)


def open_terminal(posix_script, powershell_script):
    """Open a new terminal window running one script, as someone at this
    Linux or Windows computer would: ``posix_script`` in bash on Linux,
    ``powershell_script`` in PowerShell on Windows. (True, "") once the
    window was asked for, (False, why) otherwise. Never raises."""
    import base64
    import subprocess
    if not has_screen():
        return False, "no screen to open a terminal on"
    try:
        if native_windows():
            # Encoded, so no quoting layer between here and PowerShell can
            # read the wearer's words as anything but the script's own.
            encoded = base64.b64encode(powershell_script.encode("utf-16-le")).decode("ascii")
            subprocess.Popen(["powershell.exe", "-NoExit", "-NoProfile",
                              "-EncodedCommand", encoded],
                             creationflags=0x00000010,          # CREATE_NEW_CONSOLE
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return True, ""
        for program, before in _TERMINALS:
            found = _which(program)
            if found:
                popen_detached([found] + before + ["bash", "-c", posix_script],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                return True, ""
        return False, "no terminal program found"
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)


def cloudflared_install():
    """How this host's people install cloudflared, as words to show them."""
    if is_mac():
        return "brew install cloudflared"
    if is_windows():
        return "winget install --id Cloudflare.cloudflared"
    return "your package manager (the package is cloudflared)"


def scratch_roots(roots):
    """The folders whose contents are scratch, never projects: ``roots``,
    and on Windows its temp folder, which is not under /tmp."""
    if not native_windows():
        return tuple(roots)
    import tempfile
    return tuple(roots) + (tempfile.gettempdir(),)


# ---- hook streams ------------------------------------------------------------

def read_stdin_text():
    """The hook's whole stdin, as UTF-8 whatever the console's code page:
    Claude Code writes JSON in UTF-8, and Windows' locale encoding turned
    any non-ASCII prompt into mojibake or a decode error."""
    data = sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer") else sys.stdin.read()
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def utf8_stdout():
    """Make print() write UTF-8 to stdout, which carries the decision."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass
