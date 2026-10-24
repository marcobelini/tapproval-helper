"""bridge_install — put Tapproval's Mac bridge on this computer, and keep it
current.

The bridge (WatchApp/Bridge) mirrors each card into the user's own private
iCloud, and iCloud wakes a closed watch. Until route B (#378) it was signed
for the developer's Mac alone, so everyone else's watch buzzed only with
Tapproval open (reported 2026-10-15). Now a Developer ID-signed, notarized
copy ships inside the helper itself, in bridge/, and this module installs it:
one package, nothing fetched from a second place (the owner's decision,
2026-10-16).

What it trusts, in order:

1. ``bridge.json`` beside this file — the version, the zip's place in the
   helper and its SHA-256.
2. The signature: Apple's Developer ID for the pinned team and bundle id.
3. Apple's notarization, as Gatekeeper reads it.

Any check that fails throws the copy away and leaves the bridge that was
already here running. Standard library only, like every helper file.
"""
import fcntl
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

LABEL = "com.tapproval.bridge"
APP_NAME = "TapprovalBridge.app"
MAX_BYTES = 20 * 1024 * 1024
# The bridge's own deployment target (MACOSX_DEPLOYMENT_TARGET).
MIN_MACOS = (13, 0)


class InstallError(Exception):
    """A step refused. The message is one short clause for the log."""


def bridge_dir():
    """Where the bridge lives: inside ~/.tapproval, with everything else
    Tapproval keeps on this Mac (the owner's decision, 2026-10-16).

    Not bridge/, which the public repository tracks for the bridge's
    source: bridge-app/, which its .gitignore names, so a pull never sees
    it. A re-clone moves it aside with the old checkout, and the --install
    that follows puts a fresh one in; that is why it once lived outside
    (RELEASING.md, "The Mac bridge") and why it need not any more."""
    return (os.environ.get("TAPPROVAL_BRIDGE_DIR")
            or os.path.expanduser("~/.tapproval/bridge-app"))


def legacy_dir():
    """Where the bridge lived until 2026-10-16. Only the owner's Mac ever
    had one there; it is moved out by the first install into bridge_dir()."""
    return (os.environ.get("TAPPROVAL_BRIDGE_LEGACY_DIR")
            or os.path.expanduser("~/.tapproval-bridge"))


def app_path():
    return os.path.join(bridge_dir(), APP_NAME)


def pin_path():
    """bridge.json beside this file. The pin is the trust anchor, so its
    override is honoured only inside a test run, where the suite must never
    install a real bridge because the repository happens to pin one.
    (The directory and login-job overrides stay honoured everywhere, like
    CLAUDE_LAUNCH_AGENT_PATH: they cannot weaken a check, and the second
    is what keeps a test's plist from becoming the real login job.)"""
    override = os.environ.get("TAPPROVAL_BRIDGE_PIN")
    if override and _running_under_test():
        return override
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "bridge.json")


def agent_path():
    return (os.environ.get("TAPPROVAL_BRIDGE_AGENT_PATH")
            or os.path.join(os.path.expanduser("~"), "Library",
                            "LaunchAgents", LABEL + ".plist"))


def agent_is_real():
    """With the path overridden, launchd is not touched either — the label
    is global, and a test's plist must never become the login job (the
    relay's own job learnt that on 2026-09-23)."""
    return not os.environ.get("TAPPROVAL_BRIDGE_AGENT_PATH")


def off_marker():
    """``--install --no-bridge`` leaves this, so updates never put it back."""
    return os.path.join(bridge_dir(), "OFF")


def hand_built_marker():
    """A developer's own build: the helper never replaces it."""
    return os.path.join(bridge_dir(), "HAND-BUILT")


def mac_supported(platform_name=None, mac_version=None):
    """True on macOS at or above the bridge's deployment target."""
    if (platform_name or sys.platform) != "darwin":
        return False
    text = mac_version if mac_version is not None else platform.mac_ver()[0]
    try:
        parts = tuple(int(p) for p in text.split(".")[:2])
    except ValueError:
        return False
    if len(parts) == 1:
        parts = (parts[0], 0)
    return parts >= MIN_MACOS


def read_pin(path=None):
    """The pinned bridge, or None when there is none or it is malformed.

    Every field is checked for shape here, so nothing later has to wonder
    whether a value is safe to put on a command line or in a path. The
    zip's path is resolved beside the pin, inside the helper's own folder."""
    path = path or pin_path()
    try:
        with open(path, encoding="utf-8") as handle:
            pin = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(pin, dict):
        return None
    version, file = pin.get("version"), pin.get("file")
    sha, size = pin.get("sha256"), pin.get("size")
    team, ident = pin.get("team"), pin.get("identifier")
    if not (isinstance(version, str)
            and re.fullmatch(r"\d+\.\d+\.\d+", version)):
        return None
    # Exactly bridge/TapprovalBridge-<version>.zip: no other folder, no
    # other name, nothing a crafted pin could walk out of the helper with.
    if file != "bridge/TapprovalBridge-%s.zip" % version:
        return None
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        return None
    if not (isinstance(size, int) and not isinstance(size, bool)
            and 0 < size <= MAX_BYTES):
        return None
    if not (isinstance(team, str) and re.fullmatch(r"[A-Z0-9]{10}", team)):
        return None
    if not (isinstance(ident, str)
            and re.fullmatch(r"[A-Za-z0-9.\-]+", ident)):
        return None
    return {"version": version, "file": file, "sha256": sha, "size": size,
            "team": team, "identifier": ident,
            "path": os.path.join(os.path.dirname(os.path.abspath(path)), file)}


def installed_version(app=None):
    """The installed bridge's CFBundleShortVersionString, or None."""
    info = os.path.join(app or app_path(), "Contents", "Info.plist")
    try:
        with open(info, "rb") as handle:
            value = plistlib.load(handle).get("CFBundleShortVersionString")
    except Exception:
        return None
    return value if isinstance(value, str) else None


def state(pin=None, platform_name=None, mac_version=None):
    """What this computer needs, as one word:

    unsupported  not a Mac, or a macOS older than the bridge's target
    off          the user said --no-bridge
    hand-built   a developer's own bridge is here; leave it be
    no-pin       this helper pins no bridge yet
    current      the pinned version is the one installed
    install      install the pinned version from the helper's bridge/
    """
    if not mac_supported(platform_name, mac_version):
        return "unsupported"
    if os.path.exists(off_marker()):
        return "off"
    if (os.path.exists(hand_built_marker())
            or os.path.exists(os.path.join(legacy_dir(), "HAND-BUILT"))):
        return "hand-built"
    if pin is None:
        return "no-pin"
    if installed_version() == pin["version"]:
        return "current"
    return "install"


def _run(command, timeout=60):
    """(exit status, combined output); status None when it could not run."""
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout)
    except Exception as error:
        return None, str(error)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


# Every subprocess goes through here, so the suite can stand in for ditto,
# codesign, spctl and launchctl on a machine that has none of them.
RUN = _run


def _running_under_test():
    try:
        from crash_report import running_under_test
    except Exception:
        return "pytest" in sys.modules
    return running_under_test()


def take_copy(pin, dest):
    """Copy the pinned zip out of the helper to ``dest`` and prove it is the
    pinned one. Copied first, so a pull that lands mid-install cannot change
    the file between the check and its use."""
    digest = hashlib.sha256()
    total = 0
    try:
        with open(pin["path"], "rb") as source, open(dest, "wb") as out:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > pin["size"]:
                    raise InstallError("the bridge zip is larger than pinned")
                digest.update(chunk)
                out.write(chunk)
    except InstallError:
        raise
    except OSError as error:
        raise InstallError("the helper's bridge zip could not be read (%s)"
                           % (error.strerror or error)) from error
    if total != pin["size"]:
        raise InstallError("the bridge zip is %d bytes, not the pinned %d"
                           % (total, pin["size"]))
    if digest.hexdigest() != pin["sha256"]:
        raise InstallError("the bridge zip's SHA-256 is not the pinned one")


def requirement(pin):
    """The code requirement a pinned bridge must satisfy: Apple's chain, a
    Developer ID Application certificate (the two OIDs Apple's own
    Developer ID requirement uses), the pinned team, the pinned bundle id.
    codesign evaluates it, so nothing here parses its human output. The
    leading "=" makes codesign read it as text, not as a file path."""
    return ('=anchor apple generic'
            ' and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
            ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
            ' and certificate leaf[subject.OU] = "%s"'
            ' and identifier "%s"' % (pin["team"], pin["identifier"]))


def verify(app, pin):
    """The app at ``app`` is the pinned team's, Developer ID-signed and
    notarized — or InstallError says which check refused."""
    status, out = RUN(["codesign", "--verify", "--strict", "--deep",
                       "-R", requirement(pin), app])
    if status != 0:
        raise InstallError("it is not %s signed with team %s's Developer ID"
                           % (pin["identifier"], pin["team"]))
    status, out = RUN(["spctl", "--assess", "--type", "execute", "-vv", app])
    if status != 0 or "source=Notarized Developer ID" not in out:
        raise InstallError("Gatekeeper does not accept it as notarized")


def write_agent(home=None):
    """The login job, with the keys the developer's own job has carried
    since the bridge began: start at login, restart if it ever stops.
    ``home`` is the folder whose bridge it runs: bridge_dir() unless a
    failed first install hands the job back to the old place."""
    home = home or bridge_dir()
    log = os.path.join(home, "bridge.log")
    job = {
        "Label": LABEL,
        "ProgramArguments": [os.path.join(home, APP_NAME, "Contents", "MacOS",
                                          "TapprovalBridge")],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }
    target = agent_path()
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as handle:
        plistlib.dump(job, handle)


def load_agent():
    """(Re)start the login job. True when launchd took it."""
    if not agent_is_real():
        return True
    domain = "gui/%d" % os.getuid()
    # A bootout of a job that is not loaded fails, and that is fine.
    RUN(["launchctl", "bootout", "%s/%s" % (domain, LABEL)], timeout=10)
    # The bootout finishes asynchronously: one patient retry, as the
    # relay's own login job does.
    for attempt in range(2):
        status, _ = RUN(["launchctl", "bootstrap", domain, agent_path()],
                        timeout=10)
        if status == 0:
            return True
        if attempt == 0:
            time.sleep(1.0)
    return False


def unload_agent():
    if agent_is_real():
        RUN(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), LABEL)],
            timeout=10)


def install(pin, wait_for_bridge=None):
    """Check and install the pinned bridge from the helper, then start it.

    ``wait_for_bridge`` (optional) is asked once the new bridge is loaded:
    True when the relay has heard from it. If it says False, the previous
    bridge is put back and started, and InstallError says so.
    Returns the version installed."""
    home = bridge_dir()
    os.makedirs(home, exist_ok=True)
    # One install at a time: the relay's background update and --install
    # could interleave their renames, and the loser's rollback deleted the
    # winner's bridge (2026-10-24 review). The second waits its turn.
    with open(os.path.join(home, ".install.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _install(pin, wait_for_bridge, home)


def _install(pin, wait_for_bridge, home):
    staging = tempfile.mkdtemp(prefix="staging-", dir=home)
    try:
        archive = os.path.join(staging, "bridge.zip")
        take_copy(pin, archive)
        unpacked = os.path.join(staging, "unpacked")
        # ditto, not zipfile: an app bundle holds symlinks and modes that
        # zipfile drops, and a bundle without them no longer verifies.
        status, out = RUN(["ditto", "-x", "-k", archive, unpacked])
        new = os.path.join(unpacked, APP_NAME)
        if status != 0 or not os.path.isdir(new):
            raise InstallError("the zip did not unpack to %s" % APP_NAME)
        verify(new, pin)
        if installed_version(new) != pin["version"]:
            raise InstallError("it says it is version %s, not the pinned %s"
                               % (installed_version(new), pin["version"]))

        app = app_path()
        previous = app + ".previous"
        had_previous = os.path.isdir(app)
        if had_previous:
            unload_agent()
            shutil.rmtree(previous, ignore_errors=True)
            try:
                os.rename(app, previous)
            except OSError as error:
                # Nothing swapped yet: the bridge that was stopped for the
                # swap starts again, rather than waiting for the next login.
                load_agent()
                raise InstallError("%s, so the previous one is back"
                                   % (error.strerror or error)) from error
        try:
            os.rename(new, app)
            write_agent()
            if not load_agent():
                raise InstallError("launchd did not take the login job")
            if wait_for_bridge is not None and not wait_for_bridge():
                raise InstallError("the new bridge did not start")
        except (InstallError, OSError) as error:
            # Every failure after the swap undoes it. Left half-done, the
            # new bridge would read as "current" and never be retried.
            _roll_back(app, previous, had_previous)
            reason = getattr(error, "strerror", None) or str(error)
            raise InstallError(
                "%s, so the previous one is back" % reason if had_previous
                else "%s; nothing is installed" % reason) from error
        _retire_legacy()
        return pin["version"]
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _roll_back(app, previous, had_previous):
    """Put back what was there before the swap: the previous bridge and its
    job, or nothing at all."""
    unload_agent()
    shutil.rmtree(app, ignore_errors=True)
    if had_previous and os.path.isdir(previous):
        os.rename(previous, app)
        write_agent()
        load_agent()
    elif os.path.isdir(os.path.join(legacy_dir(), APP_NAME)):
        # The first install into the new place failed on a Mac whose bridge
        # still runs from the old one: give the job back to that bridge,
        # or the Mac would be left with none.
        write_agent(legacy_dir())
        load_agent()
    else:
        try:
            os.remove(agent_path())
        except OSError:
            pass


def _retire_legacy():
    """Once a bridge runs from bridge_dir(), the old place's copies go: the
    login job (one label) already points at the new one. Anything else in
    that folder is someone's own (the owner keeps backups there) and stays."""
    old = legacy_dir()
    if os.path.realpath(old) == os.path.realpath(bridge_dir()):
        return
    for name in (APP_NAME, APP_NAME + ".previous"):
        shutil.rmtree(os.path.join(old, name), ignore_errors=True)


def remove():
    """Stop the bridge and take it and its login job away, from the old
    place as well. True when nothing of it is left running or installed."""
    unload_agent()
    try:
        os.remove(agent_path())
    except FileNotFoundError:
        pass
    except OSError:
        return False
    shutil.rmtree(app_path(), ignore_errors=True)
    # The copy kept for a rollback is a whole bridge too (2026-10-24 review).
    shutil.rmtree(app_path() + ".previous", ignore_errors=True)
    _retire_legacy()
    return not (os.path.exists(app_path())
                or os.path.exists(os.path.join(legacy_dir(), APP_NAME)))


def set_off(off):
    """Remember (or forget) that the user turned the bridge off."""
    marker = off_marker()
    if off:
        os.makedirs(os.path.dirname(marker), exist_ok=True)
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("Turned off with --install --no-bridge. "
                         "--install --bridge turns it back on.\n")
    else:
        try:
            os.remove(marker)
        except FileNotFoundError:
            pass
