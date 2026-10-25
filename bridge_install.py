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
# The login item's own label, from bridge 1.1.1. Under the old job file's
# label (1.1.0) macOS registered it and then could not start it — "spawn
# failed", exit 78 — wherever it still held its record of the old job,
# which is every Mac that ran a bridge before 1.1.0 (e2e_login_item.py,
# 2026-10-25). Each bridge's sealed job file says its own label; this is
# the one a bridge with none readable is taken to have.
ITEM_LABEL = "com.tapproval.bridge.login"
# The sealed job file's name inside the app, whatever label it carries: the
# name main.swift asks SMAppService for. Not LABEL + ".plist": a caller that
# relabels the old job (e2e_login_item.py does) then read the wrong file and
# fell back to ITEM_LABEL, which hid a bridge sealed under the shared label.
SEALED_JOB = "com.tapproval.bridge.plist"
APP_NAME = "Tapproval.app"
# What bridges before 1.1.0 were called. They were started by a job file in
# ~/Library/LaunchAgents, and macOS files such a job under the name on the
# signing certificate — the developer's legal name — whatever the file says
# (tested 2026-10-24). From 1.1.0 the bridge registers its own login item,
# so System Settings → Login Items says "Tapproval" with the App Store logo.
OLD_APP_NAME = "TapprovalBridge.app"
REGISTERS_ITSELF = (1, 1, 0)
# The login item's words for itself (Bridge/main.swift, --login-status).
# requires-approval is the user's own switch in Login Items, turned off:
# respected, never turned back on behind their back.
LOGIN_ON = ("enabled", "requires-approval")
LOGIN_WORDS = LOGIN_ON + ("not-registered", "not-found")
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


def old_app_path():
    """Where a bridge before 1.1.0 is installed, until the update replaces it."""
    return os.path.join(bridge_dir(), OLD_APP_NAME)


def current_app():
    """The bridge installed here: the new name, else the old one."""
    return app_path() if os.path.isdir(app_path()) else old_app_path()


def relay_start_path():
    """The file a self-registering bridge reads at start-up to wake the
    relay, in place of the relay's own login job. The path is fixed in the
    bridge; the override is for the suite."""
    return (os.environ.get("TAPPROVAL_RELAY_START")
            or os.path.expanduser("~/.tapproval/data/relay-start.json"))


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


def _info(app):
    try:
        with open(os.path.join(app, "Contents", "Info.plist"), "rb") as handle:
            info = plistlib.load(handle)
    except Exception:
        return {}
    return info if isinstance(info, dict) else {}


def installed_version(app=None):
    """The installed bridge's CFBundleShortVersionString, or None."""
    value = _info(app or current_app()).get("CFBundleShortVersionString")
    return value if isinstance(value, str) else None


def registers_itself(app=None):
    """Does this bridge register its own login item (1.1.0 and later)?"""
    try:
        version = tuple(int(part) for part in
                        (installed_version(app) or "").split("."))
    except ValueError:
        return False
    return version >= REGISTERS_ITSELF


def executable(app):
    """The program inside a bridge: Tapproval from 1.1.0, TapprovalBridge
    before, as its Info.plist says when it says."""
    name = _info(app).get("CFBundleExecutable")
    if not (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9]+", name)):
        name = "Tapproval" if registers_itself(app) else "TapprovalBridge"
    return os.path.join(app, "Contents", "MacOS", name)


def login_item(action, app=None):
    """Ask a bridge from 1.1.0 to register, unregister or describe its own
    login item. Returns its one word (``enabled``, ``requires-approval``,
    ``not-registered``, ``not-found``), or None when it could not answer.
    Only the bridge can do this: macOS lets an app register only itself."""
    app = app or current_app()
    status, out = RUN([executable(app), "--" + action], timeout=30)
    if status is None:
        return None
    # Its word is the first line; anything after it is the reason it gave.
    lines = (out or "").strip().splitlines()
    word = lines[0].strip() if lines else ""
    return word if word in LOGIN_WORDS else None


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


def write_agent(app=None):
    """The login job file, for a bridge before 1.1.0, with the keys the
    developer's own job has carried since the bridge began: start at login,
    restart if it ever stops. ``app`` is the bridge it runs: the installed
    one unless a failed install hands the job back to an older one."""
    app = app or current_app()
    log = os.path.join(os.path.dirname(app), "bridge.log")
    job = {
        "Label": LABEL,
        "ProgramArguments": [executable(app)],
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


def _drop_agent_file():
    """Take the old-style job away: stopped, and its file gone, so Login
    Items has no entry left under the certificate's name.

    Only that job: the bridge's own login item has the same label, and
    booting it out on every update threw the registration away and made
    the update register again (seen on a stand-in, 2026-10-24)."""
    if os.path.exists(agent_path()) or not _job_is_items(LABEL):
        unload_agent()
    try:
        os.remove(agent_path())
    except FileNotFoundError:
        pass


def item_label(app):
    """The label a self-registering bridge's sealed job file gives its login
    item: com.tapproval.bridge for 1.1.0, its own from 1.1.1."""
    sealed = os.path.join(app, "Contents", "Library", "LaunchAgents", SEALED_JOB)
    try:
        with open(sealed, "rb") as handle:
            label = plistlib.load(handle).get("Label")
    except Exception:
        label = None
    return label if isinstance(label, str) and re.fullmatch(r"[A-Za-z0-9.\-]+", label) \
        else ITEM_LABEL


def start(app):
    """Start the bridge at ``app`` and have it start at every login.
    From 1.1.0 it registers its own login item (and the old job file goes);
    before, the job file does it. True when macOS took it.

    A login item already registered is restarted, not registered again: the
    registration outlives the bundle being replaced in place (tested
    2026-10-24), and keeping it keeps the user's own switch. Off in Login
    Items stays off, and counts as taken.

    "enabled" alone proves nothing: with the old job file booted out and
    deleted, macOS still answers "enabled" for its label while launchd holds
    no job at all (helper 1.1.80 kickstarted that nothing, and every Mac
    moving from 1.0.3 rolled back, 2026-10-24). Registered means launchd
    holds the label as a ServiceManagement job; a register, even over that
    false "enabled", makes one (tested on this Mac the same day)."""
    if not registers_itself(app):
        write_agent(app)
        return load_agent()
    _drop_agent_file()
    word = login_item("login-status", app)
    if word == "requires-approval":
        return True
    if word == "enabled" and job_registered(app):
        if agent_is_real():
            # The bundle was swapped under the running bridge: run the new one.
            RUN(["launchctl", "kickstart", "-k",
                 "gui/%d/%s" % (os.getuid(), item_label(app))], timeout=10)
        return True
    word = login_item("register", app)
    return word == "requires-approval" or (word == "enabled" and job_registered(app))


def job_registered(app=None):
    """Does launchd hold this bridge's login item as a job the bridge
    registered itself (not a job file's)? Read only, so it is asked even in
    the suite."""
    return _job_is_items(item_label(app or current_app()))


def _job_is_items(label):
    status, out = RUN(["launchctl", "print", "gui/%d/%s" % (os.getuid(), label)],
                      timeout=10)
    return status == 0 and "managed_by = com.apple.xpc.ServiceManagement" in (out or "")


def stop(app, replacement=None):
    """Before a swap: stop a bridge that runs from a job file. One that
    registered itself keeps its login item and is restarted by start() —
    unless the bridge replacing it seals its item under another label (1.1.0
    to 1.1.1): then only the old bridge can take its own away."""
    if not registers_itself(app):
        unload_agent()
    elif replacement is not None and item_label(app) != item_label(replacement):
        login_item("unregister", app)


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
        was = current_app()     # an older bridge may still have the old name
        previous = app + ".previous"
        had_previous = os.path.isdir(was)
        if had_previous:
            stop(was, replacement=new)
            shutil.rmtree(previous, ignore_errors=True)
            shutil.rmtree(old_app_path() + ".previous", ignore_errors=True)
            try:
                os.rename(was, previous)
            except OSError as error:
                # Nothing swapped yet: the bridge that was stopped for the
                # swap starts again, rather than waiting for the next login.
                start(was)
                raise InstallError("%s, so the previous one is back"
                                   % (error.strerror or error)) from error
        try:
            os.rename(new, app)
            if not start(app):
                raise InstallError("macOS did not take its login item")
            if wait_for_bridge is not None and not wait_for_bridge():
                raise InstallError("the new bridge did not start")
        except (InstallError, OSError) as error:
            # Every failure after the swap undoes it. Left half-done, the
            # new bridge would read as "current" and never be retried.
            not_back = _roll_back(app, previous, had_previous, was)
            reason = getattr(error, "strerror", None) or str(error)
            if not_back:
                # Both reasons, or the first is lost under the second
                # (2026-10-25 review): the old bridge waits under .previous.
                raise InstallError(
                    "%s, and the previous bridge could not be put back: %s"
                    % (reason, not_back)) from error
            raise InstallError(
                "%s, so the previous one is back" % reason if had_previous
                else "%s; nothing is installed" % reason) from error
        _retire_legacy()
        return pin["version"]
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _roll_back(app, previous, had_previous, was):
    """Put back what was there before the swap: the previous bridge, under
    its own name and started its own way, or nothing at all. Returns why the
    previous bridge could not be put back, or "" when it was (or there was
    none): the caller is already raising, and a second error thrown from
    here would hide the first."""
    if os.path.isdir(app) and registers_itself(app) and (
            not had_previous or not registers_itself(previous)
            or item_label(previous) != item_label(app)):
        # Its login item would point at nothing, outrank the job file the
        # older bridge goes back to, or sit beside that bridge's own item.
        login_item("unregister", app)
    unload_agent()
    shutil.rmtree(app, ignore_errors=True)
    legacy = os.path.join(legacy_dir(), OLD_APP_NAME)
    if had_previous and os.path.isdir(previous):
        try:
            os.rename(previous, was)
        except OSError as error:
            return "%s (%s)" % (error.strerror or error, previous)
        start(was)
    elif os.path.isdir(legacy):
        # The first install into the new place failed on a Mac whose bridge
        # still runs from the old one: give the job back to that bridge,
        # or the Mac would be left with none.
        write_agent(legacy)
        load_agent()
    else:
        try:
            os.remove(agent_path())
        except OSError:
            pass
    return ""


def _retire_legacy():
    """Once a bridge runs from bridge_dir(), the old place's copies go: the
    login job (one label) already points at the new one. Anything else in
    that folder is someone's own (the owner keeps backups there) and stays."""
    old = legacy_dir()
    if os.path.realpath(old) == os.path.realpath(bridge_dir()):
        return
    for name in (OLD_APP_NAME, OLD_APP_NAME + ".previous"):
        shutil.rmtree(os.path.join(old, name), ignore_errors=True)


def remove():
    """Stop the bridge and take it, its login item or job and the relay's
    start-up file away, from the old place as well. True when nothing of it
    is left running or installed."""
    for app in (app_path(), old_app_path()):
        if os.path.isdir(app) and registers_itself(app):
            login_item("unregister", app)
    unload_agent()
    try:
        os.remove(agent_path())
    except FileNotFoundError:
        pass
    except OSError:
        return False
    forget_relay()
    for app in (app_path(), old_app_path()):
        shutil.rmtree(app, ignore_errors=True)
        # The copy kept for a rollback is a whole bridge too (2026-10-24 review).
        shutil.rmtree(app + ".previous", ignore_errors=True)
    _retire_legacy()
    return not (os.path.exists(app_path()) or os.path.exists(old_app_path())
                or os.path.exists(os.path.join(legacy_dir(), OLD_APP_NAME)))


def wake_relay(python, relay):
    """Hand the relay's wake-up at login to the bridge: write the file it
    reads at start-up. True when the installed bridge registered itself and
    so now wakes the relay; then the relay's own job file can go, and with
    it the Login Items row filed under the interpreter's name. A Mac whose
    bridge is older, off or missing keeps that job (False)."""
    if not (relay_may_be_woken(relay) and os.path.isdir(app_path())
            and registers_itself(app_path())
            and login_item("login-status", app_path()) in LOGIN_ON):
        forget_relay()
        return False
    path = relay_start_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"python": python, "relay": relay}, handle)
    except OSError:
        return False
    return True


# Where the bridge agrees to start a relay from (Bridge/main.swift, wakeRelay):
# a terminal install and a plugin install, under the user's home.
RELAY_HOMES = ("~/.tapproval/", "~/.claude/plugins/")


def relay_may_be_woken(relay, home=None):
    """Would the bridge start this relay? The same rule it applies, so a
    relay it would refuse keeps its own job instead of losing its wake-up."""
    home = home or os.path.expanduser("~")
    real = os.path.realpath(relay)
    return (os.path.basename(real) == "watch_relay.py" and os.path.isfile(real)
            and any(real.startswith(os.path.join(home, place[2:]))
                    for place in RELAY_HOMES))


def forget_relay():
    """The bridge no longer wakes the relay."""
    try:
        os.remove(relay_start_path())
    except OSError:
        pass


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
