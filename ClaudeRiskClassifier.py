#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClaudeRiskClassifier — risk triage for Claude Code permission prompts.

Runs as a Claude Code ``PermissionRequest`` hook. Every tool call Claude wants
to make is classified into a risk tier; the boring majority is auto-allowed so
no notification is ever raised, and only the calls that genuinely need a human
are escalated. The escalated ones also get a "wrist card" for Tapproval — a headline short
enough to read on a watch face in one glance.

Three modes:

    shadow   (default)  classify + log, but always escalate. Behaviour is
                        completely unchanged, so it is safe to leave running
                        while you collect data.
    enforce             act on the classification (auto-allow low tiers).
    report              offline analysis of the audit log.

Usage as a hook (event JSON on stdin, decision JSON on stdout)::

    python ClaudeRiskClassifier.py

Usage from the command line::

    python ClaudeRiskClassifier.py --explain "rm -rf build"
    python ClaudeRiskClassifier.py --explain "path/to/file.sql" --tool Write
    python ClaudeRiskClassifier.py --report

Wire it up in ``~/.claude/settings.json``::

    {
      "hooks": {
        "PermissionRequest": [
          {
            "matcher": "*",
            "hooks": [
              {
                "type": "command",
                "command": "python /path/to/ClaudeRiskClassifier.py",
                "timeout": 10
              }
            ]
          }
        ]
      }
    }

(``--install`` writes this for you. With ``--watch`` it also switches to
enforce mode and raises the timeout to WATCH_HOOK_TIMEOUT, a day and a
minute, because the hook then waits for the wrist; the plugin's
hooks/hooks.json carries the same.)

Design rules, in order of importance:

1. **Fail closed to the human.** Anything unrecognised, unparseable or
   ambiguous escalates. The hook never auto-allows on a guess.
2. **stdout is sacred.** Claude Code parses stdout as the decision. Nothing
   else may be written there — diagnostics go to stderr.
3. **Standard library only.** Hooks run under whatever interpreter is on PATH.

Note for future maintainers: unlike the pipeline scripts in this repository
this module must NOT call ``CountDownTimer`` and must not print progress. It is
a non-interactive hook and has to exit immediately with clean stdout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from enum import IntEnum

import tapproval_wire as wire

# argparse, shutil and tempfile are imported where they are used. They
# serve the installer and the CLI only, and this module is a hook that
# starts once per tool call, on a path that never touches them. (shlex is
# imported above: the classifier itself splits commands with it.)

__all__ = [
    "Risk",
    "classify",
    "classify_bash",
    "classify_path",
    "decide",
    "wrist_card",
    "load_policy",
    "run_install",
    "run_uninstall",
    "configure_site_rules",
]


class Risk(IntEnum):
    """Risk tiers, ordered. Higher is more dangerous."""

    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# One number the whole install can be identified by. Surfaced by --status
# and by the relay's /health, so a support question ("what are you
# running?") has an answer that does not depend on the user knowing.
__version__ = "1.1.67"

# The project's own public page. Not a deployment hostname — those belong
# in site-rules.json — but a constant of the project itself, the same way
# the support address is, and the only address --report ever prints.
PROJECT_SITE = "https://tapproval.thoughtfulsteward.org"

# How long a card may stay on the wrist. The hook timeout written by
# --watch is derived from this so it always outlives the wait. A full day:
# prompts must never expire on the user — a card stands until it is
# answered somewhere, and answering it elsewhere retracts it at once.
RELAY_WAIT_SECONDS = 86400
# The relay listens here; watch_relay.DEFAULT_PORT says the same, but this
# file must stand alone, so the number is written once more, once.
RELAY_PORT = 8977
# The relay's key file (watch_relay.AUTH_FILE), this user's, mode 0600. The
# hook signs each card with its bootstrap and believes only an answer that
# proves the same key: anything else that answers on RELAY_PORT — a
# squatter while the relay restarts — is not the relay (2026-10-16
# review, S1). CLAUDE_RISK_AUTH_FILE points an isolated relay's hook at
# that relay's own file. It lives in ~/.tapproval/data since 1.1.60; the
# relay moves the old ~/.tapproval-auth.json there once the Mac bridge can
# read it, and until then the old place is the file (watch_relay.home_file).
AUTH_FILE = wire.home_file("data", "auth.json", ".tapproval-auth.json",
                           os.path.expanduser("~/.tapproval"), os.path.expanduser("~"))

# The wrist card's two budgets. DEFAULT_POLICY quotes these, and the policy
# file may override them; wrist_card() falls back to them when it does not.
#
# Text a card copies — Claude's question, its description of a command, the
# command itself — travels whole: the phone shows all of it, and a wrist
# that cut it at 64 or 128 characters asked for an answer whose reasons had
# been dropped (2026-10-15, "The design…"). The card screen scrolls and the
# list rows clamp themselves, so the only limit left is the push
# notification's 4 KB. HEADLINE_CHARS stays the budget for the headlines the
# helper composes itself ("Delete build -r"), which are summaries, not cuts.
TEXT_CHARS = 1500
HEADLINE_CHARS = 64
DETAIL_CHARS = TEXT_CHARS
RELAY_URL = "http://127.0.0.1:%d" % RELAY_PORT

DEFAULT_POLICY = {
    # "shadow" = classify and log but never change behaviour (safe default).
    # "enforce" = act on the classification.
    "mode": "shadow",
    # Tiers at or below this are auto-allowed in enforce mode. "NONE" means
    # nothing is ever auto-allowed: the classifier only labels risk, and
    # every prompt still reaches a human. That is the default because
    # measurement showed the deciding half was worth ~5% of prompts while
    # carrying all of the misjudgement risk. Set "LOW" (or higher) with
    # --quiet if you want the boring tiers handled for you.
    "auto_allow_at_or_below": "NONE",
    # What to do with CRITICAL. "escalate" (default) or "deny".
    "critical_action": "escalate",
    "audit_log": "~/.claude/risk-audit.jsonl",
    # Hostnames, servers or network shares that are production for you.
    # Any mention of one is treated as HIGH risk. Empty by default.
    "sensitive_hosts": [],
    "headline_chars": HEADLINE_CHARS,
    "detail_chars": DETAIL_CHARS,
    # Optional watch relay (see watch_relay.py). When set, and only in
    # enforce mode, an escalation is first offered to the watch; if nobody
    # answers in relay_wait seconds the normal terminal prompt appears.
    "relay": "",
    # How long the hook waits for a wrist answer before falling back to the
    # terminal. Long enough to raise an arm; the hook's own timeout in
    # settings.json must exceed it (see WATCH_HOOK_TIMEOUT).
    "relay_wait": float(RELAY_WAIT_SECONDS),
}


# --------------------------------------------------------------------------
# Shared patterns
# --------------------------------------------------------------------------

# Reading a secret is exfiltration risk; writing one is worse.
SECRET_PATH = re.compile(
    r"(\.env(\.|\b)|id_rsa|id_ed25519|\.pem\b|\.p12\b|\.pfx\b|"
    r"credential|\bsecrets?\.(json|ya?ml|txt)|\.aws[/\\]|\.ssh[/\\]|\.netrc|"
    # The credential stores this list did not name, each of which holds a
    # live token in plain text: `cat ~/.kube/config` read SAFE until now.
    r"\.kube[/\\]config|\.npmrc|\.pypirc|\.docker[/\\]config\.json|"
    r"\.config[/\\]gh[/\\]hosts\.ya?ml|\.gitconfig\b|\.terraformrc|"
    # Tapproval's own device keys: whoever reads them can answer a card.
    r"\.tapproval-auth\.json|\.tapproval-token|\.tapproval-devices\.json|"
    r"\.tapproval[/\\]data[/\\]|"
    # Each read SAFE until the 2026-09-30 review: App Store Connect and
    # other private keys, database and vault passwords, a direnv file,
    # GnuPG and macOS keychains, shell history, a process's environment,
    # Terraform state (which stores secrets in plain text).
    r"\.p8\b|[\w-]\.key\b|\.appstoreconnect[/\\]|\.vault-token|\.pgpass|"
    r"\.my\.cnf|\.envrc\b|\.gnupg[/\\]|Keychains[/\\]|_history\b|"
    r"/proc/[^/\s]+/environ|\.tfstate\b|"
    # Claude Code's own account file, the browsers' saved cookies and
    # logins, the Messages database, and a search for a private key.
    r"\.claude\.json\b|[/\\]Cookies\b|[/\\]Login\\? Data\b|Messages[/\\]chat\.db|PRIVATE KEY)",
    re.I,
)

# Deployment-specific rules. Empty by default: this tool ships knowing
# nothing about your infrastructure. Name your own servers, shares and
# hostnames under "sensitive_hosts" in a config file and any command, path
# or file content mentioning one is treated as HIGH risk. See
# site-rules.example.json.
SITE_RULES = []


def configure_site_rules(policy):
    """Compile the deployment-specific rules named in policy.

    Returns the compiled list and installs it as the module-wide rule set,
    so that classify_bash() and classify_path() pick it up.
    """
    global SITE_RULES
    rules = []
    for host in policy.get("sensitive_hosts") or []:
        if not isinstance(host, str):
            continue
        host = host.strip()
        if host:
            rules.append(("sensitive-host", re.compile(re.escape(host), re.I),
                          Risk.HIGH))
    SITE_RULES = rules
    return rules

SQL_DESTRUCTIVE = re.compile(
    r"\b(DROP\s+(DATABASE|TABLE|PROCEDURE|VIEW|INDEX|SCHEMA)|TRUNCATE\s+TABLE)\b", re.I
)
SQL_MUTATION = re.compile(
    r"\b(INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|MERGE\s+INTO|"
    r"ALTER\s+(TABLE|PROCEDURE)|CREATE\s+(OR\s+ALTER\s+)?PROCEDURE|EXEC(UTE)?\s+)",
    re.I,
)

# Shell operators we split on to classify each segment independently.
# A lone `&` between words runs the next command too: `echo hi & rm -rf ~`
# was one segment led by echo (2026-09-30). `2>&1`, `&>` and `|&` are not it.
# A background `&` ends a command wherever it stands: bash runs `echo x&rm
# -rf ~` as two commands, and requiring a space on both sides let the second
# one ride along unseen behind a SAFE `echo` (2026-10-19 review). Only the
# `&` of a redirection (`2>&1`, `>&2`, `<&3`, `&>`) or of `&&` / `|&` is not
# one. `|&` is a pipe (stderr too), so it splits like `|`.
SEGMENT_SPLIT = re.compile(r"\s*(?:\|\||&&|\|&|;|\||\n|(?<![<>&|])&(?![&>]))\s*")

# Leading VAR=value assignments before the real command.
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+")
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\S*\s+")
# Variables that change how a command formats or reports, never which
# program runs. Any other prefix can: PATH, DYLD_INSERT_LIBRARIES,
# BASH_ENV, GIT_PAGER and GIT_SSH_COMMAND each ran a program of the
# caller's choosing behind a SAFE lead word (2026-09-30).
HARMLESS_ENV = frozenset(
    "LANG LANGUAGE TZ NO_COLOR FORCE_COLOR CLICOLOR CLICOLOR_FORCE TERM "
    "COLUMNS LINES CI PYTHONUNBUFFERED PYTHONDONTWRITEBYTECODE PYTHONHASHSEED "
    "NODE_ENV RUST_BACKTRACE RUST_LOG DEBUG VERBOSE GIT_TERMINAL_PROMPT "
    "HOMEBREW_NO_AUTO_UPDATE HOMEBREW_NO_ENV_HINTS".split())


def _assigned_names(segment):
    """The names a segment assigns before its command: `A=1 B=2 ls`."""
    names, text = [], segment.strip()
    while True:
        match = _ASSIGNMENT.match(text)
        if not match:
            return names
        names.append(match.group(1))
        text = text[match.end():]


# --------------------------------------------------------------------------
# Bash classification
# --------------------------------------------------------------------------

# Commands that cannot mutate anything on their own. A redirect or command
# substitution elsewhere in the segment still bumps the tier.
# --------------------------------------------------------------------------
# The effect ontology
# --------------------------------------------------------------------------
#
# Fourteen tables in this file answer a version of "what does this verb do",
# and every one of them is keyed on a binary's NAME. That is how
# `flyctl apps destroy myapp` came to read SAFE: `apps` is a recognised
# read verb for flyctl, and nothing looked at the word after it. Six more
# read SAFE the same way, including `git branch -D main`, `gh auth token`
# and `find / -delete`, and `--quiet` auto-allows SAFE.
#
# This asks the other question. Not "do I recognise this binary" but "what
# does this command DO, and how far does the consequence travel" — then
# derives the tier from the answer instead of carrying one per pattern.
#
# It only ever RAISES. classify_bash's bump() is a monotone join, so this
# runs first and a recognition table can no longer talk the tier back down:
# an unjustified SAFE loses to the effect the words actually name. Nothing
# below can lower a tier, which is why adding it cannot make the classifier
# more permissive than it was.


class Effect(IntEnum):
    """What a command does, independent of which binary does it."""

    OBSERVE = 0
    MUTATE = 1
    EXECUTE = 2
    DESTROY = 3
    GRANT = 4
    PUBLISH = 5


class Reach(IntEnum):
    """How far the consequence travels. SHARED is where other people see it."""

    SCRATCH = 0
    PROJECT = 1
    MACHINE = 2
    SYSTEM = 3
    SHARED = 4
    PUBLIC = 5


class Undo(IntEnum):
    """Can it be brought back? RECOVERABLE means a backup or VCS can."""

    TRIVIAL = 0
    RECOVERABLE = 1
    IRREVERSIBLE = 2


def derive_risk(effect, reach, undo=Undo.RECOVERABLE, secret=False):
    """The tier a fact implies — the guardrails, as one function.

    G1  irreversible and reach >= SHARED    -> CRITICAL
    G2  DESTROY beyond SCRATCH              -> at least HIGH
    G3  GRANT or PUBLISH                    -> at least HIGH, CRITICAL past the machine
    G4  the resource is a credential        -> at least HIGH, whatever the effect
    G5  no fact at all                      -> the caller gets None and escalates

    Every rule holds over the whole table rather than over one example,
    so two commands that do the same kind of thing cannot disagree about
    how dangerous it is. ``test_the_ontology_obeys_its_own_guardrails``
    asserts G1-G4 across every combination.
    """
    if secret:
        # Reading a credential is already exfiltration; writing one is worse.
        return Risk.CRITICAL if effect >= Effect.MUTATE else Risk.HIGH
    if effect in (Effect.PUBLISH, Effect.GRANT):
        return Risk.CRITICAL if reach >= Reach.SYSTEM else Risk.HIGH
    if effect == Effect.DESTROY:
        if reach == Reach.SCRATCH:
            return Risk.LOW
        if undo == Undo.IRREVERSIBLE and reach >= Reach.MACHINE:
            return Risk.CRITICAL
        return Risk.HIGH
    if effect == Effect.EXECUTE:
        return Risk.HIGH if reach >= Reach.MACHINE else Risk.MEDIUM
    if effect == Effect.MUTATE:
        if reach == Reach.SCRATCH:
            return Risk.LOW
        return Risk.HIGH if reach >= Reach.SHARED else Risk.MEDIUM
    # OBSERVE is never dangerous in itself. Observing a SECRET is, and that
    # is handled above — looking is what an agent does all day.
    return Risk.SAFE


# How far a tool's ordinary object lives from this machine. Only tools that
# genuinely act beyond it are listed; everything else defaults to PROJECT,
# so this can only raise the cases it was written for. `docker` and `npm`
# stay at PROJECT deliberately: their destructive verbs already carry tiers
# from SEGMENT_RULES, and the ontology must not quietly re-tier them.
TOOL_REACH = {
    "terraform": Reach.SHARED, "tofu": Reach.SHARED, "pulumi": Reach.SHARED,
    "kubectl": Reach.SHARED, "helm": Reach.SHARED, "k9s": Reach.SHARED,
    "aws": Reach.SHARED, "gcloud": Reach.SHARED, "gsutil": Reach.SHARED,
    "az": Reach.SHARED, "doctl": Reach.SHARED, "linode-cli": Reach.SHARED,
    "flyctl": Reach.SHARED, "fly": Reach.SHARED, "heroku": Reach.SHARED,
    "railway": Reach.SHARED, "render": Reach.SHARED, "supabase": Reach.SHARED,
    "wrangler": Reach.SHARED, "netlify": Reach.PUBLIC, "vercel": Reach.PUBLIC,
    "rclone": Reach.SHARED, "s3cmd": Reach.SHARED, "b2": Reach.SHARED,
    "psql": Reach.SHARED, "mysql": Reach.SHARED, "mongosh": Reach.SHARED,
    "redis-cli": Reach.SHARED, "stripe": Reach.SHARED, "twilio": Reach.SHARED,
    "launchctl": Reach.SYSTEM, "systemctl": Reach.SYSTEM, "security": Reach.SYSTEM,
}

# One word, one effect. This is the vocabulary the fourteen tables never
# had: what a word MEANS, rather than which binary is allowed to say it.
EFFECT_WORDS = {
    "destroy": Effect.DESTROY, "delete": Effect.DESTROY, "remove": Effect.DESTROY,
    "rm": Effect.DESTROY, "rmdir": Effect.DESTROY,
    "purge": Effect.DESTROY, "drop": Effect.DESTROY, "truncate": Effect.DESTROY,
    "wipe": Effect.DESTROY, "terminate": Effect.DESTROY, "flushall": Effect.DESTROY,
    "flushdb": Effect.DESTROY, "deprovision": Effect.DESTROY, "teardown": Effect.DESTROY,
    "publish": Effect.PUBLISH, "deploy": Effect.PUBLISH, "upload": Effect.PUBLISH,
    "grant": Effect.GRANT, "revoke": Effect.GRANT, "rotate": Effect.GRANT,
    "set-url": Effect.MUTATE, "set-head": Effect.MUTATE, "set-branches": Effect.MUTATE,
    "scale": Effect.MUTATE, "apply": Effect.MUTATE,
    # `rclone sync` and `aws s3 sync --delete` make the destination match
    # the source, which means deleting whatever the source does not have.
    "sync": Effect.MUTATE,
}

# Flags that carry an effect. Deliberately few and unambiguous: a flag like
# `-d` means "delete" to git and "data" to curl and "dictionary order" to
# sort, so only spellings that mean one thing everywhere are listed.
EFFECT_FLAGS = {
    "-D": Effect.DESTROY, "--delete": Effect.DESTROY, "--purge": Effect.DESTROY,
    "--prune": Effect.DESTROY,
    # find's own spelling of destruction: `-delete`, and `-exec rm`.
    "-delete": Effect.DESTROY, "-exec": Effect.DESTROY,
}

# Words that name a credential. Their presence makes the RESOURCE sensitive,
# whatever the effect: `gh auth token` and `kubectl get secret` are reads,
# and both put a live credential into the transcript.
SECRET_WORDS = frozenset(
    "token tokens secret secrets password passwords credential credentials "
    "keychain privatekey private-key apikey api-key passwd".split()
)
# The spellings tools actually use join the word to its neighbours:
# `--secret-id`, `AWS_SECRET_ACCESS_KEY`, `--api-key=`, `-field=api_key`.
# Those are a flag, a NAME=value and an environment variable — the three
# shapes where a joiner separates words. A plain lowercase name is not
# split: token-bucket.js, test_token_refresh.py, a token-service namespace
# and a fix-token-expiry branch all carry the word and none is a
# credential, and a card the user learns to tap through is how a wrist
# app stops working. That leaves `get-secret-value` alone unrecognised;
# the command it belongs to carries `--secret-id`, which is not.
_SECRET_JOINERS = re.compile(r"[-_=:,]")


def _words_name_a_secret(parts):
    """Whether any word, or any two neighbouring words rejoined, is in
    SECRET_WORDS — `api-key` and `private-key` live there as pairs."""
    if any(part in SECRET_WORDS for part in parts):
        return True
    return any(parts[i] + parts[i + 1] in SECRET_WORDS
               or parts[i] + "-" + parts[i + 1] in SECRET_WORDS
               for i in range(len(parts) - 1))


def _names_a_secret(word):
    # `${GITHUB_TOKEN}` is `$GITHUB_TOKEN`: the braces kept `token}` from
    # matching, and the braced spelling read SAFE (2026-09-30).
    bare = word.strip("-'\"").replace("${", "$").rstrip("}")
    if bare.lower() in SECRET_WORDS:
        return True
    if not (word.startswith("-") or "=" in word or bare.isupper()):
        return False
    return _words_name_a_secret([p for p in _SECRET_JOINERS.split(bare.lower()) if p])


_HOME_ITSELF = re.compile(r"^(~|\$\{?HOME\}?)/?\*?$")


def _ontology_risk(segment):
    """The effect this segment names, or None when it names none.

    Judged by vocabulary and reach, never by whether the binary is
    recognised — an unknown tool with a known verb is exactly the case the
    recognition tables cannot reach (`terraform destroy`, `rclone sync`).
    Returns ``(rule_id, Risk)`` for classify_bash to bump, so it can only
    push a tier up.
    """
    words = _tokens(segment)
    if not words:
        return None
    tool = os.path.basename(words[0]).lower()
    reach = TOOL_REACH.get(tool, Reach.PROJECT)
    # An absolute root argument means the blast radius is the machine, not
    # the project — `find / -delete` is not `find . -delete`.
    if any(w == "/" or w.startswith(("/System", "/Library", "/usr", "/etc", "/var"))
           for w in words[1:]):
        reach = max(reach, Reach.SYSTEM)
    # The home directory itself is everything the user has on this machine:
    # `find ~ -delete` is not `find . -delete` (2026-10-05 review).
    if any(_HOME_ITSELF.match(w.strip("'\"")) for w in words[1:]):
        reach = max(reach, Reach.MACHINE)

    effect = None
    for word in words[1:]:
        named = EFFECT_WORDS.get(word.lower()) or EFFECT_FLAGS.get(word)
        if named is not None:
            effect = named if effect is None else max(effect, named)

    secret = any(_names_a_secret(w) for w in words[1:])
    if effect is None and not secret:
        return None
    if effect is None:
        effect = Effect.OBSERVE
    # Destruction is the one effect that is irreversible by default: a
    # deleted namespace does not come back from a version-control history.
    undo = Undo.IRREVERSIBLE if effect == Effect.DESTROY else Undo.RECOVERABLE
    risk = derive_risk(effect, reach, undo, secret=secret)
    if risk == Risk.SAFE:
        return None
    return ("effect:%s@%s" % (effect.name.lower(), reach.name.lower()), risk)


READ_ONLY_COMMANDS = frozenset(
    """
    ls ll la cat bat head tail wc grep egrep fgrep rg ag find fd pwd cd which
    whereis type echo printf date whoami hostname uname tree du df file stat
    sort uniq diff comm basename dirname realpath readlink jq yq column less
    sw_vers system_profiler
    more nl cut tr rev tac awk true false test id groups locale ps top
    mypy flake8
    """.split()
)

# The lead commands Claude Code's OWN read-only validation answers with no
# visible prompt (its documented auto-allow list, plus git/gh/docker whose
# read subcommands it validates itself). Prompt parity may only skip the
# wrist when the whole command stays inside this set — our recognition
# tables are deliberately broader (pytest, kubectl, brew, xcodebuild -list…)
# and those DO prompt on the phone, so they must card the wrist.
CC_SILENT_LEADS = frozenset(
    """
    ls cat head tail wc grep egrep fgrep rg fd fdfind find cd pwd which type
    echo printf date whoami hostname uname tree du df file stat sort uniq
    diff comm basename dirname realpath readlink jq column nl cut tr rev tac
    true false test id groups locale ps sed xargs man help netstat base64
    sha256sum sha1sum md5sum lsof pgrep tput ss history arch ifconfig seq
    expr sleep cal uptime strings hexdump od free nproc paste fold expand
    unexpand fmt cmp numfmt tsort pr git gh docker
    """.split()
)


def phone_would_auto_allow(tool, tool_input):
    """Would Claude Code itself answer this call with no visible prompt?

    Non-Bash read tools (Read, Grep, Glob) never prompt. A Bash command is
    silent only when every segment's lead command is one Claude Code's own
    validation covers — being SAFE in OUR tables is not enough, because
    ours recognise more tools than the phone forgives.
    """
    if tool not in ("Bash", "BashOutput"):
        # Only the tools Claude Code genuinely answers by itself. This used
        # to return True for EVERY non-Bash tool, including Write, Edit and
        # every mcp__* call — safe today only because the single caller
        # gates on tier == SAFE first, which a write can never be. That
        # invariant lived in a different function; a second caller would
        # have inherited a silent yes for writes.
        return tool in READ_ONLY_TOOLS
    command = " ".join(str((tool_input or {}).get("command", "")).split())
    if not command or any(form in command for form in ("$(", "<(", ">(", "`")):
        return False
    return all(_first_token(segment) in CC_SILENT_LEADS
               for segment in _segments(command))


# Safe unless the pattern matches, in which case the command writes.
CONDITIONALLY_SAFE = {
    # -i alone or in a cluster: `sed -ri`, `-ni`, `-Ei` and `-ie` (suffix
    # "e") all edit in place, and read SAFE when only `-i` was matched.
    "sed": re.compile(r"(^|\s)-[A-Za-z]*i"),
    "ruff": re.compile(r"\b(format|--fix)\b"),
    "npm": re.compile(r"\bnpm\s+(?!test\b|ls\b|list\b|view\b|outdated\b)"),
}

# Tools judged by their first argument — a subcommand verb. SAFE only for
# verbs positively recognised as read-only; anything else falls through to
# unknown-command. This widens what the classifier *recognises*, never what
# it forgives. Aliases share one set so they cannot drift apart.
_PIP_READ_ONLY = frozenset("list show freeze --version".split())
_FLY_READ_ONLY = frozenset("status logs list info version".split())

VERB_TOOLS_READ_ONLY = {
    "gh": frozenset("browse search view list diff checks status".split()),
    "simctl": frozenset("list get_app_container getenv".split()),
    # cms and export are NOT here: `security cms -S` signs with a keychain
    # identity and `security export -t privKeys` dumps private keys — the
    # verb alone cannot tell a read from those.
    "security": frozenset(
        "find-identity find-certificate list-keychains".split()),
    "defaults": frozenset("read read-type domains".split()),
    "docker": frozenset("ps images logs inspect version info top port".split()),
    "kubectl": frozenset("get describe logs explain top version".split()),
    "brew": frozenset("list info search deps outdated config --version".split()),
    "pip": _PIP_READ_ONLY,
    "pip3": _PIP_READ_ONLY,
    "swift": frozenset("--version".split()),
    "flyctl": _FLY_READ_ONLY,
    "fly": _FLY_READ_ONLY,
    "systemctl": frozenset("status list-units is-active show".split()),
    "launchctl": frozenset("list print".split()),
    "ipconfig": frozenset("getifaddr getpacket getoption".split()),
    "networksetup": frozenset("-listallhardwareports -getinfo".split()),
    "tailscale": frozenset("status ip version netcheck".split()),
    "gcloud": frozenset("info version".split()),
    "aws": frozenset("--version help".split()),
}

# Tools whose read-only invocations are flag-shaped. SAFE only when every
# dash argument is recognised — one unknown flag and the whole segment
# falls through, because a single flag (codesign -s, plutil -convert) can
# turn a read into a write.
FLAG_TOOLS_READ_ONLY = {
    "plutil": frozenset("-p -lint".split()),
    "dns-sd": frozenset("-B -L -Z -G".split()),
    # Query flags only — never the value-taking selectors (-project,
    # -scheme, …): those describe a build, and "xcodebuild -project X
    # -scheme Y" with no verb at all RUNS one. Requiring a query flag and
    # no action verb keeps the whole family fail-closed.
    "xcodebuild": frozenset(
        "-list -version -showBuildSettings -showsdks -showdestinations".split()),
    "codesign": frozenset("-d --display -v --verify --deep --strict".split()),
}

# xcodebuild action verbs execute arbitrary Run Script build phases; their
# presence disqualifies a segment however read-only the flags look.
XCODEBUILD_ACTIONS = frozenset(
    "build clean test archive install installsrc analyze docbuild "
    "build-for-testing test-without-building".split())

# Sub-subcommands that read despite living under a writing verb — and the
# groups that are not verbs at all. `gh auth`, `fly apps`, `swift package`
# and `gcloud config` name a group; the verb is the next word. Listed as
# first-level verbs they made the whole group read-only, and until
# 2026-09-25 `gh auth logout`, `fly apps create`, `swift package update`
# and `gcloud config set project prod` all read SAFE — and with gh among
# the phone's silent leads, `gh auth logout` never reached the wrist.
SUBCOMMAND_SECOND_LEVEL = {
    ("gh", "auth"): frozenset("status".split()),
    ("fly", "apps"): frozenset("list".split()),
    ("flyctl", "apps"): frozenset("list".split()),
    ("swift", "package"): frozenset("describe dump-package show-dependencies".split()),
    ("gcloud", "config"): frozenset("list get get-value".split()),
    ("gh", "pr"): frozenset("view list diff checks status".split()),
    ("gh", "issue"): frozenset("view list status".split()),
    ("gh", "run"): frozenset("view list watch".split()),
    ("gh", "repo"): frozenset("view list".split()),
    ("gh", "release"): frozenset("view list".split()),
    ("gh", "workflow"): frozenset("view list".split()),
}

# gh api mutates when a method is spelled out — the separator is optional
# (gh accepts the attached -XDELETE form) and the value may be quoted — OR
# when any field argument is present: gh flips the default method to POST
# the moment a body field is given, no -X required.
GH_API_MUTATING = re.compile(
    r"(^|\s)(-X|--method)(\s+|=)?[\"']?(POST|PUT|PATCH|DELETE)"
    # A field switches the request to POST, its value attached or not:
    # `-ftitle=x` is a POST as surely as `-f title=x`.
    r"|(^|\s)(-[fF]|--field|--raw-field|--input)", re.I)


def _subcommand_risk(segment, token):
    """Judge a known tool by its arguments. None when we cannot tell.

    Verb tools are judged by their literal first argument; flag tools by
    every dash argument being recognised. ``xcrun`` is a wrapper, so the
    wrapped tool is judged on its own rules — ``xcrun notarytool submit``
    must not inherit safety from ``xcrun`` itself.
    """
    words = _tokens(segment)[1:]
    if token == "xcrun":
        if not words:
            return None
        if words[0] == "--find":
            return ("read-only-tool", Risk.SAFE)
        return _subcommand_risk(" ".join(words), words[0])

    flags_known = FLAG_TOOLS_READ_ONLY.get(token)
    if flags_known is not None:
        if token == "xcodebuild" and any(
                w in XCODEBUILD_ACTIONS for w in words):
            return None
        dash = [w for w in words if w.startswith("-")]
        if dash and all(w in flags_known for w in dash):
            return ("read-only-tool", Risk.SAFE)
        return None

    known = VERB_TOOLS_READ_ONLY.get(token)
    if known is None or not words:
        return None
    first = words[0]
    if token == "gh" and first == "api":
        if GH_API_MUTATING.search(segment):
            return None
        return ("read-only-tool", Risk.SAFE)
    pair = SUBCOMMAND_SECOND_LEVEL.get((token, first))
    if pair is not None:
        second = words[1] if len(words) > 1 else ""
        return ("read-only-tool", Risk.SAFE) if second in pair else None
    return ("read-only-tool", Risk.SAFE) if first in known else None


# Git subcommands that only read.
GIT_READ_ONLY = frozenset(
    "status diff log show branch remote rev-parse describe blame ls-files "
    "ls-remote shortlog config cat-file symbolic-ref".split()
)

GIT_MEDIUM = frozenset(
    "commit add merge rebase checkout switch stash tag restore cherry-pick "
    "fetch pull apply revert worktree".split()
)

# (rule_id, pattern, risk) applied to the whole command line.
WHOLE_LINE_RULES = [
    # `|&` pipes stderr too, and is as much a pipe into a shell.
    ("pipe-to-shell", re.compile(r"\|&?\s*(sudo\s+)?(ba|z|k|fi|da)?sh\b"), Risk.CRITICAL),
    # The same thing through another interpreter, or through a
    # substitution a shell then runs: `curl … | python3`,
    # `sh -c "$(curl …)"`, `bash <(curl …)` all read MEDIUM (2026-09-30).
    ("fetch-and-run",
     re.compile(r"\b(curl|wget)\b[^;&]*\|\s*(sudo\s+)?"
                r"(python[\d.]*|node|perl|ruby|php|osascript)\b"
                r"|(\b((ba|z|k|da)?sh|eval|source)|(^|\s)\.)\s[^;|]*"
                r"(\$\(|<\(|`)\s*(curl|wget)\b"), Risk.CRITICAL),
    ("fork-bomb", re.compile(r":\s*\(\s*\)\s*\{.*\}\s*;\s*:"), Risk.CRITICAL),
    ("history-rewrite", re.compile(r"\bgit\s+filter-(branch|repo)\b"), Risk.CRITICAL),
    ("cmd-substitution", re.compile(r"\$\(|[<>]\(|`"), Risk.MEDIUM),  # inner cmd classified in classify_bash()
    # Any `>` that is not a descriptor copy (`2>&1`, `>&2`) or /dev/null.
    # The lookbehind used to skip every `>` after a digit, which took
    # `1> ~/.zshrc` and `2> f` for `2>&1` and left them SAFE (2026-09-30).
    ("redirect-write", re.compile(r"(?<![<>])>>?(?!\s*(&[\d-]|/dev/null\b))"), Risk.MEDIUM),
]

# Commands that run the project's tests — which is to say, run code.
TEST_RUNNER = re.compile(
    r"(^|[\s/;&|])(pytest|py\.test|tox|nox)\b|\b(npm|yarn|pnpm|bun)\s+(run\s+)?test\b"
    r"|\bpython[\d.]*\s+-m\s+(pytest|unittest)\b")

# (rule_id, pattern, risk) applied per segment.
SEGMENT_RULES = [
    ("disk-overwrite", re.compile(r"\bdd\b[^|;&]*\bof=/dev/"), Risk.CRITICAL),
    ("format-disk", re.compile(r"\bmkfs(\.\w+)?\b"), Risk.CRITICAL),
    ("raw-device-write", re.compile(r">\s*/dev/(sd|nvme|disk|hd)"), Risk.CRITICAL),
    ("chmod-world-root", re.compile(r"\bchmod\s+(-R\s+)?0?777\s+/"), Risk.CRITICAL),
    ("sql-destructive", SQL_DESTRUCTIVE, Risk.CRITICAL),
    ("publish-artifact",
     re.compile(r"\b((npm|yarn|pnpm|cargo)\s+publish|twine\s+upload|"
                r"gh\s+release\s+create|docker\s+push)\b"), Risk.CRITICAL),

    ("sudo", re.compile(r"\bsudo\b"), Risk.HIGH),
    ("sql-mutation", SQL_MUTATION, Risk.HIGH),
    ("secret-access", SECRET_PATH, Risk.HIGH),
    ("network-upload",
     re.compile(r"\b(curl|wget)\b[^|;&]*(-X\s*(POST|PUT|PATCH)|--data|--upload-file|"
                r"(^|\s)-d\s|(^|\s)-F\s|(^|\s)-T\s)", re.I), Risk.HIGH),
    ("remote-copy", re.compile(r"\b(scp|rsync|sftp|ftp)\b"), Risk.HIGH),
    ("install-from-url",
     re.compile(r"\b(pip3?|uv|npm|yarn|pnpm)\s+(install|add)\b[^|;&]*"
                r"(https?://|git\+|@github)"), Risk.HIGH),
    ("prune-containers", re.compile(r"\bdocker\s+(system\s+)?prune\b"), Risk.HIGH),
    ("process-kill", re.compile(r"\b(killall|pkill|shutdown|reboot|halt)\b"), Risk.HIGH),
    ("credential-dump", re.compile(r"\b(printenv|env)\s*$"), Risk.HIGH),

    ("package-install",
     re.compile(r"\b(pip3?|uv|npm|yarn|pnpm|brew|apt-get|apt|choco|winget)\s+"
                r"(install|add|upgrade)\b"), Risk.MEDIUM),
    ("inline-code",
     re.compile(r"\b(python3?|node|perl|ruby|php)\s+-(c|e)\b|\beval\b"), Risk.MEDIUM),
    ("network-fetch", re.compile(r"\b(curl|wget|http|httpie|nc|ncat)\b"), Risk.MEDIUM),
    ("file-move", re.compile(r"\b(mv|cp|ln|install)\b"), Risk.MEDIUM),
    ("permission-change", re.compile(r"\b(chmod|chown|chgrp|icacls|attrib)\b"), Risk.MEDIUM),
    ("container", re.compile(r"\b(docker|podman|kubectl|helm)\b"), Risk.MEDIUM),
    ("formatter-rewrite", re.compile(r"\b(black|isort|prettier|autopep8)\b"), Risk.MEDIUM),
    # A test run runs the repository's code — conftest.py, noxfile.py, a
    # package.json script. pytest, tox and nox sat among the read-only
    # commands, so under --quiet a session could write test_x.py and run
    # it with nobody looking (2026-09-30, 2026-10-05 reviews).
    ("runs-project-code", TEST_RUNNER, Risk.MEDIUM),
]

RM_RE = re.compile(r"\brm\b((?:\s+-{1,2}[A-Za-z-]+)*)\s*(.*)")
# Any -r/-R among the flags. The tier and the wrist headline both ask,
# and they must agree on the answer.
RM_RECURSIVE = re.compile(r"-[A-Za-z]*[rR]")
# Skip git's global options before the subcommand — including the ones
# that take a value as a SEPARATE word (`git -C <dir> push …`, `git -c
# <name>=<val> push …`). The old `(?:-\S+\s+)*` swallowed only the flag,
# so `-C /repo` left `/repo` looking like the subcommand and a protected
# force-push slipped from CRITICAL down to an unknown-command MEDIUM.
_GIT_VALUE_GLOBALS = r"-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix"
GIT_RE = re.compile(
    r"\bgit\s+"
    r"(?:(?:%s)\s+\S+\s+"   # value-taking global + its separate-word value
    r"|--\S+\s+"             # --long or --long=value (value attached)
    r"|-\w+\s+)*"           # bare short flag(s)
    r"([a-z][a-z-]*)\b(.*)" % _GIT_VALUE_GLOBALS, re.I)

# Targets that mean "wipe the machine" or "wipe my home directory".
CATASTROPHIC_TARGETS = re.compile(
    r"^(/|//|/\*|~|~/|~/\*|\$\{?HOME\}?/?|\$\{?HOME\}?/\*|\.|\.\.|\*|"
    r"/(bin|boot|dev|etc|home|lib|opt|root|sbin|srv|usr|var|Users|Windows)/?\*?)$"
)


# Contents of an innermost `$(…)` (no nested parens) or a backtick pair.
# Innermost-first means nested substitutions surface one layer per pass and
# recursion in classify_bash() reaches the rest.
_SUBSTITUTION_RE = re.compile(r"[$<>]\(([^()]*)\)|`([^`]*)`")


def _segments(command):
    """Split a shell command into independently-classifiable segments."""
    return [s.strip() for s in SEGMENT_SPLIT.split(command or "") if s.strip()]


# On the unconditional path, so compiled once. The git-only patterns in
# _git_risk stay inline on purpose: re's own cache covers repeat calls, and
# hoisting them charged every non-git hook start ~170 µs — three times a
# whole classify() — for a branch most tool calls never take.
_LEADING_PAREN = re.compile(r"^\(\s*")


def _tokens(segment):
    """Words of a segment, with env assignments and a leading '(' stripped."""
    stripped = ENV_ASSIGN.sub("", segment.strip())
    stripped = _LEADING_PAREN.sub("", stripped)
    return stripped.split()


def _first_token(segment):
    """First real command token, skipping leading VAR=value assignments."""
    parts = _tokens(segment)
    return parts[0] if parts else ""


def _rm_risk(segment):
    """Classify an ``rm`` invocation by its flags and targets."""
    match = RM_RE.search(segment)
    if not match:
        return None
    flags, targets = match.group(1) or "", match.group(2) or ""
    recursive = bool(RM_RECURSIVE.search(flags))
    for target in targets.split():
        if target.startswith("-"):
            continue
        if CATASTROPHIC_TARGETS.match(target.strip("'\"")):
            return ("rm-catastrophic", Risk.CRITICAL)
    if recursive:
        return ("rm-recursive", Risk.HIGH)
    return ("rm-file", Risk.MEDIUM)


def _git_risk(segment):
    """Classify a ``git`` invocation by subcommand."""
    match = GIT_RE.search(segment)
    if not match:
        return None
    sub, rest = match.group(1).lower(), match.group(2) or ""
    forced = bool(re.search(r"(--force(?!-with-lease)|(^|\s)-f\b|\s\+)", rest))
    # Options that choose a program git will run: a pager, a diff tool, an
    # ssh command, a remote's upload-pack. Each ran behind a SAFE "git log"
    # (2026-09-30). -C only changes the directory and stays a read.
    opening = segment[match.start():match.start(1)]
    runs = bool(re.search(r"(^|\s)(-c\s*\S|--exec-path|--git-dir|--work-tree)", opening)
                or re.search(r"(^|\s)(--upload-pack|--receive-pack|--exec|--ext-diff)\b"
                             r"|(^|\s)-u\s", rest))

    if sub == "push":
        # Deleting a remote branch loses it as surely as overwriting it.
        if re.search(r"(^|\s)(--delete|-d)\b|(^|\s):\S", rest):
            forced = True
        if forced and re.search(r"\b(main|master|prod|production|release)\b", rest):
            return ("git-force-push-protected", Risk.CRITICAL)
        if forced:
            return ("git-force-push", Risk.HIGH)
        return ("git-push", Risk.HIGH)
    if sub == "reset" and "--hard" in rest:
        return ("git-reset-hard", Risk.HIGH)
    if sub == "clean" and re.search(r"-[a-z]*f", rest):
        return ("git-clean-force", Risk.HIGH)
    if sub in GIT_READ_ONLY and runs:
        return ("git-runs-a-program", Risk.MEDIUM)
    if sub == "config":
        # `config` sat in GIT_READ_ONLY, so `git config --global alias.x
        # '!rm -rf ~'` read SAFE: it is a read only when it is reading.
        if "!" in rest:
            # A `!`-alias stores a shell command that later runs as `git x`.
            return ("git-config-shell-alias", Risk.CRITICAL)
        if re.search(r"(^|\s)--(unset|unset-all|remove-section|rename-section|replace-all"
                     r"|add|edit)\b|(^|\s)-e\b", rest):
            # Deletions and edits name one key or none, so the two-word
            # rule below read them as reads (2026-10-19 review).
            return ("git-config-write", Risk.MEDIUM)
        if re.search(r"(^|\s)--(get|get-all|get-regexp|list)\b|(^|\s)-l\b", rest):
            return ("git-read", Risk.SAFE)
        if len([w for w in rest.split() if not w.startswith("-")]) >= 2:
            return ("git-config-write", Risk.MEDIUM)
        return ("git-read", Risk.SAFE)
    words = [w for w in rest.split() if not w.startswith("-")]
    if sub == "remote" and words and words[0] in (
            "add", "set-url", "remove", "rm", "rename", "set-head", "prune",
            "update", "set-branches"):
        return ("git-write", Risk.MEDIUM)
    if sub == "branch" and (
            re.search(r"(^|\s)(-[fmMcCdDu]\b|--(force|move|copy|delete|set-upstream-to|"
                      r"unset-upstream|edit-description)\b)", rest)
            or (words and not re.search(r"(^|\s)(-l|--list|--contains|--no-contains|"
                                        r"--merged|--no-merged|--points-at)\b", rest))):
        return ("git-write", Risk.MEDIUM)
    if sub in GIT_READ_ONLY:
        return ("git-read", Risk.SAFE)
    if sub in GIT_MEDIUM:
        return ("git-write", Risk.MEDIUM)
    return ("git-other", Risk.MEDIUM)


# Commands that run the command after them. `env rm -rf ~` is `rm -rf ~`;
# judged by its lead word it read HIGH instead of CRITICAL (2026-09-25).
_PASS_THROUGH = frozenset("env command builtin nice nohup exec time timeout sudo".split())
# `if true; then rm -rf ~; fi` splits into segments led by these words.
_SHELL_KEYWORDS = frozenset("if then else elif do while until !".split())
_SHELLS = frozenset("sh bash zsh dash ksh fish".split())
_IFS = re.compile(r"\$\{?IFS\}?")
_XARGS_VALUE_FLAGS = frozenset("-n -I -L -P -d -E -s -a".split())


def _unwrapped(segment):
    """The command a wrapper runs, or None when the segment is not a wrapper.

    `sh -c "…"`, `eval "…"`, `env …`, `timeout 5 …`, `\\rm`, `( … )` and
    `{ …; }` all run a command the lead word does not name; classify_bash
    judges that inner command in its own right, so a wrapper can never
    lower the tier of what it wraps."""
    text = segment.strip()
    if text.startswith("\\"):
        return text[1:]
    # `rm${IFS}-rf${IFS}~` is `rm -rf ~` to the shell.
    if _IFS.search(text):
        return _IFS.sub(" ", text)
    # `"rm" -rf ~`, `'rm'`, `r"m"`: the shell drops the quotes, and the
    # name they spell is the command that runs (2026-10-05 review).
    first = text.split(None, 1)
    if first and first[0][:1] not in "({" and any(q in first[0] for q in "'\"\\"):
        bare = re.sub(r"['\"\\]", "", first[0])
        if bare:
            return " ".join([bare] + first[1:])
    if (text.startswith("(") and text.endswith(")")) or (
            text.startswith("{") and text.endswith("}")):
        inner = text[1:-1].strip().rstrip(";").strip()
        return inner or None
    # `{ rm -rf ~; }` reaches here split at its `;`: the opening half.
    if text.startswith("{ "):
        return text[2:].strip() or None
    words = _tokens(text)
    if not words:
        return None
    lead = os.path.basename(words[0]).lower()
    if lead == "eval":
        return " ".join(words[1:]).strip("'\"") or None
    if lead in _SHELL_KEYWORDS:
        return " ".join(words[1:]) or None
    if lead in _SHELLS:
        try:
            args = shlex.split(" ".join(words[1:]))
        except ValueError:
            return None
        for i, arg in enumerate(args):
            if arg == "-c" or (arg.startswith("-") and not arg.startswith("--")
                               and "c" in arg[1:]):
                return args[i + 1] if i + 1 < len(args) else None
        return None
    if lead == "xargs":
        # `xargs rm -rf` runs rm. Skip xargs' own options to reach it.
        rest = words[1:]
        while rest and rest[0].startswith("-"):
            takes_value = rest[0] in _XARGS_VALUE_FLAGS
            rest = rest[2:] if takes_value else rest[1:]
        return " ".join(rest) or None
    if lead in _PASS_THROUGH:
        rest = words[1:]
        # Skip the wrapper's own options and arguments: `nice -n 5`,
        # `timeout -s KILL 5`, `env -i A=b`.
        while rest and (rest[0].startswith("-") or "=" in rest[0]
                        or (lead in ("timeout", "nice") and rest[0][:1].isdigit())):
            takes_value = rest[0] in ("-n", "-s", "-k", "-u", "--signal", "--kill-after") or (
                lead == "sudo" and rest[0] in ("-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"))
            rest = rest[2:] if takes_value else rest[1:]
        return " ".join(rest) or None
    return None


# Read-only tools with a spelling that writes a file or runs a command,
# each a test that takes the segment. Checked before the tool is waved
# through as a read: each of these read SAFE until 2026-09-25, and --quiet
# would have allowed them.
READ_TOOL_ESCAPES = {
    "awk": re.compile(r"system\s*\(|\|\s*[\"']|\|&|>{1,2}\s*[\"']|getline\s*<"
                      r"|(^|\s)(-f\s*\S|--file\b)").search,
    "rg": re.compile(r"(^|\s)--pre(=|\s)").search,
    "find": re.compile(r"(^|\s)-(fprint0?|fprintf|fls|execdir|ok|okdir)(\s|$)").search,
    "tree": re.compile(r"(^|\s)(-o|--output)(\s|=)").search,
    # -o alone, attached (`-ofile`) or in a cluster (`-uo file`).
    "sort": re.compile(r"(^|\s)--output(\s|=)|(^|\s)-[A-Za-z]*o|--compress-program").search,
    # fd runs a command per match (`-x`) or per batch (`-X`).
    "fd": re.compile(r"(^|\s)(-[A-Za-z]*[xX]|--exec|--exec-batch)(\s|=|$)").search,
    # sed's own commands write (`w file`, `s/a/b/w file`) and run (`e`).
    "sed": re.compile(r"(^|\s)--in-place\b|(^|[\s;{}'\"/\d$])[wW]\s+\S"
                      r"|(^|[\s;{}'\"/\d$])e(\s|['\";]|$)").search,
    # Setting the clock or the machine's name, not reading them.
    "date": re.compile(r"(^|\s)(-s|--set)\b|(^|\s)\d{6,}(\s|$)").search,
    "hostname": lambda segment: any(not w.startswith("-") for w in _tokens(segment)[1:]),
    "uniq": lambda segment: len([w for w in _tokens(segment)[1:]
                                 if not w.startswith("-") and not w.isdigit()]) >= 2,
    "security": re.compile(r"\b(list|default|login)-keychains?\b[^|;&]*\s-[sd]\b").search,
    "yq": re.compile(r"(^|\s)-[A-Za-z]*i|(^|\s)--inplace\b").search,
    "git": re.compile(r"(^|\s)--output(=|\s)").search,
}
for _awk in ("gawk", "nawk", "mawk"):
    READ_TOOL_ESCAPES[_awk] = READ_TOOL_ESCAPES["awk"]


# Reads that put a live credential into the transcript, by a spelling the
# ontology cannot see: a one-letter flag, a BSD ps option, a keychain dump.
CREDENTIAL_READS = re.compile(
    r"\bgh\s+auth\s+status\b[^|;&]*(\s-t\b|--show-token)"
    r"|\bsecurity\s+(find-(generic|internet)-password\b[^|;&]*\s-[a-z]*[wg][a-z]*\b"
    r"|dump-keychain\b|export\b)"
    r"|\bps\b(\s+-\S+)*(\s+-[a-zA-Z]*E[a-zA-Z]*|\s+[acehjlmrSTuvwxX]*e[acehjlmrSTuvwxX]*)(?=\s|$)"
    r"|\bjq\b[^|;&]*\$ENV\b")


def classify_bash(command):
    """Classify a shell command. Returns ``(Risk, [rule_id, ...])``."""
    if not command or not command.strip():
        return Risk.MEDIUM, ["empty-command"]

    risk = Risk.SAFE
    rules = []

    def bump(rule_id, level):
        nonlocal risk
        if level > risk:
            risk = level
        if rule_id not in rules:
            rules.append(rule_id)

    for rule_id, pattern, level in WHOLE_LINE_RULES + SITE_RULES:
        if pattern.search(command):
            bump(rule_id, level)

    # A command substitution runs its OWN command — `echo $(rm -rf /)` is a
    # catastrophic delete wearing an echo. The segment splitter doesn't
    # descend into `$(…)`/backticks, so classify the inner command in its
    # own right and take the max; recursion handles nesting. Without this a
    # destructive payload hid behind the blunt MEDIUM "cmd-substitution"
    # cap and could be auto-allowed under a raised threshold.
    for dollar_form, backtick_form in _SUBSTITUTION_RE.findall(command):
        inner = (dollar_form or backtick_form).strip()
        if inner:
            sub_risk, sub_rules = classify_bash(inner)
            bump("cmd-substitution-inner:" + (sub_rules[0] if sub_rules
                 else "?"), sub_risk)

    for segment in _segments(command):
        if segment.strip() in ("}", ")"):
            continue  # the closing half of a group split at its `;`
        inner = _unwrapped(segment)
        if inner is not None and inner.strip() != segment.strip():
            sub_risk, sub_rules = classify_bash(inner)
            bump("wrapped:" + (sub_rules[0] if sub_rules else "?"), sub_risk)
            # Grouping and a leading backslash change nothing but aliases.
            # A real wrapper can: `env LD_PRELOAD=x.so ls` runs x.so. It
            # keeps the unknown-command floor it always had, so unwrapping
            # can only ever raise a tier.
            if segment.strip()[:1] not in "({\\":
                bump("wrapper", Risk.MEDIUM)
            if os.path.basename(_first_token(segment)).lower() == "sudo":
                bump("sudo", Risk.HIGH)
            continue

        token = os.path.basename(_first_token(segment)).lower()

        escape = READ_TOOL_ESCAPES.get(token)
        if escape is not None and escape(segment):
            bump("read-tool-writes-or-runs", Risk.MEDIUM)

        if any(name not in HARMLESS_ENV and not name.startswith("LC_")
               for name in _assigned_names(segment)):
            bump("env-prefix", Risk.MEDIUM)

        if CREDENTIAL_READS.search(segment):
            bump("credential-read", Risk.HIGH)

        # The effect the words name, before any table gets to recognise the
        # binary. bump() takes the maximum, so a recognition table below can
        # no longer talk this back down to SAFE.
        named_effect = _ontology_risk(segment)
        if named_effect is not None:
            bump(*named_effect)

        special = _rm_risk(segment) if token == "rm" else None
        if special is None and token == "git":
            special = _git_risk(segment)
        # A positively recognised read-only invocation is judged by its
        # subcommand, not by the blunt tool-name rules below — "docker ps"
        # is not "docker run".
        if special is None:
            special = _subcommand_risk(segment, token)
        if special is not None:
            bump(*special)
            continue

        matched_rule = False
        for rule_id, pattern, level in SEGMENT_RULES:
            if pattern.search(segment):
                bump(rule_id, level)
                matched_rule = True

        if matched_rule:
            continue

        conditional = CONDITIONALLY_SAFE.get(token)
        if conditional is not None:
            if conditional.search(segment):
                bump("conditional-write", Risk.MEDIUM)
            else:
                bump("read-only", Risk.SAFE)
            continue

        if token in READ_ONLY_COMMANDS:
            bump("read-only", Risk.SAFE)
            continue

        # Unknown command: never assume it is safe.
        bump("unknown-command", Risk.MEDIUM)

    return risk, rules


# --------------------------------------------------------------------------
# Path classification (Write / Edit / NotebookEdit)
# --------------------------------------------------------------------------

LOW_RISK_PATH = re.compile(
    r"(^|[/\\])(test_[^/\\]*\.py|[^/\\]*_test\.py|[^/\\]*\.(md|rst|txt|log))$", re.I
)
INFRA_PATH = re.compile(
    r"((^|[/\\])\.github[/\\]workflows[/\\]|(^|[/\\])\.claude[/\\]settings|"
    r"(^|[/\\])(Dockerfile|docker-compose\.ya?ml|[^/\\]*\.tf|Makefile|"
    r"pyproject\.toml|package\.json|requirements\.txt)$)",
    re.I,
)
SCRATCH_PATH = re.compile(r"([/\\](tmp|scratchpad|\.cache)[/\\])", re.I)
# What every later session reads as its instructions, or runs as a command,
# agent or skill: not documentation, whatever the extension (2026-09-30).
INSTRUCTION_PATH = re.compile(
    r"(^|[/\\])(CLAUDE(\.local)?\.md|AGENTS\.md)$"
    r"|(^|[/\\])\.claude[/\\](commands|agents|skills|hooks)[/\\]", re.I)


def classify_path(path, cwd=None):
    """Classify a filesystem write target. Returns ``(Risk, [rule_id, ...])``."""
    if not path:
        return Risk.MEDIUM, ["no-path"]

    normalised = str(path).replace("\\", "/")
    # Resolve `..` before any pattern sees the path: `/tmp/../Users/me/.zshrc`
    # matched the scratch rule and read LOW (2026-09-25).
    if ".." in normalised.split("/"):
        if cwd and not os.path.isabs(normalised):
            normalised = os.path.join(str(cwd).replace("\\", "/"), normalised)
        normalised = os.path.normpath(normalised).replace("\\", "/")
        path = normalised

    if re.search(r"(^|/)\.git/", normalised):
        return Risk.CRITICAL, ["git-internals"]
    if SECRET_PATH.search(normalised):
        return Risk.CRITICAL, ["secret-file"]
    for rule_id, pattern, level in SITE_RULES:
        if pattern.search(str(path)):
            return level, [rule_id]
    if INFRA_PATH.search(normalised):
        return Risk.HIGH, ["infrastructure-file"]
    if normalised.lower().endswith(".sql"):
        # A .sql file is something a database eventually executes.
        return Risk.HIGH, ["sql-artifact"]

    if SCRATCH_PATH.search(normalised):
        return Risk.LOW, ["scratch-file"]

    if cwd:
        try:
            absolute = os.path.normcase(os.path.abspath(str(path)))
            root = os.path.normcase(os.path.abspath(str(cwd)))
            if not absolute.startswith(root.rstrip(os.sep) + os.sep) and absolute != root:
                return Risk.HIGH, ["outside-project"]
        except (ValueError, OSError):
            return Risk.HIGH, ["unresolvable-path"]

    if INSTRUCTION_PATH.search(normalised):
        return Risk.MEDIUM, ["agent-instructions"]
    if LOW_RISK_PATH.search(normalised):
        return Risk.LOW, ["docs-or-test"]

    return Risk.MEDIUM, ["project-file"]


# --------------------------------------------------------------------------
# Tool dispatch
# --------------------------------------------------------------------------

READ_ONLY_TOOLS = frozenset(
    "Read Glob Grep NotebookRead TodoWrite TaskList TaskGet ListMcpResources "
    "ReadMcpResourceTool ListAgents ListSkills ListPlugins".split()
)
WRITE_TOOLS = frozenset("Write Edit MultiEdit NotebookEdit".split())

# What the verb of an MCP tool name means. EFFECT_WORDS is shell
# vocabulary and wins; these are the verbs a connector is told that a
# shell binary is not — "merge", "reply", "submit" — and would be false
# positives as argv words (`git stash push`, `docker start`, `npm run`).
MCP_MUTATE_WORDS = frozenset(
    "create update merge push write send add set trigger submit enable "
    "disable fork resolve reply post put patch move rename archive trash "
    "forward respond insert replace save label unlabel restore".split()
)
MCP_EXECUTE_WORDS = frozenset("run execute start stop kill cancel".split())
MCP_EFFECT = dict({w: Effect.EXECUTE for w in MCP_EXECUTE_WORDS},
                  **{w: Effect.MUTATE for w in MCP_MUTATE_WORDS})
MCP_EFFECT.update(EFFECT_WORDS)
# Verbs that only read, for integration calls alone (never the words that
# judge a shell command): the owner's change C of 2026-10-02. They never
# replace a meaning a word already has, a secret in the name still makes a
# credential read (G4), and a verb outside every list stays MEDIUM.
MCP_READ_WORDS = ("get", "list", "search", "read", "fetch", "find", "query",
                  "view", "describe", "status", "lookup", "count", "inspect")
for _verb in MCP_READ_WORDS:
    MCP_EFFECT.setdefault(_verb, Effect.OBSERVE)
# Longest first, so `setup` meets `set` only after nothing longer matched.
_MCP_VERB_PREFIXES = sorted((v for v in MCP_EFFECT if len(v) >= 3),
                            key=len, reverse=True)
_MCP_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_MCP_WORDS = re.compile(r"[_\-]")


def _mcp_risk(tool):
    """Tier for an ``mcp__<server>__<tool>`` name, from its verb.

    A server name may itself contain underscores (``ccd_session_mgmt``,
    ``scheduled_tasks``), so the split is at the LAST ``__``. The regex
    this replaces used ``[^_]+`` for the server and never matched those —
    every delete on an underscored server read as an unknown MCP tool,
    two tiers below the same delete on ``github``.

    The verb is the FIRST word, as that regex also had it: judging every
    word made ``get_label`` a write because "label" is a verb elsewhere.
    Two things the regex did are kept so nothing it caught reads lower
    now — camelCase splits (``createIssue``), and a verb matches as a
    prefix (``setup_webhook``, ``runtime``).

    Reach is TOOL_REACH's answer for the server, else SHARED: a connector
    acts on something that is not this machine. For a server the table
    does not know the tier is capped at HIGH — the classifier cannot tell
    a WordPress from a PDF viewer, and G3 would otherwise call every
    ``upload_image`` CRITICAL and, under critical_action: deny, refuse it
    outright. A credential write keeps its CRITICAL: that is G4, and G4
    does not depend on reach.
    """
    server, sep, name = tool[len("mcp__"):].rpartition("__")
    if not sep or not name:
        return Risk.MEDIUM, ["mcp-unknown"]
    words = [w for w in _MCP_WORDS.split(_MCP_CAMEL.sub("_", name).lower()) if w]
    if not words:
        return Risk.MEDIUM, ["mcp-unknown"]
    verb = words[0]
    effect = MCP_EFFECT.get(verb)
    if effect is None:
        effect = next((MCP_EFFECT[v] for v in _MCP_VERB_PREFIXES
                       if verb.startswith(v)), None)
    secret = _words_name_a_secret(words)
    if effect is None and not secret:
        return Risk.MEDIUM, ["mcp-unknown"]
    effect = effect or Effect.OBSERVE
    known = server in TOOL_REACH
    risk = derive_risk(effect, TOOL_REACH.get(server, Reach.SHARED), secret=secret)
    if not known and not secret:
        risk = min(risk, Risk.HIGH)
    # A recognised read is LOW (the owner's decision, 2026-10-02: "Check PR
    # status" at MEDIUM only because the tool was an MCP one). Everything
    # else keeps the floor an unknown MCP tool has always had.
    floor = Risk.LOW if effect is Effect.OBSERVE and not secret else Risk.MEDIUM
    return max(risk, floor), ["mcp:%s" % effect.name.lower()]

CONTENT_KEYS = ("content", "new_string", "file_text", "new_source")


def _command_as_text(tool_input):
    """A command given as an argv list, joined into the one string every
    reader here expects. Claude Code sends a string; Codex's documented
    shape is a string too, but an argv list used to raise in
    classify_bash, and the hook then escalated with no card on the wrist
    at all: a prompt the wearer was never shown."""
    command = tool_input.get("command")
    if isinstance(command, (list, tuple)):
        tool_input = dict(tool_input)
        tool_input["command"] = shlex.join(str(part) for part in command)
    return tool_input


# Codex's apply_patch: one text that names every file it touches.
PATCH_FILE = re.compile(
    r"^\*\*\* (Add|Update|Delete) File: (.+?)\s*$|^\*\*\* Move to: (.+?)\s*$",
    re.MULTILINE)


def patch_files(patch):
    """``[(verb, path), ...]`` for each file an apply_patch text touches."""
    found = []
    for match in PATCH_FILE.finditer(str(patch or "")):
        if match.group(3):
            found.append(("Move", match.group(3)))
        else:
            found.append((match.group(1), match.group(2)))
    return found


def _patch_risk(patch, cwd):
    """Codex's apply_patch through the same paths as Write, Edit and rm.

    Each file is judged where it lands (classify_path), a deleted one as
    an ``rm`` of it would be, and the added lines through the same content
    scan as a written file. A patch that names no file is not understood,
    and is MEDIUM rather than SAFE.
    """
    files = patch_files(patch)
    if not files:
        return Risk.MEDIUM, ["patch-unparsed"]
    risk, rules = Risk.SAFE, []
    if not cwd:
        # With no working directory no path can be judged inside the
        # project; a relative one could land anywhere (2026-10-05 review).
        risk, rules = Risk.HIGH, ["patch-without-cwd"]
    for verb, path in files:
        level, found = classify_path(path, cwd)
        if verb == "Delete":
            removed, why = classify_bash("rm -- %s" % shlex.quote(path))
            level, found = max(level, removed), found + why
        risk = max(risk, level)
        rules += [rule for rule in found if rule not in rules]
    added = "\n".join(line[1:] for line in str(patch).splitlines()
                      if line.startswith("+"))
    return _scan_content(added, risk, rules)


def _scan_content(content, risk, rules):
    """A benign path can still carry a destructive payload."""
    if content:
        if SQL_DESTRUCTIVE.search(content):
            return max(risk, Risk.CRITICAL), rules + ["sql-destructive"]
        if SQL_MUTATION.search(content):
            return max(risk, Risk.HIGH), rules + ["sql-mutation"]
        for rule_id, pattern, level in SITE_RULES:
            if pattern.search(content):
                return max(risk, level), rules + [rule_id]
    return risk, rules


def classify(event):
    """Classify a ``PermissionRequest`` event. Returns a result dict."""
    tool = (event or {}).get("tool_name") or ""
    tool_input = (event or {}).get("tool_input") or {}
    cwd = (event or {}).get("cwd")
    if not isinstance(tool_input, dict):
        tool_input = {}
    tool_input = _command_as_text(tool_input)

    if tool in ("Bash", "BashOutput"):
        risk, rules = classify_bash(tool_input.get("command", ""))
    elif tool == "apply_patch":
        risk, rules = _patch_risk(tool_input.get("command", ""), cwd)
    elif tool in WRITE_TOOLS:
        risk, rules = classify_path(
            tool_input.get("file_path") or tool_input.get("notebook_path"), cwd
        )
        content = " ".join(
            str(tool_input.get(key, "")) for key in CONTENT_KEYS if tool_input.get(key)
        )
        # MultiEdit carries its changes as a list of edits: scanned like
        # Edit's new_string, which they are (2026-10-19 review).
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            content += " " + " ".join(str(e.get("new_string", "")) for e in edits
                                      if isinstance(e, dict))
        risk, rules = _scan_content(content, risk, rules)
    elif tool in READ_ONLY_TOOLS:
        risk, rules = Risk.SAFE, ["read-only-tool"]
    elif tool == "WebSearch":
        risk, rules = Risk.LOW, ["web-search"]
    elif tool == "WebFetch":
        risk, rules = Risk.MEDIUM, ["network-egress"]
    elif tool in ("Task", "Agent", "Workflow"):
        risk, rules = Risk.MEDIUM, ["spawns-agents"]
    elif tool.startswith("mcp__"):
        risk, rules = _mcp_risk(tool)
    elif not tool:
        risk, rules = Risk.MEDIUM, ["missing-tool-name"]
    else:
        risk, rules = Risk.MEDIUM, ["unknown-tool"]

    return {"risk": risk, "rules": rules, "tool": tool, "tool_input": tool_input}


# --------------------------------------------------------------------------
# Wrist card
# --------------------------------------------------------------------------

BASH_VERBS = {
    "rm": "Delete",
    "mv": "Move",
    "cp": "Copy",
    "mkdir": "Create dir",
    "chmod": "Chmod",
    "chown": "Chown",
    "curl": "Fetch",
    "wget": "Download",
    "docker": "Docker",
    "pip": "Install",
    "pip3": "Install",
    "npm": "npm",
    "pytest": "Run tests",
    "python": "Run",
    "python3": "Run",
    "sudo": "SUDO",
}


def _fit(text, limit):
    """Truncate to ``limit`` characters with an ellipsis.

    Every field that reaches a card or the audit log passes through here, so
    this is where credential-shaped fragments are stripped: one place, no
    way to add a new field that forgets.
    """
    text = " ".join(redact_secrets(str(text or "")).split())
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1] + "…"


def _fit_lines(text, limit):
    """_fit that keeps the text's own line breaks: a question asked in two
    paragraphs, or a here-document, is not one run-on line (owner,
    2026-10-16). Spaces still collapse within a line, and a run of blank
    lines becomes one. Credentials are stripped here too."""
    kept, blank = [], False
    for line in redact_secrets(str(text or "")).splitlines():
        line = " ".join(line.split())
        if line:
            kept.append(line)
            blank = False
        elif kept and not blank:
            kept.append("")
            blank = True
    text = "\n".join(kept).strip()
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    return text[: limit - 1] + "…"


def _short_targets(raw, budget):
    """Render path arguments compactly — basenames when the full path is long."""
    targets = [t for t in raw.split() if not t.startswith("-")]
    if not targets:
        return ""
    rendered = " ".join(targets)
    if len(rendered) <= budget:
        return rendered
    return _fit(" ".join(os.path.basename(t.rstrip("/\\")) or t for t in targets), budget)


def _bash_headline(command, limit):
    segments = _segments(command)
    if not segments:
        return _fit(command, limit)
    head = segments[0]
    extra = " +%d more" % (len(segments) - 1) if len(segments) > 1 else ""
    budget = limit - len(extra)
    token = os.path.basename(_first_token(head)).lower()

    rm_match = RM_RE.search(head) if token == "rm" else None
    if rm_match:
        recursive = bool(RM_RECURSIVE.search(rm_match.group(1) or ""))
        suffix = " -r" if recursive else ""
        targets = _short_targets(rm_match.group(2) or "", budget - 8 - len(suffix))
        return _fit("Delete %s%s" % (targets, suffix), budget) + extra

    git_match = GIT_RE.search(head) if token == "git" else None
    if git_match:
        return _fit("git %s %s" % (git_match.group(1), git_match.group(2) or ""), budget) + extra

    verb = BASH_VERBS.get(token)
    if verb:
        rest = head[len(_first_token(head)):].strip()
        return _fit("%s %s" % (verb, _short_targets(rest, budget - len(verb) - 1)), budget) + extra

    return _fit(head, budget) + extra


# One budget for every card the module ever builds — the audit log, the
# relay and --explain must describe the same truncation or they lie to
# each other. Policy keys headline_chars/detail_chars override both.


def _card_budgets(policy):
    return (int(policy.get("headline_chars", HEADLINE_CHARS)),
            int(policy.get("detail_chars", DETAIL_CHARS)))


# Secrets that show up in ordinary commands. The card and the audit log
# both carry command text, and the card also travels through iCloud, so a
# token pasted into a curl call should not ride along with it. The command
# still reads clearly — only the secret becomes "…".
SECRET_PATTERNS = [
    re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic)\s+)\S+"),
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_\-]{8})[A-Za-z0-9_\-]+"),
    re.compile(r"(?i)\b(gh[pousr]_)[A-Za-z0-9]{16,}"),
    re.compile(r"(?i)(--(?:password|token|api-key|secret)[= ])\S+"),
    re.compile(r"(?i)\b([A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)=)\S+"),
]


def redact_secrets(text):
    """Replace credential-shaped fragments with an ellipsis. Never raises."""
    try:
        result = str(text or "")
        for pattern in SECRET_PATTERNS:
            result = pattern.sub(lambda m: m.group(1) + "…", result)
        return result
    except Exception:
        return str(text or "")


# The one sentence every card must answer: Claude wants to DO WHAT to
# WHAT THING. For a tool the card builder does not know, the arguments
# hold both halves — these keys say what the call does, in the order a
# reader would ask...
ACTION_KEYS = ("method", "action", "operation", "op", "command", "query")
# ...and these say where it lands: the fields a blind tap would need to
# have seen. Order is reading order on the wrist.
TARGET_KEYS = ("projectId", "project_id", "project", "owner", "repo",
               "url", "path", "file_path", "id", "name", "title", "to",
               "recipient", "table", "host", "branch", "collection",
               "doc_id", "pull_number", "issue_number")
CARD_FACTS = 3
# Each value travels whole, as a card's question and command do: the card
# screen wraps it, and a value cut to 32 characters was the part a blind
# tap needed (2026-10-15). The list row clamps itself to one line. Three of
# these are 4.5 KB at most, well inside the relay's 256 KB body; the push
# notification carries only the headline.
FACT_CHARS = 1500


def _humanise_key(key):
    """``projectId`` → ``project``, ``file_path`` → ``file``, ``pull_number``
    → ``pull number``: the label a person would use, never the wire name."""
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    words = re.sub(r"[_\-.]+", " ", words).strip().lower()
    words = re.sub(r"\s+(id|path)$", "", words) or words
    return words or str(key)


def _fact_value(value, limit):
    """One argument as a person would say it: no quotes, no braces, a
    count for anything nested, and a path keeps its tail."""
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        return "%d field%s" % (len(value), "" if len(value) == 1 else "s")
    if isinstance(value, list):
        if not value:
            return "none"
        if len(value) <= 3 and all(isinstance(v, str) for v in value):
            joined = ", ".join(" ".join(v.split()) for v in value)
            if len(joined) <= limit:
                return joined
        return "%d item%s" % (len(value), "" if len(value) == 1 else "s")
    text = " ".join(str(value).split())
    if len(text) > limit and "/" in text.rstrip("/"):
        # A path's identifying part is its tail: "…/api/handlers.py".
        return _fit("…" + text[-(limit - 1):], limit)
    return _fit(text, limit)


def card_facts(tool_input, count=CARD_FACTS, limit=FACT_CHARS,
               skip=()):
    """The few argument facts that name the target — action keys first,
    then the fields that say where the call lands, then whatever else the
    call carries, in its own order. Never a single field: an approval
    surface that hides which repo, table or host is targeted invites a
    blind tap. Returns ``[[label, value], ...]``."""
    if not isinstance(tool_input, dict):
        return []
    facts, seen = [], set(skip)
    ordered = [k for k in ACTION_KEYS + TARGET_KEYS if k in tool_input]
    ordered += [k for k in tool_input if k not in ordered]
    for key in ordered:
        if key in seen:
            continue
        seen.add(key)
        facts.append([_humanise_key(key), _fact_value(tool_input[key], limit)])
        if len(facts) == count:
            break
    return facts


def _action_from_input(tool_input):
    """The action an argument names, in words: ``finalize_plan`` →
    ``finalize plan``. Returns ``(key, words)`` or ``(None, "")``."""
    for key in ACTION_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip() and len(value) <= 40:
            return key, " ".join(value.replace("_", " ").split())
    return None, ""


def _facts_detail(facts, limit):
    return _fit(" · ".join("%s %s" % (label, value) for label, value in facts),
                limit)


# ExitPlanMode on the wrist: the terminal's own rows, in its words and
# order (owner, 2026-10-15, #560; until then the phone's two answers, #511).
# Read from Claude Code 2.1.300's plan dialog, which sends no suggestions
# with the event, so the words are mirrored here. Its rows:
#   "Yes, clear context … and …"   a setting, off by default; it starts a new
#                                   conversation, which no hook can do
#   "Yes, and switch to BYPASS PERMISSIONS … for this session"
#                                   only when the session allows it, which a
#                                   hook cannot see; never offered from a wrist
#   "Yes, and use auto mode"        when auto mode is available, else
#   "Yes, auto-accept edits"
#   "Yes, manually approve edits"
#   "No, refine with Ultraplan …"   launches a cloud session; no hook can
#   "No, keep planning"             a text row (placeholder "Tell Claude what
#                                   to change"); the plan screen's field, sent
#                                   with PLAN_EDITS. The summary line names it
#                                   by its label, which keeps it within 80
# Each Yes is an allow that moves the session to its mode, as the dialog's
# own rows do (setMode, destination session).
PLAN_AUTO = "Yes, and use auto mode"
PLAN_ACCEPT_EDITS = "Yes, auto-accept edits"
PLAN_MANUAL = "Yes, manually approve edits"
PLAN_KEEP = "No, keep planning"
# The phone's words, on a card shown before 1.1.53 and still waiting when
# the helper updated.
PLAN_AUTO_PHONE = "Approve & auto mode"
PLAN_MODES = {PLAN_AUTO: "auto", PLAN_ACCEPT_EDITS: "acceptEdits",
              PLAN_MANUAL: "default", PLAN_AUTO_PHONE: "auto"}
PLAN_EDITS = "Suggest edits:"     # the wire prefix for dictated edits; every
                                  # watch sold sends it, so it never changes

# The words on an allow/deny card, by the agent that asked, so the wrist
# says what that agent's own prompt says. Claude's cards keep the watch's
# Allow/Deny and carry no labels at all. Codex's are the two rows of its
# approval list a hook can answer (codex-rs approval_overlay.rs, read
# 2026-10-14): a PermissionRequest hook can only allow, or deny with a
# message, which blocks the call and lets the turn go on — Codex's
# "Denied", not its "tell Codex what to do differently". The words travel
# on the card because the watch ships on Apple's schedule; a watch that
# predates them ignores them and says Allow/Deny.
AGENT_ANSWERS = {
    "codex": ("Yes, proceed", "No, continue without running it"),
}

# "Don't ask again" on an ordinary prompt, as the terminal offers it (#560,
# owner 2026-10-15). Claude Code 2.1.300 sends the prompt's
# permission_suggestions to the hook, and its dialog builds the row from
# them, filtered (J0/ho): allow rules and directories for Bash, the mode
# and directories for a file tool, a domain rule for WebFetch; only the
# localSettings and session destinations. A hook's updatedPermissions go
# through the same persistPermissions the dialog's row does, but unfiltered,
# so the filter is applied here: never a userSettings or projectSettings
# write the terminal would not have made. The labels are the terminal's,
# read off its screen on 2026-10-15:
#   "Yes, and don’t ask again for: python3 -c 'print(42)'"  (Bash, one rule;
#        the terminal shows its own guessed prefix there, "python3 *", and
#        writes that: the owner chose the exact command the suggestion
#        names, so the label says exactly what is written)
#   "Yes, and always allow access to /dir from this project"  (Bash, dirs)
#   "Yes, and switch to accept edits (auto-approve file edits and common
#        file commands) for this session"  (Write, Edit)
#   "… ; Yes, and always allow access to /a, /b for this session"
#   "Yes, and don't ask again for example.com"  (WebFetch)
# Anything this cannot validate or word gives no row: the watch then keeps
# its old "Always allow for this session", which writes nothing.
DONT_ASK_DESTINATIONS = frozenset(("localSettings", "session"))
ACCEPT_EDITS_WORDS = ("accept edits (auto-approve file edits and common "
                      "file commands)")
DONT_ASK_MAX_ITEMS = 8           # the terminal drops a row naming more
DONT_ASK_MAX_CHARS = 160         # … or one whose words run longer (Bash)
# Two copies travel (plain and marked), inside the relay's 256 KB body,
# with room to spare at three bytes a letter
# (test_the_biggest_card_still_fits_the_relays_body). Raised from 6000 on
# 2026-10-16 (owner: no plan is cut that could be carried).
PLAN_CHARS = 8000
# A wrist answer's words: up to four whole option labels, one per line,
# or a plan's dictated edits. 600 cut the fourth of four long labels, and
# a cut label is no longer one of the options (2026-10-16). The relay
# keeps the same (watch_relay.ANSWER_CHARS).
ANSWER_CHARS = 2000
# What a plan cut at PLAN_CHARS says at its end, instead of a bare " …"
# that read as the plan's own last step.
PLAN_CONTINUES = "The rest of the plan is on your computer."
# The modes Claude Code's validator accepts for setMode (2.1.280).
PERMISSION_MODES = frozenset(
    "acceptEdits auto bypassPermissions default dontAsk plan".split())


def _plan_plain(plan):
    """A plan's Markdown as lines a wrist can read: markers and emphasis
    gone, the line structure kept. Headings, bullets and numbers stay as
    words; code keeps its text without the fences."""
    lines = []
    for raw in wire.unwrap(str(plan or "").splitlines()):
        line = raw.strip()
        if line.startswith("```"):
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^[-*+]\s+", "• ", line)
        line = re.sub(r"\*\*(.+?)\*\*|__(.+?)__", lambda m: m.group(1) or m.group(2), line)
        line = re.sub(r"`([^`]*)`", r"\1", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        if line or (lines and lines[-1]):
            lines.append(line)
    return "\n".join(lines).strip()


# A plan card keeps the Markdown a watch that renders it can draw: the same
# reading tapproval_wire gives a reply in the dashboard. Headings, nesting
# and code are the plan's own.


def _plan_marked(plan):
    """A plan as the phone shows it, in what a watch can draw: a heading is
    a bold line, a nested item is indented two spaces a level, code lines
    are set apart as code, and bold stays bold (2026-10-11). A paragraph
    wrapped over several lines is one line (``_unwrap``)."""
    lines, in_fence = [], False
    for raw in wire.unwrap(str(plan or "").expandtabs(4).splitlines()):
        if wire.MD_FENCE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence:
            code = raw.strip()
            if code:
                lines.append("  " + (code if "`" in code else "`%s`" % code))
            continue
        if not raw.strip() or wire.MD_HR.match(raw) or wire.MD_TABLE_SEP.match(raw):
            if not raw.strip() and lines and lines[-1]:
                lines.append("")
            continue
        text = wire.flatten_line(raw, keep_inline=True).strip()
        if not text:
            continue
        if wire.MD_HEADING.match(raw):
            text = "**%s**" % text.replace("**", "")
            if lines and lines[-1]:
                lines.append("")   # set apart, as the phone sets it
        elif wire.MD_BULLET.match(raw) or wire.MD_NUMBER.match(raw):
            depth = (len(raw) - len(raw.lstrip(" "))) // 2
            text = "  " * min(depth, 3) + text
        lines.append(text)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


PLAN_FILE_BYTES = 256 * 1024          # a plan, not a book
TRANSCRIPT_TAIL = 2 * 1024 * 1024     # how far back to look for the plan's file


def _plans_dir(environ=None):
    environ = os.environ if environ is None else environ
    home = environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.join(home, "plans")


def _read_plan_file(path, inside=None):
    """A plan file's text, or "" when it is not one. Only a .md file is
    read, at most PLAN_FILE_BYTES; ``inside`` (when given) is the folder
    it must be in, after links are followed."""
    try:
        real = os.path.realpath(os.path.expanduser(str(path)))
        if not real.endswith(".md") or not os.path.isfile(real):
            return ""
        if inside is not None:
            root = os.path.realpath(inside)
            if os.path.commonpath([real, root]) != root:
                return ""
        with open(real, encoding="utf-8", errors="replace") as handle:
            return handle.read(PLAN_FILE_BYTES)
    except (OSError, ValueError):
        return ""


_TAIL_CACHE = {}


def _transcript_tail(transcript_path):
    """The last TRANSCRIPT_TAIL bytes of a transcript, as text, or "" when
    it cannot be read. A plan prompt asks twice (its file, auto mode): the
    one most recent tail is kept, keyed by the file's size and time, so an
    unchanged transcript is read once."""
    try:
        info = os.stat(transcript_path)
        key = (transcript_path, info.st_size, info.st_mtime_ns)
        if key in _TAIL_CACHE:
            return _TAIL_CACHE[key]
        with open(transcript_path, "rb") as handle:
            handle.seek(max(0, info.st_size - TRANSCRIPT_TAIL))
            text = handle.read(TRANSCRIPT_TAIL).decode("utf-8", "replace")
    except (OSError, TypeError, ValueError):
        return ""
    _TAIL_CACHE.clear()
    _TAIL_CACHE[key] = text
    return text


def _json_object(line):
    """One transcript or audit line as a dict, or None: not JSON, or JSON
    that is not an object (callers .get() on what comes back)."""
    try:
        entry = json.loads(line)
    except ValueError:
        return None
    return entry if isinstance(entry, dict) else None


def _transcript_plan_path(transcript_path):
    """The newest plan file the session's transcript names. Claude Code
    records it as ``attachment.planFilePath`` while plan mode is on."""
    for line in reversed(_transcript_tail(transcript_path).splitlines()):
        if '"planFilePath"' not in line:
            continue
        entry = _json_object(line)
        found = (entry.get("attachment") or {}).get("planFilePath") if entry else None
        if found:
            return str(found)
    return ""


def plan_text(tool_input, event=None, plans_dir=None):
    """The plan an ExitPlanMode call is asking about. Claude Code used to
    pass it as ``tool_input["plan"]``; since about 2026-10 the call comes
    with an empty input and the plan sits in a file, named by
    ``planFilePath`` or by the transcript (2026-10-13: every plan on the
    wrist read "Claude has a plan", with nothing to read). A path the call
    itself names must be inside the plans folder, because the model writes
    the call; the transcript's is written by Claude Code. "" when none is
    found — the card then says so, and still waits for the human."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_input.get("plan"):
        return str(tool_input["plan"])
    folder = plans_dir or _plans_dir()
    named = tool_input.get("planFilePath")
    if named:
        text = _read_plan_file(named, inside=folder)
        if text.strip():
            return text
    transcript = (event or {}).get("transcript_path")
    if transcript:
        found = _transcript_plan_path(transcript)
        if found:
            return _read_plan_file(found)
    return ""


def plan_options(auto_mode=False):
    """The terminal's Yes rows for a plan: the auto row where auto mode is
    available, the accept-edits row where it is not, then manual."""
    return [PLAN_AUTO if auto_mode else PLAN_ACCEPT_EDITS, PLAN_MANUAL]


def auto_mode_seen(event):
    """Whether this session can use auto mode, on positive evidence only.

    The terminal decides it from state no hook can read, so two things it
    leaves behind stand in: the transcript records ``permissionMode`` on
    each prompt (a session that has been in auto mode has it), and user
    settings may make auto the default. Without either, the plan card
    offers "Yes, auto-accept edits", which works wherever the dialog does."""
    try:
        with open(_settings_path(), encoding="utf-8") as handle:
            settings = json.load(handle)
        if ((settings.get("permissions") or {}).get("defaultMode")) == "auto":
            return True
    except (OSError, ValueError, AttributeError):
        pass
    transcript = (event or {}).get("transcript_path")
    if not transcript:
        return False
    for line in _transcript_tail(transcript).splitlines():
        if '"permissionMode"' not in line:
            continue
        entry = _json_object(line)
        if entry and entry.get("permissionMode") == "auto":
            return True
    return False


def _plan_card(tool_input, risk, headline_chars, detail_chars, auto_mode=False):
    # Redacted before anything is read from it: the plan travels whole,
    # line breaks and all, so it cannot rely on _fit to do this for it.
    plan = redact_secrets(str(tool_input.get("plan") or ""))
    title = ""
    for raw in plan.splitlines():
        if raw.strip():
            title = _plan_title(raw)
            break
    room = TEXT_CHARS - len("Plan: ")
    options = plan_options(auto_mode)
    return {
        "kind": "question",
        "plan_card": True,
        "tier": risk.name,
        "headline": _fit("Plan: %s" % title if title else "Claude has a plan",
                         TEXT_CHARS),
        "detail": _fit(" · ".join(options + [PLAN_KEEP]), detail_chars),
        "options": options,
        # Plain, for every watch already sold: one that predates
        # plan_marked would show its asterisks.
        "plan": _plan_fit(_plan_body(_plan_plain(plan), title, room)),
        "plan_marked": _plan_fit(_plan_body(_plan_marked(plan), title, room),
                                 marks=True),
    }


def _plan_title(line):
    """A plan's first line as the card's headline names it. A plan titled
    "Plan: …" read "Plan: Plan: …" on the wrist (#560's end-to-end check,
    2026-10-15)."""
    title = _plan_plain(line).lstrip("• ").strip()
    return re.sub(r"^plan:\s*", "", title, flags=re.IGNORECASE)


def _plan_body(text, title, room):
    """The plan without its title, which is already the card's headline:
    shown twice, one under the other, it read as a fault. A first line too
    long for the headline stays, or its end would be lost."""
    lines = text.splitlines()
    if (lines and title and len(title) <= room
            and _plan_title(lines[0]) == title):
        lines = lines[1:]
    return "\n".join(lines).strip()


def _plan_fit(text, limit=PLAN_CHARS, marks=False):
    """Cap a plan for the wrist without flattening it: its line breaks are
    its structure, which _fit (one line, whitespace collapsed) would lose.
    With ``marks``, never end inside a pair: an open ** would turn the
    rest of a rendered plan bold."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    cut = cut[:max(cut.rfind("\n"), cut.rfind(" "), limit // 2)].rstrip()
    if marks:
        for mark in ("**", "~~", "`"):
            while cut.count(mark) % 2:
                cut = cut[:cut.rfind(mark)].rstrip()
    return cut + "\n\n" + PLAN_CONTINUES


def plan_decision(chosen, options=None):
    """What a wrist answer to a plan card means for the hook:
    (behavior, message, mode).

    With ``options`` (the card's own rows), a Yes the card did not offer
    is no answer at all — behavior None, and the terminal asks: a card
    that offered "auto-accept edits" must not be answered into auto mode
    (2026-10-16 review, S13). The phone's old "Approve & auto mode" counts
    as the auto row it was."""
    said = " ".join(str(chosen or "").split())
    if said in PLAN_MODES:
        if options is not None:
            offered = {" ".join(str(o).split()) for o in options}
            if PLAN_AUTO in offered:
                offered.add(PLAN_AUTO_PHONE)
            if said not in offered:
                return None, "", None
        return "allow", "", PLAN_MODES[said]
    edits = said[len(PLAN_EDITS):].strip() if said.startswith(PLAN_EDITS) else said
    return ("deny", "The user asks for changes to the plan, from their "
            "watch: %s. Revise the plan and present it again." % edits, None)


# Integration calls that recur on the wrist, in words (the Wrist cards
# design, 2026-10-02): (server or "*", tool, action or "*") → headline.
# Servers match case-insensitively and by suffix, so a renamed or prefixed
# server ("Claude_Code_iOS_Simulator") still finds its phrase.
MCP_PHRASES = {
    ("ccd_pr", "get_status", "*"): "Check PR status",
    ("github", "push_files", "*"): "Push files to GitHub",
    ("github", "create_pull_request", "*"): "Open a pull request on GitHub",
    ("ios_simulator", "control", "launch"): "Launch the app in Simulator",
    ("ios_simulator", "control", "open_url"): "Open a link in Simulator",
    ("ios_simulator", "control", "screenshot"): "Take a Simulator screenshot",
    ("ios_simulator", "control", "tap"): "Tap in Simulator",
    ("ios_simulator", "control", "swipe"): "Swipe in Simulator",
    ("ios_simulator", "control", "text"): "Type in Simulator",
    ("ios_simulator", "control", "attach"): "Show Simulator",
    ("*", "search_threads", "*"): "Search mail",
}
_SERVER_IS_AN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _mcp_headline(tool, action):
    """What an ``mcp__<server>__<tool>`` call does, in words: a phrase for
    the calls that recur, else the tool's own words in sentence case with a
    readable server after them ("Merge pull request · github"). A server
    named by an id is left out — it would only be noise on a wrist."""
    server, sep, name = tool[len("mcp__"):].rpartition("__")
    if not sep:
        server, name = "", tool[len("mcp__"):]
    words = " ".join(name.replace("_", " ").split())
    action_raw = "_".join(str(action or "").split())
    low = server.lower()
    for (srv, verb, act), phrase in MCP_PHRASES.items():
        if verb != name.lower():
            continue
        if srv != "*" and not low.endswith(srv):
            continue
        if act not in ("*", action_raw.lower()):
            continue
        return phrase
    pieces = [words[:1].upper() + words[1:]] if words else ["Integration call"]
    if action:
        pieces.append(action)
    if server and not _SERVER_IS_AN_ID.match(server):
        pieces.append(" ".join(server.replace("_", " ").replace("-", " ").split()))
    return " · ".join(pieces)


def _questions(tool_input):
    """AskUserQuestion's questions, each as (text, option labels, whether
    several may be chosen). Labels are flattened to one line, which is
    what lets a multi-select answer carry one label per line."""
    questions = (tool_input or {}).get("questions") if isinstance(tool_input, dict) else None
    found = []
    for entry in (questions if isinstance(questions, list) else [])[:4]:
        if not isinstance(entry, dict):
            continue
        found.append((str(entry.get("question", "")), [
            " ".join(str(o.get("label", "")).split())
            for o in (entry.get("options") or [])
            if isinstance(o, dict) and o.get("label")
        ][:4], entry.get("multiSelect") is True))
    return found or [("", [], False)]


def _question_parts(tool_input):
    """Each question's heading and its options' explanations, in step with
    _questions (same questions, same options, same order). Both were
    dropped until 2026-10-16, so the wrist offered bare names where the
    terminal says what each one means."""
    questions = (tool_input or {}).get("questions") if isinstance(tool_input, dict) else None
    found = []
    for entry in (questions if isinstance(questions, list) else [])[:4]:
        if not isinstance(entry, dict):
            continue
        found.append((str(entry.get("header") or ""), [
            str(o.get("description") or "")
            for o in (entry.get("options") or [])
            if isinstance(o, dict) and o.get("label")
        ][:4]))
    return found


def questions_need_typing(tool_input):
    """Whether an AskUserQuestion call holds a question the wrist cannot
    answer: one without options to choose from. Claude Code 2.1.300's
    extended form (behind a feature flag) asks questions of kind "text"
    or "number", which carry none; malformed input carries none either.
    The wrist only chooses, and an Allow on such a card went back with no
    answers, which Claude Code drops (2026-10-15)."""
    return any(not options for _, options, _multi in _questions(tool_input))


def question_cards(card, tool_input, headline_chars=HEADLINE_CHARS,
                   detail_chars=DETAIL_CHARS):
    """One card per question of an AskUserQuestion call, in order.

    Each is ``card`` — the call's card, fingerprint and session included,
    so the relay can still withdraw it when the terminal answers — with
    that question's words and labels. With more than one question the
    headline says which ("1 of 2 · …"): until 2026-10-15 only the first
    reached the wrist, and Claude took its one label for every answer.
    A question that allows several answers says so (``multi_select``);
    a watch older than that field taps one, which is still an answer.
    """
    found = _questions(tool_input)
    parts = _question_parts(tool_input)
    cards = []
    for index, (question, options, multi) in enumerate(found):
        question = _fit_lines(question, TEXT_CHARS) or "Claude has a question"
        if len(found) > 1:
            question = "%d of %d · %s" % (index + 1, len(found), question)
        one = dict(card, kind="question",
                   headline=_fit_lines(question, TEXT_CHARS),
                   detail=_fit(" · ".join(options), detail_chars))
        for key in ("options", "multi_select", "question_header", "option_details"):
            one.pop(key, None)
        header, details = parts[index] if index < len(parts) else ("", [])
        if _fit(header, TEXT_CHARS):
            one["question_header"] = _fit(header, TEXT_CHARS)
        if options:
            one["options"] = options
            if multi:
                one["multi_select"] = True
            details = [_fit_lines(d, TEXT_CHARS) for d in details]
            if any(details) and len(details) == len(options):
                one["option_details"] = details
        cards.append(one)
    return cards


def wrist_card(tool, tool_input, risk,
               headline_chars=HEADLINE_CHARS, detail_chars=DETAIL_CHARS,
               auto_mode=False):
    """Build the compact card a watch face can render in one glance.
    ``auto_mode``: whether a plan's session can use auto mode
    (auto_mode_seen), which picks the plan's first row."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}

    if tool == "ExitPlanMode":
        return _plan_card(tool_input, risk, headline_chars, detail_chars,
                          auto_mode=auto_mode)

    if tool == "AskUserQuestion":
        # The first question's card; ask_questions sends the rest in turn.
        return question_cards({"kind": "question", "tier": risk.name},
                              tool_input, headline_chars, detail_chars)[0]

    if tool in ("Bash", "BashOutput"):
        command = tool_input.get("command", "")
        # Claude describes its own tool calls, and that description is what
        # the phone app shows ("Check mergeability of every open PR"). Use
        # the same words on the wrist; the command itself is the detail.
        described = " ".join(str(tool_input.get("description") or "").split())
        headline = (_fit(described, TEXT_CHARS) if described
                    else _bash_headline(command, headline_chars))
        detail = _fit_lines(command, detail_chars)
    elif tool == "apply_patch":
        # Codex's file edit: the same card a Write or Edit gets.
        files = patch_files(tool_input.get("command", ""))
        names = [os.path.basename(str(path).rstrip("/\\")) or path
                 for _verb, path in files]
        if len(names) == 1:
            verb = {"Add": "Write", "Delete": "Delete"}.get(files[0][0], "Edit")
            headline = _fit("%s %s" % (verb, names[0]), headline_chars)
            detail = _fit("%s %s" % (verb, files[0][1]), detail_chars)
        else:
            headline = _fit("Edit %d files" % len(names) if names
                            else "Apply a patch", headline_chars)
            detail = _fit(", ".join(names), detail_chars)
    elif tool in WRITE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        verb = "Write" if tool == "Write" else "Edit"
        headline = _fit(
            "%s %s" % (verb, os.path.basename(str(path).rstrip("/\\")) or path),
            headline_chars,
        )
        detail = _fit("%s %s" % (verb, path), detail_chars)
    else:
        # A tool the builder does not know, or an MCP call: say what it
        # does and where it lands, in words. The tool name gives the
        # "who"; an action argument ("method": "finalize_plan") gives
        # the verb; the target fields become two or three facts. The
        # detail is those same facts as one line, for the audit log and
        # a wrist app older than this field.
        action_key, action = _action_from_input(tool_input)
        if tool.startswith("mcp__"):
            headline = _fit(_mcp_headline(tool, action), headline_chars)
        else:
            pieces = [tool or "Unknown tool"] + [p for p in (action,) if p]
            headline = _fit(" · ".join(pieces), headline_chars)
        facts = card_facts(tool_input, skip=(action_key,) if action_key else ())
        detail = _facts_detail(facts, detail_chars)
        return {"tier": risk.name, "headline": headline, "detail": detail,
                "facts": facts}

    return {"tier": risk.name, "headline": headline, "detail": detail}


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


def load_policy(env=None):
    """Merge the default policy with an optional JSON file and env overrides."""
    env = os.environ if env is None else env
    policy = dict(DEFAULT_POLICY)

    config_path = env.get("CLAUDE_RISK_CONFIG")
    if config_path:
        try:
            with open(os.path.expanduser(config_path), "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                policy.update(loaded)
        except (OSError, ValueError) as error:
            print("ClaudeRiskClassifier: bad config %s (%s)" % (config_path, error),
                  file=sys.stderr)

    if env.get("CLAUDE_RISK_MODE"):
        policy["mode"] = env["CLAUDE_RISK_MODE"]
    if env.get("CLAUDE_RISK_AUDIT_LOG"):
        policy["audit_log"] = env["CLAUDE_RISK_AUDIT_LOG"]
    if env.get("CLAUDE_RISK_RELAY"):
        policy["relay"] = env["CLAUDE_RISK_RELAY"]
    if env.get("CLAUDE_RISK_AUTO_ALLOW"):
        policy["auto_allow_at_or_below"] = env["CLAUDE_RISK_AUTO_ALLOW"]
    if env.get("CLAUDE_RISK_AUTH_FILE"):
        policy["auth_file"] = env["CLAUDE_RISK_AUTH_FILE"]
    if env.get("CLAUDE_RISK_RELAY_WAIT"):
        try:
            policy["relay_wait"] = float(env["CLAUDE_RISK_RELAY_WAIT"])
        except ValueError:
            pass
    configure_site_rules(policy)
    return policy


def decide(risk, policy):
    """Map a risk tier to a decision. Returns ``(decision, reason)``.

    With the default "NONE" threshold nothing is auto-allowed: the tiers
    are a label on the card, not a verdict, so a command the classifier
    has never seen can never be waved through by accident.
    """
    setting = str(policy.get("auto_allow_at_or_below", "NONE")).upper()
    try:
        threshold = Risk[setting]
    except KeyError:
        # "NONE", "OFF" and anything unreadable all mean the same thing:
        # nothing is auto-allowed. A setting we cannot parse must fail
        # closed, never fall back to a permissive tier.
        threshold = None

    if risk >= Risk.CRITICAL:
        if str(policy.get("critical_action", "escalate")).lower() == "deny":
            return "deny", "Blocked: classified CRITICAL"
        return "escalate", "CRITICAL — needs a human"
    if threshold is not None and risk <= threshold:
        return "allow", "Auto-allowed: %s at or below %s" % (risk.name, threshold.name)
    return "escalate", "%s — needs a human" % risk.name


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------


def _audit_path(policy):
    return os.path.expanduser(str(policy.get("audit_log") or DEFAULT_POLICY["audit_log"]))


AUDIT_MAX_BYTES = 20 * 1024 * 1024      # about a year of ordinary use


def _roll_audit(path, limit=AUDIT_MAX_BYTES):
    """Move an oversized audit log aside rather than trimming it.

    The relay's own log gets truncated because it is diagnostics. This one
    is the user's record of what was decided on their behalf, and the README
    promises they can read it — so it is rotated, never cut. One previous
    generation is kept; anything older than that is theirs to archive if
    they want it.
    """
    try:
        if os.path.getsize(path) < limit:
            return False
        os.replace(path, path + ".1")
        return True
    except OSError:
        return False


def write_audit(entry, policy):
    """Append one decision to the audit trail. Never raises."""
    path = _audit_path(policy)
    _roll_audit(path)
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # The log records the command text a decision was made about, so it
        # is as sensitive as the commands themselves. Create it readable by
        # its owner only; on a shared machine the default umask is not.
        if not os.path.exists(path):
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as error:
        print("ClaudeRiskClassifier: cannot write audit log (%s)" % error, file=sys.stderr)


def read_audit(policy):
    """Read the audit trail, skipping unparseable lines."""
    path = _audit_path(policy)
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                entry = _json_object(line) if line.strip() else None
                if entry is not None:
                    entries.append(entry)
    except OSError:
        return []
    return entries


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


def repository_root(cwd):
    """The folder of the repository a working directory belongs to, or None.

    Walks up to the nearest `.git`: a folder is the repository itself, a
    worktree's file points into `<repo>/.git/worktrees/`. The home folder
    is never taken for a repository (a dotfiles checkout would claim every
    project). A few stat calls, no subprocess, never raises.
    """
    if not cwd:
        return None
    path = str(cwd).replace("\\", "/").rstrip("/")
    try:
        home = os.path.realpath(os.path.expanduser("~"))
        here = path
        for _ in range(12):
            if not here or here == "/" or os.path.realpath(here) == home:
                break
            marker = os.path.join(here, ".git")
            if os.path.isdir(marker):
                return here
            if os.path.isfile(marker):
                with open(marker, encoding="utf-8", errors="replace") as handle:
                    line = handle.readline().strip()
                gitdir = line[len("gitdir:"):].strip() if line.startswith("gitdir:") else ""
                if gitdir and not os.path.isabs(gitdir):
                    gitdir = os.path.normpath(os.path.join(here, gitdir))
                if "/.git/worktrees/" in gitdir:
                    return gitdir.split("/.git/worktrees/", 1)[0] or here
                return here
            parent = os.path.dirname(here)
            if parent == here:
                break
            here = parent
    except (OSError, ValueError):
        pass
    return None


def repository_name(cwd):
    """The name of the repository a working directory belongs to.

    The folder Claude works in is often a worktree with a name nobody chose
    ("cranky-shannon-3187c0", "wt-push") or a subfolder ("ios"); on 74% of
    287 prompts the wrist named that while the phone named the repository
    (2026-10-02). The repository_root's name; with no repository, the
    folder's own name stands. Only a name, never a path.
    """
    if not cwd:
        return None
    folder = os.path.basename(str(cwd).replace("\\", "/").rstrip("/")) or None
    root = repository_root(cwd)
    return (os.path.basename(root) if root else None) or folder


def _card_fingerprint(tool, tool_input):
    """Stable identity of the actual request, never of its display text.

    "Always allow for this session" replays on this key, so it must name
    the command itself — headlines are Claude's own free prose and two
    different commands can share one.
    """
    # Bash only: BashOutput's input is {"bash_id": …} with no command, and
    # hashing a missing key would give every BashOutput in a session one
    # shared fingerprint — one "always" tap would cover them all.
    if isinstance(tool_input, dict) and tool == "Bash":
        basis = str(tool_input.get("command", ""))
    else:
        basis = json.dumps(tool_input if isinstance(tool_input, dict) else {},
                           sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(
        ("%s\x00%s" % (tool, basis)).encode("utf-8")).hexdigest()[:16]


def _input_digests(tool, tool_input):
    """One short hash per top-level input key: how the relay recognises
    this call in the transcript when the whole-input fingerprint cannot.

    Claude Code hands the hook more than it writes down. On 2026-09-17 a
    DesignSync prompt reached the hook carrying consent fields that its
    transcript entry does not have, so the fingerprints never matched: the
    prompt was answered on the phone at 08:24 and both cards were still on
    the wrist four hours later. Per-key digests let the relay ask the
    looser question — does every key the transcript DID record agree? —
    while the fingerprint stays exact for "always allow" replay.
    """
    if not isinstance(tool_input, dict):
        return {}
    digests = {}
    for key in sorted(tool_input)[:32]:
        basis = json.dumps(tool_input[key], sort_keys=True, ensure_ascii=False)
        digests[str(key)[:64]] = hashlib.sha256(
            ("%s\x00%s\x00%s" % (tool, key, basis)).encode("utf-8")).hexdigest()[:16]
    return digests


def build_response(event, policy, agent=None):
    """Classify one event; returns ``(response_dict, audit_entry, card)``.

    The card returned here is the one the relay shows: run_hook must not
    rebuild it, or the audit log and the wrist could silently disagree.
    """
    result = classify(event)
    risk = result["risk"]
    shown = result["tool_input"]
    if result["tool"] == "ExitPlanMode" and isinstance(shown, dict) and not shown.get("plan"):
        # The card shows the plan; the fingerprint below keeps the call's
        # own input, which is what the relay matches a desk answer by.
        shown = dict(shown, plan=plan_text(shown, event))
    if (agent == "codex" and result["tool"] == "Bash"
            and isinstance(shown, dict) and shown.get("description")):
        # Codex's description is the question it puts to the person ("Do
        # you want to allow …?"), not Claude's short imperative, so the
        # card is headed by the command, as a Claude call without one is.
        shown = {k: v for k, v in shown.items() if k != "description"}
    card = wrist_card(
        result["tool"],
        shown,
        risk,
        *_card_budgets(policy),
        auto_mode=(result["tool"] == "ExitPlanMode" and auto_mode_seen(event)),
    )
    card["tool"] = result["tool"]
    card["session_id"] = str((event or {}).get("session_id") or "")[:64]
    card["fingerprint"] = _card_fingerprint(result["tool"],
                                            result["tool_input"])
    card["input_digests"] = _input_digests(result["tool"],
                                           result["tool_input"])
    # The phone offers "don't ask again" exactly when Claude Code sends
    # permission suggestions with the prompt — mirror that, so the wrist
    # never offers a third choice the phone doesn't have.
    card["can_always"] = bool((event or {}).get("permission_suggestions"))
    # Which agent asked, for a session list that holds both. Only a second
    # agent is named: a Claude card stays byte-for-byte what it was.
    if agent and agent != "claude":
        card["agent"] = agent
    if agent in AGENT_ANSWERS and not card.get("kind"):
        card["allow_label"], card["deny_label"] = AGENT_ANSWERS[agent]
    # The terminal's "don't ask again", in its words, for a watch that
    # shows them; one that predates the label keeps "Always allow for
    # this session", which writes nothing. Never on CRITICAL, as the
    # watch has never offered a third button there.
    if (card.get("can_always") and not card.get("kind") and agent in (None, "claude")
            and risk != Risk.CRITICAL):
        row = dont_ask_row(event)
        if row:
            card["always_label"] = row[0]
    decision, reason = decide(risk, policy)

    shadow = str(policy.get("mode", "shadow")).lower() != "enforce"
    effective = "escalate" if shadow else decision

    audit = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": (event or {}).get("session_id"),
        # A name, not the full path: enough to break a report down per
        # project, without writing directory structure into a log that
        # gets read aloud.
        "project": repository_name((event or {}).get("cwd")),
        "tool_use_id": (event or {}).get("tool_use_id"),
        "tool": result["tool"],
        "tier": risk.name,
        "rules": result["rules"],
        "decision": decision,
        "effective": effective,
        "mode": "shadow" if shadow else "enforce",
        "headline": card["headline"],
        "detail": card["detail"],
    }

    response = {"hookSpecificOutput": _permission_output(
        effective, "[%s] %s" % (risk.name, reason))}
    return response, audit, card


def _relay_wait(policy):
    """The policy's relay_wait in seconds, 6.0 when unset or unreadable."""
    try:
        return float(policy.get("relay_wait", 6.0))
    except (TypeError, ValueError):
        return 6.0


def _relay_key(policy):
    """The bootstrap out of the relay's key file, or "" when there is none
    to read: no key, no card (the relay refuses an unsigned one)."""
    return wire.read_bootstrap(os.path.expanduser(str(policy.get("auth_file") or AUTH_FILE)))


# The hook always signs v2, the query included even when empty: the
# relay's own rule (tapproval_wire), not a copy of it.
def _relay_signature(key, method, path, stamp, nonce, body, query=""):
    return wire.sign_request(key, method, path, stamp, nonce, body, query=query)


_relay_proof2 = wire.relay_proof2


def ask_watch(card, policy, project=None):
    """Offer an escalated card to the watch relay. Returns the verdict.

    "allow" and "deny" are a human's answer arriving from the watch — this
    is not auto-allowing, so it applies to any tier, CRITICAL included.
    Everything else — relay down, timeout, malformed reply, unexpected
    decision string, no key file, an answer without the relay's proof —
    collapses to "none" and the normal prompt appears. Never raises.
    """
    import hmac
    import time
    import urllib.error
    import urllib.parse
    import urllib.request
    import uuid

    relay = str(policy.get("relay") or "").strip().rstrip("/")
    if not relay.startswith(("http://", "https://")):
        return "none", None
    key = _relay_key(policy)
    if not key:
        print("ClaudeRiskClassifier: no relay key file, so no card",
              file=sys.stderr)
        return "none", None
    wait = max(0.0, min(_relay_wait(policy), float(RELAY_WAIT_SECONDS)))

    payload = dict(card)
    if project:
        payload["project"] = project
    # UTF-8, not \u escapes: a plan in Danish or Japanese would otherwise
    # cost six bytes a letter against the relay's 256 KB body.
    body = json.dumps({"card": payload, "wait": wait},
                      ensure_ascii=False).encode("utf-8")
    url = relay + "/card"
    stamp, nonce = int(time.time()), uuid.uuid4().hex
    mac = _relay_signature(key, "POST", urllib.parse.unquote(
        urllib.parse.urlsplit(url).path), stamp, nonce, body)
    request = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "X-Tapproval-Signature": wire.signature_header(stamp, nonce, mac)})
    try:
        with urllib.request.urlopen(request, timeout=wait + 3.0) as reply:
            raw = reply.read()
            status = reply.status
            proof = reply.headers.get("X-Tapproval-Proof2") or ""
        answer = json.loads(raw.decode("utf-8"))
    except Exception as error:
        print("ClaudeRiskClassifier: watch relay unavailable (%s)" % error,
              file=sys.stderr)
        return "none", None
    if not hmac.compare_digest(proof, _relay_proof2(key, nonce, status, raw)):
        # Something answered on the relay's port without the relay's key.
        print("ClaudeRiskClassifier: the answer did not prove the relay's "
              "key, so the terminal asks", file=sys.stderr)
        return "none", None
    if not isinstance(answer, dict):
        return "none", None
    decision = answer.get("decision")
    if decision == "answer" and answer.get("answer"):
        return "answer", str(answer["answer"])[:ANSWER_CHARS]
    if decision == "allow" and answer.get("dont_ask") is True:
        # The terminal's "don't ask again", tapped on a watch that showed
        # its words (card["always_label"]).
        return "dont_ask", None
    return (decision if decision in ("allow", "deny") else "none"), None


def ask_questions(card, tool_input, policy, project=None, ask=None):
    """Ask every question of an AskUserQuestion call on the wrist, in turn.

    Returns ``("answer", {question text: label})`` once every card has an
    answer — the shape the terminal hands the tool (2.1.300's input schema
    ``answers``). A deny on any card denies the call. Anything else — a card
    timed out, withdrawn because the terminal answered, the relay gone —
    is ``("none", None)``: half an answer is not an answer, so the terminal
    asks them all. The cards share the one wait the hook was given. A call
    holding a question the wrist cannot answer (questions_need_typing)
    sends no card at all.
    """
    import time

    if questions_need_typing(tool_input):
        return "none", None
    ask = ask or ask_watch
    wait = _relay_wait(policy)
    deadline = time.monotonic() + wait
    answers = {}
    questions = _questions(tool_input)
    for index, one in enumerate(question_cards(card, tool_input)):
        left = wait if index == 0 else deadline - time.monotonic()
        if left <= 0:
            return "none", None
        verdict, chosen = ask(one, dict(policy, relay_wait=left), project=project)
        if verdict == "deny":
            return "deny", None
        # An Allow is not an answer: it goes back with no answers, and
        # Claude Code drops an allow without them for this tool.
        if verdict != "answer" or not chosen:
            return "none", None
        text, options, multi = questions[index]
        answers[text] = _chosen_labels(chosen, options) if multi else chosen
    return "answer", answers


def _chosen_labels(chosen, options):
    """A multi-select card's answer: the watch sends every label it picked,
    one per line. As a list when each is one of the card's options — the
    shape 2.1.300's dialog hands the tool for a multiSelect question.
    Otherwise the words as they came: nothing is guessed, and Claude Code
    tells Claude to read an answer that is not an option."""
    picked = chosen.split("\n")
    return picked if all(label in options for label in picked) else chosen


def _answers_in_words(answers):
    """The terminal's own rendering of answers ("Q"="A", …), for a channel
    that carries only words. Several labels read "A, B", as there."""
    return ", ".join('"%s"="%s"' % (question, ", ".join(answer)
                                    if isinstance(answer, list) else answer)
                     for question, answer in answers.items())


def _and_list(items):
    """The terminal's list: "a", "a and b", "a, b, and c"."""
    items = list(items)
    if len(items) <= 2:
        return " and ".join(items)
    return ", ".join(items[:-1]) + ", and " + items[-1]


def _valid_update(update):
    """One permission update in the shape the CLI's validator accepts, and
    of a kind the terminal's own "don't ask again" row would apply."""
    if not isinstance(update, dict):
        return False
    kind, where = update.get("type"), update.get("destination")
    if where not in DONT_ASK_DESTINATIONS:
        return False
    if kind == "addRules":
        rules = update.get("rules")
        return (update.get("behavior") == "allow" and isinstance(rules, list)
                and bool(rules) and all(
                    isinstance(r, dict) and isinstance(r.get("toolName"), str)
                    and r["toolName"] and isinstance(r.get("ruleContent", ""), str)
                    and set(r) <= {"toolName", "ruleContent"} for r in rules)
                and set(update) == {"type", "rules", "behavior", "destination"})
    if kind == "addDirectories":
        dirs = update.get("directories")
        return (isinstance(dirs, list) and bool(dirs)
                and all(isinstance(d, str) and d for d in dirs)
                and set(update) == {"type", "directories", "destination"})
    if kind == "setMode":
        return (update.get("mode") == "acceptEdits" and where == "session"
                and set(update) == {"type", "mode", "destination"})
    return False


def dont_ask_row(event):
    """The terminal's "don't ask again" row for this prompt, as
    ``(label, updates)``, or None when it offers none this hook can give.

    Built only from the event's own ``permission_suggestions``: nothing is
    invented, and anything not understood gives no row (fail closed)."""
    event = event or {}
    tool = str(event.get("tool_name") or "")
    raw = event.get("permission_suggestions")
    if not isinstance(raw, list) or not raw:
        return None
    if tool == "Bash":
        kept = [u for u in raw if isinstance(u, dict)
                and u.get("type") in ("addRules", "addDirectories")
                and _valid_update(u)]
        rules = [r for u in kept if u["type"] == "addRules" for r in u["rules"]]
        if any(r["toolName"] != "Bash" or not r.get("ruleContent") for r in rules):
            return None
        dirs = [d for u in kept if u["type"] == "addDirectories" for d in u["directories"]]
        commands = [r["ruleContent"] for r in rules]
        if not kept or len(commands) + len(dirs) > DONT_ASK_MAX_ITEMS:
            return None
        if commands and not dirs:
            label = ("Yes, and don\u2019t ask again for: %s" % commands[0]
                     if len(commands) == 1 else
                     "Yes, and don't ask again for %s commands in %s"
                     % (_and_list(commands), event.get("cwd") or "this folder"))
        elif dirs and not commands:
            label = ("Yes, and always allow access to %s from this project"
                     % _and_list(dirs))
        elif len(dirs) == 1 and len(commands) == 1:
            label = ("Yes, and allow access to %s and %s commands"
                     % (dirs[0], commands[0]))
        else:
            label = ("Yes, and allow %s access and %s commands"
                     % (_and_list(dirs), _and_list(commands)))
        if len(label) > DONT_ASK_MAX_CHARS:
            return None
        return label, kept
    if tool in WRITE_TOOLS:
        if not all(_valid_update(u) and u["type"] in ("setMode", "addDirectories")
                   and u["destination"] == "session" for u in raw):
            return None
        parts = []
        if any(u["type"] == "setMode" for u in raw):
            parts.append("Yes, and switch to %s for this session" % ACCEPT_EDITS_WORDS)
        dirs = [d for u in raw if u["type"] == "addDirectories" for d in u["directories"]]
        if dirs:
            parts.append("Yes, and always allow access to %s for this session"
                         % ", ".join(dirs))
        if not parts or len(dirs) > DONT_ASK_MAX_ITEMS:
            return None
        return "; ".join(parts), list(raw)
    if tool == "WebFetch":
        if len(raw) != 1 or not _valid_update(raw[0]) or raw[0]["type"] != "addRules":
            return None
        rules = raw[0]["rules"]
        content = rules[0].get("ruleContent", "") if len(rules) == 1 else ""
        if (rules[0]["toolName"] != "WebFetch" or not content.startswith("domain:")
                or "*" in content or len(content) <= len("domain:")):
            return None
        return "Yes, and don't ask again for %s" % content[len("domain:"):], list(raw)
    return None


def _permission_output(behavior, message="", mode=None, updated_input=None,
                       updated_permissions=None):
    """The hookSpecificOutput block Claude Code will actually accept.

    The shape is checked, and the CLI's own validator spells it out:
    the decision must be ``{"behavior": "allow"}`` or
    ``{"behavior": "deny", "message": "..."}``. A bare string — which
    this hook emitted until 1.1.1 — fails that check, and a failed hook
    is NON-BLOCKING: the permission flow proceeds exactly as if nothing
    had answered it. That is how a wrist approval could disappear while
    the audit log recorded a perfectly good "allow", for every card, on
    every machine, silently.

    Escalation carries no decision at all. Saying nothing is what leaves
    the question with the human, and it is also what this degrades to if
    the shape is ever tightened again — fail closed by construction, not
    by a branch that has to be remembered.
    """
    output = {"hookEventName": "PermissionRequest"}
    if behavior == "allow":
        output["decision"] = {"behavior": "allow"}
        # An allow that ends a dialog must say what it allows. For a tool
        # the CLI marks as needing the user — ExitPlanMode — it drops a
        # hook's allow without updatedInput and keeps its dialog open
        # (2.1.300, runHooks: `if(!L.updatedInput&&e.requiresUserInteraction
        # ?.())return null`). No error, no log: every wrist approval of a
        # plan was dropped that way until #560 (2026-10-15).
        if isinstance(updated_input, dict):
            output["decision"]["updatedInput"] = updated_input
        # An allow may also move the session to another permission mode —
        # how each Yes on a plan works. The CLI's validator
        # (2.1.280) accepts updatedPermissions entries of type setMode with
        # a known mode and a destination; "session" touches no settings
        # file. Only modes the validator knows are ever sent.
        updates = []
        if mode in PERMISSION_MODES:
            updates.append({"type": "setMode", "mode": mode, "destination": "session"})
        # "Don't ask again": the terminal row's own updates (dont_ask_row).
        # Checked again here, at the one place a decision is built, so an
        # update the CLI's validator or its dialog would refuse is never
        # sent — a shape it rejects makes the whole answer vanish.
        if isinstance(updated_permissions, list) and all(
                _valid_update(u) for u in updated_permissions):
            updates.extend(updated_permissions)
        if updates:
            output["decision"]["updatedPermissions"] = updates
    elif behavior == "deny":
        output["decision"] = {"behavior": "deny", "message": message}
    return output


# Built by the one function allowed to build it, so the shape whose
# breakage was invisible for months has exactly one constructor.
ESCALATE_FALLBACK = {"hookSpecificOutput": _permission_output("escalate")}


def _user_permission_rules(cwd=None):
    """The user's own permissions rules, user + project scope.

    Returns ``{"allow": [...], "deny": [...], "ask": [...]}``.
    """
    paths = [_settings_path()]
    if cwd:
        paths += [os.path.join(str(cwd), ".claude", "settings.json"),
                  os.path.join(str(cwd), ".claude", "settings.local.json")]
    rules = {"allow": [], "deny": [], "ask": []}
    for path in paths:
        try:
            permissions = _read_settings(path).get("permissions") or {}
        except (OSError, ValueError):
            continue
        for kind in rules:
            rules[kind] += [p for p in (permissions.get(kind) or [])
                            if isinstance(p, str)]
    return rules


def _pattern_matches(pattern, tool, command):
    """One permissions pattern against one call.

    Mirrors Claude Code's documented forms: ``Tool``, ``Tool(exact)``,
    ``Tool(prefix *)``, ``Tool(prefix*)`` and ``Tool(prefix:*)`` — the
    form Claude Code's own /permissions UI writes.
    """
    if pattern == tool:
        return True
    if not (pattern.startswith(tool + "(") and pattern.endswith(")")):
        return False
    inner = pattern[len(tool) + 1:-1]
    if not command:
        return False
    if inner.endswith(":*"):
        prefix = inner[:-2]
        return (command == prefix
                or command.startswith(prefix + " ")
                or command.startswith(prefix + ":"))
    if inner.endswith(" *"):
        prefix = inner[:-2].rstrip()
        return command == prefix or command.startswith(prefix + " ")
    if inner.endswith("*"):
        return command.startswith(inner[:-1])
    return command == inner


def matches_user_allowlist(tool, tool_input, cwd=None):
    """Would Claude Code auto-allow this from the user's own allow rules?

    Used for prompt parity — a call the allowlist answers shows no prompt
    on the phone, so it must show none on the wrist either. A deny or ask
    rule vetoes the allowlist the same way Claude Code's own precedence
    does, so a vetoed call still escalates to a human.

    A compound Bash command is judged the way Claude Code judges it:
    split on &&, ||, ; and | — EVERY segment must have its own allow
    rule, or the phone prompts. And command substitution always prompts
    on the phone regardless of rules, so it never skips the wrist.
    """
    command = ""
    if tool in ("Bash", "BashOutput"):
        command = " ".join(
            str((tool_input or {}).get("command", "")).split())
        if "$(" in command or "`" in command:
            return False
    rules = _user_permission_rules(cwd)
    pieces = _segments(command) if command else [""]
    for pattern in rules["deny"] + rules["ask"]:
        if any(_pattern_matches(pattern, tool, piece)
               for piece in pieces):
            return False
    return all(
        any(_pattern_matches(pattern, tool, piece)
            for pattern in rules["allow"])
        for piece in pieces)


def _shared_settings_env():
    """The CLAUDE_RISK_* switches as Claude Code's settings hold them.

    One switch for both agents: --watch and --quiet write Claude Code's
    settings, and a Codex hook reads the same file rather than keeping a
    second copy that could disagree. A plugin install keeps its switches
    on its hook's command line instead, so they are read from there.
    """
    data = _read_settings_quietly(_settings_path())
    env = {key: str(value) for key, value in (data.get("env") or {}).items()
           if key.startswith("CLAUDE_RISK_")}
    if not env.get("CLAUDE_RISK_MODE"):
        plugin = _plugin_install()
        if plugin:
            env = dict(plugin.get("env") or {}, **env)
    return env


def _plan_input(event, card):
    """The input a plan's allow must carry, or None for any other card.

    ExitPlanMode is a tool the CLI marks as needing the user, and it drops
    a hook's allow without updatedInput for such a tool, keeping its dialog
    open (_permission_output). So every yes to a plan carries the call's
    own input, unchanged — a row (#560), and since #578 the Allow button
    of a watch that predates the rows and a "don't ask again" that falls
    back to allowing once, which were yeses nothing answered."""
    if not card.get("plan_card"):
        return None
    tool_input = event.get("tool_input")
    return tool_input if isinstance(tool_input, dict) else {}


def run_hook(stdin=None, stdout=None, agent=None):
    """Hook mode: read the event from stdin, write the decision to stdout.

    ``agent`` is "codex" when Codex runs the hook (its hooks.json command
    says --agent codex); Claude Code's command names no agent."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read()
        event = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("event is not a JSON object")
        if agent == "codex" and event.get("hook_event_name") not in (None, "PermissionRequest"):
            # Codex fires PreToolUse for every call, its memory job's
            # included. Only a PermissionRequest is a question; an empty
            # stdout is Codex's "no decision" for anything else.
            return 0
        if agent == "codex":
            policy = load_policy(dict(_shared_settings_env(), **os.environ))
        else:
            policy = load_policy()
        response, audit, card = build_response(event, policy, agent=agent)
        # Only an enforce-mode escalation with a relay configured can ever
        # reach the wrist; check those cheap facts before touching any
        # settings file for the parity test below.
        wants_wrist = (audit["mode"] == "enforce"
                       and audit["effective"] == "escalate"
                       and policy.get("relay"))
        # Prompt parity: the phone is the reference. Claude Code answers
        # two classes itself with no visible prompt — its own read-only
        # validation (our SAFE tier mirrors it) and the user's allow
        # rules. Neither may become a wrist card.
        # Codex decided to ask by its own rules; the Claude Code checks
        # below describe a different program's prompt.
        if wants_wrist and agent != "codex":
            phone_would_prompt = not (
                (audit["tier"] == "SAFE"
                 and phone_would_auto_allow(event.get("tool_name", ""),
                                            event.get("tool_input")))
                or matches_user_allowlist(event.get("tool_name", ""),
                                          event.get("tool_input"),
                                          event.get("cwd")))
            if not phone_would_prompt:
                audit["watch"] = "skipped-parity"
                wants_wrist = False
        if (wants_wrist and event.get("tool_name") == "AskUserQuestion"
                and questions_need_typing(event.get("tool_input"))):
            # A question the wrist can only answer with typed words stays
            # at the terminal, with the call's other questions.
            audit["watch"] = "skipped-typed-answer"
            wants_wrist = False
        if wants_wrist:
            if event.get("tool_name") == "AskUserQuestion":
                verdict, chosen = ask_questions(card, event.get("tool_input"), policy,
                                                project=audit.get("project"))
            else:
                verdict, chosen = ask_watch(card, policy,
                                            project=audit.get("project"))
            audit["watch"] = verdict
            if verdict == "answer" and chosen and card.get("plan_card"):
                # A plan answered on the wrist: approve into the mode the
                # terminal's row names, or keep planning with the user's
                # words. The approval carries the call's own input, unchanged,
                # or Claude Code ignores it (_permission_output).
                behavior, message, mode = plan_decision(chosen, card.get("options") or [])
                audit["answer"] = chosen
                if behavior is None:
                    # A row this card never offered: the terminal asks.
                    audit["watch"] = "unoffered-answer"
                else:
                    audit["effective"] = behavior
                    response["hookSpecificOutput"] = _permission_output(
                        behavior, message, mode=mode,
                        updated_input=_plan_input(event, card))
            elif verdict == "answer" and isinstance(chosen, dict) and agent != "codex":
                # Every question answered on the wrist: the call goes ahead
                # with the answers filled in, as the terminal's dialog runs
                # it, and Claude reads "Your questions have been answered".
                # The shown fields go back unchanged (2.1.300 refuses an
                # answer that alters them).
                audit["effective"] = "allow"
                audit["answer"] = _answers_in_words(chosen)
                response["hookSpecificOutput"] = _permission_output(
                    "allow", updated_input=dict(event["tool_input"], answers=chosen))
            elif verdict == "answer" and chosen:
                # Codex was never seen to take updatedInput: deny-with-reason
                # is the channel that carries the user's words back, and
                # Claude proceeds on them.
                words = (_answers_in_words(chosen) if isinstance(chosen, dict)
                         else chosen)
                audit["effective"] = "deny"
                audit["answer"] = words
                response["hookSpecificOutput"] = _permission_output(
                    "deny", "The user answered from their watch: %s" % words)
            elif verdict == "dont_ask":
                # The terminal's row: allow, and apply what it would apply.
                # Re-derived from this same event, never taken from the
                # watch; a row that cannot be rebuilt allows this once. So
                # does one the card never showed, and any CRITICAL card:
                # a lasting rule is written only where the wrist offered
                # those very words (2026-10-16 review, S5).
                row = dont_ask_row(event)
                if (audit["tier"] == Risk.CRITICAL.name or not row
                        or row[0] != card.get("always_label")):
                    row = None
                audit["effective"] = "allow"
                if row:
                    audit["updates"] = row[1]
                response["hookSpecificOutput"] = _permission_output(
                    "allow", updated_permissions=row[1] if row else None,
                    updated_input=_plan_input(event, card))
            elif verdict in ("allow", "deny"):
                audit["effective"] = verdict
                response["hookSpecificOutput"] = _permission_output(
                    verdict, "Denied from the watch.",
                    updated_input=_plan_input(event, card))
        write_audit(audit, policy)
    except Exception as error:  # fail closed to the human, never crash the session
        print("ClaudeRiskClassifier: %s" % error, file=sys.stderr)
        response = ESCALATE_FALLBACK
    stdout.write(json.dumps(response, ensure_ascii=False))
    return 0


def run_explain(target, tool):
    """Explain how a command or path would be classified."""
    tool_input = {"command": target} if tool == "Bash" else {"file_path": target}
    event = {"tool_name": tool, "tool_input": tool_input, "cwd": os.getcwd()}
    policy = load_policy()
    result = classify(event)
    card = wrist_card(result["tool"], result["tool_input"], result["risk"],
                      *_card_budgets(policy))
    decision, reason = decide(result["risk"], policy)

    print("tool      : %s" % tool)
    print("input     : %s" % target)
    print("tier      : %s" % result["risk"].name)
    print("rules     : %s" % ", ".join(result["rules"]))
    print("decision  : %s (%s)" % (decision, reason))
    print("mode      : %s" % policy.get("mode"))
    print("wrist     : [%s] %s" % (card["tier"], card["headline"]))
    print("            (%d chars)" % len(card["headline"]))
    return 0


def report_facts(entries):
    """What the audit log says, as numbers: the totals, the tier split,
    how many prompts the policy would have raised, the per-project and
    per-tool splits, the latest escalations. Pure, so a test can hold it."""
    tiers = Counter(e.get("tier", "?") for e in entries)
    by_tool = Counter(e.get("tool", "?") for e in entries
                      if e.get("decision") == "allow")
    escalations = [e for e in entries if e.get("decision") in ("escalate", "deny")]
    rows, asked = Counter(), Counter()          # per project, in one pass
    for e in entries:
        if e.get("project"):
            rows[e["project"]] += 1
            asked[e["project"]] += e.get("decision") in ("escalate", "deny")
    by_project = [(name, rows[name], asked[name],
                   100.0 * (rows[name] - asked[name]) / rows[name])
                  for name in sorted(rows)]
    total, escalated = len(entries), len(escalations)
    return {"total": total, "tiers": tiers, "escalated": escalated,
            "saved": total - escalated, "by_project": by_project,
            "by_tool": by_tool.most_common(5), "escalations": escalations[-5:]}


def share_footer(saved, asked):
    """The one place Tapproval asks a terminal for anything.

    Deliberately narrow. It belongs at the end of `--report` and nowhere
    else: `--report` is run out of curiosity about what the tool bought
    you, which is the moment it has just proved itself, whereas
    `--status` is run when something is *wrong*. Asking at the second
    moment costs more than it earns.

    It asks for one thing (tell someone), never for a rating — an iOS
    app cannot be reviewed from a desktop browser, so a rating ask here
    is a dead end — and it offers nothing in exchange, because a reward
    attached to a recommendation measurably shrinks it.

    A pure builder returning lines, so a test can read the words without
    capturing stdout.
    """
    return [
        "-" * 60,
        "That's %s prompts Tapproval answered for you, and %s"
        % (format(saved, ",d"), format(asked, ",d")),
        "it stopped to ask about.",
        "",
        "It's one person, no company. If it saves you steps, tell",
        "one other person who leaves Claude running:",
        "  %s" % PROJECT_SITE,
    ]


def run_report():
    """Summarise the audit log: how many prompts would the watch have raised?"""
    policy = load_policy()
    entries = read_audit(policy)
    if not entries:
        print("No audit entries at %s" % _audit_path(policy))
        print("Run some Claude Code sessions with the hook installed first.")
        return 0
    f = report_facts(entries)
    total, escalated, saved = f["total"], f["escalated"], f["saved"]

    print("Audit log : %s" % _audit_path(policy))
    print("Events    : %d" % total)
    print("")
    print("Risk tiers")
    for tier in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        count = f["tiers"].get(tier, 0)
        if not count:
            continue
        bar = "#" * int(round(30.0 * count / total))
        print("  %-9s %5d  %5.1f%%  %s" % (tier, count, 100.0 * count / total, bar))
    print("")
    print("Notifications")
    print("  baseline (every prompt buzzes) : %d" % total)
    print("  with this policy               : %d" % escalated)
    if total:
        print("  reduction                      : %.1f%% (%d silenced)"
              % (100.0 * saved / total, saved))
    print("")

    if len(f["by_project"]) > 1:
        print("By project")
        for name, count, asked, share in f["by_project"]:
            print("  %-24s %5d asked %4d  (%.0f%% silenced)"
                  % (name[:24], count, asked, share))
        print("")

    if f["by_tool"]:
        print("Top auto-allowed tools")
        for tool, count in f["by_tool"]:
            print("  %-24s %d" % (tool, count))
        print("")

    if f["escalations"]:
        print("Most recent escalations")
        for entry in f["escalations"]:
            print("  [%-8s] %s" % (entry.get("tier", "?"), entry.get("headline", "")))
        print("")

    print("In plain terms")
    print("  You were asked to approve something %d times." % total)
    if escalated:
        print("  With this policy you would have been asked %d times" % escalated)
        print("  \u2014 roughly 1 interruption for every %.0f you get today."
              % (float(total) / escalated))
    else:
        print("  With this policy you would not have been asked at all.")
    print("")
    print("  Next: look at the escalations above. If each one is something you")
    print("  would genuinely want to be interrupted for, the policy is working.")
    print("  If they look routine, the threshold is set too low for you.")
    print("")
    for line in share_footer(saved, escalated):
        print(line)
    return 0


# --------------------------------------------------------------------------
# Self-installation
# --------------------------------------------------------------------------

DEFAULT_SETTINGS = "~/.claude/settings.json"


def _settings_path():
    """Where Claude Code reads its settings. Overridable for tests."""
    return os.path.expanduser(
        os.environ.get("CLAUDE_SETTINGS_PATH", DEFAULT_SETTINGS)
    )


def _quote_path(path):
    """Quote a path for a shell command string, if it needs it."""
    if not re.search(r"[\s\"\']", path):
        return path
    if os.name == "nt":
        return '"%s"' % path
    return "'%s'" % path.replace("'", "'\\''")


def _hook_command():
    """The exact command Claude Code should run, using this interpreter."""
    return "%s %s" % (_quote_path(sys.executable),
                      _quote_path(os.path.abspath(__file__)))


def _relay_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "watch_relay.py")


def _relay_command():
    """SessionStart hook: make sure the relay is alive whenever Claude is."""
    return "%s %s --ensure" % (_quote_path(sys.executable),
                               _quote_path(_relay_path()))


# A reboot must not need a hand: a login item wakes the relay the moment
# the user logs back in, instead of leaving the watch searching until the
# first Claude Code session happens to start.
def _launch_agent_is_real():
    """True only when the agent file is the one launchd reads at login.

    The file path is overridable for tests; the *label* is not. Every
    install bootstraps `com.tapproval.relay` into the user's real launchd,
    so an overridden path used to replace the owner's login job with a
    job pointing at a pytest temp file — from any test that ran the
    installer as a subprocess, where the in-process launchctl stub does
    not reach. CI runs on the owner's Mac, so every CI run did it. Found
    on 2026-09-23 when a relay stopped for an update did not come back:
    launchd ran the test's plist, long deleted, and exited 2.
    """
    return not os.environ.get("CLAUDE_LAUNCH_AGENT_PATH")


def _launch_agent_path():
    """Overridable like CLAUDE_SETTINGS_PATH, so tests never touch the
    real LaunchAgents directory — and see `_launch_agent_is_real`: with
    the path overridden, launchd is not touched either."""
    return os.environ.get("CLAUDE_LAUNCH_AGENT_PATH") or os.path.join(
        os.path.expanduser("~"), "Library", "LaunchAgents",
        "com.tapproval.relay.plist")

def _launchctl(*args):
    """Run launchctl quietly: True when it succeeded. Never raises, never
    blocks an install. Its answer used to be dropped, so an install whose
    bootstrap failed still said the relay wakes at login."""
    import subprocess
    try:
        return subprocess.run(["launchctl"] + list(args),
                              capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def install_launch_agent():
    """Wake the relay at every login, so a reboot never needs a hand.

    The agent runs ``watch_relay.py --ensure`` once at load — idempotent
    and exits immediately — so it can never fight the SessionStart hook
    over the port. Crash recovery between logins stays with that hook.
    Returns True when the agent is in place. macOS only; never raises.
    """
    if sys.platform != "darwin":
        return False
    relay = _relay_path()
    if not os.path.exists(relay):
        return False
    import plistlib
    job = {"Label": "com.tapproval.relay",
           "ProgramArguments": [sys.executable, relay, "--ensure"],
           "RunAtLoad": True}
    target = _launch_agent_path()
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            plistlib.dump(job, handle)
    except OSError:
        return False
    if _launch_agent_is_real():
        import time
        uid = os.getuid()
        # A bootout of a job that is not loaded fails, and that is fine.
        _launchctl("bootout", "gui/%d/com.tapproval.relay" % uid)
        # The bootout finishes asynchronously; a bootstrap straight after it
        # can fail while launchd is still unloading. One patient retry.
        if not _launchctl("bootstrap", "gui/%d" % uid, target):
            time.sleep(1.0)
            if not _launchctl("bootstrap", "gui/%d" % uid, target):
                print("Tapproval: the login job could not be registered with "
                      "launchd, so the relay will not wake by itself after a "
                      "restart. It still starts with every Claude Code "
                      "session. Check with: launchctl print gui/%d/"
                      "com.tapproval.relay" % uid, file=sys.stderr)
                return False
    return True


def remove_launch_agent():
    """Take the login wake-up out again — part of a clean exit."""
    if sys.platform != "darwin":
        return False
    if _launch_agent_is_real():
        _launchctl("bootout", "gui/%d/com.tapproval.relay" % os.getuid())
    try:
        os.remove(_launch_agent_path())
        return True
    except OSError:
        return False


def _is_our_hook(handler):
    command = str(handler.get("command", ""))
    return (os.path.basename(__file__) in command
            or "watch_relay.py" in command)


# --------------------------------------------------------------------------
# Recognising a plugin install
#
# `/plugin install` registers our hooks from the plugin's own manifest and
# writes nothing to settings.json. Anything that reads only settings.json
# therefore tells a plugin user they are not installed, while the hook runs
# happily underneath — a confident wrong answer, which is the one failure
# mode this tool exists to prevent.

PLUGIN_NAME = "tapproval-helper"

_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _plugins_dir():
    """Where Claude Code keeps installed plugins. Overridable for tests."""
    return os.path.expanduser(
        os.environ.get("CLAUDE_PLUGINS_DIR", "~/.claude/plugins"))


def _split_assignments(parts):
    """Peel leading VAR=value words off a split shell command.

    The plugin manifest carries its configuration inline that way, so a
    naive reader takes CLAUDE_RISK_MODE=enforce for the interpreter and
    reports it as missing from PATH.
    """
    env = {}
    for index, word in enumerate(parts):
        match = _ASSIGNMENT_RE.match(word)
        if not match:
            return env, parts[index:]
        env[match.group(1)] = match.group(2)
    return env, []


def _manifest_hook(wiring):
    """Our PermissionRequest handler in a hooks manifest: (env, timeout)."""
    for handler in _settings_handlers(wiring):
        try:
            parts = shlex.split(str(handler.get("command", "")),
                                posix=(os.name != "nt"))
        except ValueError:
            parts = []
        env, _rest = _split_assignments(parts)
        return env, handler.get("timeout")
    return {}, None


def _load_json(path, default=None):
    """The parsed file, or ``default`` when it is missing or not JSON.
    For lookups where absence is an ordinary answer; the policy loader
    reports its failure instead and does not use this."""
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def _plugin_roots():
    """Every directory that could hold our installed plugin.

    Claude Code keeps an authoritative registry — ``installed_plugins.json``
    maps ``<plugin>@<marketplace>`` to the exact ``installPath`` it unpacked
    to — so read that rather than guessing at directory layout. (It unpacks
    under ``plugins/cache/``, not ``plugins/marketplaces/``, which is the
    sort of detail a guess gets wrong.)
    """
    roots = []
    env_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env_root:
        roots.append(env_root)
    registry = _load_json(os.path.join(_plugins_dir(), "installed_plugins.json"), {})
    installed = registry.get("plugins", {}) if isinstance(registry, dict) else None
    if not isinstance(installed, dict):
        return roots
    for key, entries in installed.items():
        if str(key).split("@")[0] != PLUGIN_NAME:
            continue
        for entry in entries if isinstance(entries, list) else []:
            path = isinstance(entry, dict) and entry.get("installPath")
            if path:
                roots.append(path)
    return roots


def _plugin_install():
    """Our plugin on disk, or None.

    Returns the root it was found in, the environment its hook command
    carries inline, that hook's timeout, and whether it also starts the
    relay — everything --status needs to describe a plugin install without
    looking at settings.json at all.
    """
    for root in _plugin_roots():
        manifest = _load_json(os.path.join(root, ".claude-plugin", "plugin.json"), {})
        if not isinstance(manifest, dict) or manifest.get("name") != PLUGIN_NAME:
            continue
        wiring = _load_json(os.path.join(root, "hooks", "hooks.json"))
        if not isinstance(wiring, dict):
            continue
        env, timeout = _manifest_hook(wiring)
        relay = _relay_wired(wiring)
        return {"root": root, "env": env, "timeout": timeout, "relay": relay}
    return None


def _handlers(data, event):
    """Every handler under one hook event in a settings file or a hooks
    manifest. The one walk of that shape: four copies of it used to live
    here, and a guard added to one would not have reached the rest."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    entries = hooks.get(event, []) if isinstance(hooks, dict) else []
    for entry in entries if isinstance(entries, list) else []:
        for handler in (entry.get("hooks") or []) if isinstance(entry, dict) else []:
            if isinstance(handler, dict):
                yield handler


def _settings_handlers(data):
    """Our PermissionRequest handlers in a parsed settings file."""
    return [handler for handler in _handlers(data, "PermissionRequest")
            if _is_our_hook(handler)]


def _relay_wired(data):
    """Does SessionStart start the relay, in this settings file or manifest?"""
    return any("watch_relay.py" in str(handler.get("command", ""))
               for handler in _handlers(data, "SessionStart"))


def _plugin_only_install():
    """The plugin install, when settings.json holds no hook of ours.

    That is the case where the settings-file toggles are inert: the plugin
    puts CLAUDE_RISK_MODE on the hook's own command line, and an inline
    assignment beats anything the session environment carries. Variables
    the manifest does *not* set — CLAUDE_RISK_AUTO_ALLOW, say — still come
    through from settings, so --quiet keeps working and is not guarded.
    """
    try:
        data = _read_settings(_settings_path())
    except ValueError:
        return None
    if _settings_handlers(data):
        return None
    return _plugin_install()


def _read_settings_quietly(path):
    try:
        return _read_settings(path)
    except ValueError:
        return {}


def _read_settings(path):
    """Return the parsed settings. Raises ValueError on malformed JSON."""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("settings.json is not a JSON object")
    return data


def _backup(path):
    """Copy the settings file aside before touching it. Returns the path."""
    if not os.path.exists(path):
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = "%s.bak-%s" % (path, stamp)
    with open(path, "r", encoding="utf-8") as src:
        content = src.read()
    with open(backup, "w", encoding="utf-8") as dst:
        dst.write(content)
    return backup


def _write_settings(path, data):
    # Through a symlink, to the file it names: replacing the link left a
    # dotfiles-managed settings.json as two copies, and the next re-link
    # silently undid --install (2026-10-19 review).
    path = os.path.realpath(path)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Atomic: this file holds every hook and setting the user has, not just
    # ours. A crash mid-write would corrupt all of it, so render to a temp
    # file in the same directory and rename — os.replace() is atomic on the
    # same filesystem, so the settings are always either the old or the new.
    import tempfile
    payload = json.dumps(data, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=directory or ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _sync_hook(entry_list, wanted, matcher, marker):
    """Idempotently point our hook entry in ``entry_list`` at ``wanted``.

    Ours is any handler whose command mentions ``marker`` (the script's
    file name): repointed in place when it differs, added — with the
    matcher — when absent, left alone when already right. True if the
    list changed, which is what decides whether settings are rewritten.
    """
    ours = [h for entry in entry_list for h in entry.get("hooks", [])
            if marker in str(h.get("command", ""))]
    if ours:
        if all(h.get("command") == wanted for h in ours):
            return False
        for handler in ours:
            handler["command"] = wanted
            handler.setdefault("timeout", 10)
        return True
    entry = {"hooks": [{"type": "command", "command": wanted,
                        "timeout": 10}]}
    if matcher:
        entry["matcher"] = matcher
    entry_list.append(entry)
    return True


def _remove_our_hooks(hooks):
    """Drop our handlers from both events, keeping everyone else's. Empty
    events disappear. Returns how many handlers went."""
    removed = 0
    for event in ("PermissionRequest", "SessionStart"):
        kept = []
        for entry in hooks.get(event, []):
            handlers = [h for h in entry.get("hooks", [])
                        if not _is_our_hook(h)]
            removed += len(entry.get("hooks", [])) - len(handlers)
            if handlers:
                entry["hooks"] = handlers
                kept.append(entry)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    return removed


def _strip_our_env(data):
    """The env block we injected goes too — leaving CLAUDE_RISK_* behind
    is harmless but untidy, and an uninstall should be a clean exit."""
    env = data.get("env")
    if isinstance(env, dict):
        for key in list(env):
            if key.startswith("CLAUDE_RISK_"):
                env.pop(key)
        if not env:
            data.pop("env", None)


# --------------------------------------------------------------------------
# Codex, wired beside Claude Code
#
# Codex reads hooks from $CODEX_HOME/hooks.json (default ~/.codex), in the
# same {"hooks": {Event: [{"hooks": [...]}]}} shape as Claude Code's
# settings, and answers a PermissionRequest hook in the same decision
# object. So the one hook serves both, told which agent it is by
# --agent codex. Nothing is written for someone who does not use Codex:
# a Claude-only install must not change by a byte (issue #390).

# Where the ChatGPT app keeps codex: codex-cli/bin since at least 0.162
# (seen 2026-10-14); the bare Resources/codex is the first guess, kept in
# case an older app put it there.
CODEX_APP_BINARIES = (
    "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex",
    "/Applications/ChatGPT.app/Contents/Resources/codex",
)
CODEX_APP_BINARY = CODEX_APP_BINARIES[0]


def _codex_home():
    return os.path.expanduser(os.environ.get("CODEX_HOME") or "~/.codex")


def _codex_hooks_path():
    return os.path.join(_codex_home(), "hooks.json")


def _codex_command():
    return "%s --agent codex" % _hook_command()


def ensure_codex_on_path():
    """Where the codex binary is, or None. Codex ships inside the ChatGPT
    app and need not be on PATH at all."""
    import shutil
    found = shutil.which("codex")
    if found:
        return found
    for path in CODEX_APP_BINARIES:
        if os.access(path, os.X_OK):
            return path
    return None


def _codex_hook_hash(event_label, matcher, handler):
    """Codex's trust hash for one hook, as codex-rs computes it
    (hooks/src/engine/discovery.rs hook_hash, config/src/fingerprint.rs
    version_for_toml): the event's snake_case label, the group's matcher
    and the one normalized handler, as JSON with every object's keys
    sorted and no spaces, SHA-256, prefixed "sha256:". A command handler
    normalizes to its type, command, timeout (600 when unset), async, and
    statusMessage only when set. Checked against three real hashes from
    Codex 0.162 on 2026-10-14."""
    normal = {"type": "command", "command": str(handler.get("command", "")),
              "timeout": max(1, int(handler.get("timeout") or 600)),
              "async": bool(handler.get("async", False))}
    if handler.get("statusMessage") is not None:
        normal["statusMessage"] = handler["statusMessage"]
    identity = {"event_name": event_label, "hooks": [normal]}
    if matcher is not None:
        identity["matcher"] = matcher
    text = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def codex_hook_trusted():
    """Whether Codex will run our hook: True, False, or None when there is
    nothing to trust (no Codex here, or our hook is not in its hooks.json).

    Codex runs a hook only once the person has trusted it on the CLI's
    "Hooks need review" screen, and keeps that in config.toml as
    [hooks.state."<hooks.json>:permission_request:<entry>:<hook>"] with a
    trusted_hash (seen 2026-10-14, Codex 0.162). The stored hash must equal
    the hook's current one: a handler changed in place (a new command
    path, a new timeout) is "modified" to Codex and skipped until trusted
    again. Python 3.9 has no tomllib, hence a line scan. Anything
    unreadable is False: never a confident "trusted" nobody has seen."""
    path = _codex_hooks_path()
    if not os.path.isdir(_codex_home()):
        return None
    entries = (_read_settings_quietly(path).get("hooks") or {}).get("PermissionRequest") or []
    ours = [('[hooks.state."%s:permission_request:%d:%d"]' % (path, i, j),
             _codex_hook_hash("permission_request", entry.get("matcher"), handler))
            for i, entry in enumerate(entries) if isinstance(entry, dict)
            for j, handler in enumerate(entry.get("hooks") or [])
            if isinstance(handler, dict) and _is_our_hook(handler)]
    if not ours:
        return None
    try:
        with open(os.path.join(_codex_home(), "config.toml"), encoding="utf-8") as handle:
            lines = [line.strip() for line in handle]
    except (OSError, UnicodeDecodeError):
        return False
    stored = {}
    section = None
    for line in lines:
        if line.startswith("["):
            section = line
        elif section and line.split("=", 1)[0].strip() == "trusted_hash" and "=" in line:
            stored[section] = line.split("=", 1)[1].strip().strip('"')
    return any(stored.get(section) == current for section, current in ours)


def install_codex():
    """Wire the hook into Codex's hooks.json, if Codex is used here.

    Returns "installed", "current" or None (no Codex). Codex runs a hook
    only once the user has approved it in the CLI's /hooks, which is said
    where the install is reported."""
    if not os.path.isdir(_codex_home()):
        return None
    path = _codex_hooks_path()
    try:
        data = _read_settings(path)
    except ValueError:
        print("Codex  : %s is not valid JSON; left alone." % path)
        return None
    entries = data.setdefault("hooks", {}).setdefault("PermissionRequest", [])
    changed = _sync_hook(entries, _codex_command(), "*", os.path.basename(__file__))
    for handler in _settings_handlers(data):
        if handler.get("timeout") != WATCH_HOOK_TIMEOUT:
            handler["timeout"] = WATCH_HOOK_TIMEOUT
            changed = True
    if not changed:
        return "current"
    _backup(path)
    _write_settings(path, data)
    return "installed"


def uninstall_codex():
    """Take our hook out of Codex's hooks.json, leaving everyone else's.
    True if anything was removed."""
    path = _codex_hooks_path()
    if not os.path.exists(path):
        return False
    try:
        data = _read_settings(path)
    except ValueError:
        return False
    hooks = data.get("hooks")
    if not isinstance(hooks, dict) or not _remove_our_hooks(hooks):
        return False
    if not hooks:
        data.pop("hooks", None)
    _backup(path)
    _write_settings(path, data)
    return True


def run_install(then_watch=False, bridge=None):
    """Register this script as a PermissionRequest hook. Safe to re-run.

    ``then_watch`` is set when --watch is on the same command line: the
    closing paragraph below would otherwise promise "shadow mode, work
    normally for a week" three lines before --watch prints "Wrist
    approvals are ON" — the installer said both, in that order.

    ``bridge`` is --bridge (True), --no-bridge (False) or neither (None,
    which keeps whatever the user chose before): see `_bridge_step`.
    """
    found = _settings_or_explain()
    if found is None:
        return 1
    path, data = found

    command = _hook_command()
    relay_command = _relay_command() if os.path.exists(_relay_path()) else None
    hooks = data.setdefault("hooks", {})
    entries = hooks.setdefault("PermissionRequest", [])
    starters = hooks.setdefault("SessionStart", [])

    changed = _sync_hook(entries, command, "*", os.path.basename(__file__))
    if relay_command:
        changed = _sync_hook(starters, relay_command, None,
                             "watch_relay.py") or changed
    if not starters:
        hooks.pop("SessionStart", None)

    # Even a no-op re-run repairs a missing login wake-up: installs from
    # before it existed get it the next time anything runs --install.
    agent = bool(relay_command) and install_launch_agent()
    codex = install_codex()
    closed = _bridge_step(bridge)

    if not changed:
        print("Already installed, and the paths are correct.")
        print("  Settings : %s" % path)
        print("  Command  : %s" % command)
        if agent:
            print("  Reboot   : the relay wakes again at login")
        if closed:
            print(closed)
        _say_codex(codex)
        print("  Nothing to do.")
        return 0

    backup = _backup(path)
    _write_settings(path, data)

    print("Installed.")
    print("  Settings : %s" % path)
    print("  Command  : %s" % command)
    if relay_command:
        print("  Relay    : starts itself with every Claude Code session")
    if agent:
        print("  Reboot   : the relay wakes again at login")
    if backup:
        print("  Backup   : %s" % backup)
    if closed:
        print(closed)
    _say_codex(codex)
    if then_watch:
        return 0
    print("")
    print("Nothing about your sessions changes yet: the classifier starts in")
    print("shadow mode, so every permission prompt still reaches you exactly")
    print("as before. It only writes down what it would have done.")
    print("")
    print("Next: start a new Claude Code session, work normally for a week,")
    print("then run this script again with --report.")
    return 0


def _bridge_step(choice=None):
    """--install's part in the Mac bridge (route B, #378): the line to
    print, or None when there is nothing to say yet.

    The bridge mirrors each card into the user's own iCloud, which is what
    makes a closed watch buzz. It is installed on every Mac that can run
    it, unless the user said --no-bridge; ``choice`` is that flag (False),
    --bridge (True), or neither (None: keep the earlier choice).
    """
    try:
        import bridge_install
    except Exception:
        return None
    if not bridge_install.mac_supported():
        return ("  Closed watch : buzzing with Tapproval closed needs a Mac "
                "(macOS 13 or later). Here, cards reach the watch while "
                "Tapproval is open on it.")
    if choice is False:
        bridge_install.set_off(True)
        bridge_install.remove()
        return ("  Closed watch : off (--no-bridge). Cards reach the watch "
                "while Tapproval is open on it.")
    if choice is True:
        bridge_install.set_off(False)
    pin = bridge_install.read_pin()
    state = bridge_install.state(pin)
    if state == "off":
        return ("  Closed watch : off. --install --bridge turns it on.")
    if state == "hand-built":
        return "  Closed watch : a hand-built bridge is here, left as it is"
    if state == "no-pin":
        return None
    if state == "current":
        return ("  Closed watch : buzzes through your own iCloud (bridge %s)"
                % pin["version"])
    try:
        bridge_install.install(pin)
    except bridge_install.InstallError as error:
        return ("  Closed watch : the iCloud bridge could not be installed "
                "(%s). It tries again when Claude Code next starts." % error)
    except OSError as error:
        return ("  Closed watch : the iCloud bridge could not be installed "
                "(%s). It tries again when Claude Code next starts."
                % error.strerror)
    return ("  Closed watch : buzzes through your own iCloud (bridge %s, "
            "just installed)" % pin["version"])


def _say_codex(codex):
    if codex == "installed":
        print("  Codex    : wired too; open codex in Terminal once and choose "
              "\"Trust all and continue\"")
    elif codex == "current":
        # An unchanged hooks.json says nothing about trust: ask Codex's own
        # record, and keep the instruction until it says trusted.
        if codex_hook_trusted() is True:
            print("  Codex    : wired and trusted")
        else:
            print("  Codex    : wired, not trusted yet; open codex in Terminal once "
                  "and choose \"Trust all and continue\"")


def _settings_or_explain():
    """``(path, data)`` — or None, having told the user why not.

    Every command that writes settings starts here, so the explanation a
    user gets for an unreadable file is one sentence, not three variants.
    """
    path = _settings_path()
    try:
        return path, _read_settings(path)
    except ValueError as error:
        print("Could not read %s" % path)
        print("  It is not valid JSON (%s)." % error)
        print("  Nothing was changed. Fix or move that file, then try again.")
        return None


def run_uninstall():
    """Remove our hook entry, leaving everything else in settings untouched."""
    found = _settings_or_explain()
    if found is None:
        return 1
    path, data = found

    # Nothing of ours in settings, but the plugin has us wired: removing
    # nothing and reporting success would leave the hook running.
    plugin = _plugin_only_install()
    if plugin:
        print("Installed as a Claude Code plugin, so there is nothing in")
        print("%s to remove." % path)
        print("Remove it with:")
        print("  /plugin uninstall %s" % PLUGIN_NAME)
        return 1

    hooks = data.get("hooks")
    removed = _remove_our_hooks(hooks) if isinstance(hooks, dict) else False
    if uninstall_codex():
        print("Removed from Codex's hooks too.")
    if not removed:
        # The login job is ours whatever settings say: a hand edit or an
        # earlier --uninstall took the hooks and left it pointing at a
        # script the uninstaller then deletes (2026-09-30 review).
        if remove_launch_agent():
            print("Not in settings; the login job was removed.")
        else:
            print("Not installed — nothing to remove.")
        if _remove_bridge():
            print("The Mac bridge and its login job were removed.")
        return 0

    if not hooks:
        data.pop("hooks", None)
    _strip_our_env(data)
    # Backed up only once there is something to write: the backup exists
    # to undo a write, and a run that changes nothing must leave nothing.
    backup = _backup(path)
    _write_settings(path, data)
    remove_launch_agent()
    bridge_gone = _remove_bridge()

    print("Removed. Your other settings were left untouched.")
    if bridge_gone:
        print("  Bridge   : the Mac bridge and its login job are gone")
    print("  Settings : %s" % path)
    if backup:
        print("  Backup   : %s" % backup)
    print("  The audit log was left in place; delete it yourself if you want it gone.")
    return 0


def _bridge_status_line(health):
    """--status's word on the Mac bridge, which makes a closed watch buzz."""
    try:
        import bridge_install
    except Exception:
        return None
    if not bridge_install.mac_supported():
        return ("Closed watch  : needs a Mac \u2014 here, cards arrive while "
                "Tapproval is open")
    if os.path.exists(bridge_install.off_marker()):
        return "Closed watch  : off (--no-bridge)"
    version = bridge_install.installed_version()
    if version is None:
        return ("Closed watch  : no Mac bridge yet \u2014 cards arrive while "
                "Tapproval is open")
    heard = (health or {}).get("alert_route") == "bridge"
    return "Closed watch  : bridge %s, %s" % (
        version, "running" if heard else "not heard from by the relay")


def _remove_bridge():
    """Take the Mac bridge out with the rest: True when there was one."""
    try:
        import bridge_install
    except Exception:
        return False
    if not bridge_install.mac_supported():
        return False
    if not (os.path.exists(bridge_install.app_path())
            or os.path.exists(bridge_install.agent_path())):
        return False
    return bridge_install.remove()


def _human_duration(seconds):
    """'24 hours', not '1440 minutes' — the number a person would say."""
    seconds = int(seconds)
    if seconds % 3600 == 0 and seconds >= 3600:
        hours = seconds // 3600
        return "%d hour%s" % (hours, "" if hours == 1 else "s")
    minutes = max(1, seconds // 60)
    return "%d minute%s" % (minutes, "" if minutes == 1 else "s")


WATCH_ENV = {
    "CLAUDE_RISK_MODE": "enforce",
    "CLAUDE_RISK_RELAY": RELAY_URL,
    "CLAUDE_RISK_RELAY_WAIT": str(RELAY_WAIT_SECONDS),
}

# Claude Code kills a hook at its configured timeout, so the hook must be
# allowed to outlive the wrist wait — otherwise the card vanishes mid-glance.
WATCH_HOOK_TIMEOUT = RELAY_WAIT_SECONDS + 60

# Opt-in: let the classifier handle the boring tiers instead of only
# labelling them.
QUIET_ENV = {"CLAUDE_RISK_AUTO_ALLOW": "LOW"}


def _edit_settings_env(mutate):
    """Shared plumbing for every settings-toggling command.

    Reads settings, hands the parsed data to ``mutate``, and — only when
    ``mutate`` returns a message — backs up, writes, and prints it.
    ``mutate`` returning None means everything was already as requested
    (it prints its own explanation); nothing is written then.
    """
    found = _settings_or_explain()
    if found is None:
        return 1
    path, data = found
    data.setdefault("env", {})
    message = mutate(data)
    if message is None:
        return 0
    backup = _backup(path)
    if not data["env"]:
        data.pop("env", None)
    _write_settings(path, data)
    print(message % {"path": path} if "%(path)s" in message else message)
    if backup:
        print("  Backup   : %s" % backup)
    return 0


def _set_hook_timeout(data, timeout):
    for handler in _settings_handlers(data):
        handler["timeout"] = timeout


def run_watch(enable=True):
    """Turn wrist approvals on (or off) for every Claude Code session.

    The hook reads its mode from the environment, and a hook launched by a
    real session only sees what settings.json puts there — which is why
    exporting the variables in one shell silently did nothing for the
    sessions that matter. This writes them where every session reads them.

    A plugin install is the one case this cannot reach: the manifest puts
    CLAUDE_RISK_MODE on the hook's own command line, and an inline
    assignment beats anything settings.json exports. Saying "wrist
    approvals are OFF" there would be a lie, so say what is true instead.
    """
    plugin = _plugin_only_install()
    if plugin and plugin["env"].get("CLAUDE_RISK_MODE") == "enforce":
        if enable:
            print("Wrist approvals are already on — the Claude Code plugin")
            print("turns them on for every session.")
            return 0
        print("Wrist approvals come from the Claude Code plugin, not from")
        print("%s — so this flag cannot turn them off." % _settings_path())
        print("Turn them off with:")
        print("  /plugin disable %s" % PLUGIN_NAME)
        return 1

    def mutate(data):
        env = data["env"]
        if enable:
            if all(env.get(key) == value for key, value in WATCH_ENV.items()):
                print("Wrist approvals are already on for every session.")
                return None
            env.update(WATCH_ENV)
            _set_hook_timeout(data, WATCH_HOOK_TIMEOUT)
            return (
                "Wrist approvals are ON for every new Claude Code session.\n"
                "  Settings : %(path)s\n"
                "  Relay    : " + WATCH_ENV["CLAUDE_RISK_RELAY"] + "\n"
                "  Wait     : a card stays on the watch until answered —\n"
                "             here or anywhere else (up to "
                + _human_duration(RELAY_WAIT_SECONDS) + ").\n"
                "             Lowering your wrist never retracts it. With no\n"
                "             watch around at all, prompts go straight to the\n"
                "             terminal as usual.\n"
                "\n"
                "Every risky prompt goes to your watch first. Nothing is\n"
                "auto-allowed — add --quiet if you want the SAFE and LOW\n"
                "tiers handled for you. Ignore a card and the prompt still\n"
                "appears in the terminal as usual; nothing is ever blocked.\n"
                "Turn it off again with --no-watch.\n"
                "\n"
                "Already-running sessions keep their old setting until restarted.")
        if not any(key in env for key in WATCH_ENV):
            print("Wrist approvals are already off.")
            return None
        for key in WATCH_ENV:
            env.pop(key, None)
        _set_hook_timeout(data, 10)
        return ("Wrist approvals are OFF. The classifier keeps watching and\n"
                "logging in shadow mode; nothing reaches the watch.\n"
                "\n"
                "Already-running sessions keep their old setting until restarted.")

    return _edit_settings_env(mutate)


def run_quiet(enable=True):
    """Turn auto-allowing of the boring tiers on or off, for every session."""
    def mutate(data):
        env = data["env"]
        if enable:
            if env.get("CLAUDE_RISK_AUTO_ALLOW") == QUIET_ENV["CLAUDE_RISK_AUTO_ALLOW"]:
                print("Already handling SAFE and LOW prompts for you.")
                return None
            env.update(QUIET_ENV)
            return ("SAFE and LOW prompts will be answered for you; everything\n"
                    "else still reaches you. CRITICAL is never auto-allowed.")
        if "CLAUDE_RISK_AUTO_ALLOW" not in env:
            print("Nothing is being auto-allowed — that is the default.")
            return None
        env.pop("CLAUDE_RISK_AUTO_ALLOW", None)
        return ("Nothing will be auto-allowed. Risk tiers now only label the\n"
                "card; every prompt still reaches you.")

    return _edit_settings_env(mutate)


def check_command(command):
    """Confirm a hook command can actually run.

    settings.json can name an interpreter or script that has since moved or
    been deleted — an Xcode-bundled python3 after an Xcode update, say. A
    hook that cannot start is non-blocking: Claude Code just asks the user
    instead, so the failure is silent and the log quietly stops growing.
    Returns a list of human-readable problems; empty means healthy.
    """
    import shutil
    problems = []
    try:
        parts = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        return ["the command in settings.json cannot be parsed"]
    if not parts:
        return ["the command in settings.json is empty"]
    # A hook command may set variables before naming the interpreter —
    # the plugin manifest does exactly that.
    _assignments, parts = _split_assignments(parts)
    if not parts:
        return ["that command sets variables but never runs anything"]

    interpreter = parts[0].strip('"')
    if os.sep in interpreter or (os.altsep and os.altsep in interpreter):
        if not os.path.exists(interpreter):
            problems.append("that interpreter no longer exists: %s" % interpreter)
    elif not shutil.which(interpreter):
        problems.append("%r is not on PATH" % interpreter)

    script = parts[1].strip('"') if len(parts) > 1 else None
    if script and not os.path.exists(script):
        problems.append("that script no longer exists: %s" % script)
    return problems


def status_facts():
    """Everything --status reports, as facts rather than lines, so a test
    can hold one of them without parsing a printout."""
    path = _settings_path()
    try:
        data = _read_settings(path)
        readable = True
    except ValueError:
        data, readable = {}, False
    handlers = _settings_handlers(data)
    plugin = _plugin_install()
    plugin_only = bool(plugin) and not handlers
    policy = load_policy()
    entries = read_audit(policy)
    mode = str(policy.get("mode", "shadow")).lower()
    if plugin_only:
        # The hook's own command line is the truth for a plugin install;
        # this shell's environment says nothing about it.
        mode = str(plugin["env"].get("CLAUDE_RISK_MODE", mode)).lower()
    relay_wired = _relay_wired(data) or bool(plugin and plugin["relay"])
    return {
        "settings_path": path, "readable": readable, "handlers": handlers,
        "plugin": plugin, "plugin_only": plugin_only, "mode": mode,
        "relay_wired": relay_wired, "login_item": os.path.exists(_launch_agent_path()),
        "relay_health": _relay_health(), "audit_path": _audit_path(policy),
        "entries": entries,
    }


def _relay_health():
    """The running relay's /health, or None when nothing answers."""
    return _relay_json("/health")


def _relay_json(path, timeout=1):
    """GET a path on the local relay as JSON, or None when nothing answers.
    Signed with the key file: loopback alone opens only /health (S2)."""
    try:
        import time
        import urllib.parse
        import urllib.request
        import uuid
        url = RELAY_URL + path
        headers = {}
        key = _relay_key({})
        if key:
            split = urllib.parse.urlsplit(url)
            stamp, nonce = int(time.time()), uuid.uuid4().hex
            mac = _relay_signature(key, "GET", urllib.parse.unquote(split.path),
                                   stamp, nonce, b"", split.query)
            headers["X-Tapproval-Signature"] = wire.signature_header(stamp, nonce, mac)
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            return json.loads(reply.read())
    except Exception:
        return None


def _away_answers(url):
    """Does the away address reach this relay from the internet? The relay
    answers under its secret path in JSON — a 401/403 without a key is an
    answer; Cloudflare's own error pages are HTML. None when unknown."""
    if not url:
        return None
    return wire.answers_as_relay(url.rstrip("/") + "/health", 8, "Tapproval-status")


RELAY_LOG_PATH = "~/.tapproval/logs/relay.log"


def connection_lines(health, tunnel, away_ok):
    """The Connection block of --status, as lines, and the one next step.

    `health` is the relay's /health (None: not running), `tunnel` its
    /tunnel, `away_ok` whether the away address answered from outside
    (None: not asked). Pure, so a test can hold every case."""
    lines = ["", "Connection"]
    if health is None:
        lines.append("Relay         : not running")
        lines.append("Next step     : start it: python3 ~/.tapproval/watch_relay.py --ensure")
        lines.append("Relay log     : %s" % RELAY_LOG_PATH)
        return lines
    lines.append("Relay         : running, helper %s" % health.get("helper", "?"))
    icloud = health.get("alert_route") == "bridge"
    lines.append("iCloud route  : %s" % ("on (the Mac bridge is polling)" if icloud
                                         else "off (no Mac bridge is polling)"))
    url = (tunnel or {}).get("url")
    if not url:
        lines.append("Away address  : none yet")
    elif away_ok:
        lines.append("Away address  : answers from the internet")
    elif away_ok is False:
        lines.append("Away address  : does not answer from the internet")
    else:
        lines.append("Away address  : %s" % url.split("/t/")[0])
    lines.append("Tailscale     : %s" % ((tunnel or {}).get("tailscale") or "not on Tailscale"))
    seen = health.get("watch_seen_seconds_ago")
    lines.append("Watch         : %s" % ("seen %ds ago" % seen if seen is not None
                                         else "not seen recently"))
    problems = [c.get("detail") for c in health.get("conditions") or [] if c.get("detail")]
    for detail in problems:
        lines.append("Problem       : %s" % detail)
    if problems:
        step = problems[0]
    elif url and away_ok is False:
        step = ("the away address is not answering; the relay reopens it "
                "within a few minutes, or restart it with --ensure")
    elif not health.get("paired_ever", True):
        step = "pair a watch: tell Claude Code 'Open Tapproval pairing'"
    else:
        step = "none"
    lines.append("Next step     : %s" % step)
    lines.append("Relay log     : %s" % RELAY_LOG_PATH)
    return lines


def run_status():
    """Plain-English answer to 'is this thing on?'"""
    f = status_facts()
    plugin, handlers = f["plugin"], f["handlers"]
    print("Settings file : %s" % f["settings_path"])
    if not f["readable"]:
        print("Installed     : unknown \u2014 that file is not valid JSON")
    elif f["plugin_only"]:
        print("Installed     : yes \u2014 as a Claude Code plugin")
        print("Plugin        : %s" % plugin["root"])
    elif not handlers:
        print("Installed     : no \u2014 run with --install, or install the")
        print("                Claude Code plugin")
    else:
        print("Installed     : yes")
        for handler in handlers:
            command = handler.get("command")
            print("Command       : %s" % command)
            if command != _hook_command():
                print("                (points at a different copy than this one)")
            for problem in check_command(command or ""):
                print("  BROKEN      : %s" % problem)
                print("                Nothing is being recorded. Re-run --install")
                print("                from the folder you want to use.")

    if f["mode"] == "enforce":
        print("Mode          : enforce \u2014 decisions are being acted on")
    else:
        print("Mode          : shadow \u2014 watching only, nothing is being")
        print("                blocked or auto-approved")

    if f["relay_wired"]:
        print("Relay hook    : starts itself with every Claude Code session")
    else:
        print("Relay hook    : not wired \u2014 re-run --install to add it")
    codex_wired = bool(os.path.exists(_codex_hooks_path()) and _settings_handlers(
        _read_settings_quietly(_codex_hooks_path())))
    if codex_wired:
        print("Codex         : wired; Codex runs it once approved in codex, /hooks")
    elif os.path.isdir(_codex_home()):
        print("Codex         : not wired \u2014 re-run --install to add it")
    print("Version       : %s" % __version__)
    if f["login_item"]:
        print("Reboot        : the relay wakes again at login")
    elif f["plugin_only"]:
        print("Reboot        : the first Claude Code session brings the relay")
        print("                back \u2014 the plugin adds no login item")
    else:
        print("Reboot        : no login wake-up \u2014 the relay waits for"
              " the first session; re-run --install to add it")
    health = f["relay_health"]
    closed = _bridge_status_line(health)
    if closed:
        print(closed)
    tunnel = _relay_json("/tunnel") if health is not None else None
    away = _away_answers((tunnel or {}).get("url")) if tunnel else None
    for line in connection_lines(health, tunnel, away):
        print(line)
    print("")

    entries = f["entries"]
    print("Audit log     : %s" % f["audit_path"])
    if entries:
        print("Decisions     : %d recorded" % len(entries))
        first = str(entries[0].get("ts", ""))[:10]
        if first:
            print("Collecting    : since %s" % first)
        print("")
        print("Ready to summarise \u2014 run this script again with --report.")
    elif handlers or plugin:
        print("Decisions     : none yet")
        print("")
        print("If you have used Claude Code since installing and this is still")
        print("empty, the hook is not firing. Check that you started a new")
        print("session, and that your permission mode actually prompts you.")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    # The hook's own call — no arguments, or Codex's ``--agent codex`` —
    # skips argparse: it runs once per tool call and would never use it.
    if not argv or (len(argv) == 2 and argv[0] == "--agent"
                    and argv[1] in ("claude", "codex")):
        return _guarded(run_hook, agent=argv[1] if argv else None)
    import argparse
    parser = argparse.ArgumentParser(
        description="Risk triage for Claude Code permission prompts.",
        epilog="With no arguments, reads a PermissionRequest event on stdin.",
    )
    parser.add_argument("--explain", metavar="INPUT",
                        help="classify a command or path and print the reasoning")
    parser.add_argument("--tool", default="Bash",
                        help="tool name to use with --explain (default: Bash)")
    parser.add_argument("--report", action="store_true",
                        help="summarise the audit log")
    parser.add_argument("--agent", choices=("claude", "codex"), default=None,
                        help="which agent runs this hook (Codex's hooks.json says codex)")
    parser.add_argument("--install", action="store_true",
                        help="register this script as a hook in settings.json")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove the hook from settings.json")
    parser.add_argument("--status", action="store_true",
                        help="report whether the hook is installed and collecting")
    parser.add_argument("--quiet", action="store_true",
                        help="also let the classifier handle SAFE and LOW "
                             "prompts for you instead of only labelling them")
    parser.add_argument("--no-quiet", action="store_true",
                        help="stop auto-allowing anything (the default)")
    parser.add_argument("--watch", action="store_true",
                        help="send risky prompts to the watch, in every session")
    parser.add_argument("--no-watch", action="store_true",
                        help="stop sending prompts to the watch (back to shadow)")
    parser.add_argument("--no-bridge", action="store_true",
                        help="with --install: leave out (or remove) the Mac "
                             "bridge that lets a closed watch buzz through "
                             "your iCloud")
    parser.add_argument("--bridge", action="store_true",
                        help="with --install: put the Mac bridge back after "
                             "--no-bridge")
    return _guarded(_dispatch, parser.parse_args(argv))


def _guarded(run, *args, **kwargs):
    try:
        return run(*args, **kwargs)
    except BrokenPipeError:
        # Someone piped us into `head` or quit `less` early. Not an error.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


def _dispatch(args):
    if args.install:
        code = run_install(then_watch=args.watch,
                           bridge=(False if args.no_bridge
                                   else True if args.bridge else None))
        if code or not args.watch:
            return code
        print("")
        return run_watch(True)
    if args.uninstall:
        return run_uninstall()
    if args.quiet:
        return run_quiet(True)
    if args.no_quiet:
        return run_quiet(False)
    if args.watch:
        return run_watch(True)
    if args.no_watch:
        return run_watch(False)
    if args.status:
        return run_status()
    if args.report:
        return run_report()
    if args.explain is not None:
        return run_explain(args.explain, args.tool)
    return run_hook(agent=args.agent)


if __name__ == "__main__":
    sys.exit(main())
