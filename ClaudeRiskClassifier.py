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

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from enum import IntEnum

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


# How long a card may stay on the wrist. The hook timeout written by
# --watch is derived from this so it always outlives the wait. A full day:
# prompts must never expire on the user — a card stands until it is
# answered somewhere, and answering it elsewhere retracts it at once.
RELAY_WAIT_SECONDS = 86400

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
    "headline_chars": 64,
    "detail_chars": 80,
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
    r"credential|\bsecrets?\.(json|ya?ml|txt)|\.aws[/\\]|\.ssh[/\\]|\.netrc)",
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
SEGMENT_SPLIT = re.compile(r"\s*(?:\|\||&&|;|\||\n)\s*")

# Leading VAR=value assignments before the real command.
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+")


# --------------------------------------------------------------------------
# Bash classification
# --------------------------------------------------------------------------

# Commands that cannot mutate anything on their own. A redirect or command
# substitution elsewhere in the segment still bumps the tier.
READ_ONLY_COMMANDS = frozenset(
    """
    ls ll la cat bat head tail wc grep egrep fgrep rg ag find fd pwd cd which
    whereis type echo printf date whoami hostname uname tree du df file stat
    sort uniq diff comm basename dirname realpath readlink jq yq column less
    sw_vers system_profiler
    more nl cut tr rev tac awk true false test id groups locale ps top
    pytest mypy flake8 tox nox
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
        return True
    command = " ".join(str((tool_input or {}).get("command", "")).split())
    if not command or "$(" in command or "`" in command:
        return False
    return all(_first_token(segment) in CC_SILENT_LEADS
               for segment in _segments(command))


# Safe unless the pattern matches, in which case the command writes.
CONDITIONALLY_SAFE = {
    "sed": re.compile(r"(^|\s)-i\b"),
    "ruff": re.compile(r"\b(format|--fix)\b"),
    "npm": re.compile(r"\bnpm\s+(?!test\b|ls\b|list\b|view\b|outdated\b)"),
}

# Tools judged by their first argument — a subcommand verb. SAFE only for
# verbs positively recognised as read-only; anything else falls through to
# unknown-command. This widens what the classifier *recognises*, never what
# it forgives. Aliases share one set so they cannot drift apart.
_PIP_READ_ONLY = frozenset("list show freeze --version".split())
_FLY_READ_ONLY = frozenset("status logs list info version apps".split())

VERB_TOOLS_READ_ONLY = {
    "gh": frozenset("auth browse search view list diff checks status".split()),
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
    "swift": frozenset("--version package".split()),
    "flyctl": _FLY_READ_ONLY,
    "fly": _FLY_READ_ONLY,
    "systemctl": frozenset("status list-units is-active show".split()),
    "launchctl": frozenset("list print".split()),
    "ipconfig": frozenset("getifaddr getpacket getoption".split()),
    "networksetup": frozenset("-listallhardwareports -getinfo".split()),
    "tailscale": frozenset("status ip version netcheck".split()),
    "gcloud": frozenset("info version config".split()),
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

# Sub-subcommands that read despite living under a writing verb.
SUBCOMMAND_SECOND_LEVEL = {
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
    r"|(^|\s)(-f|-F|--field|--raw-field|--input)(\s|=|$)", re.I)


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
    ("pipe-to-shell", re.compile(r"\|\s*(sudo\s+)?(ba|z|k|fi|da)?sh\b"), Risk.CRITICAL),
    ("fork-bomb", re.compile(r":\s*\(\s*\)\s*\{.*\}\s*;\s*:"), Risk.CRITICAL),
    ("history-rewrite", re.compile(r"\bgit\s+filter-(branch|repo)\b"), Risk.CRITICAL),
    ("cmd-substitution", re.compile(r"\$\(|`"), Risk.MEDIUM),
    ("redirect-write", re.compile(r"(?<![0-9<>])>>?(?!\s*/dev/null)"), Risk.MEDIUM),
]

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
]

RM_RE = re.compile(r"\brm\b((?:\s+-{1,2}[A-Za-z-]+)*)\s*(.*)")
GIT_RE = re.compile(r"\bgit\s+(?:-\S+\s+)*([a-z][a-z-]*)\b(.*)", re.I)

# Targets that mean "wipe the machine" or "wipe my home directory".
CATASTROPHIC_TARGETS = re.compile(
    r"^(/|//|/\*|~|~/|~/\*|\$HOME|\$HOME/\*|\.|\.\.|\*|"
    r"/(bin|boot|dev|etc|home|lib|opt|root|sbin|srv|usr|var|Users|Windows)/?\*?)$"
)


def _segments(command):
    """Split a shell command into independently-classifiable segments."""
    return [s.strip() for s in SEGMENT_SPLIT.split(command or "") if s.strip()]


def _tokens(segment):
    """Words of a segment, with env assignments and a leading '(' stripped."""
    stripped = ENV_ASSIGN.sub("", segment.strip())
    stripped = re.sub(r"^\(\s*", "", stripped)
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
    recursive = bool(re.search(r"-[A-Za-z]*[rR]", flags))
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

    if sub == "push":
        if forced and re.search(r"\b(main|master|prod|production|release)\b", rest):
            return ("git-force-push-protected", Risk.CRITICAL)
        if forced:
            return ("git-force-push", Risk.HIGH)
        return ("git-push", Risk.HIGH)
    if sub == "reset" and "--hard" in rest:
        return ("git-reset-hard", Risk.HIGH)
    if sub == "clean" and re.search(r"-[a-z]*f", rest):
        return ("git-clean-force", Risk.HIGH)
    if sub in GIT_READ_ONLY:
        return ("git-read", Risk.SAFE)
    if sub in GIT_MEDIUM:
        return ("git-write", Risk.MEDIUM)
    return ("git-other", Risk.MEDIUM)


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

    for segment in _segments(command):
        token = os.path.basename(_first_token(segment)).lower()

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


def classify_path(path, cwd=None):
    """Classify a filesystem write target. Returns ``(Risk, [rule_id, ...])``."""
    if not path:
        return Risk.MEDIUM, ["no-path"]

    normalised = str(path).replace("\\", "/")

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

MCP_WRITE = re.compile(
    r"^mcp__[^_]+__(create|update|delete|merge|push|write|send|add|remove|set|"
    r"publish|trigger|run|submit|enable|disable|fork|resolve|reply)",
    re.I,
)

CONTENT_KEYS = ("content", "new_string", "file_text", "new_source")


def classify(event):
    """Classify a ``PermissionRequest`` event. Returns a result dict."""
    tool = (event or {}).get("tool_name") or ""
    tool_input = (event or {}).get("tool_input") or {}
    cwd = (event or {}).get("cwd")
    if not isinstance(tool_input, dict):
        tool_input = {}

    if tool == "Bash" or tool == "BashOutput":
        risk, rules = classify_bash(tool_input.get("command", ""))
    elif tool in WRITE_TOOLS:
        risk, rules = classify_path(
            tool_input.get("file_path") or tool_input.get("notebook_path"), cwd
        )
        # A benign path can still carry a destructive payload.
        content = " ".join(
            str(tool_input.get(key, "")) for key in CONTENT_KEYS if tool_input.get(key)
        )
        if content:
            if SQL_DESTRUCTIVE.search(content):
                risk, rules = max(risk, Risk.CRITICAL), rules + ["sql-destructive"]
            elif SQL_MUTATION.search(content):
                risk, rules = max(risk, Risk.HIGH), rules + ["sql-mutation"]
            else:
                for rule_id, pattern, level in SITE_RULES:
                    if pattern.search(content):
                        risk, rules = max(risk, level), rules + [rule_id]
                        break
    elif tool in READ_ONLY_TOOLS:
        risk, rules = Risk.SAFE, ["read-only-tool"]
    elif tool == "WebSearch":
        risk, rules = Risk.LOW, ["web-search"]
    elif tool == "WebFetch":
        risk, rules = Risk.MEDIUM, ["network-egress"]
    elif tool in ("Task", "Agent", "Workflow"):
        risk, rules = Risk.MEDIUM, ["spawns-agents"]
    elif tool.startswith("mcp__"):
        if MCP_WRITE.match(tool):
            risk, rules = Risk.HIGH, ["mcp-write"]
        else:
            risk, rules = Risk.MEDIUM, ["mcp-unknown"]
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
    """Truncate to ``limit`` characters with an ellipsis."""
    text = " ".join(str(text or "").split())
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
        recursive = bool(re.search(r"-[A-Za-z]*[rR]", rm_match.group(1) or ""))
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
HEADLINE_CHARS = 64
DETAIL_CHARS = 80


def _card_budgets(policy):
    return (int(policy.get("headline_chars", HEADLINE_CHARS)),
            int(policy.get("detail_chars", DETAIL_CHARS)))


def wrist_card(tool, tool_input, risk,
               headline_chars=HEADLINE_CHARS, detail_chars=DETAIL_CHARS):
    """Build the compact card a watch face can render in one glance."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}

    if tool == "AskUserQuestion":
        questions = tool_input.get("questions")
        first = (questions[0]
                 if isinstance(questions, list) and questions else {})
        if isinstance(first, dict):
            question = " ".join(str(first.get("question", "")).split())
            options = [
                " ".join(str(o.get("label", "")).split())
                for o in (first.get("options") or [])
                if isinstance(o, dict) and o.get("label")
            ][:4]
        else:
            question, options = "", []
        card = {
            "kind": "question",
            "tier": risk.name,
            "headline": _fit(question or "Claude has a question",
                             headline_chars * 2),
            "detail": _fit(" · ".join(options), detail_chars),
        }
        if options:
            card["options"] = options
        return card

    if tool in ("Bash", "BashOutput"):
        command = tool_input.get("command", "")
        # Claude describes its own tool calls, and that description is what
        # the phone app shows ("Check mergeability of every open PR"). Use
        # the same words on the wrist; the command itself is the detail.
        described = " ".join(str(tool_input.get("description") or "").split())
        headline = (_fit(described, headline_chars) if described
                    else _bash_headline(command, headline_chars))
        detail = _fit(command, detail_chars)
    elif tool in WRITE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        verb = "Write" if tool == "Write" else "Edit"
        headline = _fit(
            "%s %s" % (verb, os.path.basename(str(path).rstrip("/\\")) or path),
            headline_chars,
        )
        detail = _fit("%s %s" % (verb, path), detail_chars)
    elif tool.startswith("mcp__"):
        parts = tool.split("__")
        server = parts[1] if len(parts) > 1 else "mcp"
        action = parts[2] if len(parts) > 2 else ""
        headline = _fit("%s: %s" % (server, action.replace("_", " ")), headline_chars)
        detail = _fit(json.dumps(tool_input, ensure_ascii=False), detail_chars)
    else:
        headline = _fit(tool or "Unknown tool", headline_chars)
        # The full arguments, truncated — never a single field: an approval
        # surface that hides which repo/table/host is targeted invites a
        # blind tap.
        detail = _fit(json.dumps(tool_input, ensure_ascii=False),
                      detail_chars)

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


def write_audit(entry, policy):
    """Append one decision to the audit trail. Never raises."""
    path = _audit_path(policy)
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
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
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return entries


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


def _project_name(cwd):
    """Folder name of the session's working directory.

    Deliberately the basename, not the full path: enough to break a report
    down per project, without writing directory structure into a log that
    gets read aloud.
    """
    if not cwd:
        return None
    return os.path.basename(str(cwd).replace("\\", "/").rstrip("/")) or None


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


def build_response(event, policy):
    """Classify one event; returns ``(response_dict, audit_entry, card)``.

    The card returned here is the one the relay shows: run_hook must not
    rebuild it, or the audit log and the wrist could silently disagree.
    """
    result = classify(event)
    risk = result["risk"]
    card = wrist_card(
        result["tool"],
        result["tool_input"],
        risk,
        *_card_budgets(policy),
    )
    card["tool"] = result["tool"]
    card["session_id"] = str((event or {}).get("session_id") or "")[:64]
    card["fingerprint"] = _card_fingerprint(result["tool"],
                                            result["tool_input"])
    # The phone offers "don't ask again" exactly when Claude Code sends
    # permission suggestions with the prompt — mirror that, so the wrist
    # never offers a third choice the phone doesn't have.
    card["can_always"] = bool((event or {}).get("permission_suggestions"))
    decision, reason = decide(risk, policy)

    shadow = str(policy.get("mode", "shadow")).lower() != "enforce"
    effective = "escalate" if shadow else decision

    audit = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": (event or {}).get("session_id"),
        "project": _project_name((event or {}).get("cwd")),
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

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": effective,
            "decisionReason": "[%s] %s" % (risk.name, reason),
        }
    }
    return response, audit, card


def ask_watch(card, policy, project=None):
    """Offer an escalated card to the watch relay. Returns the verdict.

    "allow" and "deny" are a human's answer arriving from the watch — this
    is not auto-allowing, so it applies to any tier, CRITICAL included.
    Everything else — relay down, timeout, malformed reply, unexpected
    decision string — collapses to "none" and the normal prompt appears.
    Never raises.
    """
    import urllib.error
    import urllib.request

    relay = str(policy.get("relay") or "").strip().rstrip("/")
    if not relay.startswith(("http://", "https://")):
        return "none", None
    try:
        wait = float(policy.get("relay_wait", 6.0))
    except (TypeError, ValueError):
        wait = 6.0
    wait = max(0.0, min(wait, float(RELAY_WAIT_SECONDS)))

    payload = dict(card)
    if project:
        payload["project"] = project
    body = json.dumps({"card": payload, "wait": wait}).encode("utf-8")
    request = urllib.request.Request(
        relay + "/card", data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=wait + 3.0) as reply:
            answer = json.loads(reply.read().decode("utf-8"))
    except Exception as error:
        print("ClaudeRiskClassifier: watch relay unavailable (%s)" % error,
              file=sys.stderr)
        return "none", None
    if not isinstance(answer, dict):
        return "none", None
    decision = answer.get("decision")
    if decision == "answer" and answer.get("answer"):
        return "answer", str(answer["answer"])[:200]
    return (decision if decision in ("allow", "deny") else "none"), None


ESCALATE_FALLBACK = {
    "hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": "escalate",
        "decisionReason": "Risk classifier failed — deferring to human",
    }
}


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


def run_hook(stdin=None, stdout=None):
    """Hook mode: read the event from stdin, write the decision to stdout."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        raw = stdin.read()
        event = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("event is not a JSON object")
        policy = load_policy()
        response, audit, card = build_response(event, policy)
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
        if wants_wrist:
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
        if wants_wrist:
            verdict, chosen = ask_watch(card, policy,
                                        project=audit.get("project"))
            audit["watch"] = verdict
            if verdict == "answer" and chosen:
                # A question card answered on the wrist: deny-with-reason is
                # the one hook channel that can carry the user's words back
                # to Claude, which then proceeds on the chosen option.
                audit["effective"] = "deny"
                audit["answer"] = chosen
                response["hookSpecificOutput"]["decision"] = "deny"
                response["hookSpecificOutput"]["decisionReason"] = (
                    "The user answered from their watch: %s" % chosen)
            elif verdict in ("allow", "deny"):
                audit["effective"] = verdict
                response["hookSpecificOutput"]["decision"] = verdict
                response["hookSpecificOutput"]["decisionReason"] += (
                    " — %s from watch"
                    % ("approved" if verdict == "allow" else "denied"))
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


def run_report():
    """Summarise the audit log: how many prompts would the watch have raised?"""
    policy = load_policy()
    entries = read_audit(policy)
    if not entries:
        print("No audit entries at %s" % _audit_path(policy))
        print("Run some Claude Code sessions with the hook installed first.")
        return 0

    total = len(entries)
    tiers = Counter(e.get("tier", "?") for e in entries)
    decisions = Counter(e.get("decision", "?") for e in entries)
    escalated = decisions.get("escalate", 0) + decisions.get("deny", 0)
    saved = total - escalated

    print("Audit log : %s" % _audit_path(policy))
    print("Events    : %d" % total)
    print("")
    print("Risk tiers")
    for tier in ("SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        count = tiers.get(tier, 0)
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

    projects = sorted({e.get("project") for e in entries if e.get("project")})
    if len(projects) > 1:
        print("By project")
        for name in projects:
            rows = [e for e in entries if e.get("project") == name]
            asked = len([e for e in rows
                         if e.get("decision") in ("escalate", "deny")])
            share = 100.0 * (len(rows) - asked) / len(rows) if rows else 0.0
            print("  %-24s %5d asked %4d  (%.0f%% silenced)"
                  % (name[:24], len(rows), asked, share))
        print("")

    by_tool = Counter(e.get("tool", "?") for e in entries if e.get("decision") == "allow")
    if by_tool:
        print("Top auto-allowed tools")
        for tool, count in by_tool.most_common(5):
            print("  %-24s %d" % (tool, count))
        print("")

    escalations = [e for e in entries if e.get("decision") in ("escalate", "deny")]
    if escalations:
        print("Most recent escalations")
        for entry in escalations[-5:]:
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


def _is_our_hook(handler):
    command = str(handler.get("command", ""))
    return (os.path.basename(__file__) in command
            or "watch_relay.py" in command)


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
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2) + "\n")


def run_install():
    """Register this script as a PermissionRequest hook. Safe to re-run."""
    path = _settings_path()
    try:
        data = _read_settings(path)
    except ValueError as error:
        print("Could not read %s" % path)
        print("  It is not valid JSON (%s)." % error)
        print("  Nothing was changed. Fix or move that file, then try again.")
        return 1

    command = _hook_command()
    relay_command = _relay_command() if os.path.exists(_relay_path()) else None
    hooks = data.setdefault("hooks", {})
    entries = hooks.setdefault("PermissionRequest", [])
    starters = hooks.setdefault("SessionStart", [])

    def _sync(entry_list, wanted, matcher, marker):
        """Idempotently point our hook entry at ``wanted``. True if changed."""
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

    changed = _sync(entries, command, "*", os.path.basename(__file__))
    if relay_command:
        changed = _sync(starters, relay_command, None,
                        "watch_relay.py") or changed
    if not starters:
        hooks.pop("SessionStart", None)

    if not changed:
        print("Already installed, and the paths are correct.")
        print("  Settings : %s" % path)
        print("  Command  : %s" % command)
        print("  Nothing to do.")
        return 0

    backup = _backup(path)
    _write_settings(path, data)

    print("Installed.")
    print("  Settings : %s" % path)
    print("  Command  : %s" % command)
    if relay_command:
        print("  Relay    : starts itself with every Claude Code session")
    if backup:
        print("  Backup   : %s" % backup)
    print("")
    print("Nothing about your sessions changes yet: the classifier starts in")
    print("shadow mode, so every permission prompt still reaches you exactly")
    print("as before. It only writes down what it would have done.")
    print("")
    print("Next: start a new Claude Code session, work normally for a week,")
    print("then run this script again with --report.")
    return 0


def run_uninstall():
    """Remove our hook entry, leaving everything else in settings untouched."""
    path = _settings_path()
    try:
        data = _read_settings(path)
    except ValueError as error:
        print("Could not read %s (%s). Nothing was changed." % (path, error))
        return 1

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        print("Not installed — nothing to remove.")
        return 0

    backup = _backup(path)
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

    if not removed:
        print("Not installed — nothing to remove.")
        return 0

    if not hooks:
        data.pop("hooks", None)
    # The env block we injected goes too — leaving CLAUDE_RISK_* behind
    # is harmless but untidy, and an uninstall should be a clean exit.
    env = data.get("env")
    if isinstance(env, dict):
        for key in list(env):
            if key.startswith("CLAUDE_RISK_"):
                env.pop(key)
        if not env:
            data.pop("env", None)
    _write_settings(path, data)

    print("Removed. Your other settings were left untouched.")
    print("  Settings : %s" % path)
    if backup:
        print("  Backup   : %s" % backup)
    print("  The audit log was left in place; delete it yourself if you want it gone.")
    return 0


WATCH_ENV = {
    "CLAUDE_RISK_MODE": "enforce",
    "CLAUDE_RISK_RELAY": "http://127.0.0.1:%d" % 8977,
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
    path = _settings_path()
    try:
        data = _read_settings(path)
    except ValueError as error:
        print("Could not read %s (%s). Nothing was changed." % (path, error))
        return 1
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
    for entry in data.get("hooks", {}).get("PermissionRequest", []):
        for handler in entry.get("hooks", []):
            if _is_our_hook(handler):
                handler["timeout"] = timeout


def run_watch(enable=True):
    """Turn wrist approvals on (or off) for every Claude Code session.

    The hook reads its mode from the environment, and a hook launched by a
    real session only sees what settings.json puts there — which is why
    exporting the variables in one shell silently did nothing for the
    sessions that matter. This writes them where every session reads them.
    """
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
                + str(RELAY_WAIT_SECONDS // 60) + " minutes).\n"
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
    problems = []
    try:
        parts = shlex.split(command, posix=(os.name != "nt"))
    except ValueError:
        return ["the command in settings.json cannot be parsed"]
    if not parts:
        return ["the command in settings.json is empty"]

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


def run_status():
    """Plain-English answer to 'is this thing on?'"""
    path = _settings_path()
    try:
        data = _read_settings(path)
        readable = True
    except ValueError:
        data, readable = {}, False

    handlers = [h
                for entry in data.get("hooks", {}).get("PermissionRequest", [])
                for h in entry.get("hooks", [])
                if _is_our_hook(h)]
    policy = load_policy()
    entries = read_audit(policy)
    mode = str(policy.get("mode", "shadow")).lower()

    print("Settings file : %s" % path)
    if not readable:
        print("Installed     : unknown \u2014 that file is not valid JSON")
    elif not handlers:
        print("Installed     : no \u2014 run with --install")
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

    if mode == "enforce":
        print("Mode          : enforce \u2014 decisions are being acted on")
    else:
        print("Mode          : shadow \u2014 watching only, nothing is being")
        print("                blocked or auto-approved")

    relay_wired = any(
        "watch_relay.py" in str(h.get("command", ""))
        for entry in data.get("hooks", {}).get("SessionStart", [])
        for h in entry.get("hooks", []))
    if relay_wired:
        print("Relay hook    : starts itself with every Claude Code session")
    else:
        print("Relay hook    : not wired \u2014 re-run --install to add it")
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:8977/health",
                                    timeout=1) as reply:
            health = json.loads(reply.read())
        seen = health.get("watch_seen_seconds_ago")
        watch = ("watch seen %ds ago" % seen) if seen is not None \
            else "no watch yet"
        print("Relay         : running (%s)" % watch)
    except Exception:
        print("Relay         : not running right now (starts with the next")
        print("                Claude Code session)")

    print("Audit log     : %s" % _audit_path(policy))
    if entries:
        print("Decisions     : %d recorded" % len(entries))
        first = str(entries[0].get("ts", ""))[:10]
        if first:
            print("Collecting    : since %s" % first)
        print("")
        print("Ready to summarise \u2014 run this script again with --report.")
    elif handlers:
        print("Decisions     : none yet")
        print("")
        print("If you have used Claude Code since installing and this is still")
        print("empty, the hook is not firing. Check that you started a new")
        print("session, and that your permission mode actually prompts you.")
    return 0


def main(argv=None):
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
    args = parser.parse_args(argv)

    try:
        return _dispatch(args)
    except BrokenPipeError:
        # Someone piped us into `head` or quit `less` early. Not an error.
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0


def _dispatch(args):
    if args.install:
        return run_install()
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
    return run_hook()


if __name__ == "__main__":
    sys.exit(main())
