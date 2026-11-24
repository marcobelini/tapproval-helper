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
import fnmatch
import os
import posixpath
import re
import shlex
import sys
from collections import Counter
from datetime import datetime, timezone
from enum import IntEnum

import tapproval_wire as wire
import tapproval_host as _host  # noqa: E402  after wire: a hook missing both names wire

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
__version__ = "1.1.139"

# The project's own public page. Not a deployment hostname — those belong
# in site-rules.json — but a constant of the project itself, the same way
# the support address is, and the only address --report ever prints.
PROJECT_SITE = "https://tapproval.thoughtfulsteward.org"

# How long a card may stay on the wrist. The hook timeout written by
# --watch is derived from this so it always outlives the wait. A full day:
# prompts must never expire on the user — a card stands until it is
# answered somewhere, and answering it elsewhere retracts it at once.
RELAY_WAIT_SECONDS = 86400
# A relay that dies holding a card cuts the hook's connection, and the
# card was gone from the wrist for good (2026-10-23: a user's two cards,
# lost to a helper restart). Its replacement is usually listening within
# seconds, so the hook waits this long for one and posts the card again,
# at most RELAY_REPOSTS times. Only a cut connection counts: a relay that
# was never there, or a wait that ran out, still means the terminal asks.
RELAY_RETURN_SECONDS = 60.0
RELAY_REPOSTS = 3
# The socket outlives the card's wait by this much, so the relay's own
# "nobody answered" arrives before the hook gives up on it.
RELAY_REPLY_GRACE = 3.0
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
_SECRET_FILES = (
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
    r"\.claude\.json\b|[/\\]Cookies\b|[/\\]Login\\? Data\b|Messages[/\\]chat\.db|PRIVATE KEY|"
    # Codex's own account file, and a secret folder named without its
    # slash: `grep -r "" ~/.aws` and `ls ~/.ssh` read SAFE while the same
    # with a trailing `/` read HIGH (2026-11-01 review). A whole name only:
    # `notes.aws` and `.sshd_config_backups` are not the folder.
    r"\.codex[/\\]auth\.json\b|"
    # The token files of tools TOOL_REACH already knows, each a live login
    # in plain text and each SAFE to `cat` until the 2026-11-16 review:
    # fly, gcloud, Azure, Supabase, wrangler, glab and yarn.
    r"\.fly[/\\]config\.ya?ml|\.config[/\\]gcloud[/\\]|\.azure[/\\]|"
    r"\.supabase[/\\]access-token|\.wrangler[/\\]config[/\\]|"
    r"\.config[/\\]glab-cli[/\\]|\.yarnrc\.yml\b|"
    # The rest of the token stores in plain text, each SAFE to `cat` and
    # to the Read tool until the 2026-11-21 review: rclone, s3cmd, doctl,
    # Netlify, Stripe, Twilio, Linode, Backblaze, Railway, Vercel, every
    # kubeconfig in ~/.kube (not only `config`; its caches excepted),
    # Copilot, Composer, Maven, Gradle, ngrok, Sentry, Databricks, boto,
    # Firefox's saved logins and their key, GNOME's keyrings, and the
    # relay's own tunnel record.
    r"rclone\.conf\b|(?<![\w-])\.s3cfg\b|doctl[/\\]config\.ya?ml|netlify[/\\]config\.json|"
    r"stripe[/\\]config\.toml|\.twilio-cli[/\\]|\.config[/\\]linode-cli\b|"
    r"\.b2_account_info\b|\.railway[/\\]config\.json|vercel(?:\.cli)?[/\\]auth\.json|"
    r"\.kube[/\\](?!(?:http-)?cache(?:[/\\]|$|\s))[^\s/\\'\"]|"
    r"github-copilot[/\\](?:hosts|apps)\.json|\.config[/\\]github-copilot[/\\]|composer[/\\]auth\.json|"
    r"\.m2[/\\]settings(?:-security)?\.xml|\.gradle[/\\]gradle\.properties|"
    r"ngrok2?[/\\]ngrok\.ya?ml|(?<![\w-])\.sentryclirc\b|(?<![\w-])\.databrickscfg\b|"
    r"(?<![\w-])\.boto(?![\w.-])|(?<![\w-])(?:logins\.json|key[34]\.db)\b|"
    r"\.local[/\\]share[/\\]keyrings\b|\.tapproval-tunnel\.json|"
    # And these, each SAFE to `cat` and to the Read tool until the
    # 2026-11-22b review: sops' age keys, cloudflared's tunnel credentials,
    # wrangler's local secrets, Streamlit's, hub, Bundler, CircleCI,
    # configstore and hcloud logins, Java keystores, Terraform's variables,
    # an ssh key kept outside ~/.ssh, and zsh's history.
    r"sops[/\\]age[/\\]keys\.txt\b|\.cloudflared[/\\][^\s/\\]+\.json\b|(?<![\w-])\.dev\.vars\b|"
    r"\bsecrets?\.toml\b|\.config[/\\]hub\b|\.bundle[/\\]config\b|\.circleci[/\\]cli\.ya?ml\b|"
    r"\.config[/\\]configstore[/\\]|\.config[/\\]hcloud[/\\]|\.(?:keystore|jks)\b|"
    r"\.tfvars\b|\bid_(?:ecdsa|dsa)(?:_sk)?\b|\.zsh_sessions[/\\]|(?<![\w-])\.histfile\b|"
    r"(?<![\w-])\.(?:aws|ssh|gnupg|appstoreconnect)(?![\w.-])|\.tapproval[/\\]data(?![\w.-]))")
# A folder that holds one of the stores above, named on its own: a
# recursive search, a diff or a listing of it reads the store (`grep -r .
# ~/.tapproval` read SAFE, 2026-11-21 review). Only the folder itself:
# `~/.tapproval/relay.log` is a log. It counts only for a command that
# reads a folder's files (_SecretRead): a `cd` into it, or `git -C` it,
# reads none, and the owner's own `cd ~/.tapproval` is common. And only
# after a slash, as a path: a bare `.codex` is Swift's enum case far more
# often than the folder (a `cd ~` before it is followed below).
# The token stores of the 2026-11-16 list are folders too: `grep -r .
# ~/.azure` and `ls ~/.config/gcloud` read SAFE (2026-11-22 review).
# ~/.config itself holds gh's, gcloud's, rclone's and Copilot's stores: a
# `grep -r . ~/.config/` read every one of them SAFE (2026-11-22b review).
_SECRET_FOLDERS = (r"(?<=[/\\])\.(?:tapproval|codex|kube|config[/\\]gh|config[/\\]gcloud|azure"
                   r"|docker|fly|wrangler|supabase|twilio-cli|railway|m2|gradle|config"
                   r"|cloudflared|config[/\\](?:glab-cli|rclone|github-copilot|sops))"
                   r"[/\\]?(?![\w./\\-])")
SECRET_PATH = re.compile(_SECRET_FILES + "|" + _SECRET_FOLDERS, re.I)
# What lists names or sizes and never prints what a file says.
_NAME_LISTERS = frozenset("ls tree du stat file find fd wc".split())
# Every session's transcript holds its wrist code, which marks a message as
# the wearer's own words: one session reading another's could speak for the
# wearer (2026-11-22b review). MEDIUM, a card, not a secret: the owner reads
# them often, and it is the code's only copy most sessions can reach.
TRANSCRIPT_PATH = re.compile(r"\.claude[/\\]projects(?![\w.-])|\.codex[/\\](?:archived_)?sessions(?![\w.-])",
                             re.I)
SECRET_FILE_PATH = re.compile(_SECRET_FILES, re.I)


# What reads a folder's files when handed the folder: `git -C ~/.tapproval
# log` and `cd ~/.tapproval` read none of them, `grep -r`, `ls` and
# `git diff --no-index` do.
_FOLDER_READERS = frozenset(
    "grep egrep fgrep zgrep rgrep ggrep rg ag ack diff find fd ls tree tar zip 7z cp rsync "
    "scp sftp cat head tail less more bat strings xxd hexdump od file stat wc du sha256sum "
    "shasum md5 md5sum base64 gzip bzip2 xz zstd cpio pax ditto open code vim nano emacs "
    "sqlite3 jq yq awk sed sort uniq".split())


def _reads_a_folder(segment):
    """The command word after any env assignments: `LANG=C grep -r .
    ~/.tapproval` read SAFE, its first word an assignment (2026-11-22
    review). A wrapper (`sudo`, `env -u X`) is read again, unwrapped."""
    words = _tokens(segment.lstrip("{ "))
    if not words:
        return False
    lead = os.path.basename(_QUOTING.sub("", words[0])).lower()
    return lead in _FOLDER_READERS or (lead == "git" and "diff" in words)


class _SecretRead:
    """SECRET_PATH for a segment, with a folder named on its own counted
    only for a command that reads the folder's files."""

    @staticmethod
    def search(segment):
        if not SECRET_PATH.search(segment):
            return False
        return bool(SECRET_FILE_PATH.search(segment)) or _reads_a_folder(segment)

# A wildcard the shell expands before the tool sees it. Inside a hidden
# folder of the home directory — `~/.ss?/id_rs?`, `~/.config/*/hosts.yml`,
# `~/.s{sh}/id_{rsa}` — it names a secret store the literal list above
# cannot see, so it reads as one. Wildcards over visible files are left
# alone: `cat *.md` is not a credential read (2026-10-25 review). So is a
# wildcard in a hidden file's own name anywhere — `cat .en?` read SAFE
# beside `cat .env*`'s HIGH (2026-10-26 review); `./*.sh` is not one.
#
# The hidden name is read outside quotes, or as a quoted word that is that
# name and nothing else (`head '.npmr?'`): read anywhere, every jq filter
# was a secret read — `-q '.files[] | …'`, `--jq '.[0]'` — 1,263 of the
# owner's commands HIGH (2026-10-28). A bracket is a wildcard only around
# a letter: `.items[]` and `.body[1500:5000]` are jq, `.ss[h]` is a glob.
_HOME_HIDDEN_GLOB = re.compile(
    r"(?:^|[\s='\"])(?:~|\$\{?HOME\}?|/Users/[^/\s]+|/home/[^/\s]+)/\.[^\s'\"();|&<>]*[*?\[{]")
_HIDDEN_NAME_GLOB = (r"\.[\w-][\w.-]*(?:[*?]|\[!?[A-Za-z][^\]\s]*\]|\{[^}\s]*\})"
                     r"[\w.*?\[\]{},-]*")
_HIDDEN_GLOB_BARE = re.compile(r"(?:^|[\s=/])(?:%s|\.[*?])" % _HIDDEN_NAME_GLOB)
_HIDDEN_GLOB_WORD = re.compile(r"(?:[\w./-]*/)?%s" % _HIDDEN_NAME_GLOB)
_QUOTED = re.compile(r"'([^']*)'|\"((?:\\.|[^\"\\])*)\"")
# A heredoc's marker: group 1 the `-` that strips tabs, group 3 the delimiter.
_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([\w.@:+-]+)\2")


def _without_heredoc_bodies(text):
    """``text`` with each heredoc's body left out: it is a program's input,
    and the shell expands no wildcard in it (`python3 - <<'EOF'` with a
    `.env*` in its code read HIGH, 2026-10-28)."""
    kept, pending = [], []
    for line in text.split("\n"):
        if pending:
            delimiter, tabs = pending[0]
            if (line.lstrip("\t") if tabs else line) == delimiter:
                pending.pop(0)
            continue
        kept.append(line)
        pending = [(m.group(3), bool(m.group(1))) for m in _HEREDOC.finditer(line)]
    return "\n".join(kept)


class _SecretGlob:
    """SECRET_GLOB's `search`, by the rules above."""

    @staticmethod
    def search(text):
        text = _without_heredoc_bodies(text)
        if _HOME_HIDDEN_GLOB.search(text):
            return True
        if _HIDDEN_GLOB_BARE.search(_QUOTED.sub(" ", text)):
            return True
        return any(_HIDDEN_GLOB_WORD.fullmatch(single or double)
                   for single, double in _QUOTED.findall(text))


SECRET_GLOB = _SecretGlob()

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

# The second and third lines are the 2026-11-16 review's: `TRUNCATE users`
# is a whole statement without the word TABLE, a role or a function is
# dropped as finally as a table, and COPY … PROGRAM runs a shell on the
# database's host. Each wants the shape of a statement after it (a name,
# then an end), because these words are also English: "truncate the
# output" and "drop user input" are not SQL, and `truncate -s 0 f` is a
# program.
_SQL_NAME = r"(?:IF\s+EXISTS\s+)?[\w.\"`\[\]@'%]+"
_SQL_END = r"\s*(?:;|,|CASCADE\b|RESTRICT\b|RESTART\b|CONTINUE\b|[\"']|$)"
SQL_DESTRUCTIVE = re.compile(
    r"\b(DROP\s+(DATABASE|TABLE|PROCEDURE|VIEW|INDEX|SCHEMA)|TRUNCATE\s+TABLE)\b"
    r"|\bTRUNCATE\s+(?:ONLY\s+)?" + _SQL_NAME + _SQL_END +
    r"|\bDROP\s+(?:USER|ROLE|FUNCTION|TRIGGER|SEQUENCE|TYPE|EXTENSION|MATERIALIZED\s+VIEW)\s+"
    + _SQL_NAME + r"(?:\([^)]*\))?" + _SQL_END +
    r"|\bDROP\s+OWNED\s+BY\b|\bCOPY\b[^;]*\b(?:TO|FROM)\s+PROGRAM\b", re.I
)
_SQL_MUTATION = re.compile(
    r"\b(INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|MERGE\s+INTO|"
    # A table alias, ONLY, a join, and the writes that replace a row: each
    # read LOW through an MCP query (2026-11-21 review). REPLACE INTO only
    # before what SQL puts there, so "replace into the text" is prose.
    # The alias is never an English joining word: "update docs to set X"
    # and "update README and set the flag" are prose (2026-11-22 review).
    r"UPDATE\s+(?:ONLY\s+)?[\w.\"`\[\]]+\s+(?:AS\s+)?"
    r"(?!(?:to|and|or|then|so|with|for|by|in|at|of|also|again|it|this|that|them|now)\s)\w+\s+SET\b|"
    r"(?:REPLACE|INSERT\s+OR\s+(?:REPLACE|IGNORE|ABORT|FAIL|ROLLBACK))\s+INTO\s+[\w.\"`]+\s*(?:\(|VALUES\b|SELECT\b|SET\b|DEFAULT\b)|"
    r"ALTER\s+(TABLE|PROCEDURE)|CREATE\s+(OR\s+ALTER\s+)?PROCEDURE"
    # Who may do what, and who can log in: the same review.
    r"|(?:GRANT|REVOKE)\s+[\w, ()]+\s+ON\s+[\w.*\"` ]+\s+(?:TO|FROM)\b"
    r"|(?:ALTER|CREATE)\s+(?:USER|ROLE)\s+[\w\"`'@%]+)",
    re.I,
)
_SQL_JOIN_UPDATE = re.compile(
    r"\bUPDATE\s+[\w.\"`]+(?:\s+(?:AS\s+)?\w+)?\s+(?:(?:INNER|LEFT|RIGHT|CROSS)\s+)?JOIN\b",
    re.I)
_SQL_SET = re.compile(r"\bSET\b", re.I)


def _set_after(pattern, text):
    """Does a match of ``pattern`` stand before a SET in the same statement?
    Read once over each statement, not once from every match: `[^;]*?`
    after each `UPDATE … JOIN` took 1.8 s on 56 KB of them (2026-11-22)."""
    for statement in text.split(";"):
        sets = [found.start() for found in _SQL_SET.finditer(statement)]
        if sets and any(found.end() <= sets[-1] for found in pattern.finditer(statement)):
            return True
    return False


class _SqlMutation:
    """SQL_MUTATION's one regex, and `UPDATE … JOIN … SET` (MySQL's form)
    read in one pass."""

    @staticmethod
    def search(text):
        text = text or ""
        return bool(_SQL_MUTATION.search(text) or _set_after(_SQL_JOIN_UPDATE, text))


SQL_MUTATION = _SqlMutation()
# A stored procedure — but `exec` is also every shell's, VM's and container
# tool's word: a list of binaries it did not mean grew to seven and still
# read `ssh host 'exec ls'` as SQL (#872, 2026-10-24). In a command it
# counts only beside an SQL client; in a file or an MCP call, where there is
# no program to go by, it counts as it always did. find's `-exec` never.
SQL_EXEC = re.compile(r"(?<!-)\bEXEC(UTE)?\s+", re.I)
SQL_CLIENTS = frozenset(
    "sqlcmd psql mysql mariadb sqlite3 osql isql duckdb snowsql bq mongosh cqlsh "
    "clickhouse-client".split())

# Shell operators we split on to classify each segment independently.
# A lone `&` between words runs the next command too: `echo hi & rm -rf ~`
# was one segment led by echo (2026-09-30). `2>&1`, `&>` and `|&` are not it.
# A background `&` ends a command wherever it stands: bash runs `echo x&rm
# -rf ~` as two commands, and requiring a space on both sides let the second
# one ride along unseen behind a SAFE `echo` (2026-10-19 review). Only the
# `&` of a redirection (`2>&1`, `>&2`, `<&3`, `&>`) or of `&&` / `|&` is not
# one. `|&` is a pipe (stderr too), so it splits like `|`.
SEGMENT_SPLIT = re.compile(r"\s*(?:\|\||&&|\|&|;|\||\n|(?<![<>&|])&(?![&>]))\s*")

# Leading VAR=value assignments before the real command; group 1 the name.
ENV_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\S*\s+")
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
        match = ENV_ASSIGN.match(text)
        if not match:
            return names
        names.append(match.group(1))
        text = text[match.end():]


# --------------------------------------------------------------------------
# Bash classification
# --------------------------------------------------------------------------

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
    "diskutil": Reach.SYSTEM,
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
    "scale": Effect.MUTATE, "apply": Effect.MUTATE,
    # `rclone sync` and `aws s3 sync --delete` make the destination match
    # the source, which means deleting whatever the source does not have.
    "sync": Effect.MUTATE,
}

# A tool's own words, beside the shared ones: what a word means to that
# tool alone, and, where it reaches further than the tool usually does, how
# far. `set-url` is git's, not every tool's; a registry's `push` is public,
# though the same tool's `add` changes only the project. Each entry may only
# sharpen a shared word, never soften it (#872, 2026-10-24).
_REGISTRY_WORDS = {
    "publish": (Effect.PUBLISH, Reach.PUBLIC), "push": (Effect.PUBLISH, Reach.PUBLIC),
    "upload": (Effect.PUBLISH, Reach.PUBLIC),
    # Gone for everyone who depends on it, in one step.
    "unpublish": (Effect.DESTROY, Reach.PUBLIC), "yank": (Effect.DESTROY, Reach.PUBLIC),
}
TOOL_EFFECT_WORDS = {
    "git": {"set-url": Effect.MUTATE, "set-head": Effect.MUTATE,
            "set-branches": Effect.MUTATE,
            # `stash clear`, `reflog expire`: work thrown away, as reset --hard.
            "clear": Effect.DESTROY, "expire": Effect.DESTROY},
    # Every prune deletes what nothing uses — images, volumes, networks —
    # not only `system prune`'s (#872).
    "docker": dict(_REGISTRY_WORDS, prune=Effect.DESTROY),
    # `aws s3 rb` removes a bucket; the one verb AWS does not spell out.
    "aws": {"rb": Effect.DESTROY},
}
for _registry in ("npm", "pnpm", "yarn", "cargo", "poetry", "gem", "twine", "helm"):
    TOOL_EFFECT_WORDS[_registry] = dict(_REGISTRY_WORDS)
# launchctl's verbs that start a job, now and at every login: EXECUTE at
# the reach of the system, as the job does (2026-11-21 review).
TOOL_EFFECT_WORDS["launchctl"] = {"load": Effect.EXECUTE, "bootstrap": Effect.EXECUTE,
                                  "submit": Effect.EXECUTE, "enable": Effect.EXECUTE}
# `helm uninstall` is `helm delete` under its newer name; diskutil's verbs
# are disks wiped, as mkfs is. Each read MEDIUM beside its synonym's
# CRITICAL (2026-10-25 review).
TOOL_EFFECT_WORDS["helm"]["uninstall"] = Effect.DESTROY
TOOL_EFFECT_WORDS["diskutil"] = {
    "erasedisk": Effect.DESTROY, "erasevolume": Effect.DESTROY,
    "zerodisk": Effect.DESTROY, "randomdisk": Effect.DESTROY,
    "secureerase": Effect.DESTROY, "reformat": Effect.DESTROY,
    "partitiondisk": Effect.DESTROY, "apfs": Effect.MUTATE,
    "deletecontainer": Effect.DESTROY, "deletevolume": Effect.DESTROY,
}

# Flags that carry an effect. Deliberately few and unambiguous: a flag like
# `-d` means "delete" to git and "data" to curl and "dictionary order" to
# sort, so only spellings that mean one thing everywhere are listed.
EFFECT_FLAGS = {
    "-D": Effect.DESTROY, "--delete": Effect.DESTROY, "--purge": Effect.DESTROY,
    "--prune": Effect.DESTROY,
    # find's own spelling of destruction. `-exec` is judged by the command
    # it runs instead (_find_runs): `-exec grep` destroys nothing.
    "-delete": Effect.DESTROY,
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


_SECRET_SUFFIXES = ("password", "passwd", "token", "secret", "apikey")
_VARIABLE_IN_WORD = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def _names_a_secret(word):
    # `${GITHUB_TOKEN}` is `$GITHUB_TOKEN`: the braces kept `token}` from
    # matching, and the braced spelling read SAFE (2026-09-30).
    bare = word.strip("-'\"").replace("${", "$").rstrip("}")
    if bare.lower() in SECRET_WORDS:
        return True
    # The same variable inside a word: `https://evil/$GITHUB_TOKEN` hands
    # the token to whoever answers, and read SAFE through `git ls-remote`
    # while `echo $GITHUB_TOKEN` read HIGH (2026-11-21 review).
    for name in _VARIABLE_IN_WORD.findall(word):
        if name != bare.lstrip("$") and _names_a_secret("$" + name.upper()):
            return True
    if not (word.startswith("-") or "=" in word or bare.isupper()):
        return False
    # `$PGPASSWORD` and `$GHTOKEN` run the word into the name with no joiner
    # (2026-11-22b review). Upper case only: a variable's spelling.
    name = bare.lstrip("$")
    if name.isupper() and name.lower().endswith(_SECRET_SUFFIXES):
        return True
    return _words_name_a_secret([p for p in _SECRET_JOINERS.split(bare.lower()) if p])


# `${HOME:?}` and `${HOME?words}` are $HOME with a guard against an unset
# value: the same folder when the command runs (2026-11-14 review).
_HOME_VARIABLE = r"\$(?:HOME|\{HOME(?::?\?[^}]*)?\})"
_HOME_ITSELF = re.compile(r"^(~|%s)/?\*?$" % _HOME_VARIABLE)


def _reached_path(word):
    """A path argument as the shell reaches it: `~`, `~user` and `$HOME`
    written out, and `.`, `..` and doubled slashes folded. `$HOME/..`,
    `~you` and `/Users/.` named the folder of every home, or the home
    folder, and were not seen as either (2026-11-21 review). A relative
    path comes back as written, without its quotes."""
    path = word.strip("'\"")
    home = os.path.expanduser("~")
    if len(home) > 1:
        path = re.sub(r"^(?:~|%s)(?=/|$)" % _HOME_VARIABLE, lambda _: home, path)
    named = re.match(r"^~([A-Za-z0-9_][\w.-]*)(?=/|$)", path)
    if named:
        other = os.path.expanduser("~" + named.group(1))
        if not other.startswith("~"):
            path = other + path[named.end():]
    if path.startswith("/") and path not in ("//", "//*"):
        path = posixpath.normpath(path)
    return path


def _is_home(word):
    """`~`, `$HOME`, or the home folder by its absolute path, with or
    without a trailing `/` or `/*`. The hook runs as that user, so the path
    is known: `rm -rf /Users/<you>` read HIGH beside `rm -rf ~`'s CRITICAL
    (2026-10-25 review)."""
    path = word.strip("'\"")
    if _HOME_ITSELF.match(path):
        return True
    home = os.path.expanduser("~")
    if len(home) < 2:
        return False
    # `~/.` is the home folder too (2026-10-26 review), and so is `~you`.
    path = _reached_path(path.rstrip("*") or "/")
    return os.path.normpath(path or "/") == os.path.normpath(home)
# The machine's own folders: one list for every tool. find and rm kept two
# that disagreed — `find /Users -delete` read HIGH beside `rm -rf /Users`'s
# CRITICAL, and `rm -rf /System` HIGH beside find's — and a bare prefix took
# /usrlocal for /usr (#872, 2026-10-24).
SYSTEM_ROOTS = ("/System", "/Library", "/usr", "/etc", "/var", "/bin", "/sbin", "/boot",
                "/dev", "/lib", "/opt", "/root", "/srv", "/private")
# Every account's home at once: the machine, not one project.
MACHINE_ROOTS = ("/Users", "/home")


def _root_reach(word):
    """How far a path argument reaches: SYSTEM for the root or anything in
    a system folder, MACHINE for the folder of every home, else None."""
    path = word.strip("'\"")
    if path in ("/", "//", "/*"):
        return Reach.SYSTEM
    # Folded, so `/./`, `/tmp/..` and `$HOME/..` are what they reach. A
    # path written from the home folder that stays inside it reaches only
    # the home folder, which `_is_home` judges.
    written = path.rstrip("*")
    bare = _reached_path(written).rstrip("/") or "/"
    # Folded to the root by its steps (`/./`, `/tmp/..`). A word that is
    # only slashes, stars or quotes is not a path: `"`, `*` and the `/**`
    # of a comment read as the root in 3,000 real commands.
    if bare == "/":
        return Reach.SYSTEM if written.strip("/") else None
    if not written.startswith("/"):
        home = os.path.normpath(os.path.expanduser("~")).replace("\\", "/")
        if bare == home or bare.startswith(home.rstrip("/") + "/"):
            return None
    if any(bare == root or bare.startswith(root + "/") for root in SYSTEM_ROOTS):
        return Reach.SYSTEM
    if bare in MACHINE_ROOTS:
        return Reach.MACHINE
    return None


# A search through the whole home folder, every home, or the disk reads
# every key and token in it: `grep -rA40 OPENSSH ~` prints the private
# keys, and read SAFE, because no single secret store is named
# (2026-11-16 review). grep reads hidden folders when it recurses;
# ripgrep and ag only when told to.
_GREPS = frozenset("grep egrep fgrep zgrep rgrep ggrep".split())
_HIDDEN_ON_REQUEST = frozenset(("rg", "ag"))
_HIDDEN_FLAGS = frozenset(("--hidden", "-.", "--no-ignore", "--unrestricted"))


def _is_everything(word):
    """The home folder, the folder of every home, or the root — by any
    spelling the disk takes for one: `~/..`, `/Users/x/..`, `/.`, `///`,
    and `~x`, which is another account's home (2026-11-21 review)."""
    if (_is_home(word) or _root_reach(word) == Reach.MACHINE
            or word.strip("'\"") in ("/", "//", "/*")):
        return True
    place = _whole_place(word)
    return place is not None and (
        place in ("/", "//") or place in MACHINE_ROOTS
        or any(posixpath.dirname(place) == root for root in MACHINE_ROOTS))


# A home that stands for any: `~` is one level below a folder of homes,
# wherever this machine keeps them, so `~/..` is that folder. Read without
# the real home, so the answer is the same on every host.
_ANY_HOME = "/Users/~"


def _whole_place(word):
    """``word`` as an absolute, normalised path, `~` and `~user` read as
    homes; None for a relative one."""
    path = word.strip("'\"")
    if not path:
        return None  # a quote alone, not the root
    path = path.rstrip("*") or "/"
    path = re.sub(r"^(?:~|%s)(?=/|$)" % _HOME_VARIABLE, _ANY_HOME, path)
    path = re.sub(r"^~(?=[\w.-]+(?:/|$))", "/Users/", path)
    if not path.startswith("/"):
        return None
    return posixpath.normpath(path)


def _searches_every_file(token, segment, folder=None):
    words = _tokens(segment)[1:]
    places = [w for w in words if not w.startswith("-")]
    if folder:
        # `cd ~ && grep -r KEY .` searches the home folder (#1414).
        places += [folder.rstrip("/") + "/" + w for w in places
                   if not w.startswith(("/", "~", "$"))]
    if not any(_is_everything(w) for w in places):
        return False
    flags = [w for w in words if w.startswith("-")]
    if token in _GREPS:
        # `-d recurse` is -r by its other name (2026-11-21 review).
        spelled = " ".join(words)
        if re.search(r"(^|\s)(-d\s*|--directories(=|\s+))recurse\b", spelled):
            return True
        return token == "rgrep" or any(
            words[i] in ("-d", "--directories") and words[i + 1] == "recurse"
            for i in range(len(words) - 1)) or any(
            f in ("--recursive", "--dereference-recursive", "--directories=recurse",
                  "-drecurse")
            or (not f.startswith("--") and ("r" in f or "R" in f)) for f in flags)
    if token in _HIDDEN_ON_REQUEST:
        return any(f in _HIDDEN_FLAGS or re.fullmatch(r"-[A-Za-z]*u[A-Za-z]*", f)
                   for f in flags)
    if token == "diff":
        return any(f == "--recursive" or (not f.startswith("--") and "r" in f)
                   for f in flags)
    return False


def _joined_verb(word, own):
    """The effect of a verb joined to its object: AWS spells every action
    `terminate-instances`, `delete-stack`, so none of them matched the
    one-word vocabulary and a production stack deletion read MEDIUM
    (2026-10-25 review). Only a bare word is split — not a flag, a path or
    a file name — so `cat delete-me.txt` names nothing."""
    if word.startswith("-") or "-" not in word or any(c in word for c in "./\\=:"):
        return None
    verb = word.split("-", 1)[0].lower()
    return own.get(verb) or EFFECT_WORDS.get(verb)


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
    for w in words[1:]:
        further = _root_reach(w)
        if further is not None:
            reach = max(reach, further)
    # The home directory itself is everything the user has on this machine:
    # `find ~ -delete` is not `find . -delete` (2026-10-05 review).
    if any(_is_home(w) for w in words[1:]):
        reach = max(reach, Reach.MACHINE)

    effect = None
    own = TOOL_EFFECT_WORDS.get(tool, {})
    for word in words[1:]:
        named = own.get(word.lower()) or EFFECT_WORDS.get(word.lower()) or EFFECT_FLAGS.get(word)
        if named is None:
            named = _joined_verb(word, own)
        if isinstance(named, tuple):
            named, further = named
            reach = max(reach, further)
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


# Commands that cannot mutate anything on their own. A redirect or command
# substitution elsewhere in the segment still bumps the tier.
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
    # macOS spells it -I as well (2026-11-21 review).
    "sed": re.compile(r"(^|\s)-[A-Za-z]*[iI]"),
    # `\b--fix` never matched: there is no word boundary before a `-`.
    # ruff also writes its report anywhere (`-o ~/.zshrc`), edits every
    # file with --add-noqa, and `clean` deletes its caches (2026-11-21).
    "ruff": re.compile(r"\b(?:format|clean)\b|(^|\s)--fix\b|(^|\s)--add-noqa\b"
                       r"|(^|\s)(?:-o|--output-file)(?:\s|=|$)|(^|\s)-o\S"),
    "npm": re.compile(r"\bnpm\s+(?!test\b|ls\b|list\b|view\b|outdated\b)"),
}

# Tools judged by their first argument — a subcommand verb. SAFE only for
# verbs positively recognised as read-only; anything else falls through to
# unknown-command. This widens what the classifier *recognises*, never what
# it forgives. Aliases share one set so they cannot drift apart.
_PIP_READ_ONLY = frozenset("list show freeze --version".split())
_FLY_READ_ONLY = frozenset("status logs list info".split())

VERB_TOOLS_READ_ONLY = {
    # gh's own top-level commands only. `view`, `list`, `diff` and `checks`
    # were here and are not gh commands, so `gh diff` runs whatever alias
    # or extension carries that name, and read SAFE (2026-11-16 review).
    # `gh pr view` and its kin are in SUBCOMMAND_SECOND_LEVEL.
    "gh": frozenset("browse search status".split()),
    "simctl": frozenset("list get_app_container getenv".split()),
    # cms and export are NOT here: `security cms -S` signs with a keychain
    # identity and `security export -t privKeys` dumps private keys — the
    # verb alone cannot tell a read from those.
    "security": frozenset(
        "find-identity find-certificate list-keychains".split()),
    "defaults": frozenset("read read-type domains".split()),
    # Not `inspect`: it prints a container's environment, passwords and
    # all (2026-11-22b review).
    "docker": frozenset("ps images logs version info top port".split()),
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
    # -G looks a name up, and the name can carry data out: a lookup of
    # `<secret>.evil.example` reaches whoever answers for it (2026-11-21).
    "dns-sd": frozenset("-B -L -Z".split()),
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
    # `fly version upgrade` installs a new flyctl (2026-11-21 review);
    # `fly version` alone, the "" here, reads.
    ("fly", "version"): frozenset(("", "--json")),
    ("flyctl", "version"): frozenset(("", "--json")),
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
#
# The method is read the other way round since the 2026-11-16 review: only
# a literal GET is a read. Looking for POST, PUT, PATCH or DELETE written
# plainly left `-X "DEL"ETE` and `-X ${M:-DELETE}` SAFE, and with a token
# that may delete repositories that deletes one.
GH_API_METHOD = re.compile(r"(?:^|\s)(?:-X|--method)(?:\s+|=)?(?P<method>\S*)")
# A field switches the request to POST, its value attached or not:
# `-ftitle=x` is a POST as surely as `-f title=x`.
GH_API_FIELDS = re.compile(r"(^|\s)(-[fF]|--field|--raw-field|--input)")


def _gh_api_mutates(segment):
    if GH_API_FIELDS.search(segment):
        return True
    # As gh receives it: the shell has dropped the quotes by then.
    return any(found.group("method").upper() != "GET"
               for found in GH_API_METHOD.finditer(_QUOTING.sub("", segment)))


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
        if words[0] in ("--find", "-f"):
            # A later `--run` wins: `xcrun --find --run python3 x.py` runs
            # it, and read SAFE (2026-11-22b review).
            runs = [i for i, w in enumerate(words) if w in ("-r", "--run")]
            if not runs:
                return ("read-only-tool", Risk.SAFE)
            words = words[runs[0] + 1:]
            if not words:
                return None
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
        if _gh_api_mutates(segment):
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
# What may stand between a pipe and the interpreter it feeds: words that
# pass their arguments on, and the interpreter's own folder. `| /bin/sh`
# and `| env bash` read MEDIUM beside `| sh`'s CRITICAL (2026-11-16 review).
# A folder is a path as the shell would take one (`/bin/`, `./`, `~/x/`):
# anything looser took the `|^/bin/bash` of a quoted search pattern for a
# pipe (seen on a real command while checking this change).
_FOLDER = r"(?:(?:~|\.{1,2})?/(?:[\w.+-]+/)*)?"
_PIPED_INTO = r"(?:(?:sudo|" + _FOLDER + r"env|command|exec|nohup)\s+)*" + _FOLDER

class _Then:
    """``first``, then ``then`` later in the same stretch of text: the
    pattern `first[^stops]*then`, read in linear time. Written as one
    pattern, every `curl` on a line scanned to the line's end, and
    `"curl " * 4000` held the hook three seconds, sixteen times as long
    for each fourfold (2026-11-21 review)."""

    def __init__(self, first, then, stops, flags=0):
        self.first = re.compile(first, flags)
        self.then = re.compile(then, flags)
        self.stops = re.compile("[%s]" % stops)

    def search(self, text):
        for stretch in self.stops.split(text):
            found = self.first.search(stretch)
            if found and self.then.search(stretch, found.end()):
                return True
        return False


class _Either:
    """Any of several patterns, as one `search`."""

    def __init__(self, *patterns):
        self.patterns = patterns

    def search(self, text):
        return any(pattern.search(text) for pattern in self.patterns)


class _GlobQualifiers:
    """Finds a zsh glob qualifier that runs code: `e` with a delimiter, or
    `+` and a function name, in the parentheses after an unquoted glob
    (`*`, `?`, `]`) or as `(#q…)`. Only qualifier letters may stand before
    the `e`, and quoted text is skipped: a first, looser pattern took
    `--format='%(refname:short)'`, Swift's `.font(.system(` and Markdown's
    `[evidence](evidence/…)` for qualifiers in thousands of real commands.
    A bare word with a qualifier and no glob (`foo(e:…:)`) is not seen:
    tried on 2026-11-21, it took unquoted code (`open(`, Swift's `name:`)
    for qualifiers in 400 real commands."""

    # zsh takes nearly any character as the delimiter after `e`:
    # `*(e@id@)` and `*(e!cmd!)` read SAFE (2026-11-22 review). Not `-`, `.`
    # or `,`, which ended a Markdown link's name (`[x](app-store-sub…)`) in
    # 40 real commands; and `+name` after `N` or `.` alone (`*(N+cmd)`),
    # since `*(w+pad)` is a sum in Python.
    _QUALIFIERS = r"(?:#q)?[-/.@=p*%rwxAIERWXsStfedDlUGugamcLMTNnoOY^0-9\[\],]{0,16}?"
    # `[`, `<`, `*`, `?` and `=` delimit too, `[…]` and `<…>` as pairs:
    # `*(e[rm -rf ~])` read SAFE (2026-11-22b review). `.` and `,` only
    # where the closing one ends the qualifier, `(e.cmd.)`, which no
    # Markdown link's name does.
    _RUNS = re.compile(_QUALIFIERS + r"e(?:[:'\"{/@!#%^|~;\[<*?=]|([.,])[^)\n]*\1\))")
    # `+name` only after `*`, `?` or `(#q`: after `]` it is Markdown's
    # `[+x+](+x+)` far more often than a bracket glob.
    _CALLS = re.compile(r"(?:#q)?[.N]{0,3}\+[A-Za-z_]")

    def search(self, command):
        command = command or ""
        quote = None
        escaped = False
        comment = False
        for i, ch in enumerate(command):
            # A comment runs to the end of its line, quotes and all: the
            # `'` of `# it's` hid the next line's qualifier (2026-11-22).
            if comment:
                comment = ch != "\n"
                continue
            if escaped:
                escaped = False
                continue
            # `$'…'` takes a backslash as an escape, `'…'` does not.
            if ch == "\\" and quote != "'":
                escaped = True
                continue
            if quote:
                if ch == quote[-1]:
                    quote = None
                continue
            if ch == "#" and (not i or command[i - 1] in " \t\n;&|"):
                comment = True
                continue
            if ch == "'" and i and command[i - 1] == "$":
                quote = "$'"
                continue
            if ch in "'\"":
                quote = ch
                continue
            # After `)` as well: a group is a glob, `(src)(e:cmd:)` (2026-11-22b).
            if ch == "(" and i and (command[i - 1] in "*?])" or command.startswith("(#q", i)):
                found = self._RUNS.match(command, i + 1)
                if not found and command[i - 1] not in "])":
                    found = self._CALLS.match(command, i + 1)
                if found:
                    return found
        return None


WHOLE_LINE_RULES = [
    # `|&` pipes stderr too, and is as much a pipe into a shell.
    ("pipe-to-shell", re.compile(r"\|&?\s*" + _PIPED_INTO + r"(ba|z|k|fi|da|c|tc)?sh\b"),
     Risk.CRITICAL),
    # The same thing through another interpreter, or through a
    # substitution a shell then runs: `curl … | python3`,
    # `sh -c "$(curl …)"`, `bash <(curl …)` all read MEDIUM (2026-09-30).
    ("fetch-and-run",
     _Either(_Then(r"\b(curl|wget)\b",
                   r"\|\s*" + _PIPED_INTO + r"(python[\d.]*|node|perl|ruby|php|osascript)\b",
                   ";&"),
             _Then(r"(\b((ba|z|k|da)?sh|eval|source)|(^|\s)\.)\s",
                   r"(\$\(|<\(|`)\s*(curl|wget)\b", ";|")), Risk.CRITICAL),
    ("fork-bomb", re.compile(r":\s*\(\s*\)\s*\{.*\}\s*;\s*:"), Risk.CRITICAL),
    ("history-rewrite", re.compile(r"\bgit\s+filter-(branch|repo)\b"), Risk.CRITICAL),
    ("cmd-substitution", re.compile(r"\$\(|[<>]\(|(?<!\S)=\(|`"), Risk.MEDIUM),  # inner cmd classified in classify_bash()
    # zsh, macOS's shell, runs the string in a glob qualifier once per
    # matching file: `ls *(e:'rm -rf ~':)` read SAFE behind `ls`, and so did
    # `*(+func)` (2026-11-21 review). See _GlobQualifiers.
    ("glob-qualifier-runs-code", _GlobQualifiers(), Risk.CRITICAL),
    # Any `>` that is not a descriptor copy (`2>&1`, `>&2`) or /dev/null.
    # The lookbehind used to skip every `>` after a digit, which took
    # `1> ~/.zshrc` and `2> f` for `2>&1` and left them SAFE (2026-09-30).
    # `<>` opens its file for reading AND writing, and writes from the
    # first byte: `cat payload 1<>~/.zshrc` was SAFE because the lookbehind
    # skipped a `>` after `<` as well as after `>` (2026-11-16 review).
    ("redirect-write", re.compile(r"(?<!>)>>?(?!\s*(&[\d-]|/dev/null\b))"), Risk.MEDIUM),
]

# Commands that run the project's tests — which is to say, run code.
TEST_RUNNER = re.compile(
    r"(^|[\s/;&|])(pytest|py\.test|tox|nox)\b|\b(npm|yarn|pnpm|bun)\s+(run\s+)?test\b"
    r"|\bpython[\d.]*\s+-m\s+(pytest|unittest)\b")

# (rule_id, pattern, risk) applied per segment.
SEGMENT_RULES = [
    # gh's way to give a name to a shell command, as git's `!` alias is,
    # and its way to install somebody's program under a gh name.
    ("gh-shell-alias",
     re.compile(r"\bgh\s+alias\s+(set|import)\b[^|;&]*(\s--shell\b|\s-s\b|\s[\"']?!)"),
     Risk.CRITICAL),
    ("gh-extension-install",
     re.compile(r"\bgh\s+ext(ension)?\s+(install|upgrade|exec)\b"), Risk.HIGH),
    ("disk-overwrite", _Then(r"\bdd\b", r"\bof=/dev/", "|;&"), Risk.CRITICAL),
    ("format-disk", re.compile(r"\bmkfs(\.\w+)?\b"), Risk.CRITICAL),
    ("raw-device-write", re.compile(r">\s*/dev/(sd|nvme|disk|hd)"), Risk.CRITICAL),
    ("chmod-world-root", re.compile(r"\bchmod\s+(-R\s+)?0?777\s+/"), Risk.CRITICAL),
    ("sql-destructive", SQL_DESTRUCTIVE, Risk.CRITICAL),
    ("publish-artifact",
     re.compile(r"\b((npm|yarn|pnpm|cargo)\s+publish|twine\s+upload|"
                r"gh\s+release\s+create|docker\s+push)\b"), Risk.CRITICAL),

    ("sudo", re.compile(r"\bsudo\b"), Risk.HIGH),
    ("sql-mutation", SQL_MUTATION, Risk.HIGH),
    ("secret-access", _SecretRead(), Risk.HIGH),
    ("network-upload",
     _Then(r"\b(curl|wget)\b",
           r"(-X\s*(POST|PUT|PATCH)|--data|--upload-file|"
           # The long spellings: `--request POST`, curl's `--json`,
           # wget's `--post-data`, `--post-file`, `--body-*` and
           # `--method PUT` (2026-10-25 review).
           r"--request[\s=]*(POST|PUT|PATCH)|--json\b|--post-(data|file)\b|"
           r"--body-(data|file)\b|--method[\s=]*(POST|PUT|PATCH)|"
           r"(^|\s)-d\s|(^|\s)-F\s|(^|\s)-T\s"
           # Their value attached: `-d@data`, `-Fx=@f`, `-T./f` (2026-11-21).
           r"|(?-i:(^|\s)-[dFT][^\s-]))", "|;&", re.I), Risk.HIGH),
    ("remote-copy", re.compile(r"\b(scp|rsync|sftp|ftp)\b"), Risk.HIGH),
    ("install-from-url",
     _Then(r"\b(pip3?|uv|npm|yarn|pnpm)\s+(install|add)\b", r"(https?://|git\+|@github)",
           "|;&"), Risk.HIGH),
    ("prune-containers", re.compile(r"\bdocker\s+(system\s+)?prune\b"), Risk.HIGH),
    ("process-kill", re.compile(r"\b(killall|pkill|shutdown|reboot|halt)\b"), Risk.HIGH),
    # What runs later on its own, or how the machine behaves: a new or
    # emptied crontab (`-l` alone lists it), and a preference written
    # outside any project. Each read MEDIUM (2026-11-21 review).
    ("crontab-write", re.compile(r"(?:^|[\s/])crontab\b(?!\s+-l\s*$)"), Risk.HIGH),
    ("machine-settings",
     re.compile(r"\bdefaults\s+(?:-currentHost\s+|-host\s+\S+\s+)?(?:write|import|rename)\b"),
     Risk.HIGH),
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

RM_RE = re.compile(r"\brm\b((?:\s+-{1,2}[A-Za-z-]+)*)\s*(.*)", re.I)
# Any -r/-R among the flags. The tier and the wrist headline both ask,
# and they must agree on the answer.
RM_RECURSIVE = re.compile(r"-[A-Za-z]*[rR]")
# Skip git's global options before the subcommand — including the ones
# that take a value as a SEPARATE word (`git -C <dir> push …`, `git -c
# <name>=<val> push …`). The old `(?:-\S+\s+)*` swallowed only the flag,
# so `-C /repo` left `/repo` looking like the subcommand and a protected
# force-push slipped from CRITICAL down to an unknown-command MEDIUM.
# `-[Cc]`, not `-C|-c`: the pattern ignores case, so the two spellings were
# two readings of the same word, and the fix of 2026-11-14 only made the
# blow-up smaller (40 options a third of a second, 50 ten seconds).
_GIT_VALUE_GLOBALS = r"-[Cc]|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix"
# Each option has ONE reading: a value-taking global is never also a bare
# flag. With two, `git -c -c -c … 1` was tried every way before the match
# failed, twice as long for each `-c` or so, and 30 of them held the hook
# for good (2026-11-14 review).
GIT_RE = re.compile(
    r"\bgit\s+"
    r"(?:(?:%(v)s)\s+\S+\s+"            # value-taking global + its separate-word value
    r"|(?!(?:%(v)s)\s)--\S+\s+"         # --long or --long=value (value attached)
    r"|(?!(?:%(v)s)\s)-\w+\s+)*"        # bare short flag(s)
    r"([a-z][a-z-]*)\b(.*)" % {"v": _GIT_VALUE_GLOBALS}, re.I)

# Targets that mean "wipe the machine" or "wipe my home directory". The
# current folder and its parent by any spelling: `./` and `../` read HIGH
# beside `.`'s CRITICAL (2026-10-25 review).
CATASTROPHIC_TARGETS = re.compile(
    r"^(/|//|/\*|~|~/|~/\*|\$\{?HOME\}?/?|\$\{?HOME\}?/\*|\.\.?/?\*?|\*|"
    r"(%s)/?\*?)$" % "|".join(re.escape(root) for root in
                              SYSTEM_ROOTS + MACHINE_ROOTS + ("/Windows",))
)


class _Unread(Exception):
    """A substitution the reader could not take apart."""



def _substitutions(text):
    """What each outermost `$(…)`, backtick pair, `<(…)`, `>(…)` and
    zsh `=(…)` in ``text`` runs, read the way the shell reads it: nothing
    inside single quotes or a quoted heredoc, a `)` inside quotes is not
    the end, and a heredoc's body is its own text. `$((…))` is arithmetic;
    what it holds is read for substitutions of its own. zsh's `=(…)` only
    starts a word: `a=(b c)` is an array. Raises _Unread on
    one left open. The text pattern this replaces could not see a `)` in
    quotes or a heredoc, and called 944 of the owner's commands CRITICAL
    unread (2026-10-28)."""
    found = []
    _scan(text, 0, None, found)
    return found


def _scan(text, i, closer, found):
    """Read from ``i`` to ``closer`` (`)` or None for the end), adding the
    inner text of each substitution met at this level to ``found`` (None:
    only skip them). Returns the index after ``closer``."""
    n, quote, depth, heredocs = len(text), None, 0, []
    while i < n:
        c = text[i]
        if quote == "'":
            quote = None if c == "'" else quote
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "\n" and heredocs and quote is None:
            i = _skip_heredocs(text, i + 1, heredocs, found)
            heredocs = []
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            i += 1
            continue
        if c == "'" and quote is None:
            quote = "'"
            i += 1
            continue
        if c == "`":
            end = i + 1
            while end < n and text[end] != "`":
                end += 2 if text[end] == "\\" else 1
            if end >= n:
                raise _Unread()
            if found is not None:
                found.append(text[i + 1:end])
            i = end + 1
            continue
        opens = (text.startswith("$(", i)
                 or (quote is None and c in "<>" and text.startswith("(", i + 1))
                 or (quote is None and c == "=" and text.startswith("(", i + 1)
                     and (i == 0 or text[i - 1].isspace())))
        if opens:
            if text.startswith("$((", i):
                # Arithmetic: its own substitutions count, its text does not.
                end = _scan(text, i + 3, ")", None)
                if found is not None:
                    found.extend(_substitutions(text[i + 3:end - 1]))
                i = end + (1 if text.startswith(")", end) else 0)
                continue
            start = i + 2
            end = _scan(text, start, ")", None)
            if found is not None:
                found.append(text[start:end - 1])
            i = end
            continue
        if quote is None:
            if c == "<" and _HEREDOC.match(text, i) and not text.startswith("<<<", i):
                match = _HEREDOC.match(text, i)
                heredocs.append((match.group(3), bool(match.group(2)), bool(match.group(1))))
                i = match.end()
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0 and closer == ")":
                    return i + 1
                depth = max(0, depth - 1)
        i += 1
    if closer is not None:
        raise _Unread()
    return i


def _skip_heredocs(text, i, heredocs, found):
    """Past the bodies of the heredocs opened on the line just ended. An
    unquoted delimiter's body still runs its substitutions."""
    for delimiter, quoted, tabs in heredocs:
        start = i
        while i <= len(text):
            end = text.find("\n", i)
            line = text[i:] if end < 0 else text[i:end]
            if (line.lstrip("\t") if tabs else line) == delimiter:
                if not quoted and found is not None:
                    found.extend(_substitutions(text[start:i].replace('"', " ").replace("'", " ")))
                i = len(text) if end < 0 else end + 1
                break
            if end < 0:
                # No closing line: the rest is the body.
                if not quoted and found is not None:
                    found.extend(_substitutions(text[start:].replace('"', " ").replace("'", " ")))
                return len(text)
            i = end + 1
    return i


def _segments(command):
    """Split a shell command into independently-classifiable segments."""
    return [s.strip() for s in SEGMENT_SPLIT.split(command or "") if s.strip()]


# On the unconditional path, so compiled once. The git-only patterns in
# _git_risk stay inline on purpose: re's own cache covers repeat calls, and
# hoisting them charged every non-git hook start ~170 µs — three times a
# whole classify() — for a branch most tool calls never take.
_LEADING_PAREN = re.compile(r"^\(\s*")


_ENV_ASSIGNS = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+")


def _tokens(segment):
    """Words of a segment, with env assignments and a leading '(' stripped.
    All of them: `LANG=C TZ=UTC git push -f` took `tz=utc` for the command
    and read MEDIUM (2026-10-24 review)."""
    stripped = _ENV_ASSIGNS.sub("", segment.strip())
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
        if (CATASTROPHIC_TARGETS.match(target.strip("'\""))
                or CATASTROPHIC_TARGETS.match(_reached_path(target).rstrip("/") or "/")
                or _is_home(target)):
            return ("rm-catastrophic", Risk.CRITICAL)
    if recursive:
        return ("rm-recursive", Risk.HIGH)
    return ("rm-file", Risk.MEDIUM)


# Config keys whose value is a program git runs later.
_GIT_CONFIG_RUNS = re.compile(
    r"(^|\s)(core\.(pager|fsmonitor|sshcommand|hookspath|editor|askpass|gitproxy)"
    r"|pager\.\S+|(diff|merge)\.\S+\.(command|cmd|textconv|driver)"
    r"|filter\.\S+\.(clean|smudge|process)|sequence\.editor|credential\.helper"
    r"|gpg\.(\S+\.)?program|uploadpack\.packobjectshook"
    # Another config file, with any of the above in it, read from then on
    # (2026-11-21 review: MEDIUM beside core.hooksPath's HIGH).
    r"|include\.path|includeif\.\S+\.path)(\s|$)", re.I)
# A long option of git's that names a program it runs, by any start git
# takes for it: `--upl=/tmp/x.sh` is `--upload-pack` (2026-11-21 review).
_GIT_RUNS_OPTIONS = ("upload-pack", "receive-pack", "exec", "ext-diff")
# A `-c` that defines a `!` alias for this one run: `git -c alias.x='!id' x`.
_GIT_C_SHELL_ALIAS = re.compile(r"(^|\s)-c\s*['\"]?alias\.[^=\s]+=\s*['\"]?!", re.I)


def _abbreviates(words, names):
    """Does a word give a long option by a start of one of ``names``? GNU
    getopt, git and Python's argparse all take any unambiguous start of a
    long option: `sort --compress-prog=x.sh`, `git ls-remote --upl=x.sh`.
    Any start counts, ambiguous or not: the tool refuses those itself."""
    for word in words:
        word = _QUOTING.sub("", word)
        if word.startswith("--") and len(word) > 2:
            given = word[2:].split("=", 1)[0]
            if given and any(name.startswith(given) for name in names):
                return True
    return False


def _is_scratch_folder(folder):
    """A folder anything may be written into at LOW: the system's temp
    folder, or a tmp/scratchpad/.cache folder. A repository there could
    have had its config written too (2026-11-21 review)."""
    plain = str(folder).strip("'\"").replace("\\", "/")
    return bool(TEMP_ROOT.match(plain) or SCRATCH_PATH.search("/" + plain.lstrip("./") + "/"))


def _git_risk(segment):
    """Classify a ``git`` invocation by subcommand."""
    match = GIT_RE.search(segment)
    if not match:
        return None
    sub, rest = match.group(1).lower(), match.group(2) or ""
    forced = bool(re.search(r"(--force(?!-with-lease)|(^|\s)-[A-Za-z]*f[A-Za-z]*\b|\s\+)",
                            rest))
    # Options that choose a program git will run: a pager, a diff tool, an
    # ssh command, a remote's upload-pack. Each ran behind a SAFE "git log"
    # (2026-09-30). -C only changes the directory and stays a read.
    opening = segment[match.start():match.start(1)]
    runs = bool(re.search(r"(^|\s)(-c\s*\S|--config-env|--exec-path|--git-dir|--work-tree)",
                          opening)
                or re.search(r"(^|\s)(--upload-pack|--receive-pack|--exec|--ext-diff)\b"
                             r"|(^|\s)-u\s", rest)
                or _abbreviates(rest.split(), _GIT_RUNS_OPTIONS))
    # A repository in a scratch folder was written there at LOW, its config
    # included, and `core.fsmonitor` runs on `git status` (2026-11-21 review).
    for target in re.findall(r"(?:^|\s)-C\s*(\S+)", opening):
        if _is_scratch_folder(target):
            runs = True
    if _GIT_C_SHELL_ALIAS.search(opening):
        # The same `!` alias `git config` stores, for this one command.
        return ("git-config-shell-alias", Risk.CRITICAL)

    if sub == "push":
        # `--mirror` makes the remote what this checkout is: every branch
        # the remote has and this one lacks is deleted (2026-11-16 review).
        # git takes any start of a long option: `--mirr`, `--forc` and
        # `--del` read one step lower (2026-11-22 review).
        words = rest.split()
        if re.search(r"(^|\s)--mirror\b", rest) or _abbreviates(words, ("mirror",)):
            return ("git-push-mirror", Risk.CRITICAL)
        if _abbreviates(words, ("force",)):
            forced = True
        # Deleting a remote branch loses it as surely as overwriting it.
        if re.search(r"(^|\s)(--delete|-d)\b|(^|\s):\S", rest) or _abbreviates(words, ("delete",)):
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
    if _git_discards_work(sub, rest):
        return ("git-discards-work", Risk.HIGH)
    if sub in GIT_READ_ONLY and runs:
        return ("git-runs-a-program", Risk.MEDIUM)
    if sub == "ls-remote" and any(
            "://" in w or re.match(r"[\w.-]+@[\w.-]+:", w)
            for w in rest.split() if not w.startswith("-")):
        # A request to the address it names, as curl's is.
        return ("network-fetch", Risk.MEDIUM)
    if sub == "config":
        # `config` sat in GIT_READ_ONLY, so `git config --global alias.x
        # '!rm -rf ~'` read SAFE: it is a read only when it is reading.
        if "!" in rest:
            # A `!`-alias stores a shell command that later runs as `git x`.
            return ("git-config-shell-alias", Risk.CRITICAL)
        if _GIT_CONFIG_RUNS.search(rest) and len(
                [w for w in rest.split() if not w.startswith("-")]) >= 2:
            # A setting naming a program git runs later, as a `!` alias
            # does — behind a SAFE `git status` (2026-10-24 review).
            return ("git-config-names-a-program", Risk.HIGH)
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
    if sub == "symbolic-ref" and (len(words) >= 2 or re.search(
            r"(^|\s)(-d|--delete)\b", rest)):
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


def _find_runs(segment):
    """The commands a find's -exec, -execdir, -ok and -okdir run."""
    try:
        words = shlex.split(segment)
    except ValueError:
        words = segment.split()
    runs, current = [], None
    for word in words:
        if current is None:
            if word in ("-exec", "-execdir", "-ok", "-okdir"):
                current = []
        elif word in (";", "\\;", "+"):
            runs.append(current)
            current = None
        else:
            current.append(word)
    if current:
        runs.append(current)
    return [" ".join(shlex.quote(w) for w in run) for run in runs if run]


def _git_discards_work(sub, rest):
    """Does this throw away uncommitted work or history, as `reset --hard`
    does? Each read MEDIUM beside reset's HIGH until 2026-10-24."""
    if sub == "checkout":
        # Forced, or naming paths: `git checkout -- x` and `git checkout .`.
        return bool(re.search(r"(^|\s)(-[A-Za-z]*f[A-Za-z]*|--force|--)(\s|$)|(^|\s)\.(\s|$)",
                              rest))
    if sub == "restore":
        # Only `--staged` alone keeps the working tree.
        staged = re.search(r"(^|\s)(-S|--staged)\b", rest)
        worktree = re.search(r"(^|\s)(-W|--worktree)\b", rest)
        return bool(worktree or not staged)
    if sub == "stash":
        return bool(re.match(r"\s*clear\b", rest))
    if sub == "update-ref":
        return bool(re.search(r"(^|\s)-d\b", rest))
    if sub == "reflog":
        return bool(re.match(r"\s*(expire|delete)\b", rest))
    return False


# Commands that run the command after them. `env rm -rf ~` is `rm -rf ~`;
# judged by its lead word it read HIGH instead of CRITICAL (2026-09-25).
_PASS_THROUGH = frozenset("env command builtin nice nohup exec time timeout sudo doas".split())
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
        # All of them at once: one call per backslash ran out of stack at
        # 20,000 of them, and the hook escalated with no card (2026-11-21).
        return text.lstrip("\\")
    # `rm${IFS}-rf${IFS}~` is `rm -rf ~` to the shell.
    if _IFS.search(text):
        return _IFS.sub(" ", text)
    # `"rm" -rf ~`, `'rm'`, `r"m"`: the shell drops the quotes, and the
    # name they spell is the command that runs (2026-10-05 review).
    first = text.split(None, 1)
    if first and first[0][:1] not in "({" and any(q in first[0] for q in "'\"\\"):
        bare = _QUOTING.sub("", first[0])
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
            args, whole = shlex.split(" ".join(words[1:])), True
        except ValueError:
            # `bash -c "rm -rf ~; echo done"` reaches here cut at its `;`,
            # an unclosed quote: the script is whatever follows -c here.
            args, whole = re.sub(r"['\"]", "", " ".join(words[1:])).split(), False
        for i, arg in enumerate(args):
            if arg == "-c" or (arg.startswith("-") and not arg.startswith("--")
                               and "c" in arg[1:]):
                if i + 1 >= len(args):
                    return None
                return args[i + 1] if whole else " ".join(args[i + 1:])
            # A here-string is the script as surely as -c's argument:
            # `bash <<< 'rm -rf ~'` read MEDIUM (2026-11-21 review).
            if arg == "<<<":
                return " ".join(args[i + 1:i + 2]) or None
            if arg.startswith("<<<"):
                return arg[3:] or None
        return None
    if lead == "ssh":
        return _ssh_remote_command(words[1:])
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


# ssh's options that take a value, as a separate word or attached.
_SSH_VALUE_FLAGS = frozenset("bcDEeFIiJLlmOopQRSWwB")


def _ssh_remote_command(args):
    """The command an `ssh host …` line runs on the far side, or None for a
    login. It runs there as a shell line, and `ssh host 'rm -rf /'` read
    MEDIUM (2026-11-21 review)."""
    try:
        args = shlex.split(" ".join(args))
    except ValueError:
        args = re.sub(r"['\"]", "", " ".join(args)).split()
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        flag = args[i]
        letters = flag[1:]
        # The first letter that takes a value takes the rest, or the next word.
        taking = next((n for n, c in enumerate(letters) if c in _SSH_VALUE_FLAGS), None)
        i += 2 if taking is not None and taking == len(letters) - 1 else 1
    if i < len(args) and args[i] == "--":
        i += 1
    remote = args[i + 1:]
    return " ".join(remote) or None


# A file in the home folder's own settings: a dotfile or dot-folder, or a
# launch agent. Written to by a Bash command it is outside the project, as
# the Write tool's `outside-project` is HIGH: `cp payload ~/.zshrc`, `tee
# -a ~/.bashrc`, `curl -o ~/.zshrc URL` and `echo x >> ~/.zshrc` read
# MEDIUM (2026-11-21 review).
# Claude Code's own memory notes and the Trash are left out: an agent
# writes the one all day, and the other is where a moved file waits.
_HOME_DOT_TARGET = re.compile(
    r"['\"]?(?:~|%s|/Users/[^/\s]+|/home/[^/\s]+)/"
    r"(?!\.claude/projects/|\.Trash(?:/|$))(?:\.[\w-]|Library/Launch)"
    % _HOME_VARIABLE)
_REDIRECT_TARGET = re.compile(r"(?<![<>&])(?:\d|&)?>>?\|?\s*(?!&)([^\s;|&<>]+)")


def _collapsed(target):
    """``~/.Trash/../.zshrc`` as the file it names, ``~/.zshrc``: a step
    back out of a folder must not hide a home dotfile (2026-11-22 review).
    Read beside the target as written, so it can only add a match."""
    return posixpath.normpath(target) if ".." in target else target


def _write_targets(token, segment):
    """The files this segment writes, as far as its words say: what a
    redirect, tee, cp/mv/ln/install, curl's -o, wget's -O and dd's of=
    name."""
    targets = [m.group(1) for m in _REDIRECT_TARGET.finditer(segment)]
    words = _tokens(segment)[1:]
    plain = [w for w in words if not w.startswith("-")]
    if token == "tee":
        targets += plain
    elif token in ("cp", "mv", "ln", "install", "rsync") and len(plain) >= 2:
        targets.append(plain[-1])
    elif token in ("curl", "wget"):
        short = "o" if token == "curl" else "O"
        long = "--output" if token == "curl" else "--output-document"
        for i, word in enumerate(words):
            value = None
            if word == long or (word.startswith("-") and not word.startswith("--")
                                and word.endswith(short)):
                value = words[i + 1] if i + 1 < len(words) else None
            elif word.startswith(long + "="):
                value = word.split("=", 1)[1]
            elif word.startswith("-" + short) and not word.startswith("--"):
                value = word[2:]
            if value:
                targets.append(value)
    elif token == "dd":
        targets += [w[3:] for w in words if w.startswith("of=")]
    return targets


# kubectl flags that turn a read into something else: a raw API path, a
# server or credentials other than the configured ones (the login token goes
# to whoever `--server` names), and a kubeconfig, which names a program
# kubectl runs to fetch credentials.
_KUBE_REACH_FLAGS = re.compile(
    r"(^|\s)(--raw|-s|--server|--kubeconfig|--token|--as|--as-group|--as-uid|--user"
    r"|--username|--password|--client-key|--client-certificate|--certificate-authority"
    r"|--insecure-skip-tls-verify|--tls-server-name|--proxy-url|--cache-dir)(=|\s|$)").search


# Read-only tools with a spelling that writes a file or runs a command,
# each a test that takes the segment. Checked before the tool is waved
# through as a read: each of these read SAFE until 2026-09-25, and --quiet
# would have allowed them.
READ_TOOL_ESCAPES = {
    "awk": re.compile(r"system\s*\(|\|\s*[\"']|\|&|>{1,2}\s*[\"']|getline\s*<"
                      # A program or an extension from a file, unseen: gawk's
                      # -E/--exec and -l/--load as much as -f and -i.
                      r"|(^|\s)(-[fiEl]\s*\S|--file\b|--include\b|--exec\b|--load\b)"
                      r"|@include\b|@load\b").search,
    # --pre runs a program per file; --hostname-bin runs one to learn the
    # machine's name for hyperlinks (ripgrep 14; 2026-11-16 review).
    "rg": re.compile(r"(^|\s)--(pre|hostname-bin)(=|\s)").search,
    "find": re.compile(r"(^|\s)-(fprint0?|fprintf|fls)(\s|$)").search,
    # -o in a cluster too: `tree -ao ~/.zshrc` (2026-11-21 review).
    "tree": re.compile(r"(^|\s)(-[A-Za-z]*o[A-Za-z]*|--output)(\s|=|$)").search,
    # -o alone, attached (`-ofile`) or in a cluster (`-uo file`); the long
    # options by any start getopt takes (`--compress-prog=`, `--o=`).
    "sort": lambda segment: bool(
        re.search(r"(^|\s)--output(\s|=)|(^|\s)-[A-Za-z]*o|--compress-program", segment)
        or _abbreviates(_tokens(segment)[1:], ("output", "compress-program"))),
    # fd runs a command per match (`-x`) or per batch (`-X`), the command
    # attached or not: `fd -xrm` is `fd -x rm` (2026-11-21 review).
    "fd": lambda segment: any(_fd_runs(word) for word in _tokens(segment)[1:]),
    "ag": lambda segment: _abbreviates(_tokens(segment)[1:], ("pager",)),
    # -C compiles a magic file and writes it beside the one -m names.
    "file": re.compile(r"(^|\s)(-[A-Za-z]*C|--compile\b)").search,
    # sed's own commands write (`w file`, `s/a/b/w file`) and run (`e`).
    # `!` negates an address and stands before the command: `$!e sh x`.
    # `w` takes its file with no space before it too: `w/Users/x/.zshrc`
    # read SAFE (2026-11-21 review). Unspaced, only before a path, so the
    # `w` of `/warning/` stays a letter.
    "sed": re.compile(r"(^|\s)--in-place\b|(^|[\s;{}'\"/\d$!])[wW](\s+\S|[/~])"
                      r"|(^|[\s;{}'\"/\d$!])e(\s|['\";]|$)"
                      # Their argument attached, after an address or at the
                      # (2026-11-21 review): `1wout.txt`, `1eid`, `$!eid`, `;wq`.
                      # Not after a space or a quote, where a word starting
                      # with w or e is a file's name, nor `$`/`{`, where it
                      # is a variable's; and an `e` before `/` is hex (`\x1e/`).
                      # The address is a number on its own: `e2e_x.py` is a name.
                      r"|(?:(?<![\w.\-/])\d|[;!])(?:[wW](?![\s\d'\";}])|e(?![\s\d'\";}/,.]))"
                      # The same two as flags of `s`, after other flags:
                      # `s/a/b/pw file` writes and `s/a/b/ge` runs each
                      # line as a command. Only a `w` or `e` right after
                      # the last delimiter was seen (2026-11-16 review).
                      # A backslash is read one way only, as an escape: read
                      # both ways, a run of them was tried every way, and a
                      # real `s/\\\\\\\\s…/` held the hook 15 s (2026-11-21).
                      # A letter delimits too: `sxaxbxw f` writes f
                      # (2026-11-22b review). Only where a command starts
                      # and within one word, so `/start/,/end/p` is not one.
                      r"|(?:^|(?<=['\";{}!\s]))s(?P<l>[A-Za-z])(?:(?!(?P=l))[^\\\s'\"])*(?P=l)"
                      r"(?:(?!(?P=l))[^\\\s'\"])*(?P=l)[gpiImM0-9]*(?:[wW]\s|e(?=$|['\";}\s]))"
                      r"|(?<![A-Za-z])s(?P<d>[^\sA-Za-z0-9\\])(?:\\.|(?!(?P=d))[^\\])*(?P=d)"
                      r"(?:\\.|(?!(?P=d))[^\\])*(?P=d)[gpiImM0-9]*[wWe]"
                      # A script file holds the same commands, unseen.
                      r"|(^|\s)(-[A-Za-z]*f|--file\b)").search,
    # A config file names plugins, and both import them.
    # mypy also writes reports, installs packages and runs an interpreter;
    # flake8 appends whatever --format says to --output-file, and bat runs
    # its pager (2026-11-14 review: each read SAFE).
    # argparse takes any start of a long option, as getopt does.
    "mypy": lambda segment: bool(
        re.search(r"(^|\s)--(config-file|junit-xml|install-types|python-executable"
                  r"|[a-z-]+-report)\b", segment)
        or _abbreviates(_tokens(segment)[1:], ("config-file", "junit-xml",
                                                "install-types", "python-executable"))),
    "flake8": lambda segment: bool(
        re.search(r"(^|\s)--(config|append-config|output-file)\b", segment)
        or _abbreviates(_tokens(segment)[1:], ("config", "append-config", "output-file"))),
    "bat": re.compile(r"(^|\s)--pager(=|\s)").search,
    # `kubectl get` read SAFE whatever followed it (2026-11-16 review).
    "kubectl": _KUBE_REACH_FLAGS,
    "oc": _KUBE_REACH_FLAGS,
    # Setting the clock or the machine's name, not reading them.
    "date": re.compile(r"(^|\s)(-s|--set)\b|(^|\s)\d{6,}(\s|$)").search,
    "hostname": lambda segment: any(not w.startswith("-") for w in _tokens(segment)[1:]),
    "uniq": lambda segment: len([w for w in _tokens(segment)[1:]
                                 if not w.startswith("-") and not w.isdigit()]) >= 2,
    "security": re.compile(r"\b(list|default|login)-keychains?\b[^|;&]*\s-[sd]\b").search,
    # -s/--split-exp writes one file per document, named by the
    # expression, anywhere (2026-11-21 review).
    # Anywhere in a cluster, up to a letter that takes the rest as its
    # argument (o, p, I): `-iP` read SAFE (2026-11-22 review).
    # Python's yq spells it `--in-place`, and argparse takes `--in-pl`
    # (2026-11-22b review).
    "yq": lambda segment: bool(
        re.search(r"(^|\s)-[A-HJ-Za-nq-z]*[is]|(^|\s)--(inplace|in-place|split-exp)\b", segment)
        or _abbreviates(_tokens(segment)[1:], ("inplace", "in-place", "split-exp"))),
    # pip's general options reach past a read: `--log` appends to any file,
    # `--python` runs the file it names, `--cache-dir` writes there; optparse
    # takes any start of them (2026-11-22b review).
    "pip": lambda segment: _abbreviates(_tokens(segment)[1:],
                                        ("log", "log-file", "python", "cache-dir")),
    "git": lambda segment: bool(re.search(r"(^|\s)--output(=|\s)", segment)
                                or _abbreviates(_tokens(segment)[1:], ("output",))),
}
for _awk in ("gawk", "nawk", "mawk"):
    READ_TOOL_ESCAPES[_awk] = READ_TOOL_ESCAPES["awk"]
READ_TOOL_ESCAPES["pip3"] = READ_TOOL_ESCAPES["pip"]
# sed takes any start of its long options too: `--in-pl` (2026-11-21 review).
_SED_ESCAPE = READ_TOOL_ESCAPES["sed"]
_SHELL_ESCAPE = re.compile(r"\\(.)")
# And as the shell hands it over: `s/x/y\/w\ f` unquoted is `s/x/y/w f`,
# which writes f, and read SAFE (2026-11-22 review). Read both ways.
READ_TOOL_ESCAPES["sed"] = lambda segment: bool(
    _SED_ESCAPE(segment) or _SED_ESCAPE(_SHELL_ESCAPE.sub(r"\1", segment))
    or _abbreviates(_tokens(segment)[1:], ("in-place", "file")))


# fd's short options: those that take a value take the rest of the word.
_FD_VALUE_FLAGS = frozenset("dtecEjSoXx")


def _fd_runs(word):
    """Does this word of an fd command ask it to run a command?"""
    if word in ("--exec", "--exec-batch") or word.startswith(("--exec=", "--exec-batch=")):
        return True
    if not word.startswith("-") or word.startswith("--"):
        return False
    for letter in word[1:]:
        if letter in "xX":
            return True
        if letter in _FD_VALUE_FLAGS:
            return False  # the rest of the word is this option's value
    return False


# The same file by another spelling. The shell drops quotes and backslashes
# inside a word, writes out each choice in braces, and the disk takes `//`,
# `/./` and `x/../` for nothing at all; and a `cd` puts the folder in one
# command and the file in the next. Each of these named a secret store and
# read SAFE (2026-11-14 review): `cd ~/.tapproval && cat data/auth.json`,
# `cat ~/.codex//auth.json`, `cat ~/.a''ws/cre''dentials`,
# `cat ~/{.a,}ws/cre{d,}entials`. Read here over the whole command, and
# only ever to find a secret path: nothing else is judged by this reading.
_SLASH_RUN = re.compile(r"/(?:\.?/)+")
_UP_STEP = re.compile(r"(?:(?<=^)|(?<=[/\s=]))(?!\.\.?/)[^/\s=]+/\.\./")
_BRACES = re.compile(r"\{([^{}\s]*,[^{}\s]*)\}")
_BRACE_SPELLINGS = 32
_CHANGES_FOLDER = frozenset(("cd", "pushd"))
_RELATIVE_NAME = re.compile(r"[\w.][\w.@%+/-]*")
# The files a store folder holds, for a wildcard to be tried against. Only
# names that are no secret on their own: `credentials` or `id_rsa` would
# make every wildcard after every `cd` one.
_STORE_NAMES = ("data", "data/auth.json", "auth.json", "config", "hosts.yml", "config.json",
                "token", "access-token", "config.yml", "config.yaml",
                "settings.xml", "settings-security.xml", "gradle.properties")
# A store whose file is a secret by its name alone, tried only in its own
# folder: `rclone.conf` among the names above made every wildcard after
# every `cd` a secret read, in 338 real commands (2026-11-22 review).
_FOLDER_STORE_NAMES = {"rclone": ("rclone.conf",)}
# A word the shell expands to file names in the current folder.
_RELATIVE_GLOB = re.compile(r"(?=[^*?\[]*[*?\[])[\w.*?\[\]{}][\w.@%+/*?\[\]{},!-]*")
# Words that are nothing once the shell has read them, or quotes by
# another spelling: `$@`, `$*` (outside a script), `$'…'` and `$"…"`.
_NOTHING_WORDS = re.compile(r"\$(?:[@*]|\{[@*]\})|\$(?=['\"])")
_KUBE_SECRET = re.compile(r"(?:^|[\s,])secrets?(?:\.[\w.-]*)?(?:/|,)|,secrets?(?=\s|$)"
                          # In an API path (`get --raw …/secrets/db`), and as
                          # a word once the shell's quotes are gone
                          # (`get se""cret db`): 2026-11-16 review.
                          r"|/secrets?(?=/|\s|$)|(?:^|\s)secrets?(?=\s|$)"
                          # `secrets.` is the core group's, `secret.v1.` the
                          # whole name (2026-11-22b review).
                          r"|(?:^|\s)secrets?\.(?:v1\.?)?(?=\s|$)", re.I)


def _plain_path(text):
    """``text`` with the path steps that change nothing taken out."""
    text = _SLASH_RUN.sub("/", text)
    for _ in range(8):
        shorter = _UP_STEP.sub("", text)
        if shorter == text:
            break
        text = _SLASH_RUN.sub("/", shorter)
    return text


def _brace_spellings(word):
    """Every word the shell writes for ``word``'s braces; None for more
    than anyone would read."""
    parts = _BRACES.split(word)
    spellings = [""]
    for index, part in enumerate(parts):
        choices = part.split(",") if index % 2 else [part]
        if len(spellings) * len(choices) > _BRACE_SPELLINGS:
            return None
        spellings = [left + right for left in spellings for right in choices]
    return spellings


def _glob_names(path, pattern):
    """Does the shell's wildcard ``pattern`` name ``path``? A bracket the
    shell would take as itself (`[n-f]`) names nothing here."""
    try:
        return fnmatch.fnmatchcase(path, pattern)
    except re.error:
        return False


def _plain_words(segment):
    """A segment's words with the shell's quotes gone."""
    return [_QUOTING.sub("", w).rstrip(")}") for w in _tokens(segment.lstrip("({ "))]


def _folder_after(segment, folder):
    """The folder the next segment runs in, after this one: a `cd` or
    `pushd` changes it, anything else leaves it."""
    words = _plain_words(segment)
    if not words or os.path.basename(words[0]).lower() not in _CHANGES_FOLDER:
        return folder
    target = next((w for w in words[1:] if not w.startswith("-")), "")
    if not target or target == "-":
        return None
    if folder and not target.startswith(("/", "~", "$")):
        return folder.rstrip("/") + "/" + target
    return target


def _secret_by_another_spelling(command):
    """Does the command name a secret store once it is read as the shell
    and the disk read it?"""
    # A heredoc's body is a program's input, not this shell's file names.
    command = _without_heredoc_bodies(command)
    # `$@` and `$*` are nothing at all outside a script, and `$'…'` and
    # `$"…"` are quotes: `cat ~/.kube/con$@fig` and `cat ~/.k$'ube'/config`
    # read the kubeconfig and read SAFE (2026-11-21 review).
    written = command
    command = _NOTHING_WORDS.sub("", command)
    bare = _QUOTING.sub("", command)
    plain = _plain_path(bare)
    if plain != written and (SECRET_FILE_PATH.search(plain) or any(
            _SecretRead.search(segment) for segment in _segments(plain))):
        return True
    for word in plain.split():
        if "{" in word and "," in word:
            spellings = _brace_spellings(word)
            if spellings is None:
                # Too many to read, in a hidden or a home path: unread.
                if word.startswith((".", "~", "$HOME", "${HOME}")) or "/." in word:
                    return True
            elif any(SECRET_PATH.search(_plain_path(s) + "/") for s in spellings):
                return True
    folder = None
    for segment in _segments(command):
        words = _plain_words(segment)
        if not words:
            continue
        if os.path.basename(words[0]).lower() in _CHANGES_FOLDER:
            folder = _folder_after(segment, folder)
            continue
        if folder is None:
            continue
        for word in words[1:]:
            # A wildcard is the shell's to expand, in the folder the `cd`
            # chose: `cd ~/.codex && cat *` read SAFE (2026-11-21 review).
            if _RELATIVE_GLOB.fullmatch(word) and not word.startswith("-"):
                # Whether the wildcard, in the folder the `cd` chose, can
                # name a store: tried against the stores' own names there.
                # `cat */*` in ~/.tapproval reaches data/auth.json; `*.py`
                # there, and a pattern in any other hidden folder, do not.
                joined = posixpath.normpath(_plain_path(folder.rstrip("/") + "/" + word))
                steps = joined.split("/")
                fixed = next((i for i, step in enumerate(steps)
                              if any(c in step for c in "*?[")), None)
                if fixed is None:
                    # The step with the wildcard was undone (`*/..`): the
                    # word names the folder itself (2026-11-22 review).
                    if SECRET_PATH.search(joined + "/") and _reads_a_folder(segment):
                        return True
                    continue
                listed = "/".join(steps[:fixed]) or "/"
                names = _STORE_NAMES + _FOLDER_STORE_NAMES.get(posixpath.basename(listed), ())
                if any(_glob_names(listed + "/" + name, joined)
                       and SECRET_FILE_PATH.search(listed + "/" + name)
                       for name in names):
                    return True
                continue
            # A file's name, as a word on its own: `await cookies()` in a
            # message after a `cd` is not the browser's Cookies file.
            if not _RELATIVE_NAME.fullmatch(word):
                continue
            named = posixpath.normpath(_plain_path(folder.rstrip("/") + "/" + word))
            # normpath drops a trailing slash the store patterns need:
            # `cd ~/.config && grep -r . gcloud/` read SAFE (2026-11-22).
            if word.endswith("/"):
                named += "/"
            if SECRET_FILE_PATH.search(named) or (
                    SECRET_PATH.search(named) and _reads_a_folder(segment)):
                return True
    return False


# An awk program that runs a command or writes a file through a NAME, read
# over the whole command, where the program's quotes are whole. The segment
# splitter knows no quotes: it cut `awk 'BEGIN { cat = "sh"; printf "rm -rf
# ~" | cat }'` at the `;` and the `|`, each piece began with a read-only
# word, and the line read SAFE (2026-11-14 review). A `|` or `>` after
# print is output; in a pattern (`/a|b/`, `$3 > 100`) it is not.
_AWK_WORD = re.compile(r"\b[gnm]?awk\b")
_AWK_STRING = re.compile(r'\\?"(?:\\.|[^"\\])*?\\?"')
_AWK_RUNS = re.compile(r"system\s*\(|\b(?:print|printf)\b[^;}\n]*[|>]"
                       r"|\|\s*getline|getline\s*<|\|&|@load\b|@include\b")


def _awk_program_runs(command):
    """Does an awk program on this line run a command or write a file?"""
    found = _AWK_WORD.search(command)
    if not found:
        return False
    for quoted in _QUOTED.finditer(command, found.end()):
        program = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
        if "{" not in program and "@" not in program:
            continue  # a separator or a variable's value, not a program
        if _AWK_RUNS.search(_AWK_STRING.sub('""', program)):
            return True
    return False


# A program handed to an interpreter on its command line, and the shell
# command such a program runs: `python3 -c 'import os; os.system("rm -rf
# ~")'` read MEDIUM as inline code, whatever the code ran, and osascript's
# `do shell script "rm -rf ~"` read MEDIUM as an unknown program
# (2026-11-21 review). Read over the whole command, where the program's
# quotes are whole; only a string handed to a call that runs a command
# counts, so `print("rm -rf ~")` is not one.
_INLINE_FLAG = re.compile(
    r"\b(python[\d.]*|node|nodejs|deno|bun|perl|ruby|php)\b"
    r"(?:\s+-[A-Za-z]+)*\s+-[A-Za-z]*[cerpE]\s*(?=['\"])")
_RUNS_A_COMMAND = re.compile(
    r"(?:\b(?:system|popen|exec[A-Za-z]*|spawn[A-Za-z]*|shell_exec|passthru)"
    r"|\bsubprocess\.(?:run|call|check_output|check_call|getoutput|getstatusoutput|Popen))"
    r"\s*\(\s*")
_LITERAL = re.compile(r"'((?:\\.|[^'\\])*)'|\"((?:\\.|[^\"\\])*)\"")
_BACKTICKS = re.compile(r"`([^`]*)`")
_DO_SHELL_SCRIPT = re.compile(r"\bdo\s+shell\s+script\s+\"((?:\\.|[^\"\\])*)\"", re.I)
_ADMIN = re.compile(r"\bwith\s+administrator\s+privileges\b", re.I)


def _commands_in_inline_code(command):
    """Every shell command an inline program on this line hands to a call
    that runs one, and every `do shell script` an AppleScript runs."""
    found = []
    for flag in _INLINE_FLAG.finditer(command):
        quoted = _QUOTED.match(command, flag.end())
        if not quoted:
            continue
        code = quoted.group(1) if quoted.group(1) is not None else quoted.group(2)
        for call in _RUNS_A_COMMAND.finditer(code):
            at = call.end()
            if code.startswith("[", at):
                # An argv list: `subprocess.run(["rm", "-rf", "~"])`.
                end = code.find("]", at)
                words = [single or double for single, double in
                         _LITERAL.findall(code[at:end if end > 0 else len(code)])]
                if words:
                    found.append(" ".join(shlex.quote(w) for w in words))
                continue
            literal = _LITERAL.match(code, at)
            if literal:
                found.append(literal.group(1) if literal.group(1) is not None
                             else literal.group(2))
        # Backticks run a command in perl, ruby and php; in JavaScript
        # they are a template string.
        if flag.group(1) in ("perl", "ruby", "php"):
            found.extend(_BACKTICKS.findall(code))
    if "osascript" in command:
        for script in _DO_SHELL_SCRIPT.finditer(command):
            found.append(re.sub(r"\\(.)", r"\1", script.group(1)))
    return [text for text in found if text.strip()]


# Reads that put a live credential into the transcript, by a spelling the
# ontology cannot see: a one-letter flag, a BSD ps option, a keychain dump.
CREDENTIAL_READS = re.compile(
    r"\bgh\s+auth\s+status\b[^|;&]*(\s-t\b|--show-token)"
    r"|\bsecurity\s+(find-(generic|internet)-password\b[^|;&]*\s-[a-z]*[wg][a-z]*\b"
    r"|dump-keychain\b|export\b)"
    r"|\bps\b(\s+-\S+)*(\s+-[a-zA-Z]*E[a-zA-Z]*|\s+[acehjlmrSTuvwxX]*e[acehjlmrSTuvwxX]*)(?=\s|$)"
    # jq's `env` and awk's `ENVIRON` are the whole environment too; a field
    # called `.env` is not (2026-10-25 review).
    r"|\bjq\b[^|;&]*(\$ENV\b|(?<![.\w$])env\b)"
    r"|\b[gnm]?awk\b[^|;&]*\bENVIRON\b"
    # yq's `env(NAME)` and `strenv(NAME)`, as jq's `env` (2026-11-22b review).
    r"|\byq\b[^|;&]*\b(?:str)?env\s*\(")


_QUOTING = re.compile(r"['\"\\]")


_BARE_WORD = re.compile(r"[\w-]+")


def _bare_verbs(segment):
    """The segment with its subcommand as the program receives it. The
    shell drops quotes, so `git remote "set-url" origin …` retargets the
    remote and `kubectl "delete" ns prod` deletes it; every word test here
    matched the quoted spelling, and they read SAFE and MEDIUM (2026-11-16
    review). Only the first two words after the command, before any flag,
    and only a single word with its quotes closed: a commit message, a
    search pattern and a read tool's arguments are data, and stay as
    written."""
    words = _tokens(segment)
    for word in words[1:3]:
        if word.startswith("-"):
            break
        if not _QUOTING.search(word) or word.count('"') % 2 or word.count("'") % 2:
            continue
        bare = _QUOTING.sub("", word)
        if _BARE_WORD.fullmatch(bare):
            segment = segment.replace(word, bare, 1)
    return segment


def _bare_flags(segment):
    """The segment with its flags as the program receives them. The shell
    drops quotes and backslashes, so `find ~ '-delete'` deletes, and
    `sed '-i'` edits in place; every flag test here matched the quoted
    spelling and read SAFE (2026-10-24 review). Only words that come out
    as a flag (or git's `+ref`) are touched: unquoting everything would
    turn a commit message into commands."""
    words = segment.split()
    bare = [_QUOTING.sub("", w) for w in words]
    bare = [bare[i] if bare[i][:1] in ("-", "+") else w for i, w in enumerate(words)]
    return " ".join(bare) if bare != words else segment


_SUBSTITUTION_DEPTH = 16
# Wrappers inside wrappers: `sudo env nice timeout 5 bash -c …` is six.
_WRAPPER_DEPTH = 32


def classify_bash(command):
    """Classify a shell command. Returns ``(Risk, [rule_id, ...])``."""
    risk, rules, _ = _classify_bash(command, 0)
    return risk, rules


def _classify_bash(command, _depth, fragment=False):
    """classify_bash, with the tier each rule reached, so a substitution
    can be named by the rule that made it what it is. ``fragment`` is a
    piece the segment splitter cut out (it knows neither quotes nor
    heredocs): its substitutions were read whole from the command it came
    from, so one left open in the piece is the cut, not the shell."""
    if not command or not command.strip():
        return Risk.MEDIUM, ["empty-command"], {"empty-command": Risk.MEDIUM}

    risk = Risk.SAFE
    rules = []
    levels = {}

    def bump(rule_id, level):
        nonlocal risk
        if level > risk:
            risk = level
        if rule_id not in rules:
            rules.append(rule_id)
        levels[rule_id] = max(level, levels.get(rule_id, Risk.SAFE))

    for rule_id, pattern, level in WHOLE_LINE_RULES + SITE_RULES:
        if pattern.search(command):
            bump(rule_id, level)
    # A wildcard naming a hidden file, read once over the whole command,
    # where its quotes are whole: the segment splitter cuts `grep "a\|.*b"`
    # at the `\|`, and the half it leaves showed a bare `.*` (2026-10-28).
    # A fragment's command was read already.
    hidden_glob = not fragment and bool(SECRET_GLOB.search(command))
    if hidden_glob:
        bump("secret-glob", Risk.HIGH)
    if not fragment and _secret_by_another_spelling(command):
        bump("secret-access", Risk.HIGH)
    if not fragment and _awk_program_runs(command):
        bump("read-tool-writes-or-runs", Risk.MEDIUM)
    if not fragment and _depth < _SUBSTITUTION_DEPTH:
        for inline in _commands_in_inline_code(command):
            sub_risk, sub_rules, _ = _classify_bash(inline, _depth + 1)
            # A read stays the inline code's own MEDIUM; what the program
            # runs counts when it is worse.
            if sub_risk >= Risk.HIGH:
                bump("inline-code-runs:" + (sub_rules[0] if sub_rules else "?"), sub_risk)
        if "osascript" in command and _ADMIN.search(command):
            bump("sudo", Risk.HIGH)
    if SQL_EXEC.search(command) and any(
            os.path.basename(_first_token(segment)).lower() in SQL_CLIENTS
            for segment in _segments(command)):
        bump("sql-mutation", Risk.HIGH)

    # A command substitution runs its OWN command — `echo $(rm -rf /)` is a
    # catastrophic delete wearing an echo. The segment splitter doesn't
    # descend into `$(…)`/backticks, so classify the inner command in its
    # own right and take the max. Without this a destructive payload hid
    # behind the blunt MEDIUM "cmd-substitution" cap and could be
    # auto-allowed under a raised threshold.
    #
    # Each substitution is read the way the shell reads it (_substitutions)
    # and classified in its own right, the layers inside it by the same
    # call. One the reader cannot take apart, or nested past any honest
    # command, was never classified: unread is the worst it could be
    # (2026-10-26 review), and narrowly so — the text pattern before it
    # called every `)` in quotes unread (2026-10-28).
    try:
        inners = _substitutions(command)
    except _Unread:
        inners = []
        if not fragment:
            bump("cmd-substitution-unread", Risk.CRITICAL)
    for inner in inners:
        inner = inner.strip()
        if not inner:
            continue
        if _depth >= _SUBSTITUTION_DEPTH:
            bump("cmd-substitution-unread", Risk.CRITICAL)
            break
        sub_risk, sub_rules, sub_levels = _classify_bash(inner, _depth + 1)
        # Named by the rule that made the inner command what it is, however
        # deep that rule sits; a tie goes to what the command does over the
        # substitution bookkeeping.
        top = max(sub_levels.values(), default=Risk.SAFE)
        cause = next((r for r in sub_rules if sub_levels[r] == top
                      and not r.startswith("cmd-substitution")), None) or next(
            (r for r in sub_rules if sub_levels[r] == top), "?")
        if cause.startswith("cmd-substitution-inner:"):
            cause = cause[len("cmd-substitution-inner:"):]
        bump("cmd-substitution-inner:" + cause, sub_risk)

    folder = None
    for segment in _segments(command):
        if segment.strip() in ("}", ")"):
            continue  # the closing half of a group split at its `;`
        folder = _folder_after(segment, folder)
        inner = _unwrapped(segment)
        if inner is not None and inner.strip() != segment.strip():
            if _depth >= _WRAPPER_DEPTH:
                # Wrapped past any honest command (`eval eval … ls`): it
                # was never read, and unread is the worst it could be.
                bump("wrapped-unread", Risk.CRITICAL)
                continue
            sub_risk, sub_rules, _ = _classify_bash(inner, _depth + 1, fragment=True)
            bump("wrapped:" + (sub_rules[0] if sub_rules else "?"), sub_risk)
            # Grouping and a leading backslash change nothing but aliases.
            # A real wrapper can: `env LD_PRELOAD=x.so ls` runs x.so. It
            # keeps the unknown-command floor it always had, so unwrapping
            # can only ever raise a tier. Two backslashes or more are no
            # alias trick anyone types.
            if segment.strip()[:1] not in "({\\" or segment.strip().startswith("\\\\"):
                bump("wrapper", Risk.MEDIUM)
            if os.path.basename(_first_token(segment)).lower() == "sudo":
                bump("sudo", Risk.HIGH)
            continue

        segment = _bare_flags(segment)
        token = os.path.basename(_first_token(segment)).lower()
        # Only for a program the tables know. A line of code inside a
        # here-document is split into segments too, and `func delete\(` or
        # `action === 'remove-plan'` is not a subcommand: de-quoting those
        # raised 19 real commands for nothing while this was being checked.
        if token == "git" or token in TOOL_REACH or token in TOOL_EFFECT_WORDS:
            segment = _bare_verbs(segment)

        escape = READ_TOOL_ESCAPES.get(token)
        if escape is not None and escape(segment):
            bump("read-tool-writes-or-runs", Risk.MEDIUM)

        if token == "find":
            # Judged by what it runs, once per match: a read stays a
            # MEDIUM (it still runs a command), anything more is HIGH or
            # whatever the command is on its own, if that is worse.
            for inner in _find_runs(segment):
                sub_risk, sub_rules, _ = _classify_bash(inner, _depth + 1, fragment=True)
                bump("find-exec:" + (sub_rules[0] if sub_rules else "?"),
                     Risk.MEDIUM if sub_risk <= Risk.LOW else max(sub_risk, Risk.HIGH))

        if any(name not in HARMLESS_ENV and not name.startswith("LC_")
               for name in _assigned_names(segment)):
            bump("env-prefix", Risk.MEDIUM)

        if CREDENTIAL_READS.search(segment):
            bump("credential-read", Risk.HIGH)
        if (token in _FOLDER_READERS and token not in _NAME_LISTERS
                and TRANSCRIPT_PATH.search(segment)):
            bump("transcript-read", Risk.MEDIUM)
        if _searches_every_file(token, segment, folder):
            bump("home-wide-search", Risk.HIGH)
        if any(_HOME_DOT_TARGET.match(target) or _HOME_DOT_TARGET.match(_collapsed(target))
               for target in _write_targets(token, segment)):
            bump("writes-home-dotfile", Risk.HIGH)
        # kubectl's `kind/name` and `kind,kind`: the word `secret` joined to
        # a neighbour the word list never splits on.
        if token in ("kubectl", "oc") and _KUBE_SECRET.search(_QUOTING.sub("", segment)):
            bump("secret-access", Risk.HIGH)

        # The effect the words name, before any table gets to recognise the
        # binary. bump() takes the maximum, so a recognition table below can
        # no longer talk this back down to SAFE.
        named_effect = _ontology_risk(segment)
        if named_effect is not None:
            bump(*named_effect)

        special = _rm_risk(segment) if token == "rm" else None
        if special is None and token == "git":
            special = _git_risk(segment)
            # `cd /tmp/r && git status` is `git -C /tmp/r status`
            # (2026-11-21 review: the -C form alone was seen).
            if folder and _is_scratch_folder(folder):
                bump("git-runs-a-program", Risk.MEDIUM)
        # A positively recognised read-only invocation is judged by its
        # subcommand, not by the blunt tool-name rules below — "docker ps"
        # is not "docker run".
        if special is None:
            special = _subcommand_risk(segment, token)
        if special is not None:
            # A recognised read is still a read of what it names: `git show
            # HEAD:.env` skipped the rule below and read SAFE while `cat
            # .env` read HIGH (2026-10-25 review). The secret rule alone
            # runs here; the blunt tool-name rules stay out, which is the
            # point of recognising the invocation.
            if _SecretRead.search(segment) or hidden_glob:
                bump("secret-access", Risk.HIGH)
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

    return risk, rules, levels


# --------------------------------------------------------------------------
# Path classification (Write / Edit / NotebookEdit)
# --------------------------------------------------------------------------

LOW_RISK_PATH = re.compile(
    r"(^|[/\\])(test_[^/\\]*\.py|[^/\\]*_test\.py|[^/\\]*\.(md|rst|txt|log))$", re.I
)
INFRA_PATH = re.compile(
    r"((^|[/\\])\.github[/\\]workflows[/\\]|(^|[/\\])\.claude[/\\]settings|"
    r"(^|[/\\])(Dockerfile|docker-compose\.ya?ml|[^/\\]*\.tf|Makefile|"
    # CMakeLists.txt and every requirements or constraints list run code
    # at the next build or install, and read LOW as .txt (2026-11-21).
    r"pyproject\.toml|package\.json|requirements[\w.-]*\.txt|constraints[\w.-]*\.txt|"
    r"CMakeLists\.txt)$)",
    re.I,
)
SCRATCH_PATH = re.compile(r"([/\\](tmp|scratchpad|\.cache)[/\\])", re.I)
# What every later session reads as its instructions, or runs as a command,
# agent or skill: not documentation, whatever the extension (2026-09-30).
INSTRUCTION_PATH = re.compile(
    r"(^|[/\\])(CLAUDE(\.local)?\.md|AGENTS(\.override)?\.md)$"
    r"|(^|[/\\])\.claude[/\\](commands|agents|skills|hooks|rules)[/\\]"
    # Codex loads its skills and prompts from these in later sessions: a
    # write there read LOW (2026-11-22b review).
    r"|(^|[/\\])\.(agents|codex)[/\\](skills|prompts)[/\\]", re.I)


TEMP_ROOT = re.compile(r"(/private)?/tmp/", re.I)


def _within(path, cwd):
    """Is ``path`` inside ``cwd``? None when either cannot be resolved."""
    try:
        absolute = os.path.normcase(os.path.abspath(str(path)))
        root = os.path.normcase(os.path.abspath(str(cwd)))
    except (ValueError, OSError):
        return None
    return absolute == root or absolute.startswith(root.rstrip(os.sep) + os.sep)


def _through_links(path, cwd):
    """Where a write really lands when a link on its way leads elsewhere,
    as ``(real path, real cwd)``; None when nothing on the way is a link
    or the path cannot be resolved."""
    try:
        written = str(path)
        if cwd and not os.path.isabs(written):
            written = os.path.join(str(cwd), written)
        absolute = os.path.abspath(written)
        real = os.path.realpath(absolute)
        if os.path.normcase(real) == os.path.normcase(absolute):
            return None
        return real, (os.path.realpath(str(cwd)) if cwd else None)
    except (ValueError, OSError):
        return None


def classify_path(path, cwd=None):
    """Classify a filesystem write target. Returns ``(Risk, [rule_id, ...])``.

    A link in the project is judged where it leads, as well as where it
    stands: `docs/notes.md`, a committed link to `~/.zshrc`, read LOW
    (2026-11-21 review)."""
    here = _classify_path_as_written(path, cwd)
    if not path:
        return here
    landing = _through_links(path, cwd)
    if landing is None:
        return here
    there = _classify_path_as_written(*landing)
    if there[0] > here[0]:
        return there[0], there[1] + ["through-link"]
    return here


def _classify_path_as_written(path, cwd=None):
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

    # `.git` itself too: in a worktree it is a file (`gitdir: …`), and
    # rewriting it re-points the checkout (2026-10-25 review).
    if re.search(r"(^|/)\.git(/|$)", normalised, re.I):
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

    # Scratch only where scratch lives: the system's temp folder, or a
    # tmp/.cache inside the project. ~/.cache/pre-commit holds hooks that
    # run on the next commit (2026-10-24).
    if SCRATCH_PATH.search(normalised) and (
            not cwd or TEMP_ROOT.match(normalised) or _within(path, cwd)):
        # A skill or CLAUDE.md in a folder named tmp is still read as
        # instructions: `.claude/skills/tmp/SKILL.md` read LOW (2026-11-21).
        if INSTRUCTION_PATH.search(normalised):
            return Risk.MEDIUM, ["agent-instructions"]
        return Risk.LOW, ["scratch-file"]

    if cwd:
        inside = _within(path, cwd)
        if inside is None:
            return Risk.HIGH, ["unresolvable-path"]
        if not inside:
            return Risk.HIGH, ["outside-project"]

    if INSTRUCTION_PATH.search(normalised):
        return Risk.MEDIUM, ["agent-instructions"]
    if LOW_RISK_PATH.search(normalised):
        return Risk.LOW, ["docs-or-test"]

    return Risk.MEDIUM, ["project-file"]


# --------------------------------------------------------------------------
# Tool dispatch
# --------------------------------------------------------------------------

def _read_tool_risk(tool, tool_input):
    """A read tool is SAFE unless it reads a secret, which is HIGH, as
    `cat` of the same file is: Read on ~/.ssh/id_rsa was SAFE, and whoever
    reads the relay's key file can answer a card (2026-10-24 review).
    Grep's pattern is what it searches for, not where, so only Glob's
    counts; Grep's `glob` is where, and read SAFE until the 2026-11-01
    review (`glob: ".aws/*"`)."""
    # `uri`: ReadMcpResourceTool's `file:///…/.ssh/id_rsa` read SAFE
    # (2026-11-16 review).
    keys = (("file_path", "notebook_path", "path", "glob", "uri")
            + (("pattern",) if tool == "Glob" else ()))
    # A path that is not text (a list, a number) is nothing the checks
    # below can read, so a secret inside it read SAFE (#1371): it escalates,
    # as Bash's command-not-text does. Absent or null reads nothing.
    if any(tool_input.get(key) is not None and not isinstance(tool_input.get(key), str)
           for key in keys):
        return Risk.MEDIUM, ["path-not-text"]
    for key in keys:
        value = tool_input.get(key)
        if isinstance(value, str) and _names_a_secret_path(value):
            return Risk.HIGH, ["secret-read"]
    # Grep reads what it searches, hidden folders included: the whole home
    # folder is every secret in it (2026-11-16 review). Glob lists names.
    where = tool_input.get("path")
    if tool == "Grep" and isinstance(where, str) and _is_everything(where.strip()):
        return Risk.HIGH, ["home-wide-search"]
    if any(isinstance(tool_input.get(key), str) and TRANSCRIPT_PATH.search(tool_input[key])
           for key in keys):
        return Risk.MEDIUM, ["transcript-read"]
    return Risk.SAFE, ["read-only-tool"]


def _names_a_secret_path(value):
    """True for a path, or a wildcard over one, that names a secret store.
    A folder named on its own (`~/.aws`) is the folder's contents, and a
    wildcard inside a hidden folder (`**/.ss?/*`) is read as the shell's
    rule reads it."""
    value = _plain_path(value.replace("\\", "/"))
    return bool(SECRET_PATH.search(value + "/") or SECRET_GLOB.search(" " + value))


def _path_like(value):
    """A tool input that is a path rather than prose: one line, short, and
    shaped like a path. An MCP message about "the credentials doc" is not a
    read of one. A space is prose only when the value does not start where
    a path does: "~/Library/Application Support/…/Login Data" is a path,
    and dropping it hid every secret under a folder with a space in its
    name (2026-11-09 review)."""
    text = value.strip()
    if "\n" in value or len(value) >= 1024:
        return False
    if text.startswith(("/", "~/", "$HOME/")) or re.match(r"[A-Za-z]:[\\/]", text):
        return True
    return " " not in text and (text.startswith((".", "~", "$HOME")) or "/" in text
                                or "\\" in text)


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
    # `search_and_delete` does both: every verb a name chains counts, and
    # `get_or_create` creates (2026-11-16 review: "or" was not a chain).
    # Two verbs with no joiner do both too: `search_replace` replaces
    # (2026-11-22b review). Only a second verb that is seldom a noun:
    # `get_label` and `list_tags` read labels and tags.
    verbs = [words[0]] + [words[i + 1] for i in range(len(words) - 1)
                          if words[i] in ("and", "then", "or")
                          or (words[i + 1] in _MCP_SECOND_VERBS
                              and _mcp_verb_effect(words[i]) is not None)]
    effects = [effect for effect in map(_mcp_verb_effect, verbs) if effect is not None]
    effect = max(effects) if effects else None
    # A password manager's every answer is a credential, whatever its
    # verb: `mcp__1password__get_item` read LOW (2026-11-21 review).
    secret = _words_name_a_secret(words) or _is_secret_server(server)
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

# Servers whose every answer is a credential.
SECRET_SERVERS = frozenset(
    "1password onepassword op bitwarden bw vault hashicorp-vault hashicorp_vault keychain "
    "lastpass keeper dashlane doppler infisical secretsmanager secrets-manager "
    "aws-secrets-manager keepass keepassxc proton-pass pass gopass".split())


def _is_secret_server(server):
    name = server.lower()
    return name in SECRET_SERVERS or _words_name_a_secret(
        [w for w in _MCP_WORDS.split(name) if w])


# A database connector, by its server's or its tool's name, and the keys
# its statement comes in. A `query` that is not a statement is a search,
# so the keys count only on a connector these names call a database.
_DATABASE_NAME = re.compile(
    r"postgres|mysql|maria|sqlite|sql|mongo|redis|valkey|supabase|neon|database|"
    r"(?:^|[_-])db(?:$|[_-])|bigquery|snowflake|clickhouse|duckdb|cockroach|"
    r"planetscale|prisma|turso|libsql|cassandra|dynamo", re.I)
_STATEMENT_KEYS = ("sql", "query", "statement", "statements", "command", "cmd", "q")
# Statements that only read. `WITH` only before a SELECT; a SELECT only
# without a function that writes a file, reads one, or ends a session.
_READ_STATEMENT = re.compile(r"^\s*\(*\s*(?:SELECT|SHOW|EXPLAIN|DESCRIBE|DESC|WITH|VALUES|TABLE)\b",
                             re.I)
_SELECT_WRITES = re.compile(
    r"\b(?:lo_export|lo_import|lo_unlink|pg_read_file|pg_read_binary_file|pg_ls_dir|"
    r"pg_stat_file|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|"
    r"pg_promote|pg_switch_wal|set_config|dblink\w*|load_file|sys_exec|sys_eval|"
    r"nextval|setval)\s*\(|\bINTO\s+(?:OUT|DUMP)FILE\b"
    r"|\b(?:INSERT|UPDATE|DELETE|MERGE)\b", re.I)
_SQL_SELECT = re.compile(r"\bSELECT\b", re.I)
_SQL_INTO = re.compile(r"\bINTO\s+(?!@)\w", re.I)


def _select_writes(statement):
    """_SELECT_WRITES, and `SELECT … INTO name` (a new table) read in one
    pass: `[^;]*` from every SELECT grew with the square of the text."""
    if _SELECT_WRITES.search(statement):
        return True
    for piece in statement.split(";"):
        first = _SQL_SELECT.search(piece)
        if first and _SQL_INTO.search(piece, first.end()):
            return True
    return False
_MUTATING_STATEMENT = re.compile(
    r"^\s*(?:INSERT|UPDATE|DELETE|MERGE|REPLACE|UPSERT|ALTER|GRANT|REVOKE|COPY|CALL|EXEC"
    r"|EXECUTE|DO|LOAD|IMPORT|RENAME|SET\s+ROLE|SECURITY|REINDEX|CLUSTER|VACUUM)\b", re.I)
_DESTRUCTIVE_STATEMENT = re.compile(
    r"^\s*(?:DROP|TRUNCATE|FLUSHALL|FLUSHDB)\b"
    r"|\.(?:deleteMany|deleteOne|remove|drop|dropDatabase|dropIndex|dropIndexes|findAndModify"
    r"|findOneAndDelete)\s*\(", re.I)
# Mongo's shell methods that only read, and Redis's read commands.
_MONGO_CALL = re.compile(r"^\s*db(?:\.[\w$]+|\[[^\]]*\])*\.(\w+)\s*\(")
_MONGO_READS = frozenset(
    "find findOne count countDocuments estimatedDocumentCount distinct explain getIndexes "
    "stats getCollectionNames getCollectionInfos listCollections dataSize totalSize".split())
_REDIS_READS = frozenset(
    "GET MGET KEYS SCAN HGET HMGET HGETALL HKEYS HVALS HLEN HEXISTS HSCAN LRANGE LLEN LINDEX "
    "SMEMBERS SISMEMBER SCARD SSCAN ZRANGE ZRANGEBYSCORE ZREVRANGE ZCARD ZSCORE ZSCAN TYPE "
    "TTL PTTL EXISTS INFO PING DBSIZE STRLEN GETRANGE XRANGE XREVRANGE XLEN XINFO MEMORY "
    "OBJECT ECHO TIME".split())


def _statement_risk(statement):
    """The tier one statement given to a database connector earns, or None
    for a read."""
    if _DESTRUCTIVE_STATEMENT.search(statement):
        return Risk.CRITICAL
    mongo = _MONGO_CALL.match(statement)
    if mongo:
        return None if mongo.group(1) in _MONGO_READS else Risk.MEDIUM
    if _READ_STATEMENT.match(statement):
        return Risk.MEDIUM if _select_writes(statement) else None
    first = statement.split(None, 1)[0].upper() if statement.split() else ""
    if first in _REDIS_READS:
        return None
    if _MUTATING_STATEMENT.match(statement):
        return Risk.HIGH
    return Risk.MEDIUM


def _database_statement_risk(tool, tool_input):
    """A database connector's statements, judged one by one: anything but
    a read is at least MEDIUM, a write HIGH, a drop CRITICAL. A `query`
    tool is named a read, and `CREATE FUNCTION … plpython3u`, `ALTER
    SYSTEM` and `db.users.deleteMany({})` all read LOW (2026-11-21
    review)."""
    if "sql" not in tool_input and not _DATABASE_NAME.search(tool[len("mcp__"):]):
        return None
    worst = None
    for key in _STATEMENT_KEYS:
        value = tool_input.get(key)
        texts = value if isinstance(value, list) else [value]
        for text in texts:
            if not isinstance(text, str) or not text.strip():
                continue
            # Comments, string literals and dollar-quoted bodies hold no
            # statement of their own (the raw text is scanned elsewhere).
            text = re.sub(r"\$(\w*)\$.*?\$\1\$", "''", text, flags=re.S)
            text = re.sub(r"'(?:[^']|'')*'", "''", text)
            text = re.sub(r"--[^\n]*|/\*.*?\*/", " ", text, flags=re.S)
            for statement in text.split(";"):
                if not statement.strip():
                    continue
                level = _statement_risk(statement)
                if level is not None and (worst is None or level > worst):
                    worst = level
    return worst


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
    elif command is not None and not isinstance(command, str):
        # A number or an object where the text belongs raised in every
        # reader after this one, and the hook escalated with no card
        # (2026-11-21 review). As text, it is at least read and shown.
        tool_input = dict(tool_input)
        tool_input["command"] = json.dumps(command, default=str)
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


_READ_VERB_ENDINGS = ("", "s", "es", "ing", "ed")


_MCP_SECOND_VERBS = frozenset(
    "replace delete remove write overwrite erase purge drop destroy rename move insert "
    "upsert modify".split())


def _mcp_verb_effect(verb):
    effect = MCP_EFFECT.get(verb)
    if effect is None:
        found = next((v for v in _MCP_VERB_PREFIXES if verb.startswith(v)), None)
        if found is None:
            return None
        effect = MCP_EFFECT[found]
        # A prefix may make a word a write (`setup_webhook`), never a
        # read: `countersign_envelope` is not a count, and read LOW
        # (2026-11-16 review). A read is its own word, or an inflection.
        if effect is Effect.OBSERVE and verb[len(found):] not in _READ_VERB_ENDINGS:
            return None
    return effect


def _strings_in(value):
    """Every string inside a tool's input, however deep."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings_in(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings_in(item)


def _scan_content(content, risk, rules):
    """A benign path can still carry a destructive payload."""
    if content:
        if SQL_DESTRUCTIVE.search(content):
            return max(risk, Risk.CRITICAL), rules + ["sql-destructive"]
        if SQL_MUTATION.search(content) or SQL_EXEC.search(content):
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
    odd = not isinstance(tool_input.get("command", ""), (str, list, tuple))
    tool_input = _command_as_text(tool_input)

    if tool in ("Bash", "BashOutput"):
        risk, rules = classify_bash(tool_input.get("command", ""))
        # A session already inside a scratch repository runs its config on
        # `git status`, as `cd /tmp/r && git status` does (2026-11-22b).
        if (risk < Risk.MEDIUM and isinstance(cwd, str) and cwd and _is_scratch_folder(cwd)
                and re.search(r"(?:^|[\s;&|(])git(?:\s|$)", str(tool_input.get("command", "")))):
            risk, rules = Risk.MEDIUM, rules + ["git-runs-a-program"]
        if odd:
            risk, rules = max(risk, Risk.MEDIUM), rules + ["command-not-text"]
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
        risk, rules = _read_tool_risk(tool, tool_input)
    elif tool == "WebSearch":
        risk, rules = Risk.LOW, ["web-search"]
    elif tool == "WebFetch":
        risk, rules = Risk.MEDIUM, ["network-egress"]
    elif tool in ("Task", "Agent", "Workflow"):
        risk, rules = Risk.MEDIUM, ["spawns-agents"]
    elif tool.startswith("mcp__"):
        # The name says what kind of call; the input says what it does: a
        # `query` carrying DROP TABLE read LOW (2026-10-24 review).
        risk, rules = _scan_content(" ".join(_strings_in(tool_input)), *_mcp_risk(tool))
        statement = _database_statement_risk(tool, tool_input)
        if statement is not None and statement > risk:
            risk, rules = statement, rules + ["database-statement"]
        # A connector that reads files reads secrets too: an MCP read of
        # ~/.ssh/id_rsa read LOW (2026-11-01 review). Raised, never lowered.
        if risk < Risk.HIGH and any(_path_like(v) and _names_a_secret_path(v)
                                    for v in _strings_in(tool_input)):
            risk, rules = Risk.HIGH, rules + ["secret-read"]
        # A read that goes to an address it is handed is WebFetch by
        # another name, and WebFetch is MEDIUM: `mcp__fetch__fetch` with
        # any URL read LOW (2026-11-16 review).
        # A list of them, or an `address`, as well (2026-11-22b review).
        if risk < Risk.MEDIUM and any(
                re.match(r"https?://", value.strip(), re.I)
                for key in ("url", "uri", "href", "link", "urls", "address", "endpoint")
                for value in _strings_in(tool_input.get(key))):
            risk, rules = Risk.MEDIUM, rules + ["network-egress"]
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
    """The policy's card lengths, the defaults when unset or unreadable:
    an unreadable one raised, and every prompt lost its card."""
    def chars(name, default):
        try:
            return int(policy.get(name, default))
        except (TypeError, ValueError):
            return default
    return chars("headline_chars", HEADLINE_CHARS), chars("detail_chars", DETAIL_CHARS)


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
        wire.mark_line(raw, lines)
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


_json_object = wire.json_object


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


def _question_entries(tool_input):
    """AskUserQuestion's questions, read once: each as (text, heading,
    [(label, explanation)], whether several may be chosen). Labels are
    flattened to one line, which is what lets a multi-select answer carry
    one label per line. The heading and the explanations were dropped
    until 2026-10-16, so the wrist offered bare names where the terminal
    says what each one means."""
    questions = (tool_input or {}).get("questions") if isinstance(tool_input, dict) else None
    found = []
    for entry in (questions if isinstance(questions, list) else [])[:4]:
        if not isinstance(entry, dict):
            continue
        found.append((str(entry.get("question", "")), str(entry.get("header") or ""), [
            (" ".join(str(o.get("label", "")).split()), str(o.get("description") or ""))
            for o in (entry.get("options") or [])
            if isinstance(o, dict) and o.get("label")
        ][:4], entry.get("multiSelect") is True))
    return found


def _questions(tool_input):
    """Each question as (text, option labels, whether several may be
    chosen); one empty question when there are none."""
    return [(text, [label for label, _ in options], multi)
            for text, _header, options, multi in _question_entries(tool_input)
            ] or [("", [], False)]


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
    found = _question_entries(tool_input) or [("", "", [], False)]
    cards = []
    for index, (question, header, pairs, multi) in enumerate(found):
        options = [label for label, _ in pairs]
        question = _fit_lines(question, TEXT_CHARS) or "Claude has a question"
        if len(found) > 1:
            question = "%d of %d · %s" % (index + 1, len(found), question)
        one = dict(card, kind="question",
                   headline=_fit_lines(question, TEXT_CHARS),
                   detail=_fit(" · ".join(options), detail_chars))
        for key in ("options", "multi_select", "question_header", "option_details"):
            one.pop(key, None)
        if _fit(header, TEXT_CHARS):
            one["question_header"] = _fit(header, TEXT_CHARS)
        if options:
            one["options"] = options
            if multi:
                one["multi_select"] = True
            details = [_fit_lines(d, TEXT_CHARS) for _, d in pairs]
            if any(details):
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


# Environment variables that override one policy key each, as text.
_ENV_POLICY = (
    ("CLAUDE_RISK_MODE", "mode"),
    ("CLAUDE_RISK_AUDIT_LOG", "audit_log"),
    ("CLAUDE_RISK_RELAY", "relay"),
    ("CLAUDE_RISK_AUTO_ALLOW", "auto_allow_at_or_below"),
    ("CLAUDE_RISK_AUTH_FILE", "auth_file"),
)


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

    for name, key in _ENV_POLICY:
        if env.get(name):
            policy[key] = env[name]
    if env.get("CLAUDE_RISK_RELAY_WAIT"):
        try:
            policy["relay_wait"] = float(env["CLAUDE_RISK_RELAY_WAIT"])
        except ValueError:
            pass
    configure_site_rules(policy)
    return policy


# Their "allow" is an answer only the person can give: a plan approved, a
# question answered. No threshold stands in for that.
PERSON_ONLY_TOOLS = frozenset(("ExitPlanMode", "AskUserQuestion"))


def decide(risk, policy, tool=None):
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
    if threshold is not None and risk <= threshold and tool not in PERSON_ONLY_TOOLS:
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
            _host.restrict_to_owner(path)
        # A lone surrogate in a command string is written escaped rather
        # than raising UnicodeEncodeError out of here; and whatever else
        # goes wrong is said, not raised — a failure here used to replace
        # a verdict the watch had already given (2026-10-25 review).
        with open(path, "a", encoding="utf-8", errors="backslashreplace") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as error:
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
                return _native_path(here)
            if os.path.isfile(marker):
                with open(marker, encoding="utf-8", errors="replace") as handle:
                    line = handle.readline().strip()
                gitdir = line[len("gitdir:"):].strip() if line.startswith("gitdir:") else ""
                if gitdir and not os.path.isabs(gitdir):
                    gitdir = os.path.normpath(os.path.join(here, gitdir))
                # Worked on in "/" form: Windows' normpath gave back "\".
                gitdir = gitdir.replace("\\", "/")
                if "/.git/worktrees/" in gitdir:
                    return _native_path(gitdir.split("/.git/worktrees/", 1)[0] or here)
                return _native_path(here)
            parent = os.path.dirname(here)
            if parent == here:
                break
            here = parent
    except (OSError, ValueError):
        pass
    return None


def _native_path(path):
    """A path worked on in "/" form, given back as this computer writes
    it: unchanged on macOS and Linux, "\\" again on Windows, so it still
    equals the session's own cwd."""
    return path.replace("/", os.sep)


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
    decision, reason = decide(risk, policy, tool=result["tool"])
    # The user's own "ask" rule means a person answers: --quiet allowed a
    # SAFE call Claude Code had been told to ask about (2026-11-22b review).
    if decision == "allow" and asks_the_user(result["tool"], result["tool_input"],
                                             (event or {}).get("cwd")):
        decision, reason = "escalate", "%s — the user's own rule asks" % risk.name

    shadow = str(policy.get("mode", "shadow")).lower() != "enforce"
    effective = "escalate" if shadow else decision

    audit = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent": agent or "claude",
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
_relay_proof2 = wire.relay_proof2


def _relay_cut(error):
    """True when a relay took the card and then the connection broke: the
    relay died holding it. Refused, timed out or unreadable is not a cut."""
    import http.client
    import urllib.error

    if isinstance(error, urllib.error.URLError) and isinstance(error.reason, BaseException):
        error = error.reason
    return isinstance(error, (ConnectionResetError, ConnectionAbortedError,
                              BrokenPipeError, http.client.IncompleteRead))


def _relay_listening(relay, until):
    """Wait, until the monotonic time ``until``, for something to listen on
    the relay's port again. Whatever answers there must still prove the
    relay's key before its answer counts."""
    import socket
    import time
    import urllib.parse

    parts = urllib.parse.urlsplit(relay)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    while time.monotonic() < until:
        try:
            socket.create_connection((parts.hostname, port), timeout=1.0).close()
            return True
        except OSError:
            time.sleep(0.25)
    return False


def _signed_post(key, url, body):
    """A POST of ``body`` to the relay, signed with ``key``, and the nonce
    its answer's proof must name. A fresh nonce each call: the relay
    refuses one it has seen."""
    import urllib.parse
    import urllib.request
    signature, nonce = wire.signed_header(
        key, "POST", urllib.parse.unquote(urllib.parse.urlsplit(url).path), body)
    return urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "X-Tapproval-Signature": signature}), nonce


def ask_watch(card, policy, project=None):
    """Offer an escalated card to the watch relay. Returns the verdict.

    "allow" and "deny" are a human's answer arriving from the watch — this
    is not auto-allowing, so it applies to any tier, CRITICAL included.
    Everything else — relay down, timeout, malformed reply, unexpected
    decision string, no key file, an answer without the relay's proof —
    collapses to "none" and the normal prompt appears. Never raises.
    """
    import time
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
    # The card's id, chosen here so that a repost keeps it: a tap on the
    # iCloud copy a dead relay left on the watch then answers this very
    # card (#795).
    payload["post_id"] = uuid.uuid4().hex[:12]
    url = relay + "/card"
    deadline = time.monotonic() + wait
    reposts = 0
    while True:
        # A repost asks only for the time the first post had left.
        remaining = wait if not reposts else deadline - time.monotonic()
        # UTF-8, not \u escapes: a plan in Danish or Japanese would otherwise
        # cost six bytes a letter against the relay's 256 KB body.
        body = json.dumps({"card": payload, "wait": remaining},
                          ensure_ascii=False).encode("utf-8")
        request, nonce = _signed_post(key, url, body)
        try:
            with urllib.request.urlopen(
                    request, timeout=remaining + RELAY_REPLY_GRACE) as reply:
                raw = reply.read()
                status = reply.status
                proof = reply.headers.get("X-Tapproval-Proof2") or ""
            answer = json.loads(raw.decode("utf-8"))
            break
        except Exception as error:
            if not _relay_cut(error) or reposts >= RELAY_REPOSTS:
                print("ClaudeRiskClassifier: watch relay unavailable (%s)" % error,
                      file=sys.stderr)
                return "none", None
            reposts += 1
            print("ClaudeRiskClassifier: the relay dropped the card (%s); "
                  "posting it again when it is back" % error, file=sys.stderr)
            back_by = min(deadline - 1.0, time.monotonic() + RELAY_RETURN_SECONDS)
            if not _relay_listening(relay, back_by):
                print("ClaudeRiskClassifier: no relay came back, so the "
                      "terminal asks", file=sys.stderr)
                return "none", None
    if not wire.proves_relay(key, nonce, status, raw, proof):
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

# The Claude app's tool a session archives itself with, when the wrist asks
# it to. In auto mode no prompt came: the app's own safety check refused a
# call asked through another session's message (2026-11-24), so Archive on
# the watch did nothing. A PreToolUse "ask" for this one tool puts the
# question to the person, as in ask-first mode, and the PermissionRequest
# hook carries it to the wrist. It never answers for them. Spelled here
# because the hook cannot import watch_dashboard; a test holds the two equal.
ARCHIVE_TOOL = "mcp__ccd_session_mgmt__archive_session"
ARCHIVE_ASK_OUTPUT = {"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "Archive asked from the watch: approve it there or here.",
}}


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


def asks_the_user(tool, tool_input, cwd=None):
    """Does one of the user's own ask or deny rules name this call? Before
    any automatic allow. A Bash rule is matched per segment, as Claude Code
    matches it; any other rule for this tool counts whatever its
    parenthesis says (`Read(~/Documents/**)`), since a path pattern this
    file cannot match the way Claude Code does must fail closed. Never
    raises: unreadable settings name no rule."""
    try:
        rules = _user_permission_rules(cwd)
        named = [p for p in rules["deny"] + rules["ask"]
                 if p == tool or p.startswith(str(tool) + "(")]
        if not named:
            return False
        if tool not in ("Bash", "BashOutput"):
            return True
        command = " ".join(str((tool_input or {}).get("command", "")).split())
        pieces = _segments(command) if command else [""]
        return any(_pattern_matches(p, tool, piece) for p in named for piece in pieces)
    except Exception:   # noqa: BLE001 — a rule we cannot read asks nothing
        return False


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


def prepare_codex_sync(event, policy):
    """Let Codex show its native prompt only after the relay has joined it.

    A failed attachment leaves the question with Codex. It must never create
    a separate watch approval. Merely reaching a local port is not proof.
    """
    import http.client
    import urllib.request

    session_id = event.get("session_id")
    relay = str(policy.get("relay") or "").rstrip("/")
    key = _relay_key(policy)
    if not session_id or not key or not relay.startswith(("http://", "https://")):
        return False
    url = relay + "/codex/attach"
    payload = {"session_id": session_id}
    if event.get("tool_name") == "apply_patch":
        payload["approval"] = {name: event.get(name) for name in (
            "session_id", "turn_id", "transcript_path", "cwd", "tool_name", "tool_input")}
    request, nonce = _signed_post(key, url, json.dumps(payload).encode("utf-8"))
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            raw, status = reply.read(), reply.status
            proof = reply.headers.get("X-Tapproval-Proof2") or ""
        if not wire.proves_relay(key, nonce, status, raw, proof):
            return False
        return status == 200 and json.loads(raw).get("attached") is True
    except (OSError, ValueError, AttributeError, http.client.HTTPException):
        # HTTPException: a reply cut short or a bad status line is no OSError,
        # and escaped here with the hook's audit line (#1371).
        return False


def run_hook(stdin=None, stdout=None, agent=None):
    """Hook mode: read the event from stdin, write the decision to stdout.

    ``agent`` is "codex" when Codex runs the hook (its hooks.json command
    says --agent codex); Claude Code's command names no agent."""
    from_console = stdin is None
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    try:
        if from_console:
            # As UTF-8, whatever the console's code page (Windows).
            raw = _host.read_stdin_text()
        else:
            raw = stdin.read()
        event = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("event is not a JSON object")
        if agent != "codex" and event.get("hook_event_name") == "PreToolUse":
            # Only the archive tool is ever matched to this hook; anything
            # else says nothing, which leaves Claude Code's own decision.
            if event.get("tool_name") == ARCHIVE_TOOL:
                json.dump(ARCHIVE_ASK_OUTPUT, stdout)
                stdout.write("\n")
            return 0
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
        if agent == "codex":
            # Codex owns both automatic review and human approval. Our risk
            # policy supplies labels, never an additional approval decision.
            attached = (audit["mode"] == "enforce" and policy.get("relay")
                        and prepare_codex_sync(event, policy))
            audit.update(decision="escalate", effective="escalate",
                         watch="native" if attached else "native-unavailable")
            write_audit(audit, policy)
            json.dump(ESCALATE_FALLBACK, stdout)
            stdout.write("\n")
            return 0
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
    # ASCII: the decision is already made, and a stdout that cannot
    # encode a plan's accents raised here, which Claude Code reads as a
    # non-blocking hook (2026-10-24 review).
    stdout.write(json.dumps(response))
    return 0


def run_explain(target, tool):
    """Explain how a command or path would be classified."""
    tool_input = {"command": target} if tool == "Bash" else {"file_path": target}
    event = {"tool_name": tool, "tool_input": tool_input, "cwd": os.getcwd()}
    policy = load_policy()
    result = classify(event)
    card = wrist_card(result["tool"], result["tool_input"], result["risk"],
                      *_card_budgets(policy))
    decision, reason = decide(result["risk"], policy, tool=result["tool"])

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
    """Quote a path for a shell command string, if it needs it. On Windows
    always, for PowerShell: Git Bash would read a bare C:\\ path's
    backslashes as escapes, so Windows hooks name PowerShell (_hook_shell)."""
    if _host.is_windows():
        return "'%s'" % path.replace("'", "''")
    if not re.search(r"[\s\"\']", path):
        return path
    return "'%s'" % path.replace("'", "'\\''")


def _hook_shell():
    """The shell our hook entries name: PowerShell on Windows, where its
    call operator runs a quoted path; the default (sh) elsewhere."""
    return "powershell" if _host.is_windows() else None


def _run_prefix():
    """PowerShell runs a quoted path only after its call operator."""
    return "& " if _host.is_windows() else ""


def _split_command(command):
    """A hook command's words, as the shell that runs it reads them."""
    if not _host.is_windows():
        return shlex.split(command)
    # PowerShell's quoting: '' is one quote inside '...'; no escapes in "...".
    parts = []
    for word in re.findall(r"'(?:[^']|'')*'|\"[^\"]*\"|\S+", command):
        if word.startswith("'") and word.endswith("'") and len(word) > 1:
            word = word[1:-1].replace("''", "'")
        elif word.startswith('"') and word.endswith('"') and len(word) > 1:
            word = word[1:-1]
        elif word[:1] in ("'", '"'):
            raise ValueError("No closing quotation")         # as shlex says it
        parts.append(word)
    return parts[1:] if parts[:1] == ["&"] else parts


def _hook_command():
    """The exact command Claude Code should run, using this interpreter."""
    return "%s%s %s" % (_run_prefix(), _quote_path(sys.executable),
                        _quote_path(os.path.abspath(__file__)))


def _relay_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "watch_relay.py")


def _relay_command():
    """Shared SessionStart hook: keep the helper current for either agent."""
    return "%s%s %s --ensure" % (_run_prefix(), _quote_path(sys.executable),
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
    Returns True when the agent is in place. Never raises. Linux and
    Windows have no launchd: a login file does the same there.
    """
    if not _host.is_mac():
        return _install_login_file()
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


def _login_file():
    """Where the login file goes: the test override, or the host's own."""
    return os.environ.get("CLAUDE_LAUNCH_AGENT_PATH") or _host.login_file_path()


def _install_login_file():
    """Linux's XDG autostart entry or Windows' Startup-folder file, running
    ``watch_relay.py --ensure`` at each login, as the Mac's launchd job does.
    True when it is in place."""
    relay, target = _relay_path(), _login_file()
    if not target or not os.path.exists(relay):
        return False
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(_host.login_file_text(sys.executable, relay))
    except OSError:
        return False
    # Only once the new one is written: an old name left beside it would
    # show the computer two startup entries, and removed first, none.
    _remove_old_login_files(target)
    return True


def rename_old_login_file():
    """A helper before 2026-11 named its Linux or Windows login file after
    one of its parts ("Tapproval relay"). Write it again under the
    product's name, and only where an old one is: an install that never
    had a login file gains none. True when one was rewritten."""
    if _host.is_mac():
        return False
    target = _login_file()
    if not any(os.path.exists(old) for old in _host.old_login_file_paths(target)):
        return False
    return _install_login_file()


def _remove_old_login_files(target):
    """Take away the login files written under their old names ("Tapproval
    relay"), beside today's. Never raises."""
    for old in _host.old_login_file_paths(target):
        try:
            os.remove(old)
        except OSError:
            pass


def wake_relay_at_login():
    """Make sure something wakes the relay at login. A bridge from 1.1.0
    does it, as part of the one "Tapproval" item in Login Items, and the
    relay's own job — which macOS lists under the interpreter's name,
    "Python" or "Xcode" — goes. Otherwise the relay's own job does it.
    True when one of them is in place."""
    try:
        import bridge_install
        if bridge_install.mac_supported() and bridge_install.wake_relay(
                sys.executable, _relay_path()):
            remove_launch_agent()
            return True
    except Exception:
        pass
    return install_launch_agent()


def remove_launch_agent():
    """Take the login wake-up out again — part of a clean exit."""
    if not _host.is_mac():
        target = _login_file()
        _remove_old_login_files(target)
        try:
            os.remove(target)
            return True
        except (OSError, TypeError):
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
            parts = _split_command(str(handler.get("command", "")))
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
    # Microseconds, and a count past them: `--install --watch` backs up
    # twice, and in the same second the second copy overwrote the user's
    # original (2026-11-22b review).
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = "%s.bak-%s" % (path, stamp)
    count = 1
    while os.path.exists(backup):
        count += 1
        backup = "%s.bak-%s-%d" % (path, stamp, count)
    with open(path, "r", encoding="utf-8") as src:
        content = src.read()
    with open(backup, "w", encoding="utf-8") as dst:
        # As private as the original: settings.json can hold keys, and a
        # 0600 file's copy was readable by every account. Before the
        # content, so it is never there to read. Windows keeps no such
        # bits, and a filesystem that refuses is no reason to stop.
        try:
            import stat
            os.chmod(backup, stat.S_IMODE(os.stat(path).st_mode))
        except OSError:
            pass
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


def _event_list(data, event):
    """``data["hooks"][event]`` as a list to edit, made when it is absent,
    null or empty; None when it holds something else, which is the user's
    and is left alone. `"hooks": null` and the like crashed --install and
    --uninstall with a traceback (2026-11-21 review)."""
    hooks = data.get("hooks")
    if hooks is None or (not hooks and isinstance(hooks, (list, dict))):
        hooks = data["hooks"] = {} if not isinstance(hooks, dict) else hooks
    if not isinstance(hooks, dict):
        return None
    entries = hooks.get(event)
    if entries is None or (not entries and isinstance(entries, (list, dict))):
        entries = hooks[event] = [] if not isinstance(entries, list) else entries
    return entries if isinstance(entries, list) else None


def _left_alone(path, what="its \"hooks\""):
    print("Settings : %s holds %s in a shape this installer does not read; "
          "left alone. Nothing was changed." % (path, what))


def _sync_hook(entry_list, wanted, matcher, marker):
    """Idempotently point our hook entry in ``entry_list`` at ``wanted``.

    Ours is any handler whose command mentions ``marker`` (the script's
    file name): repointed in place when it differs, added — with the
    matcher — when absent, left alone when already right. True if the
    list changed, which is what decides whether settings are rewritten.
    """
    shell = _hook_shell()
    ours = [h for entry in entry_list if isinstance(entry, dict)
            for h in (entry.get("hooks") if isinstance(entry.get("hooks"), list) else [])
            if isinstance(h, dict) and marker in str(h.get("command", ""))]
    if ours:
        if all(h.get("command") == wanted and h.get("shell") == shell for h in ours):
            return False
        for handler in ours:
            handler["command"] = wanted
            handler.setdefault("timeout", 10)
            if shell:
                handler["shell"] = shell
            else:
                handler.pop("shell", None)
        return True
    handler = {"type": "command", "command": wanted, "timeout": 10}
    if shell:
        handler["shell"] = shell
    entry = {"hooks": [handler]}
    if matcher:
        entry["matcher"] = matcher
    entry_list.append(entry)
    return True


def _remove_our_hooks(hooks):
    """Drop our handlers from every event we wire, keeping everyone else's. Empty
    events disappear. Returns how many handlers went."""
    removed = 0
    for event in ("PermissionRequest", "SessionStart", "PreToolUse"):
        entries = hooks.get(event)
        if entries is None:
            continue
        if not isinstance(entries, list):
            continue           # the user's, in a shape we never wrote
        kept = []
        for entry in entries:
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            if not isinstance(inner, list):
                kept.append(entry)
                continue
            handlers = [h for h in inner
                        if not (isinstance(h, dict) and _is_our_hook(h))]
            removed += len(inner) - len(handlers)
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
    hooks = _read_settings_quietly(path).get("hooks")
    entries = (hooks.get("PermissionRequest") if isinstance(hooks, dict) else None) or []
    if not isinstance(entries, list):
        entries = []
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
    entries = _event_list(data, "PermissionRequest")
    starters = _event_list(data, "SessionStart") if os.path.exists(_relay_path()) else []
    if entries is None or starters is None:
        print("Codex  : %s holds its hooks in a shape this installer does not "
              "read; left alone." % path)
        return None
    changed = _sync_hook(entries, _codex_command(), "*", os.path.basename(__file__))
    if os.path.exists(_relay_path()):
        changed = _sync_hook(starters, _relay_command(), None,
                             "watch_relay.py") or changed
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


# ---- the short command --------------------------------------------------------
#
# ``tapproval status`` instead of ``python3 ~/.tapproval/ClaudeRiskClassifier.py
# --status``: one short front for what Base already does, on every host
# (design/tapproval-base-on-the-computer.md, stage 0). It adds no ability.

#: The words ``tapproval`` understands.
COMMAND_WORDS = ("status", "pair", "update", "uninstall", "help")
#: How the launcher calls this file. Never bare: with no arguments this file
#: is the hook, and would sit waiting for an event on stdin.
COMMAND_FLAG = "--tapproval"
_COMMAND_MARK = "Tapproval Base: the short command"
COMMAND_HELP = """tapproval: the computer half of Tapproval (Tapproval Base)

  tapproval status      what Base sees, and the one next step
  tapproval pair        let a new watch pair, for ten minutes
  tapproval update      fetch the latest Base now
  tapproval uninstall   remove Base from this computer"""


def searched_bin(home=None, path=None):
    """``~/.local/bin`` when it exists and the terminal already searches
    it, else None. Base never edits shell settings to make room for a
    command, and never makes the folder."""
    home = os.path.expanduser("~") if home is None else home
    path = os.environ.get("PATH", "") if path is None else path
    folder = os.path.join(home, ".local", "bin")
    if not os.path.isdir(folder):
        return None
    real = os.path.realpath(folder)
    for entry in path.split(os.pathsep):
        if entry and os.path.realpath(os.path.expanduser(entry)) == real:
            return folder
    return None


def _command_path():
    """Where the launcher goes, or None when there is nowhere the terminal
    already looks. ``TAPPROVAL_COMMAND_DIR`` is the tests' override; set
    empty, it means nowhere. Without it, an install whose settings path is
    overridden gets no command either."""
    folder = os.environ.get("TAPPROVAL_COMMAND_DIR")
    if folder is None:
        # An install pointed at settings of its own is a test's or a trial,
        # not this person's: it puts nothing on their PATH.
        if os.environ.get("CLAUDE_SETTINGS_PATH"):
            return None
        folder = searched_bin()
    if not folder:
        return None
    return os.path.join(folder, "tapproval.cmd" if _host.is_windows() else "tapproval")


def command_text(python, script):
    """The launcher: two lines that hand every word to this file."""
    if _host.is_windows():
        # One line, so cmd has read all of it before ``uninstall`` deletes
        # the file it is reading.
        return ('@echo off\r\nrem %s. Its installer wrote this file; '
                'its uninstall removes it.\r\n"%s" "%s" %s %%* & exit /b\r\n'
                % (_COMMAND_MARK, python, script, COMMAND_FLAG))
    def quoted(word):
        return "'%s'" % word.replace("'", "'\\''")
    return ("#!/bin/sh\n# %s. Its installer wrote this file; its uninstall "
            "removes it.\nexec %s %s %s \"$@\"\n"
            % (_COMMAND_MARK, quoted(python), quoted(script), COMMAND_FLAG))


def _is_our_command(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return _COMMAND_MARK in handle.read(600)
    except OSError:
        return False


def install_command():
    """Put ``tapproval`` where the terminal already finds commands. True
    when it is there. A ``tapproval`` that is somebody else's stays theirs.
    Never raises."""
    target = _command_path()
    if not target:
        return False
    if os.path.lexists(target) and not _is_our_command(target):
        return False
    try:
        fresh = target + ".new"
        with open(fresh, "w", encoding="utf-8", newline="") as handle:
            handle.write(command_text(sys.executable, os.path.abspath(__file__)))
        os.chmod(fresh, 0o755)
        os.replace(fresh, target)
        return True
    except OSError:
        return False


def remove_command():
    """Take the launcher away again, and only one this installer wrote."""
    target = _command_path()
    if not target or not _is_our_command(target):
        return False
    try:
        os.remove(target)
        return True
    except OSError:
        return False


def run_command(words):
    """``tapproval <word>``. 0 when the word's own work says so; 2 for a
    word it does not know."""
    word = words[0] if words else "help"
    if word not in COMMAND_WORDS or len(words) > 1:
        print(COMMAND_HELP, file=sys.stderr)
        return 2
    if word == "help":
        print(COMMAND_HELP)
        return 0
    if word == "status":
        return run_status()
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    if word in ("pair", "update"):
        return subprocess.call([sys.executable, _relay_path(), "--" + word])
    if _host.is_windows():
        script = os.path.join(here, "uninstall.ps1")
        call = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", script]
    else:
        script = os.path.join(here, "uninstall.sh")
        call = ["bash", script]
    if not os.path.exists(script):
        print("Tapproval: the uninstaller is not beside this helper (%s). "
              "A plugin install is removed with /plugin uninstall %s; the "
              "README says how to clear what that leaves."
              % (script, PLUGIN_NAME), file=sys.stderr)
        return 1
    return subprocess.call(call)


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
    entries = _event_list(data, "PermissionRequest")
    starters = _event_list(data, "SessionStart")
    archivers = _event_list(data, "PreToolUse")
    if entries is None or starters is None or archivers is None:
        _left_alone(path)
        return 1
    hooks = data["hooks"]

    changed = _sync_hook(entries, command, "*", os.path.basename(__file__))
    changed = _sync_hook(archivers, command, ARCHIVE_TOOL,
                         os.path.basename(__file__)) or changed
    if relay_command:
        changed = _sync_hook(starters, relay_command, None,
                             "watch_relay.py") or changed
    if not starters:
        hooks.pop("SessionStart", None)

    # The settings are written before the slow steps (Codex, the bridge's
    # notarization check, the login wake-up), never after them: written
    # after, the copy read here overwrote whatever Claude Code had saved in
    # the meantime (2026-11-21 review).
    backup = _backup(path) if changed else None
    if changed:
        _write_settings(path, data)

    codex = install_codex()
    closed = _bridge_step(bridge)
    # Even a no-op re-run repairs a missing login wake-up: installs from
    # before it existed get it the next time anything runs --install.
    # After the bridge, which may take the wake-up over.
    agent = bool(relay_command) and wake_relay_at_login()
    short = install_command()

    if not changed:
        print("Already installed, and the paths are correct.")
        print("  Settings : %s" % path)
        print("  Command  : %s" % command)
        if agent:
            print("  Reboot   : the relay wakes again at login")
        if closed:
            print(closed)
        _say_codex(codex)
        _say_command(short)
        print("  Nothing to do.")
        return 0

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
    _say_command(short)
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
    said = ("  Closed watch : buzzes through your own iCloud (bridge %s, "
            "just installed)" % pin["version"])
    if bridge_install.registers_itself():
        said += ("\n  Login Items  : macOS lists it as Tapproval. It carries "
                 "cards to your watch through iCloud and wakes the relay "
                 "after a restart.")
    return said


def _say_command(short):
    if short:
        print("  Shortcut : type \"tapproval status\" in a terminal "
              "(also pair, update, uninstall)")


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
    # The short command and the login entry are ours whatever settings.json
    # says, so they go first: an unreadable file or a plugin install ended
    # the uninstall before either was looked for (2026-11-14 review).
    remove_command()
    login_removed = remove_launch_agent()
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
        if login_removed:
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
            or os.path.exists(bridge_install.old_app_path())
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
    if data.get("env") is None:
        data["env"] = {}       # `"env": null` crashed --watch (2026-11-21 review)
    if not isinstance(data["env"], dict):
        _left_alone(path, 'its "env"')
        return 1
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
                # A hook added back by hand or by a fresh install carries
                # the plain 10 s: Claude Code then ends it long before the
                # wrist answers (2026-11-21 review). Already on is only
                # true once every handler of ours outlives the wait.
                if any(handler.get("timeout") != WATCH_HOOK_TIMEOUT
                       for handler in _settings_handlers(data)):
                    _set_hook_timeout(data, WATCH_HOOK_TIMEOUT)
                    return ("Wrist approvals were on; the hook's time limit "
                            "now outlasts the wait again.\n  Settings : %(path)s")
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
        parts = _split_command(command)
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


def session_env(data, env=None):
    """The environment a session's hook runs in: this shell's, with what
    settings.json exports for the hook on top. --status is typed in a plain
    terminal, where none of that is set, and read "shadow" from it while
    every session was in enforce (2026-11-10)."""
    merged = dict(os.environ if env is None else env)
    exported = data.get("env") if isinstance(data, dict) else None
    if isinstance(exported, dict):
        for name, value in exported.items():
            if isinstance(name, str) and name.startswith("CLAUDE_RISK_") \
                    and isinstance(value, (str, int, float)) and not isinstance(value, bool):
                merged[name] = str(value)
    return merged


def wakes_at_login():
    """Is something in place that wakes the relay at login? On Linux and
    Windows the login file; on a Mac the relay's own job, or the bridge
    that took the wake-up over from it (1.1.0 and later), which leaves no
    job file to find. Never raises."""
    if not _host.is_mac():
        target = _login_file()
        return bool(target) and os.path.exists(target)
    if os.path.exists(_launch_agent_path()):
        return True
    try:
        import bridge_install
        return bool(bridge_install.mac_supported() and bridge_install.wakes_relay())
    except Exception:
        return False


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
    policy = load_policy(session_env(data))
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
        "relay_wired": relay_wired, "login_item": wakes_at_login(),
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
        import urllib.parse
        import urllib.request
        url = RELAY_URL + path
        headers = {}
        key = _relay_key({})
        if key:
            split = urllib.parse.urlsplit(url)
            headers["X-Tapproval-Signature"], _ = wire.signed_header(
                key, "GET", urllib.parse.unquote(split.path), b"", split.query)
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            answer = json.loads(reply.read())
        # The relay answers these in objects; a list or a number is some
        # other program on the port, and --status read it as a relay's.
        return answer if isinstance(answer, dict) else None
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
    known = isinstance(seen, (int, float)) and not isinstance(seen, bool)
    lines.append("Watch         : %s" % ("seen %ds ago" % seen if known
                                         else "not seen recently"))
    conditions = health.get("conditions")
    problems = [c["detail"] for c in (conditions if isinstance(conditions, list) else [])
                if isinstance(c, dict) and isinstance(c.get("detail"), str) and c["detail"]]
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
        if codex_hook_trusted() is True:
            print("Codex         : wired and trusted")
        else:
            print("Codex         : wired, not trusted yet; open codex in Terminal once "
                  "and choose \"Trust all and continue\"")
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
    # ``tapproval <word>`` through its launcher, or the word typed after
    # this file's own name.
    if argv[0] == COMMAND_FLAG:
        return _guarded(run_command, argv[1:])
    if argv[0] in COMMAND_WORDS:
        return _guarded(run_command, argv)
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
