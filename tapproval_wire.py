#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tapproval_wire — the few pure rules the hook, the relay and the
dashboard must agree on, written once.

The hook cannot import the relay or the dashboard: that costs it 0.4-1.5 s
on every permission prompt. So everything it needed was copied, and parity
tests held the copies equal (issue #731). This file is what they shared:
how a request is signed and an answer proved, how plan Markdown reads on a
wrist, where the helper's files are, and what answering as the relay looks
like from outside.

Rules for this file: standard library only (hard constraint 1), nothing
done at import beyond compiling a few patterns, and pure functions only.
Deciding who may do what stays in the relay: verify_signature, nonces and
which signature versions are accepted are not here. If this file is
missing, the hook fails to start and Claude Code asks in the terminal, as
it always does when no hook answers: fail closed (hard constraint 3).
crash_report.py keeps its own copy of the path rule, because it must work
when nothing else imports.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

# ---- signing ---------------------------------------------------------------
#
# A signed request carries "v2 <stamp> <nonce> <mac>": an HMAC-SHA256, with
# a device key or the key file's bootstrap, over the method, the path, the
# query, the time, a nonce and the body's SHA-256. v1 is the same without
# the query line, from watches and bridges built before it. The relay
# answers with proofs only a holder of the same key can make.


def signature_message(method, path, stamp, nonce, body=b"", query=None):
    """What a signature covers. v1 (``query`` None) is the method, the path
    (percent-decoded, no query), the time, the nonce and the body; v2
    (``query`` given, even empty) adds the raw query string, which v1 left
    open: a signed request for `?id=A` could be sent on as `?id=B`
    (2026-09-30 review)."""
    parts = [str(method).upper(), str(path)]
    if query is not None:
        parts.append(str(query))
    parts += [str(stamp), str(nonce), hashlib.sha256(body or b"").hexdigest()]
    return "\n".join(parts).encode("utf-8")


def sign_request(token, method, path, stamp, nonce, body=b"", query=None):
    import hmac      # here, not at the top: most prompts sign nothing
    return hmac.new(str(token).encode("utf-8"),
                    signature_message(method, path, stamp, nonce, body, query),
                    hashlib.sha256).hexdigest()


def signature_header(stamp, nonce, mac):
    """The X-Tapproval-Signature value for a v2 signature."""
    return "v2 %d %s %s" % (stamp, nonce, mac)


def relay_proof(token, nonce):
    """What the relay answers a signed request with: only a holder of the
    same key can produce it for this nonce."""
    import hmac
    return hmac.new(str(token).encode("utf-8"),
                    ("tapproval-proof\n%s" % nonce).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def relay_proof2(token, nonce, status, body):
    """The proof over the answer itself: the nonce, the status and the
    SHA-256 of the body. relay_proof names only the nonce, so a proof
    could be kept while the body under it was rewritten (2026-09-30
    review). A watch that has seen this header requires it from then on."""
    import hmac
    message = "tapproval-proof2\n%s\n%d\n%s" % (
        nonce, int(status), hashlib.sha256(body or b"").hexdigest())
    return hmac.new(str(token).encode("utf-8"), message.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def read_bootstrap(path):
    """The bootstrap out of a relay key file, or "" when there is none to
    read. Never raises: no key is an answer, and the caller decides."""
    try:
        with open(path, encoding="utf-8") as handle:
            return str(json.load(handle).get("bootstrap") or "")
    except (OSError, ValueError, AttributeError):
        return ""


# ---- where the helper's files are -----------------------------------------


def home_file(folder, name, legacy, tapproval_dir, legacy_home):
    """Where one of the helper's files is: <tapproval_dir>/<folder>/<name>,
    unless only the old loose file <legacy_home>/<legacy> exists yet. The
    relay moves the old ones once (move_loose_files)."""
    new = os.path.join(tapproval_dir, folder, name)
    old = os.path.join(legacy_home, legacy)
    if not os.path.exists(new) and os.path.exists(old):
        return old
    return new


# ---- answering as the relay -----------------------------------------------


def answers_as_relay(url, timeout, agent):
    """Does ``url`` (a /health under the away address) reach this relay?
    The relay answers under its secret path in JSON, and a 401 or 403
    without a key is still an answer; Cloudflare answers a tunnel with
    nothing behind it in HTML (502, 530). False when nothing answered.
    Never raises."""
    import urllib.error
    import urllib.request
    request = urllib.request.Request(url, headers={"User-Agent": agent})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            status, ctype = reply.status, reply.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        status = error.code
        ctype = error.headers.get("Content-Type", "") if error.headers else ""
    except Exception:
        return False
    return status in (200, 401, 403) and "json" in (ctype or "")


# ---- Markdown, as a wrist reads it ----------------------------------------
#
# A reply in the dashboard and a plan on the hook's card read the same way:
# block markup read, inline marks kept for a watch that draws them, a
# wrapped paragraph one line.

MD_FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
MD_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+")
MD_QUOTE = re.compile(r"^\s{0,3}>\s?")
MD_BULLET = re.compile(r"^(\s*)[-*+]\s+")
MD_NUMBER = re.compile(r"^\s*\d+[.)]\s+")
MD_HR = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
MD_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
MD_IMAGE = re.compile(r"!\[([^\]]*)\]\([^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
MD_CODE = re.compile(r"`+([^`]*)`+")
MD_STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*"
                       r"|(?<!\w)__(?=\S)(.+?)(?<=\S)__(?!\w)")
MD_EM = re.compile(r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])"
                   r"|(?<!\w)_(?=\S)([^_\n]+?)(?<=\S)_(?!\w)")
MD_STRIKE = re.compile(r"~~(.+?)~~")
MD_HTML = re.compile(r"</?[a-zA-Z][^>]*>")
MD_ESCAPE = re.compile(r"\\([\\`*_{}\[\]()#+\-.!>])")


def flatten_line(line, keep_inline=False):
    """One Markdown line reduced to what it says. ``keep_inline`` leaves
    code, emphasis and strike marks for a caller that styles them itself."""
    line = MD_HEADING.sub("", line)
    line = MD_QUOTE.sub("", line)
    line = MD_BULLET.sub(r"\1• ", line)
    if line.lstrip().startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        line = " · ".join(c for c in cells if c)
    line = MD_IMAGE.sub(r"\1", line)
    line = MD_LINK.sub(r"\1", line)
    if not keep_inline:
        line = MD_CODE.sub(r"\1", line)
        line = MD_STRONG.sub(lambda m: m.group(1) or m.group(2), line)
        line = MD_EM.sub(lambda m: m.group(1) or m.group(2), line)
        line = MD_STRIKE.sub(r"\1", line)
    line = MD_HTML.sub("", line)
    return MD_ESCAPE.sub(r"\1", line)


def unwrap(lines):
    """Markdown lines with each wrapped paragraph or point joined into one
    line, as Markdown itself reads them. The watch draws a line at a time,
    so a ``**bold**`` opened on one line of a hard-wrapped text and closed
    on the next showed its asterisks (the owner's wrist, 2026-10-14). A
    line that starts something of its own — a heading, a point, a quote, a
    table row, a rule, a fence — is never joined, and nothing joins onto a
    heading, a table row or code."""
    out, joinable, in_fence = [], False, False
    for raw in lines:
        if MD_FENCE.match(raw):
            in_fence, joinable = not in_fence, False
            out.append(raw)
            continue
        closed = (not raw.strip() or in_fence or MD_HEADING.match(raw)
                  or MD_HR.match(raw) or MD_TABLE_SEP.match(raw)
                  or raw.lstrip().startswith("|"))
        opens = MD_BULLET.match(raw) or MD_NUMBER.match(raw) or MD_QUOTE.match(raw)
        if joinable and not (closed or opens):
            out[-1] = out[-1].rstrip() + " " + raw.strip()
        else:
            out.append(raw)
            joinable = not closed
        # A hard break — a trailing backslash or two spaces — is a line
        # break the writer asked for, never a wrap; its backslash is markup.
        if joinable and (out[-1].endswith("  ") or out[-1].endswith("\\")):
            end = out[-1].rstrip(" ")
            out[-1] = (end[:-1] if end.endswith("\\") else end).rstrip()
            joinable = False
    return out


# ---- a wrist message in an open session's inbox ----------------------------
#
# Claude Code gives every session an inbox socket (cross-session messaging),
# and a message posted there becomes a turn of the open session itself: the
# terminal and the phone follow it, where a headless `claude --resume -p`
# was a side thread neither saw (#246, tested 2026-10-22). Claude Code files
# such a message as a hidden "from another session" line, which the phone
# does not show, so the message asks Claude to say the wearer's words back
# first. The relay writes it; the dashboard reads the words back out for the
# wrist's thread. Tapproval's own wording is the marker, not Claude Code's
# wrapping, which differs between versions.

WRIST_INBOX_OPENER = "From the user's Apple Watch (Tapproval), in their own words:"
# The note's opening stays the same from version to version: it is where
# the wrist finds the end of the words, in this and older messages alike.
WRIST_INBOX_NOTE_START = "(Their phone and terminal don't show this message."
# A watch and the words in italics, the owner's choice of hint (2026-10-22;
# 1.1.64 asked for "From your watch: ").
# Claude Code files the message as one from another session, which can
# never count as the user's approval; a question it asks back can, because
# the hook turns it into a card on the watch and the tap is the user's own
# answer (proven 2026-10-22: "Ship it" approved that way). So the message
# says how to get the go-ahead.
WRIST_INBOX_NOTE = ("(Their phone and terminal don't show this message. Open "
                    "your reply with one line: \u231a and their words in "
                    "italics, shortened if long, like *\u231a What's left?* "
                    "If what they ask needs their go-ahead (anything you would "
                    "confirm with them before doing it), ask them with "
                    "AskUserQuestion first: Tapproval shows the question on "
                    "their watch, and their answer there is their own.)")


# Settings' "Short replies", which a headless run gets as Claude Code's
# Concise style; an open session keeps its own style, so it is asked.
WRIST_INBOX_BRIEF = "Keep the answer short: they read it on a watch."


def wrist_inbox_message(text, brief=False):
    """What the relay posts into a session's inbox for one wrist message."""
    note = WRIST_INBOX_NOTE + (" " + WRIST_INBOX_BRIEF if brief else "")
    return "%s\n\n%s\n\n%s" % (WRIST_INBOX_OPENER, text, note)


def wrist_words(content):
    """The wearer's words from a delivered inbox message, or None when the
    text is not one of ours."""
    if not isinstance(content, str):
        return None
    start = content.find(WRIST_INBOX_OPENER)
    if start < 0:
        return None
    rest = content[start + len(WRIST_INBOX_OPENER):]
    end = rest.rfind(WRIST_INBOX_NOTE_START)
    if end < 0:
        return None
    return rest[:end].strip() or None
