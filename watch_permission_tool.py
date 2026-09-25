"""The wrist answers a permission prompt that has no terminal to appear in.

    claude --resume <id> -p "..." \
      --mcp-config '{"mcpServers":{"tapproval":{"command":"python3",
                     "args":["~/.tapproval/watch_permission_tool.py"]}}}' \
      --permission-prompt-tool mcp__tapproval__approve

Every quick send from the watch runs `claude --resume -p`, and a headless
run never fires the PermissionRequest hook: the hook belongs to the
interactive terminal. So a wrist instruction that needed a yes had
nowhere to ask — it stopped at the first risky command and said nothing
about why. That is what this closes: Claude Code hands the question to
this tool instead, and this tool hands it to the same wrist that sent the
instruction, through the same relay and the same card the hook uses.

It speaks MCP over stdin/stdout — JSON-RPC 2.0, three methods — because
that is the shape Claude Code expects a permission tool to arrive in. No
dependencies: hooks and helpers here run under whatever python3 is on
PATH.

**It fails closed, and differently from the hook.** The hook may answer
"none" and let the ordinary prompt appear, because a person is sitting at
the terminal. Here nobody is: the run was started from a wrist, and if
the wrist does not answer there is no second surface to fall back to. So
silence, a relay that is down, a malformed reply and an unreadable
request all become **deny**, with a sentence saying which — a denial that
explains itself is a message; a hang is not.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

PROTOCOL = "2024-11-05"
TOOL = "approve"
VERSION = "1"


def _classifier():
    """The classifier, or None. Imported lazily so a broken install still
    speaks MCP well enough to deny in words rather than dying on stdin."""
    try:
        import ClaudeRiskClassifier
        return ClaudeRiskClassifier
    except Exception:                                   # pragma: no cover
        return None


def deny(message):
    return {"behavior": "deny", "message": message}


def decide(tool_name, tool_input, crc=None, cwd=None):
    """Ask the wrist about one tool call. Returns the permission decision.

    Never raises: a permission tool that throws is a session that stops
    with a stack trace where an answer should be.
    """
    crc = crc or _classifier()
    if crc is None:
        return deny("Tapproval could not read its own classifier on this "
                    "computer, so it cannot describe this command to your "
                    "watch. Answer it at the keyboard.")
    if not isinstance(tool_input, dict):
        tool_input = {}
    try:
        policy = crc.load_policy()
        if not str(policy.get("relay") or "").strip():
            return deny("Tapproval has no relay address configured, so there "
                        "is no watch to ask. Answer this at the keyboard.")
        result = crc.classify({"tool_name": tool_name, "tool_input": tool_input,
                               "cwd": cwd})
        # The same threshold the hook obeys, for the same reason: a wrist
        # that is asked about every `ls` stops reading the cards. With the
        # default "NONE" nothing is waved through and every prompt travels
        # — which is the honest default, not the quiet one. CRITICAL is
        # never auto-allowed here either; `decide` holds that.
        verdict, reason = crc.decide(result["risk"], policy)
        if verdict == "allow":
            return {"behavior": "allow", "updatedInput": tool_input}
        if verdict == "deny":
            return deny(reason or "Blocked by your Tapproval policy.")
        card = crc.wrist_card(tool_name, tool_input, result["risk"])
        verdict, _answer = crc.ask_watch(card, policy)
    except Exception as error:                          # never a stack trace
        return deny("Tapproval could not ask your watch (%s). Answer this at "
                    "the keyboard." % error)
    if verdict == "allow":
        return {"behavior": "allow", "updatedInput": tool_input}
    if verdict == "deny":
        return deny("You denied this on your watch.")
    return deny("Your watch did not answer in time, and a message sent from "
                "the wrist has no terminal to fall back to. Nothing was run.")


def _result(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def handle(message, crc=None):
    """One JSON-RPC message in, one reply out — or None for a notification,
    which by the protocol is answered with silence, not with an error."""
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        return None
    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tapproval", "version": VERSION}})
    if method == "tools/list":
        return _result(request_id, {"tools": [{
            "name": TOOL,
            "description": ("Ask the watch that sent this instruction whether "
                            "one tool call may go ahead."),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string"},
                    "input": {"type": "object"},
                    "tool_use_id": {"type": "string"}},
                "required": ["tool_name", "input"]}}]})
    if method == "tools/call":
        params = message.get("params") or {}
        if params.get("name") != TOOL:
            return {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601,
                              "message": "no tool named %r" % params.get("name")}}
        arguments = params.get("arguments") or {}
        decision = decide(arguments.get("tool_name") or arguments.get("toolName") or "",
                          arguments.get("input") or arguments.get("toolInput") or {},
                          crc=crc, cwd=arguments.get("cwd"))
        # The decision rides as JSON inside a text block: that is how a
        # permission tool answers, and Claude Code parses the text.
        return _result(request_id, {
            "content": [{"type": "text", "text": json.dumps(decision)}]})
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32601, "message": "unknown method %r" % method}}


def serve(stdin=None, stdout=None, crc=None):
    """Read messages until the pipe closes. One JSON object per line."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue                                    # not ours to answer
        reply = handle(message, crc=crc)
        if reply is None:
            continue
        stdout.write(json.dumps(reply) + "\n")
        stdout.flush()


if __name__ == "__main__":
    serve()
