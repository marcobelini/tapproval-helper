"""Activity is conversation usage, independent of auto-approval settings."""
import json
import os
import time
from datetime import datetime, timezone

import pytest

import watch_dashboard as dashboard


NOW = datetime(2026, 10, 27, 12, tzinfo=timezone.utc).timestamp()
STAMP = "2026-10-27T10:00:00Z"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "CLAUDE_PROJECTS", str(tmp_path / "projects"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.setattr(dashboard, "_audit_log_path", lambda: str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("TZ", "UTC")
    if hasattr(time, "tzset"):
        time.tzset()
    elif time.timezone or time.altzone:
        pytest.skip("this host's clock cannot be set to UTC, and is not on it")
    dashboard._CONVERSATION_CACHE.clear()
    dashboard._ACTIVITY_STATE.clear()
    dashboard._RECAP_CACHE.clear()
    dashboard._OVERVIEW_CACHE.clear()
    yield
    dashboard._CONVERSATION_CACHE.clear()
    monkeypatch.undo()
    time.tzset()


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def claude(tmp_path, sid="cc", stamp=STAMP, output=10):
    return write(tmp_path / "projects" / "-garden" / (sid + ".jsonl"), [
        {"type": "assistant", "timestamp": stamp,
         "message": {"id": sid, "role": "assistant", "content": "Done",
                     "usage": {"output_tokens": output}}}])


def codex(tmp_path, outputs=(20,), sid="cx", stamp=STAMP):
    rows = [{"type": "session_meta", "payload": {"id": sid}},
            {"type": "response_item", "timestamp": stamp,
             "payload": {"type": "message", "role": "user",
                         "content": [{"type": "input_text", "text": "Check garden"}]}}]
    rows += [{"type": "event_msg", "timestamp": stamp,
              "payload": {"type": "token_count", "info": {
                  "total_token_usage": {"output_tokens": output}}}} for output in outputs]
    return write(tmp_path / "codex" / "sessions" / ("rollout-" + sid + ".jsonl"), rows)


def test_closed_sessions_are_counted_by_messages_not_file_modification(tmp_path):
    path = claude(tmp_path)
    os.utime(path, (1, 1))
    codex(tmp_path)
    facts = dashboard.conversation_activity(now=NOW)
    assert facts["sessions"] == facts["all_sessions"] == 2
    assert facts["agents"] == [{"agent": "codex", "sessions": 1},
                               {"agent": "claude", "sessions": 1}]


def test_single_agent_and_empty_have_no_invented_peer(tmp_path):
    assert dashboard.conversation_activity(now=NOW)["agents"] == []
    codex(tmp_path)
    facts = dashboard.conversation_activity(now=NOW)
    assert facts["agents"] == [{"agent": "codex", "sessions": 1}]


def test_calendar_day_is_not_a_rolling_24_hours(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Copenhagen")
    time.tzset()
    claude(tmp_path, "yesterday", "2026-10-26T22:30:00Z")
    claude(tmp_path, "today", "2026-10-26T23:30:00Z", 12)
    facts = dashboard.conversation_activity(now=NOW)
    assert facts["sessions"] == 1 and facts["all_sessions"] == 2
    assert facts["usage"][0]["today_output"] == 12


def test_codex_cumulative_snapshots_and_duplicate_rollouts_do_not_double_count(tmp_path):
    path = codex(tmp_path, outputs=(20, 20, 35, 35))
    copy = path.parent / "rollout-copy.jsonl"
    copy.write_bytes(path.read_bytes())
    facts = dashboard.conversation_activity(now=NOW)
    assert facts["sessions"] == 1
    assert facts["usage"][0]["today_output"] == 35


def test_streaming_claude_snapshots_count_one_message(tmp_path):
    path = claude(tmp_path)
    with path.open("a") as handle:
        handle.write(path.read_text())
    assert dashboard.conversation_activity(now=NOW)["usage"][0]["today_output"] == 10


def test_claude_identity_survives_a_copied_transcript(tmp_path):
    path = claude(tmp_path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["sessionId"] = "original-session"
    write(path, rows)
    write(path.parent / "copy.jsonl", rows)
    facts = dashboard.conversation_activity(now=NOW)
    assert facts["sessions"] == 1
    assert facts["usage"][0]["today_output"] == 10


def test_unknown_usage_is_not_zero_and_partial_data_is_marked(tmp_path):
    claude(tmp_path)
    codex(tmp_path, outputs=())
    facts = dashboard.usage_summary(now=NOW)
    assert facts["output_complete"] is False
    codex_usage = next(row for row in facts["agents"] if row["agent"] == "codex")
    assert codex_usage["measured"] is False
    assert codex_usage["today_output"] is None


def test_no_message_no_session_and_harness_messages_do_not_count(tmp_path):
    path = codex(tmp_path, outputs=())
    text = path.read_text().replace("Check garden", "<environment_context>setup")
    path.write_text(text)
    assert dashboard.conversation_activity(now=NOW)["sessions"] == 0


def test_append_partial_line_rotation_and_unchanged_file(tmp_path, monkeypatch):
    path = codex(tmp_path)
    assert dashboard.conversation_activity(now=NOW)["sessions"] == 1
    offsets = []
    original = dashboard._read_appended

    def read(path, offset, **kwargs):
        offsets.append(offset)
        return original(path, offset, **kwargs)

    monkeypatch.setattr(dashboard, "_read_appended", read)
    row = json.dumps({"type": "event_msg", "timestamp": STAMP, "payload": {
        "type": "token_count", "info": {"total_token_usage": {"output_tokens": 45}}}})
    with path.open("a") as handle:
        handle.write(row[:30])
    assert dashboard.conversation_activity(now=NOW)["usage"][0]["today_output"] == 20
    with path.open("a") as handle:
        handle.write(row[30:] + "\n")
    assert dashboard.conversation_activity(now=NOW)["usage"][0]["today_output"] == 45
    assert offsets and all(offset > 0 for offset in offsets)
    path.write_text("{}\n")
    assert dashboard.conversation_activity(now=NOW)["sessions"] == 0


def test_decisions_exclude_shadow_auto_approvals_and_parity_skips(tmp_path):
    rows = [dict(ts=STAMP, mode="shadow", decision="escalate"),
            dict(ts=STAMP, mode="enforce", decision="allow"),
            dict(ts=STAMP, mode="enforce", decision="escalate", watch="skipped-parity"),
            dict(ts=STAMP, mode="enforce", decision="escalate", agent="codex", watch="native"),
            dict(ts=STAMP, mode="enforce", decision="escalate", watch="allow"),
            dict(ts=STAMP, mode="enforce", decision="receipt", watch="deny",
                 agent="codex", audit_type="watch_receipt")]
    write(tmp_path / "audit.jsonl", rows)
    for facts in [dashboard.activity_summary(now=NOW), dashboard.recap_summary(now=NOW)]:
        assert facts["decisions_needed"] == 2
        assert facts["recorded_watch_answers"] == 2
    assert dashboard.activity_summary(now=NOW)["recent"][0]["agent"] == "codex"


def test_native_receipt_is_only_an_answer_not_another_prompt(tmp_path):
    import ClaudeRiskClassifier as classifier
    from codex_approvals import ApprovalSync
    from unittest.mock import patch
    path = tmp_path / "audit.jsonl"
    with patch.object(classifier, "load_policy", return_value={"audit_log": str(path)}):
        ApprovalSync._audit_answer({"session_id": "cx", "headline": "Tests", "tier": "LOW"}, "allow")
    facts = dashboard.activity_summary(now=NOW + 86400 * 365)
    assert facts["decisions_needed"] == 0
    assert dashboard.recap_summary(now=NOW)["recorded_watch_answers"] == 1


def test_future_message_is_retried_when_the_clock_reaches_it(tmp_path):
    codex(tmp_path, stamp="2026-10-27T12:01:00Z")
    assert dashboard.conversation_activity(now=NOW)["sessions"] == 0
    assert dashboard.conversation_activity(now=NOW + 120)["sessions"] == 1


def test_initial_history_scan_does_not_block_the_watch(tmp_path, monkeypatch):
    import threading
    release = threading.Event()

    def scan(**_kwargs):
        assert release.wait(2)
        return {"sessions": 0, "agents": [], "usage": []}

    monkeypatch.setattr(dashboard, "conversation_activity", scan)
    try:
        facts = dashboard.activity_summary(now=NOW, background=True)
        assert facts["sessions_loading"] is True
        assert facts["session_count"] is None
    finally:
        release.set()
        for thread in threading.enumerate():
            if thread.name == "activity-history":
                thread.join(2)
    assert dashboard.activity_summary(now=NOW, background=True)["session_count"] == 0


def _reads_from_the_start(monkeypatch):
    """Every transcript the next pass opens at its first byte."""
    restarted = []
    real = dashboard._read_appended

    def spy(path, offset, *args, **kwargs):
        if offset == 0:
            restarted.append(path)
        return real(path, offset, *args, **kwargs)
    monkeypatch.setattr(dashboard, "_read_appended", spy)
    return restarted


def test_a_second_pass_reads_no_transcript_again_however_many_there_are(
        tmp_path, monkeypatch):
    """Past 4,096 transcripts each one read pushed out the one the pass
    needed next, so every file was read from its first byte about every
    ten seconds (2026-11-14 review)."""
    folder = tmp_path / "projects" / "-garden"
    folder.mkdir(parents=True)
    row = json.dumps({"type": "assistant", "timestamp": STAMP,
                      "message": {"id": "m", "role": "assistant", "content": "Done",
                                  "usage": {"output_tokens": 1}}}) + "\n"
    for index in range(4200):
        (folder / ("s%04d.jsonl" % index)).write_text(row)
    assert dashboard.conversation_activity(now=NOW)["all_sessions"] == 4200
    restarted = _reads_from_the_start(monkeypatch)
    assert dashboard.conversation_activity(now=NOW)["all_sessions"] == 4200
    assert restarted == []


def test_a_transcript_that_is_gone_is_forgotten(tmp_path):
    """The relay runs for weeks: what it remembers is what is on the disk."""
    kept = claude(tmp_path, sid="kept")
    gone = claude(tmp_path, sid="gone")
    dashboard.conversation_activity(now=NOW)
    assert {str(kept), str(gone)} <= set(dashboard._CONVERSATION_CACHE)
    gone.unlink()
    assert dashboard.conversation_activity(now=NOW)["all_sessions"] == 1
    assert str(gone) not in dashboard._CONVERSATION_CACHE
    assert str(kept) in dashboard._CONVERSATION_CACHE
