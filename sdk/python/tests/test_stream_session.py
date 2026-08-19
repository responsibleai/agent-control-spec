# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Streaming session contract: incremental release accounting for a
policy target the host holds as a stream (specification section 18.1).
The session gates, the host emits. Every engine rejection surfaces as a
Python exception; nothing silently no-ops."""

from __future__ import annotations

import pytest
from agent_control_spec import StreamSession
from agent_hooks import Decision, Transform, Verdict


def _allow() -> Verdict:
    return Verdict(decision=Decision.ALLOW)


def _deny() -> Verdict:
    return Verdict(decision=Decision.DENY, reason="blocked_by_policy")


def _transform() -> Verdict:
    return Verdict(
        decision=Decision.TRANSFORM,
        transform=Transform(path="$target.content", value="[redacted]"),
    )


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_blocking_session_releases_the_prefix_a_task_clears_and_finishes_clean():
    session = StreamSession(
        safety_level="blocking",
        response_tasks=["pii"],
    )
    # Safety level "blocking" holds every span until the watermark
    # covers it, so nothing is emittable before a `cleared` outcome.
    assert session.safe_offset("response") == 0

    assert session.observe_text("model_generated", "hello world") == 11
    assert session.pending("response") == 11
    # Nothing has cleared yet, so the offset a host may emit through has
    # not moved even though runes arrived.
    assert session.safe_offset("response") == 0

    session.record_outcome("pii", "model_generated", 0, 11, "cleared")
    assert session.advance("response") == 11
    assert session.safe_offset("response") == 11

    settlement = session.finish()
    assert settlement == {
        "reason": {"kind": "complete"},
        "transformed": False,
        "is_clean": True,
    }
    # A settled session hands out no offset to emit through, whatever
    # the reason. Confirmed stays available for the audit record.
    assert session.safe_offset("response") is None
    assert session.watermark("response")["confirmed"] == 11
    assert session.is_ended is True
    assert session.end_reason == {"kind": "complete"}


def test_advance_reports_none_when_no_task_moved_forward():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "hi")
    # No outcome recorded, so the watermark has nothing to commit and
    # `advance` must not synthesize progress.
    assert session.advance("response") is None
    assert session.safe_offset("response") == 0


# ---------------------------------------------------------------------
# Denial is terminal and audit path stays readable
# ---------------------------------------------------------------------


def test_a_denial_terminates_the_session_and_confirmed_stays_readable():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "safe prefix ")  # 12 runes
    session.record_outcome("pii", "model_generated", 0, 12, "cleared")
    session.advance("response")
    # Establish that the host would have been allowed to release the
    # first twelve runes, so the audit path is meaningful.
    assert session.safe_offset("response") == 12

    session.observe_text("model_generated", "bad tail")  # +8 runes, offsets 12..20
    session.record_outcome("pii", "model_generated", 12, 20, "denied")

    # Denial withholds everything a host has not already emitted,
    # including runes a task had cleared, so `safe_offset` becomes None.
    assert session.safe_offset("response") is None
    assert session.is_ended is True

    # The confirmed offset the audit needs is still readable. This is
    # the release ceiling the session reached, not permission to emit.
    watermark = session.watermark("response")
    assert watermark["confirmed"] == 12
    assert watermark["received"] == 20
    assert session.end_reason == {
        "kind": "denied",
        "track": "response",
        "task": "pii",
        "start": 12,
        "end": 20,
    }

    settlement = session.finish()
    assert settlement["is_clean"] is False
    assert settlement["transformed"] is False
    assert settlement["reason"]["kind"] == "denied"


def test_denial_through_a_verdict_reaches_the_same_terminal_state():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "bad content")  # 11 runes
    session.record_verdict("pii", "model_generated", 0, 11, _deny())

    reason = session.end_reason
    assert reason["kind"] == "denied"
    assert reason["task"] == "pii"
    assert reason["start"] == 0 and reason["end"] == 11


# ---------------------------------------------------------------------
# Multi-task: the watermark is the minimum across configured tasks
# ---------------------------------------------------------------------


def test_the_watermark_waits_for_every_task_configured_on_the_track():
    session = StreamSession(response_tasks=["pii", "safety"])
    session.observe_text("model_generated", "sentence one.")  # 13 runes

    # Only one of two tasks has cleared the span. The confirmed offset
    # is the minimum across both, so the release ceiling stays at zero.
    session.record_outcome("pii", "model_generated", 0, 13, "cleared")
    assert session.advance("response") is None
    assert session.safe_offset("response") == 0
    assert session.pending("response") == 13

    # Second task clears the same span. The minimum jumps to 13, so
    # the watermark advances and the prefix becomes emittable.
    session.record_outcome("safety", "model_generated", 0, 13, "cleared")
    assert session.advance("response") == 13
    assert session.safe_offset("response") == 13

    watermark = session.watermark("response")
    assert sorted(watermark["tasks"]) == ["pii", "safety"]

    completion = session.finish()
    assert completion["is_clean"] is True


# ---------------------------------------------------------------------
# observe_text counts runes, not UTF-16 code units
# ---------------------------------------------------------------------


def test_observe_text_counts_runes_not_utf16_code_units_or_bytes():
    session = StreamSession(response_tasks=["pii"])
    astral = "😀"  # one rune, but two UTF-16 code units and four UTF-8 bytes
    # Sanity guard: this text really is a two-code-unit astral character,
    # so the assertion below is actually testing the rune boundary.
    assert len(astral.encode("utf-16-le")) // 2 == 2

    assert session.observe_text("model_generated", astral) == 1
    session.record_outcome("pii", "model_generated", 0, 1, "cleared")
    assert session.advance("response") == 1
    assert session.safe_offset("response") == 1


# ---------------------------------------------------------------------
# Unmediated tracks fail closed instead of silently releasing
# ---------------------------------------------------------------------


def test_payload_on_an_unmediated_track_fails_closed():
    # No `request_tasks`, so the request track is not mediated and text
    # on it has nothing to gate it. That is a fail closed condition, not
    # a silent release.
    session = StreamSession(response_tasks=["pii"])
    with pytest.raises(ValueError, match="unmediated request track"):
        session.observe_text("user_request", "hello")
    # The failed observation was itself the terminal step for the
    # session, so subsequent state matches the general terminal contract.
    assert session.is_ended is True
    assert session.safe_offset("request") is None
    assert session.end_reason["kind"] == "failed"


def test_a_session_mediating_neither_track_is_refused_at_construction():
    # No tasks means the session would gate nothing at all.
    with pytest.raises(ValueError):
        StreamSession(safety_level="blocking")


# ---------------------------------------------------------------------
# Boundary errors surface with the engine's own message
# ---------------------------------------------------------------------


def test_unknown_safety_level_raises_before_a_session_exists():
    with pytest.raises(ValueError, match="unknown streaming safety level"):
        StreamSession(safety_level="permissive", response_tasks=["pii"])


def test_unknown_track_name_raises_on_read_paths():
    session = StreamSession(response_tasks=["pii"])
    with pytest.raises(ValueError, match="unknown stream track"):
        session.safe_offset("responses")
    with pytest.raises(ValueError, match="unknown stream track"):
        session.watermark("responses")


def test_unknown_outcome_and_source_type_raise():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "hello")
    with pytest.raises(ValueError, match="unknown segment outcome"):
        session.record_outcome("pii", "model_generated", 0, 5, "allow")
    # Still functional because the outcome parse fails before touching
    # the session.
    assert session.is_ended is False
    with pytest.raises(ValueError, match="unknown stream source type"):
        session.observe("assistant", 1)


def test_unknown_task_raises_and_terminates_the_session():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "hello")
    with pytest.raises(ValueError, match="outcome named task safety"):
        session.record_outcome("safety", "model_generated", 0, 5, "cleared")
    # An engine-side rejection settled the session; safe_offset accepts
    # that as terminal.
    assert session.is_ended is True
    assert session.safe_offset("response") is None


# ---------------------------------------------------------------------
# Independent per-track offsets
# ---------------------------------------------------------------------


def test_request_and_response_are_independent_offset_spaces():
    session = StreamSession(
        safety_level="blocking",
        request_tasks=["prompt_guard"],
        response_tasks=["pii"],
        request_start_rune_offset=100,
        response_start_rune_offset=250,
    )
    # Independent origins survive into the watermark unchanged.
    assert session.watermark("request")["confirmed"] == 100
    assert session.watermark("response")["confirmed"] == 250

    # Advancing one track does not disturb the other. A task on the
    # response track clears a span, and the request track's ceiling
    # holds where it started.
    session.observe_text("model_generated", "hi")  # +2 runes on response
    session.record_outcome("pii", "model_generated", 250, 252, "cleared")
    assert session.advance("response") == 252
    assert session.safe_offset("response") == 252
    assert session.safe_offset("request") == 100

    # Now do the same on the request track. A user request span clears,
    # and the response ceiling stays put.
    session.observe_text("user_request", "prompt")  # +6 runes on request
    session.record_outcome("prompt_guard", "user_request", 100, 106, "cleared")
    assert session.advance("request") == 106
    assert session.safe_offset("request") == 106
    assert session.safe_offset("response") == 252

    completion = session.finish()
    assert completion["is_clean"] is True


# ---------------------------------------------------------------------
# Verdict shape is validated, and a transform ends the stream rewritten
# ---------------------------------------------------------------------


def test_a_transform_verdict_ends_the_session_rewritten_and_reports_transformed():
    session = StreamSession(safety_level="blocking", response_tasks=["pii"])
    session.observe_text("model_generated", "raw output")  # 10 runes
    session.record_verdict("pii", "model_generated", 0, 10, _transform())

    assert session.transformed is True
    assert session.is_ended is True
    reason = session.end_reason
    assert reason == {
        "kind": "rewritten",
        "track": "response",
        "task": "pii",
        "start": 0,
        "end": 10,
    }
    settlement = session.finish()
    assert settlement["transformed"] is True
    assert settlement["is_clean"] is False


def test_a_malformed_verdict_fails_the_stream_closed_without_clearing():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "content")  # 7 runes
    # A `transform` decision without a transform body is a shape section
    # 5 does not admit. The typed constructor already refuses to build
    # this, so a host cannot reach the session with it as a typed value.
    # A wire dict is exactly how one arrives from an out-of-process peer
    # that decided without validating, and the session must fail closed
    # here rather than clearing the span.
    malformed_wire = {"decision": "transform"}
    with pytest.raises(ValueError):
        session.record_verdict("pii", "model_generated", 0, 7, malformed_wire)
    assert session.is_ended is True
    assert session.end_reason["kind"] == "failed"


# ---------------------------------------------------------------------
# `record_verdict` accepts a wire dict too, not just a typed Verdict
# ---------------------------------------------------------------------


def test_record_verdict_accepts_a_wire_dict_from_a_serialized_verdict():
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "hello")
    # Any host that decoded a verdict from the wire holds it as a dict,
    # so the wrapper accepts that shape without a round trip through the
    # typed constructor.
    session.record_verdict(
        "pii",
        "model_generated",
        0,
        5,
        {"decision": "allow"},
    )
    assert session.advance("response") == 5
    completion = session.finish()
    assert completion["is_clean"] is True


# ---------------------------------------------------------------------
# Rune offsets are `u32` on the wire. pyo3's automatic `u32` conversion
# raises `OverflowError` on any Python integer outside `[0, 2**32)`,
# so a bindings-level guard is not needed here — Node's is a workaround
# for N-API's silent ToUint32 wrap. Pin the guarantee anyway: a future
# change to accept `i64` and cast later would silently re-open the same
# hole the Node wrapper is now guarding against, and this test would
# fail loudly instead.
# ---------------------------------------------------------------------


def test_observe_refuses_a_rune_offset_at_or_past_the_u32_boundary():
    session = StreamSession(response_tasks=["pii"])
    with pytest.raises(OverflowError):
        session.observe("model_generated", 2**32)
    # Session state must be untouched: the raise happened before any
    # native accounting ran.
    assert session.watermark("response")["received"] == 0


def test_observe_refuses_a_negative_rune_offset():
    session = StreamSession(response_tasks=["pii"])
    with pytest.raises(OverflowError):
        session.observe("model_generated", -1)
    assert session.watermark("response")["received"] == 0


def test_record_outcome_refuses_an_end_offset_past_the_u32_boundary():
    # The exact failure mode the Node guard exists to prevent: a wrap
    # to a small value would mark a *cleared* prefix on text no task
    # evaluated. Python raises before the native call, so nothing
    # clears.
    session = StreamSession(response_tasks=["pii"])
    session.observe_text("model_generated", "hello")
    with pytest.raises(OverflowError):
        session.record_outcome("pii", "model_generated", 0, 2**32 + 5, "cleared")
    assert session.safe_offset("response") == 0


def test_record_outcome_refuses_a_start_offset_at_the_u32_boundary():
    session = StreamSession(response_tasks=["pii"])
    with pytest.raises(OverflowError):
        session.record_outcome("pii", "model_generated", 2**32, 5, "cleared")


def test_record_verdict_refuses_rune_offsets_past_the_u32_boundary():
    # The verdict path enters the same accounting as record_outcome,
    # so the guarantee must be symmetric.
    session = StreamSession(response_tasks=["safety"])
    session.observe_text("model_generated", "hello")
    with pytest.raises(OverflowError):
        session.record_verdict(
            "safety", "model_generated", 0, 2**32 + 5, {"decision": "allow"}
        )
    with pytest.raises(OverflowError):
        session.record_verdict(
            "safety", "model_generated", -1, 5, {"decision": "allow"}
        )
    assert session.safe_offset("response") == 0


def test_stream_session_refuses_a_start_rune_offset_in_config_past_the_u32_boundary():
    with pytest.raises(OverflowError):
        StreamSession(
            response_tasks=["pii"],
            response_start_rune_offset=2**32,
        )
    with pytest.raises(OverflowError):
        StreamSession(
            request_tasks=["moderation"],
            request_start_rune_offset=-1,
        )
