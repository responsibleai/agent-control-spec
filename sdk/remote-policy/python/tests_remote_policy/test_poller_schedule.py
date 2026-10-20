# Copyright (c) Microsoft. All rights reserved.
"""Lease-aware refresh scheduling, driven by a virtual event-loop clock."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import math
import selectors
from collections.abc import Callable, Coroutine, Sequence, Sized
from datetime import datetime, timedelta
from functools import partial
from typing import Any, TypeVar, cast

import pytest
from agent_control_spec_remote_policy.poller import (
    LEASE_REFRESH_MARGIN_SECONDS,
    AgentPolicy,
    Changed,
    NotModified,
    PolicyPoller,
    PolicySourceError,
    PolicyUnavailable,
    PollerConfig,
    _lease_refresh_delay,
)

from .test_remote_policy import (
    NOW,
    FakeClock,
    MemorySource,
    configuration,
    document,
    reply,
)

T = TypeVar("T")


class VirtualTimeLoop(asyncio.SelectorEventLoop):
    """An event loop whose clock jumps to its next timer instead of waiting.

    It relies on two private attributes of ``BaseEventLoop`` that have been stable
    across CPython releases: the timer heap and the ready queue.
    """

    def __init__(self) -> None:
        super().__init__()
        self._virtual_time = 0.0
        self._idle_turns = 0

    def time(self) -> float:
        return self._virtual_time

    def _run_once(self) -> None:
        before = self._virtual_time
        scheduled = cast("list[asyncio.TimerHandle]", getattr(self, "_scheduled"))  # noqa: B009
        ready = cast("Sized", getattr(self, "_ready"))  # noqa: B009
        # A cancelled timer left on the heap must not set the next deadline: the
        # parent drops it and would then wait in real time for the live timer.
        live = [handle.when() for handle in scheduled if not handle.cancelled()]
        if live and not ready:
            self._virtual_time = max(self._virtual_time, min(live))
        # A loop that never lets time advance would hang the suite: fail instead.
        self._idle_turns = 0 if self._virtual_time != before else self._idle_turns + 1
        if self._idle_turns > 50_000:
            raise AssertionError("the virtual clock stopped advancing")
        cast("Callable[[], None]", getattr(super(), "_run_once"))()  # noqa: B009


def run_virtual(scenario: Coroutine[Any, Any, T]) -> T:
    with asyncio.Runner(loop_factory=VirtualTimeLoop) as runner:
        return runner.run(scenario)


class LoopClock:
    """Wall and monotonic time that follow the virtual loop clock."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._start = loop.time()

    def _elapsed(self) -> float:
        return self._loop.time() - self._start

    def utcnow(self) -> datetime:
        return NOW + timedelta(seconds=self._elapsed())

    def monotonic(self) -> float:
        return 100.0 + self._elapsed()


class TimedSource(MemorySource):
    """Record the loop time of every fetch; fail or slow the fetches a test selects."""

    def __init__(self, config: PollerConfig, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(config)
        self.times: list[float] = []
        self.agents: list[str] = []
        self.failures: dict[int, PolicySourceError] = {}
        self.durations: dict[int, float] = {}
        self._loop = loop
        self._origin = loop.time()

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        index = len(self.times)
        self.times.append(self._loop.time() - self._origin)
        self.agents.append(selection.agent_id)
        if index in self.durations:
            await asyncio.sleep(self.durations[index])
        if index in self.failures:
            raise self.failures[index]
        return await super().fetch(selection, if_none_match)


def lease(
    selection: AgentPolicy, *, issued: float, expires: float, revision: int = 1
) -> Changed:
    """An envelope; offsets are seconds from the test's wall start."""
    return reply(
        document(
            selection,
            revision=revision,
            issued_at=NOW + timedelta(seconds=issued),
            expires_at=NOW + timedelta(seconds=expires),
        )
    )


def publish_revision(
    source: MemorySource,
    selection: AgentPolicy,
    *,
    issued: float = 600,
    expires: float = 1500,
) -> None:
    source.responses[selection.agent_id] = reply(
        document(
            selection,
            revision=2,
            issued_at=NOW + timedelta(seconds=issued),
            expires_at=NOW + timedelta(seconds=expires),
        )
    )


@pytest.mark.parametrize(
    "remaining,expected",
    [
        (86400, 86239.5),
        (900, 739.5),
        (310.01, 149.51),
        (310, 149.5),
        (160.5, 74.75),
        (85.75, 37.375),
        (48.375, 18.6875),
        (31, 10.0),
        (30.9, 19.9),
        (21, 10.0),
        (20.9, 9.9),
        (11.0000005, None),
        (11, None),
        (0, None),
        (-5, None),
    ],
)
def test_lease_refresh_delay_table(remaining: float, expected: float | None) -> None:
    actual = _lease_refresh_delay(remaining, 300, 10)
    if expected is None:
        assert actual is None
    else:
        assert actual == pytest.approx(expected)


@pytest.mark.parametrize("interval,timeout", [(300, 10), (60, 5), (3600, 120), (10, 4)])
def test_lease_refresh_attempts_are_bounded_and_end_at_the_latest_start(
    interval: float, timeout: float
) -> None:
    limit = math.ceil(math.log2((interval + timeout) / timeout)) + 1
    window = interval + timeout
    for start in (
        3 * window,
        window,
        window * 0.75,
        window / 2,
        3 * timeout,
        1.5 * timeout + 1,
    ):
        remaining = start
        waits: list[float] = []
        while (delay := _lease_refresh_delay(remaining, interval, timeout)) is not None:
            waits.append(delay)
            remaining -= delay
            assert len(waits) <= limit
            assert remaining >= timeout + LEASE_REFRESH_MARGIN_SECONDS - 1e-9
        if waits:
            # The last attempt starts one request plus the margin before expiry;
            # every earlier wait is at least one request timeout.
            assert remaining == pytest.approx(timeout + LEASE_REFRESH_MARGIN_SECONDS)
            assert all(wait >= timeout for wait in waits[:-1])


def test_lease_aware_refresh_adds_bounded_attempts_before_expiry() -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        source = TimedSource(config, loop)
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            await asyncio.sleep(899.5)
            # A 304 never extends the lease: this is still the first revision.
            assert poller.get_policy("agent0").revision == 1
        return source.times

    times = run_virtual(scenario())
    # Startup and fixed-rate polls at 300 and 600, then retries timed from the
    # window opening at 590 (310 seconds before the 900 second lease expires),
    # the last one 11 seconds before expiry.
    assert times == pytest.approx(
        [0, 300, 600, 739.5, 814.25, 851.625, 870.3125, 889.0]
    )


def test_a_fixed_rate_poll_that_misses_the_window_cannot_skip_it() -> None:
    async def scenario() -> tuple[list[float], list[tuple[float, int | None]]]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        # The lease runs out at 910.01. Polls at 300 and 600 see more than a window
        # left, and the poll at 900 would be too late, so only attempts timed from
        # the window opening (at 600.01) can save it.
        source.responses["agent0"] = lease(selection, issued=0, expires=910.01)
        source.failures[3] = PolicySourceError("transient", "service")
        samples: list[tuple[float, int | None]] = []
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            publisher = loop.call_later(
                800,
                partial(publish_revision, source, selection, issued=800, expires=1700),
            )
            try:
                while loop.time() - origin < 1000:
                    try:
                        revision: int | None = poller.get_policy("agent0").revision
                    except PolicyUnavailable:
                        revision = None
                    samples.append((loop.time() - origin, revision))
                    await asyncio.sleep(5)
            finally:
                publisher.cancel()
        return source.times, samples

    times, samples = run_virtual(scenario())
    # The first early attempt (749.51) meets a transient error before the second
    # revision exists; the retry at 824.26 installs it, 86 seconds before expiry.
    assert times == pytest.approx([0, 300, 600, 749.51, 824.26, 900])
    assert all(revision is not None for _, revision in samples)


def test_a_slow_request_still_leaves_the_final_attempt() -> None:
    async def scenario() -> tuple[list[float], int]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        # The attempt starting at 870.3125 takes 9 seconds, leaving 9.6875 seconds
        # of slack: less than one timeout, but the last attempt is still due.
        source.durations[6] = 9
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            loop.call_later(
                885,
                partial(publish_revision, source, selection, issued=885, expires=1785),
            )
            await asyncio.sleep(899.5)
            revision = poller.get_policy("agent0").revision
        return source.times, revision

    times, revision = run_virtual(scenario())
    assert times == pytest.approx(
        [0, 300, 600, 739.5, 814.25, 851.625, 870.3125, 889.0]
    )
    assert revision == 2  # Installed at 889, 11 seconds before the lease expired.


def test_transient_failure_inside_the_lease_is_retried_without_failing_closed() -> None:
    async def scenario() -> tuple[list[float], list[tuple[float, int | None]]]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        # The first revision's lease was issued 50 seconds before startup.
        source.responses["agent0"] = lease(selection, issued=-50, expires=850)
        source.failures[3] = PolicySourceError("transient", "service")
        samples: list[tuple[float, int | None]] = []
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            publisher = loop.call_later(600.5, publish_revision, source, selection)
            try:
                while loop.time() - origin < 1190:
                    try:
                        revision: int | None = poller.get_policy("agent0").revision
                    except PolicyUnavailable:
                        revision = None
                    samples.append((loop.time() - origin, revision))
                    await asyncio.sleep(5)
            finally:
                publisher.cancel()
        return source.times, samples

    times, samples = run_virtual(scenario())
    # The poll at 600 is early for the second revision; the first early attempt
    # at 689.5 meets a transient error; the next installs it 86 seconds before
    # the first lease expires at 850. Fixed-rate polling alone would next poll at 900.
    assert times == pytest.approx([0, 300, 600, 689.5, 764.25, 900])
    assert all(revision is not None for _, revision in samples)
    assert {revision for when, revision in samples if when < 764.25} == {1}
    assert {revision for when, revision in samples if when > 765} == {2}


@pytest.mark.parametrize("outcome", ["replaced", "fenced"])
def test_manual_refresh_drops_the_planned_lease_attempt(outcome: str) -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=-50, expires=850)
        source.failures[3] = PolicySourceError("authoritative", "forbidden")
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            await asyncio.sleep(650 - (loop.time() - origin))
            if outcome == "replaced":
                source.failures.clear()
                publish_revision(source, selection)
                assert (await poller.refresh("agent0")).revision == 2
            else:
                with pytest.raises(PolicySourceError):
                    await poller.refresh("agent0")
            await asyncio.sleep(899.5 - (loop.time() - origin))
        return source.times

    # The attempt planned for 689.5 belonged to the replaced or fenced snapshot,
    # so only the manual refresh at 650 follows the poll at 600.
    assert run_virtual(scenario()) == pytest.approx([0, 300, 600, 650])


def test_a_snapshot_change_replans_without_consuming_a_fixed_rate_poll() -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=0, expires=24 * 3600)
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            await asyncio.sleep(100)
            publish_revision(source, selection, issued=0, expires=24 * 3600)
            assert (await poller.refresh("agent0")).revision == 2
            await asyncio.sleep(650 - (loop.time() - origin))
        return source.times

    # The change wakes the scheduler only to plan again. The polls at 300 and 600
    # keep their places; a wake that ran a poll would have moved them to 600.
    assert run_virtual(scenario()) == pytest.approx([0, 100, 300, 600])


def test_manual_refresh_that_shortens_the_lease_wakes_the_scheduler() -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        # The scheduler sleeps until its poll at 300 on a lease that ends at 1500.
        source.responses["agent0"] = lease(selection, issued=0, expires=1500)
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            await asyncio.sleep(100)
            # A newer revision whose lease ends at 250: its window is already open.
            publish_revision(source, selection, issued=-650, expires=250)
            assert (await poller.refresh("agent0")).revision == 2
            await asyncio.sleep(260 - (loop.time() - origin))
        return source.times

    # Planning restarts at 100 instead of waiting for the poll at 300, which would
    # come after the lease had already expired.
    assert run_virtual(scenario()) == pytest.approx(
        [0, 100, 169.5, 204.25, 221.625, 239.0]
    )


def test_only_the_agent_near_expiry_is_refreshed_early() -> None:
    async def scenario() -> list[tuple[float, str]]:
        loop = asyncio.get_running_loop()
        config = configuration(2, interval=300, timeout=10)
        near, far = config.agents
        source = TimedSource(config, loop)
        source.responses[near.agent_id] = lease(near, issued=-50, expires=850)
        source.responses[far.agent_id] = lease(far, issued=0, expires=24 * 3600)
        async with PolicyPoller(config, source, clock=LoopClock(loop)):
            await asyncio.sleep(899.5)
        return list(zip(source.times, source.agents, strict=True))

    fetches = run_virtual(scenario())
    assert sorted(agent for when, agent in fetches if when in (0, 300, 600)) == [
        "agent0",
        "agent0",
        "agent0",
        "agent1",
        "agent1",
        "agent1",
    ]
    early = [(when, agent) for when, agent in fetches if when not in (0, 300, 600)]
    assert [agent for _, agent in early] == ["agent0"] * 5
    assert [when for when, _ in early] == pytest.approx(
        [689.5, 764.25, 801.625, 820.3125, 839.0]
    )


STORM_LIMIT = 400


class ChurningSource(TimedSource):
    """Every fetch returns a newer revision whose lease is almost over."""

    def __init__(
        self,
        config: PollerConfig,
        loop: asyncio.AbstractEventLoop,
        *,
        remaining: float,
    ) -> None:
        super().__init__(config, loop)
        self.remaining = remaining
        self.revisions: dict[str, int] = {}

    async def fetch(
        self, selection: AgentPolicy, if_none_match: str | None
    ) -> Changed | NotModified:
        now = self._loop.time() - self._origin
        self.times.append(now)
        self.agents.append(selection.agent_id)
        if len(self.times) > STORM_LIMIT:
            # Stop a runaway scheduler here instead of letting it spin for minutes.
            raise PolicySourceError("authoritative", "storm")
        revision = self.revisions.get(selection.agent_id, 0) + 1
        self.revisions[selection.agent_id] = revision
        return lease(
            selection,
            revision=revision,
            issued=now + self.remaining - 900,
            expires=now + self.remaining,
        )


@pytest.mark.parametrize(
    "remaining,not_before,expected",
    [
        (11.001, 0, 0.001),
        (11.001, 10, None),
        (20.9, 10, None),
        (21, 10, 10.0),
        (20.9999995, 10, 10.0),
        (25, 12, 14.0),
        (25, 15, None),
        (310, 200, 200.0),
        (310, -3, 149.5),
        (900, 5, 739.5),
    ],
)
def test_lease_refresh_delay_keeps_the_spacing_between_attempts(
    remaining: float, not_before: float, expected: float | None
) -> None:
    actual = _lease_refresh_delay(remaining, 300, 10, not_before)
    if expected is None:
        assert actual is None
    else:
        assert actual == pytest.approx(expected)


@pytest.mark.parametrize(
    "remaining,attempt", [(11.001, 0.001), (11.5, 0.5), (20.9, 9.9)]
)
def test_a_service_issuing_ever_newer_short_leases_is_not_hammered(
    remaining: float, attempt: float
) -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        source = ChurningSource(config, loop, remaining=remaining)
        async with PolicyPoller(config, source, clock=LoopClock(loop)):
            await asyncio.sleep(700)
        return source.times

    # Each reply installs a revision with `remaining` seconds left. The per-lease
    # schedule alone would meet that with another attempt `attempt` seconds later,
    # and again on every reply. Spaced by a request timeout across revisions, the
    # poller makes one extra attempt after each fixed-rate poll and then waits:
    # a second one could not start by the latest start.
    assert run_virtual(scenario()) == pytest.approx(
        [0, attempt, 300, 300 + attempt, 600, 600 + attempt]
    )


def test_a_runaway_service_cannot_hammer_many_agents() -> None:
    async def scenario() -> list[tuple[float, str]]:
        loop = asyncio.get_running_loop()
        config = configuration(32, interval=300, timeout=10)
        source = ChurningSource(config, loop, remaining=11.001)
        async with PolicyPoller(config, source, clock=LoopClock(loop)):
            await asyncio.sleep(700)
        return list(zip(source.times, source.agents, strict=True))

    fetches = run_virtual(scenario())
    agents = {agent for _, agent in fetches}
    assert len(agents) == 32
    for agent in agents:
        assert [when for when, name in fetches if name == agent] == pytest.approx(
            [0, 0.001, 300, 300.001, 600, 600.001]
        )


def test_a_fence_in_the_turn_the_timer_fires_cancels_the_early_attempt() -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=-50, expires=850)
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            # The scheduler's timer for the first early attempt is due at 689.5.
            # A late authoritative reply fences the agent in that same loop turn,
            # whichever of the two callbacks the loop runs first.
            loop.call_at(
                origin + 689.5, poller._fence, poller._entries["agent0"], "forbidden"
            )
            await asyncio.sleep(850 - (loop.time() - origin))
            assert poller.status("agent0").state == "unavailable"
        return source.times

    # Only the fixed-rate polls: the early attempt planned for the fenced snapshot
    # never starts, and the next poll would be at 900.
    assert run_virtual(scenario()) == pytest.approx([0, 300, 600])


def test_replan_signals_cannot_starve_an_overdue_fixed_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> list[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=0, expires=24 * 3600)
        origin = loop.time()
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            signal = poller._replan
            clear = signal.clear

            def clear_and_rearm() -> None:
                clear()
                # The worst case: a snapshot change lands in the next turn each
                # time the scheduler consumes the previous signal, from the moment
                # the poll is due until the poll has run.
                if loop.time() - origin >= 300 and len(source.times) < 2:
                    loop.call_at(loop.time(), signal.set)

            monkeypatch.setattr(signal, "clear", clear_and_rearm)
            # The first signal arrives in the turn the poll at 300 falls due.
            loop.call_at(origin + 300, signal.set)
            await asyncio.sleep(350)
        return source.times

    # A scheduler that let each signal win over the due poll would replan forever
    # at 300; the virtual loop reports that as a clock that stopped advancing.
    assert run_virtual(scenario()) == pytest.approx([0, 300])


class TickingClock(FakeClock):
    """A policy clock that moves on between reads, as a real one does."""

    def __init__(self) -> None:
        super().__init__()
        self.tick = 0.0

    def monotonic(self) -> float:
        reading = self.elapsed
        self.elapsed += self.tick
        return reading


@pytest.mark.parametrize("current", [95.0, 95.00001, 99.0, 99.999])
@pytest.mark.parametrize("started,planned", [(90.0, True), (90.01, False)])
def test_spacing_and_remaining_lease_share_one_clock_sample(
    current: float, started: float, planned: bool
) -> None:
    async def scenario() -> dict[str, tuple[float, float]]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        # The lease ends at 111 on the policy clock, so the latest safe start is
        # 100 (one timeout and the margin earlier).
        source.responses["agent0"] = lease(selection, issued=-789, expires=111)
        clock = TickingClock()
        clock.elapsed = 0.0
        async with PolicyPoller(config, source, clock=clock) as poller:
            assert poller._entries["agent0"].snapshot is not None
            clock.elapsed, clock.tick = current, 1e-5
            due: dict[str, tuple[float, float]] = {}
            # The loop sample taken for planning (95) can differ from the policy
            # clock reading by microseconds, and a second read would differ again;
            # the outcome must not depend on either.
            poller._plan_lease_refreshes(due, {"agent0": started}, 95.0)
            return due

    due = run_virtual(scenario())
    if not planned:
        # A last attempt at 90.01 cannot be followed by one before 100.01.
        assert due == {}
    else:
        # A last attempt at 90 allows 100, which is also the latest safe start.
        when, deadline = due["agent0"]
        assert deadline == 111
        assert when == pytest.approx(95.0 + (100.0 - current), abs=1e-6)


def test_authoritative_denial_stops_lease_retries() -> None:
    async def scenario() -> tuple[list[float], str]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=-50, expires=850)
        source.failures[3] = PolicySourceError("authoritative", "forbidden")
        async with PolicyPoller(config, source, clock=LoopClock(loop)) as poller:
            await asyncio.sleep(899)
            state = poller.status("agent0").state
        return source.times, state

    times, state = run_virtual(scenario())
    # Access was fenced at 689.5; the next attempt is the fixed-rate poll at 900.
    assert times == pytest.approx([0, 300, 600, 689.5])
    assert state == "unavailable"


def test_leases_longer_than_one_interval_keep_the_fixed_rate() -> None:
    async def scenario() -> Sequence[float]:
        loop = asyncio.get_running_loop()
        config = configuration(1, interval=300, timeout=10)
        selection = config.agents[0]
        source = TimedSource(config, loop)
        source.responses["agent0"] = lease(selection, issued=0, expires=24 * 3600)
        async with PolicyPoller(config, source, clock=LoopClock(loop)):
            await asyncio.sleep(2999.5)
        return source.times

    assert run_virtual(scenario()) == pytest.approx(
        [0, 300, 600, 900, 1200, 1500, 1800, 2100, 2400, 2700]
    )


def test_virtual_loop_skips_cancelled_timers_without_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polls: list[float | None] = []

    async def scenario() -> float:
        loop = asyncio.get_running_loop()
        selector = cast("selectors.BaseSelector", getattr(loop, "_selector"))  # noqa: B009
        select = selector.select

        def recording(
            timeout: float | None = None,
        ) -> list[tuple[selectors.SelectorKey, int]]:
            polls.append(timeout)
            return select(timeout)

        monkeypatch.setattr(selector, "select", recording)
        stale = loop.call_later(2, lambda: None)
        loop.call_later(0.5, stale.cancel)
        await asyncio.sleep(4)
        return loop.time()

    assert run_virtual(scenario()) == pytest.approx(4)
    # Jumping to the cancelled timer at 2 would make the parent loop block in the
    # selector for the two virtual seconds left until the live one at 4. Checking
    # what the loop asks the selector for is independent of how fast the host is.
    assert polls
    assert all(poll == 0 for poll in polls)
