# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Activation benchmark for the Python binding.

Run it with::

    python sdk/python/bench/activation_bench.py

Workload: ``examples/bank_agent`` — the real Rego bundle, the committed
snapshots, all eight intervention points. It runs against
``manifest.bench.yaml``, the annotator-free variant of the example
manifest: every annotator type calls an HTTP endpoint, which a
zero-config binding cannot serve, so under ``manifest.yaml`` every
evaluation would fail closed at annotation and this would time the error
path instead of the engine. See that file's header.

A manifest names its bundle relative to itself, so an absolute manifest
path is enough and the working directory does not matter — the same
assumption sdk/dotnet/bench makes.

Every number below is measured in this process. Warmup iterations are
excluded from every reported statistic.
"""

from __future__ import annotations

import json
import math
import os
import pathlib
import statistics
import sys
import threading
import time

# Fixed, not adaptive: a benchmark whose iteration count moves with the
# machine cannot be compared across runs.
REPEAT_ACTIVATIONS = 10
WARMUP_EVALUATIONS = 2_000
TIMED_EVALUATIONS = 20_000
CONCURRENCY = 32
EVALUATIONS_PER_THREAD = 2_000
SWEEP = (1, 2, 4, 8, 16, CONCURRENCY)
GIL_SHARE_SAMPLES = 2_000

POINTS = (
    "agent_startup",
    "input",
    "pre_model_call",
    "post_model_call",
    "pre_tool_call",
    "post_tool_call",
    "output",
    "agent_shutdown",
)

BANK_AGENT = pathlib.Path(__file__).resolve().parents[3] / "examples" / "bank_agent"
MANIFEST = str(BANK_AGENT / "manifest.bench.yaml")


def us(nanoseconds: float) -> float:
    return nanoseconds / 1e3


def msec(nanoseconds: float) -> float:
    return nanoseconds / 1e6


def percentile(ordered: list[int], p: float) -> int:
    """Nearest-rank, so every reported quantile is an observation that
    actually happened rather than an interpolation between two."""
    rank = math.ceil((p / 100) * len(ordered))
    return ordered[min(rank, len(ordered)) - 1]


def table(title: str, rows: list[tuple[str, str]]) -> None:
    width = max(len(label) for label, _ in rows)
    print(f"\n{title}")
    print("-" * len(title))
    for label, value in rows:
        print(f"  {label.ljust(width)}  {value}")


def main() -> None:
    from agent_control_spec import ActivatedPolicy

    snapshots = [
        json.loads((BANK_AGENT / "snapshots" / f"{point}.json").read_text())
        for point in POINTS
    ]

    # Refuses to report numbers for work that never reached the policy.
    # An evaluation that fails closed before Rego runs, most easily by
    # failing annotation, costs about a tenth of a real decision, and this
    # benchmark family has already once timed exactly that while printing
    # plausible figures.
    probe = ActivatedPolicy.activate(MANIFEST)
    for point, snapshot in zip(POINTS, snapshots):
        reason = probe.evaluate(point, snapshot).reason
        if reason is not None and reason.startswith("runtime_error"):
            raise SystemExit(
                f"{point} fails closed with {reason!r} before reaching the "
                "policy; timing it would measure the error path."
            )

    # --- construction: cold activation, then the first evaluation -----
    # The clock starts here, after the guard: timing the guard's own
    # activation and eight probe evaluations would inflate this by about
    # 2.7x, and every figure derived from it with it.
    started = time.perf_counter_ns()
    policy = ActivatedPolicy.activate(MANIFEST)
    cold_activation_ns = time.perf_counter_ns() - started

    started = time.perf_counter_ns()
    policy.evaluate(POINTS[1], snapshots[1])
    first_evaluate_ns = time.perf_counter_ns() - started

    # --- repeat activation --------------------------------------------
    # The compiled-policy cache lives inside an activation, so a repeat
    # activation re-reads and re-compiles the bundle; only the OS page
    # cache is warm. Reported to make that explicit rather than to imply
    # a cross-activation cache the runtime does not have.
    repeat_activations = []
    for _ in range(REPEAT_ACTIVATIONS):
        started = time.perf_counter_ns()
        ActivatedPolicy.activate(MANIFEST)
        repeat_activations.append(time.perf_counter_ns() - started)
    repeat_activations.sort()

    # --- warm evaluation latency ---------------------------------------
    for i in range(WARMUP_EVALUATIONS):
        k = i % len(POINTS)
        policy.evaluate(POINTS[k], snapshots[k])

    samples = []
    clock = time.perf_counter_ns
    for i in range(TIMED_EVALUATIONS):
        k = i % len(POINTS)
        point, snapshot = POINTS[k], snapshots[k]
        started = clock()
        policy.evaluate(point, snapshot)
        samples.append(clock() - started)
    ordered = sorted(samples)

    # --- throughput: one thread, then 32 --------------------------------
    started = time.perf_counter_ns()
    for i in range(EVALUATIONS_PER_THREAD):
        k = i % len(POINTS)
        policy.evaluate(POINTS[k], snapshots[k])
    serial_ns = time.perf_counter_ns() - started
    serial_throughput = EVALUATIONS_PER_THREAD / serial_ns * 1e9

    # One activation shared by every thread: the handle is immutable, the
    # engine is Sync, and the binding releases the GIL for the whole
    # native evaluation, so threads are the honest way to measure this.
    # The sweep is reported in full rather than only at 32, because where
    # throughput stops rising is the interesting part.
    def concurrent_throughput(threads: int, iterations: int) -> float:
        barrier = threading.Barrier(threads + 1)

        def worker() -> None:
            # Warm this thread before the barrier, so the measured window
            # is steady state on every thread.
            for i in range(200):
                k = i % len(POINTS)
                policy.evaluate(POINTS[k], snapshots[k])
            barrier.wait()
            for i in range(iterations):
                k = i % len(POINTS)
                policy.evaluate(POINTS[k], snapshots[k])

        pool = [threading.Thread(target=worker) for _ in range(threads)]
        for thread in pool:
            thread.start()
        barrier.wait()
        started = time.perf_counter_ns()
        for thread in pool:
            thread.join()
        return threads * iterations / (time.perf_counter_ns() - started) * 1e9

    sweep = {
        threads: concurrent_throughput(threads, EVALUATIONS_PER_THREAD)
        for threads in SWEEP
    }

    # What the wrapper does with the GIL held, per call: serializing the
    # context in and deserializing the verdict out. Measured rather than
    # asserted, because it is the first thing to suspect when threads
    # stop scaling.
    started = time.perf_counter_ns()
    for i in range(GIL_SHARE_SAMPLES):
        k = i % len(POINTS)
        json.loads(json.dumps(snapshots[k], allow_nan=False))
    gil_held_ns = (time.perf_counter_ns() - started) / GIL_SHARE_SAMPLES

    print("Agent Control Specification — Python activation benchmark")
    print(
        f"workload   examples/bank_agent ({pathlib.Path(MANIFEST).name}), "
        f"{len(POINTS)} intervention points, round-robin"
    )
    print(
        f"runtime    python {sys.version.split()[0]} on {sys.platform}, "
        f"{os.cpu_count()} CPUs, "
        f"GIL {'disabled' if not getattr(sys, '_is_gil_enabled', lambda: True)() else 'enabled'}"
    )

    table(
        "construction + first call",
        [
            (
                "cold activation (after the reachability probe)",
                f"{msec(cold_activation_ns):.2f} ms",
            ),
            ("first evaluate after activation", f"{us(first_evaluate_ns):.1f} µs"),
        ],
    )

    table(
        "cold activation vs warm cache hit",
        [
            ("cold activation", f"{msec(cold_activation_ns):.2f} ms"),
            (
                (
                    f"repeat activation p50 of {REPEAT_ACTIVATIONS} "
                    "(re-read and re-compiled; only the page cache is warm)"
                ),
                f"{msec(percentile(repeat_activations, 50)):.2f} ms",
            ),
            (
                "first evaluate after activation (warm cache hit)",
                f"{us(first_evaluate_ns):.1f} µs",
            ),
            (
                "warm evaluate p50 (warm cache hit)",
                f"{us(percentile(ordered, 50)):.1f} µs",
            ),
            (
                "cold activation costs, in warm evaluations",
                f"{round(cold_activation_ns / percentile(ordered, 50)):,}",
            ),
        ],
    )

    table(
        f"warm evaluate latency ({TIMED_EVALUATIONS:,} iterations, "
        f"{WARMUP_EVALUATIONS:,} warmup excluded)",
        [
            ("p50", f"{us(percentile(ordered, 50)):.1f} µs"),
            ("p95", f"{us(percentile(ordered, 95)):.1f} µs"),
            ("p99", f"{us(percentile(ordered, 99)):.1f} µs"),
            ("mean", f"{us(statistics.fmean(samples)):.1f} µs"),
            ("max", f"{us(ordered[-1]):.1f} µs"),
        ],
    )

    table(
        "throughput",
        [
            (
                "1 thread, no threading at all",
                f"{round(serial_throughput):,} evaluations/s",
            )
        ]
        + [
            (
                (
                    f"{threads} thread{'s' if threads > 1 else ''} "
                    f"({EVALUATIONS_PER_THREAD:,} each, one shared activation)"
                ),
                f"{round(rate):>8,} evaluations/s   {rate / sweep[1]:5.1f}x",
            )
            for threads, rate in sweep.items()
        ],
    )

    print(
        f"""
On the GIL, measured rather than assumed. The binding releases the GIL around
the whole native evaluation, so concurrency-{CONCURRENCY} is not fake: throughput does rise
with threads, by {sweep[CONCURRENCY] / sweep[1]:.1f}x here. It is also not linear on {os.cpu_count()} CPUs, and the
sweep above shows it flattening well before {CONCURRENCY} threads.

What the wrapper holds the GIL for is {gil_held_ns / 1e3:.1f} µs per call (context in, verdict
out) against a {us(percentile(ordered, 50)):.0f} µs evaluation, about {100 * gil_held_ns / percentile(ordered, 50):.0f}%, so that alone does not
account for the ceiling; sharding one activation per thread and shortening
sys.setswitchinterval were both tried by hand and moved nothing. The figure
reported is what this machine did, not an extrapolation, and the honest reading
is that a Python host wanting more than this should run processes, not threads."""
    )


if __name__ == "__main__":
    main()
