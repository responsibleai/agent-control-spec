# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Local, event-gated fixtures shared by async integration tests."""

import asyncio
import contextvars
import threading

MANIFEST = """
agent_control_specification_version: "0.4.0-alpha.1"
policies:
  gate:
    type: rego
    query: data.gate.verdict
annotators:
  classify:
    type: classifier
intervention_points:
  input:
    policy_target: $.input
    annotations:
      classify:
        from: $target.content
    policy:
      id: gate
"""
BUNDLES = {
    "gate": {
        "modules": {
            "gate.rego": (
                'package gate\nverdict := {"decision": "allow"} '
                "if { input.annotations.classify.completed == true }"
            )
        }
    }
}
TRACE = contextvars.ContextVar("acs_test_trace", default=None)


class GatedAnnotator:
    def __init__(self):
        self.loop = asyncio.get_running_loop()
        self.entered = asyncio.Queue()
        self.gates = [threading.Event() for _ in range(16)]
        self.calls = 0
        self.inputs = []
        self.lock = threading.Lock()
        self.finished = set()

    def dispatch(self, name, definition, policy_input):
        with self.lock:
            index = self.calls
            self.calls += 1
            self.inputs.append(policy_input["policy_target"]["value"]["content"])
        self.loop.call_soon_threadsafe(self.entered.put_nowait, (index, TRACE.get()))
        if not self.gates[index].wait(5):
            raise RuntimeError("test did not release annotator")
        self.finished.add(index)
        return {"completed": True}

    def release_all(self):
        for gate in self.gates:
            gate.set()


async def until(predicate):
    # This is a hang guard, not a performance threshold.
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0)


async def entered(gate):
    return await asyncio.wait_for(gate.entered.get(), 3)
