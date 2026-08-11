# Streaming

Specification section 18.1 defines the incremental stream profile: a host
that emits a response while it is still arriving needs to know how much
of it is safe to release so far. `StreamSession` answers that question.

The session is release accounting, not evaluation. Each segment is one
ordinary stateless evaluation through the normal runtime; the session
records what those evaluations cleared and reports the offset that every
mediating task has agreed to. It holds no text, so emitting released
runes and applying a rewrite stay host obligations.

## Availability

| Language | Package | Streaming |
| --- | --- | --- |
| Rust | `agent-control-spec` | opt in with `features = ["streaming"]` |
| Python | `agent-control-spec` | always present |
| Node | `@responsibleai/agent-control-spec` | always present |
| .NET | `ResponsibleAI.AgentControlSpec` | always present |

The feature is off by default in the Rust crate because a `StreamSession`
carries per-stream state, which the default surface deliberately does
not, and because a host that assembles a whole payload before evaluating
it never needs the module. The bindings enable it unconditionally: a
Python, Node or .NET consumer installs a prebuilt binary and cannot flip
a cargo feature.

## The shape of a session

Every language exposes the same eight operations.

| Operation | What it does |
| --- | --- |
| `observe` / `observe_text` | report that runes arrived on a track |
| `record_outcome` | report what one task decided about one span |
| `record_verdict` | the same, taking a verdict as the runtime returns it |
| `advance` | recompute a track's watermark against recorded outcomes |
| `safe_offset` | the offset safe to release, as of the last `advance` |
| `watermark` | how far a track got, and which tasks must clear it |
| `end_of_payloads` | no further payload will arrive |
| `finish` | settle, returning why the stream ended |

Two details decide whether a host is correct.

**Recording an outcome does not release anything.** `advance` moves the
watermark; `safe_offset` reads it. A host that records outcomes and polls
`safe_offset` without ever calling `advance` will release nothing and
appear to hang.

**An absent safe offset is not zero.** Once a session ends, whether
cleanly, by refusal, or by rewrite, there is no offset anyone may emit
through, and `safe_offset` says so in the language's own vocabulary:
`None` in Rust and Python, `null` in Node, `null` in .NET. That is a
value, not an error. A host that polls until it stops advancing stops on
its own. Reading it as `0` or as `-1` would release text no task
evaluated.

The offset the track reached stays readable through `watermark` after
settlement, so an audit record can still say how far the stream got.

## Rust

```toml
agent-control-spec = { version = "0.4", features = ["streaming"] }
```

```rust
use agent_control_spec::stream_session::*;

let mut session = StreamSession::new(StreamSessionConfig {
    safety_level: SafetyLevel::Blocking,
    request_start_rune_offset: 0,
    response_start_rune_offset: 0,
    request_tasks: vec![],
    response_tasks: vec!["pii".to_string()],
})?;

let received = session.observe_text(StreamSourceType::ModelGenerated, "hello")?;
let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, received)?;
session.record_outcome("pii", &span, SegmentOutcome::Cleared)?;

session.advance(StreamTrack::Response);
assert_eq!(session.safe_offset(StreamTrack::Response), Some(5));
```

## Python

```python
from agent_control_spec import StreamSession

session = StreamSession(safety_level="blocking", response_tasks=["pii"])

received = session.observe_text("model_generated", "hello")
session.record_outcome("pii", "model_generated", 0, received, "cleared")

session.advance("response")
assert session.safe_offset("response") == 5

session.finish()
assert session.safe_offset("response") is None
```

## Node

```ts
import { StreamSession } from "@responsibleai/agent-control-spec";

const session = new StreamSession({
  safetyLevel: "blocking",
  responseTasks: ["pii"],
});

const received = session.observeText("model_generated", "hello");
session.recordOutcome("pii", "model_generated", 0, received, "cleared");

session.advance("response");
console.log(session.safeOffset("response")); // 5

session.finish();
console.log(session.safeOffset("response")); // null
```

## .NET

```csharp
using AgentControlSpec;

using var session = new StreamSession(
    SafetyLevel.Blocking, responseTasks: ["pii"]);

var received = session.ObserveText(StreamSourceType.ModelGenerated, "hello");
session.RecordOutcome(
    "pii", StreamSourceType.ModelGenerated, 0, received, SegmentOutcome.Cleared);

session.Advance(StreamTrack.Response);
Console.WriteLine(session.SafeOffset(StreamTrack.Response)); // 5

session.Finish();
Console.WriteLine(session.SafeOffset(StreamTrack.Response)); // null
```

## Counting runes

Offsets are counted in runes, meaning Unicode scalar values, not code
units and not bytes. The distinction is load bearing: an emoji is one
rune, two UTF-16 code units and four UTF-8 bytes, so a .NET host using
`string.Length` or a Node host using `String.prototype.length` would
release twice what a task evaluated.

Prefer `observe_text`, which hands the text to the engine and lets it
count. Reserve `observe` for a host that already has a rune count from
the same source of truth.

## Verdicts feed straight back

`record_verdict` takes a verdict exactly as the runtime returns one, so a
host that evaluates a segment through `ActivatedPolicy` passes the result
in without translating it. `allow` clears, `deny` refuses, and
`transform` records a rewrite, which is terminal.

## Cross-language agreement

The four bindings reach the engine through four different mechanisms: a
direct crate dependency, pyo3, napi, and a C ABI with P/Invoke over it.
Each converts enums, offsets and the absent release point at its own
boundary, so agreement is not structural.

`tests/conformance/parity/cross_language_parity.py` runs the whole
public surface, streaming and otherwise, in all four and fails on any
divergence. It is part of CI.
