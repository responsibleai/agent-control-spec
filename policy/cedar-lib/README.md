# AGT stock Cedar policy library

This directory ships the AGT stock policy library written in Cedar, the
sibling of the Rego library at `policy-engine/policy/lib/`. Each file
mirrors the same named Rego library so a manifest author can pick the
engine that fits the host environment and reuse the same gate semantics.
The Cedar library realises the AGT verdict surface described in
`policy-engine/spec/SPECIFICATION.md` §14 and §12.4 and
the cedar advice schema at
`policy-engine/spec/schema/cedar_advice.schema.json`.

## File catalogue

| File | Mirror | Decision shape |
| --- | --- | --- |
| `budgets.cedar` | `budgets.rego` | `forbid` on tool call count or token count thresholds |
| `patterns.cedar` | `patterns.rego` | `forbid` on `like` PII substring signatures |
| `content_hash.cedar` | `content_hash.rego` | `forbid` on tool content hash mismatch or missing observed hash |
| `egress.cedar` | `egress.rego` | `forbid` when destination host is not in the resource allowlist |
| `drift.cedar` | `drift.rego` | `permit` with `warn` advice when drift score crosses threshold |
| `confidence.cedar` | `confidence.rego` | `forbid` when confidence score is below threshold |
| `redact.cedar` | `redact.rego` | `permit` with `transform` advice replacing `$target.value` wholesale |
| `approval.cedar` | `approval.rego` | `permit` with `escalate` advice for approver gated actions |
| `ifc.cedar` | `agt_ifc.rego` | `forbid` when sink clearance does not dominate every source label |
| `agt_default.cedar` | `agt_default.rego` | Composes every gate above with a baseline permit |

Each Cedar policy file has a matching `_test.json` driven by the Cedar
CLI `run-tests` subcommand. The runner script `run_tests.sh` invokes
`cedar check-parse` and `cedar run-tests` against every pair and
returns non zero on any failure.

## How the request context is built

The bundled dispatcher in `engine/src/cedar.rs` builds the Cedar request
from the policy input per `spec/SPECIFICATION.md` §12.4. The context is
the whole snapshot, `envelope` included, plus the annotations as one
nested `annotations` record. That is the shape every file here reads.

| Policy reads | Comes from |
| --- | --- |
| `context.tool_call.args.host` | `snapshot.tool_call.args.host` |
| `context.envelope.budgets.tool_call_count` | `snapshot.envelope.budgets.tool_call_count` |
| `context.input.body` | `snapshot.input.body` |
| `context.annotations.confidence.score` | the `confidence` annotator's output, member `score` |

Values translate as follows. A JSON integer becomes a `Long`. Every
other JSON number, `100.0` and `1e2` included, becomes a `decimal`
rounded to four fractional digits, ties to even; compare it with
`decimal("...")` literals through `.greaterThan` and its siblings. A
`Long` and a `decimal` never compare equal: `<`, `>` and the decimal
methods across the two types fail the evaluation closed, but `==`, `!=`,
`contains`, `containsAll` and `containsAny` are silently `false` (`true`
for `!=`). A gate that tests a snapshot number for equality or
membership against a `Long` literal misses `100.0`; pin the type with a
schema, or use an ordering comparison. A `null` record member is
dropped, so guard reads with `has`. A `null` set element, an integer
outside the `Long` range, a float outside the decimal range, a record
key Cedar's JSON format reserves (`__entity`, `__extn`, `__expr`), or a
snapshot member named `annotations` fails the evaluation closed with
`runtime_error:policy_invocation_failed`. The mapping cannot be
overridden: a cedar policy that sets `query`, or a cedar binding with any
field other than `id`, is rejected when the manifest loads.

## How the Cedar verdict shape maps to AGT verdicts

| Cedar evaluation result | AGT verdict |
| --- | --- |
| `Deny`, one or more `forbid` matched | `{decision: "deny", reason: <@id of the first contributing forbid, in file order>}` |
| `Deny`, nothing matched | `{decision: "deny", reason: "no_matching_policy"}` |
| Any decision, Cedar reports an evaluation error for any policy | `{decision: "deny", reason: "runtime_error:policy_invocation_failed"}`; no `@id` surfaces, and the dispatcher detail names the policy and the error kind only |
| `Allow` with no advice | `{decision: "allow"}` |
| `Allow`, one or more contributing permits carry `@advice` | The most restrictive advice, `escalate` over `transform` over `warn`, first in file order among equals, validated against `cedar_advice.schema.json` and translated to `{decision: "warn"|"escalate"|"transform", ...}` |

The `@id` annotation on each `forbid` policy is the AGT deny reason
that surfaces on the verdict; a `forbid` without one, or with an empty
or blank `@id`, surfaces its Cedar policy id, `policy<n>` for the n-th
policy in the file. An unguarded read of a missing attribute is an
evaluation error, and one such error anywhere in the set fails the
request closed even when another `forbid` fired, so guard every
optional read with `has`. The `@advice` annotation on a `permit`
carries the cedar advice JSON payload. The schema enforces that
`advice.verdict` is one of `warn`, `escalate`, or `transform`. A
`transform` advice MUST carry a `transform.path` rooted at `$target`
and a replacement `transform.value`. When several permits with advice
match one request, the most restrictive advice wins, and the first in
file order among equals; file order gives no other precedence. Advice
on every matching permit must be valid, or the request fails closed.
This library declares approval (escalate) before redact (transform)
before drift (warn) so the file reads in the same order the dispatcher
ranks them.

## Schemas

A `schema_path` makes Cedar check the policy set, the entities and the
request against the schema. The request context is never empty, so the
schema MUST declare the §12.4 context shape for every action it lists, or
every request is rejected. Cedar records are closed: a member the
snapshot carries and the schema does not declare is an error. Declare
members the snapshot may omit with `"required": false`, and members that
arrive as floats as `{"type": "Extension", "name": "decimal"}`. The
dispatcher builds the context without the schema and checks it against
the schema afterwards, so a `decimal` typed attribute matches a JSON
number only, and an attribute typed as an entity never matches: a
snapshot cannot name an entity. A minimal shape for `pre_tool_call` with
the egress and budget gates:

```json
"pre_tool_call": {"appliesTo": {
  "principalTypes": ["Agent"], "resourceTypes": ["Tool"],
  "context": {"type": "Record", "attributes": {
    "envelope": {"type": "Record", "attributes": {
      "agent": {"type": "Record", "attributes": {"id": {"type": "String"}}},
      "budgets": {"type": "Record", "required": false, "attributes": {
        "tool_call_count": {"type": "Long", "required": false},
        "token_count": {"type": "Long", "required": false}
      }}
    }},
    "tool_call": {"type": "Record", "attributes": {
      "name": {"type": "String"},
      "args": {"type": "Record", "attributes": {
        "host": {"type": "String", "required": false}
      }}
    }},
    "annotations": {"type": "Record", "attributes": {}}
  }}
}}
```

This library ships without a schema because tool `args` differ per
host.

## Binding a Cedar policy from an AGT manifest

The manifest binds a Cedar policy through the `cedar` type per D3.1.
Example.

```yaml
policies:
  default:
    type: cedar
    policy_path: ./policy/cedar-lib/agt_default.cedar
    entities_path: ./policy/data/resources.json
intervention_points:
  pre_tool_call:
    tool_name_from: $snap.tool_call.name
    policy_target: $snap.tool_call.args
    policy:
      id: default
```

The host loads the resource entity attributes that parameterise the
policy (thresholds, allowlists, clearance closures, content hashes)
through the `entities_path` field. The entity UIDs MUST match the
resource UIDs that the dispatcher constructs from the AGT snapshot per
D3.2, namely `Tool::"<name>"` for tool intervention points and
`PolicyTarget::"<kind>"` for other intervention points.

## Cedar limits compared to the Rego library

Cedar is purposely a smaller language than Rego and lacks several
operations the AGT Rego library uses. Authors who hit a limit stay on
the Rego library which exposes the full strength surface. The limits
worth knowing.

- **No regex.** Cedar only supports the `like` operator with `*`
  wildcards. The `patterns.cedar` library detects PII structural
  signatures (email substring, dash separated SSN, dash separated
  credit card) only. The Rego library `data.agt.patterns` runs the
  canonical RE2 patterns from
  `agent-os/src/agent_os/integrations/base.py::PII_PATTERNS`.
- **No URL parser.** Cedar has no host extractor, no string
  `.contains`, no `.split`. The `egress.cedar` library compares a
  bare host or domain that the host SDK or an annotator has already
  projected into `context.tool_call.args.host`,
  `context.tool_call.args.domain`, or
  `context.annotations.egress.destination`. The Rego library
  `data.agt.egress` parses URLs and applies glob style host patterns.
- **No multi span transform.** Cedar annotations are static strings.
  The `redact.cedar` library can only emit a fixed transform payload
  that wholesale replaces `$target.value` with the literal
  `"[REDACTED]"`. The Rego library `data.agt.redact` runs
  `regex.replace` to substitute matched spans in place.
- **Decimal, not float.** A JSON float reaches the context as a Cedar
  `decimal` with four fractional digits, and a decimal does not compare
  with a `Long`: `<` and `>=` across the two fail closed, `==` and
  `contains` are silently false. This library reads only integer
  counts and scores, so confidence and drift scores MUST be scaled to
  integer ranges (for example 0..100) before they reach the snapshot.
  The float budgets `elapsed_seconds` and `cost_usd` arrive as decimals
  and are not modelled in `budgets.cedar`; a host policy can compare
  them with `decimal("...")` literals and `.greaterThanOrEqual`.
- **No lattice agility at evaluation time.** Cedar cannot iterate
  over a set to compute lattice closures inside policy evaluation.
  The `ifc.cedar` library expects the host to precompute the closure
  into the resource entity attribute `clearance_dominated_labels`.
  The Rego library `data.agt.ifc` exposes
  `dominates_with_lattice` and `verdict_with_lattice` that take the
  lattice document at call time.

## Test runner

Install the Cedar CLI once. CI pins 4.12.0, the version of the
`cedar-policy` crate the engine links.

```sh
cargo install cedar-policy-cli --version 4.12.0 --locked
```

Run the suite.

```sh
./run_tests.sh
```

The runner sets `CEDAR_BIN` from the environment when present and
falls back to `cedar` on `PATH`, then to `~/.cargo/bin/cedar`. The
`cedar-lib` job in `.github/workflows/ci.yml` builds the pinned CLI from
its checksum-verified crate tarball and calls the runner directly.
