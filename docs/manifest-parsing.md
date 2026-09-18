# Manifest parsing and resource limits

Manifest YAML is a string-keyed, finite, JSON-compatible data format. The engine
uses `serde-saphyr` for parsing and a small Serde adapter for strict scalar
typing. It does not coerce strings to numbers or deserialize structs from
positional sequences. All nested structs, including `extends` URL entries, must
be mappings. The parser's streaming locations and Serde field paths are retained.
Normalization preserves line numbers; columns within a normalized scalar can
refer to its normalized spelling. Diagnostics omit source snippets.

Quote strings and keys that look like canonical numbers, booleans or null.
An empty plain value is null; use `""` for an empty string. Legacy spellings
`010`, `1_000`, `0X1F` and mixed-case `tRuE` remain strings. Explicit `!!str`
forces string type and explicit `!!int`, `!!float`, `!!bool` and `!!null`
determine the corresponding scalar type. Unsupported and non-specific `!`
tags are rejected on scalars and collections. Duplicate keys are rejected,
including in dynamic metadata and adapter configuration. `<<` is an ordinary
key, not merge expansion. Exactly one document is accepted.

`intervention_points` may be omitted or an empty mapping, but not null.
Unknown reserved directives (for example `%FOO bar`) are ignored. The tested
parser accepts colon-tab value separation, tabs after a sequence dash, and a
tab after spaces before a mapping key. A tab at the start of block indentation
is rejected; this is not a blanket rejection of every indentation tab.
A leading UTF-8 BOM is accepted; a BOM between document fields is rejected.

## Host-controlled budgets

| `Limits` field | Default | Meaning |
| --- | ---: | --- |
| `max_merged_manifest_bytes` | 1,048,576 | Each source, expanded YAML scalar bytes, retained anchor string bytes, and serialized composed manifest |
| `max_manifest_depth` | 64 | YAML collection depth and alias replay stack depth |
| `max_manifest_nodes` | 100,000 | Expanded YAML nodes, including mapping keys |
| `max_manifest_events` | 300,000 | Each of scan-event and alias-replay-event budgets; comments excluded |
| `max_manifest_aliases` | 50,000 | Alias references and expansions of each anchor |
| `max_manifest_anchors` | 50,000 | Anchor definitions |
| `max_manifest_anchor_events` | 10,000 | Cumulative event copies retained for anchors, including nested retention |

The lower retained-event budget rejects compact exponentially expanding anchors
early; hosts with large legitimate anchors can raise it. Repeated use of one
small anchor is allowed without an alias/anchor ratio heuristic. Expanded
nodes, scalar bytes and replay events are still charged independently.
Every anchor retains at least one event, so the default retained-event budget
also constrains the effective anchor count to at most 10,000, below the nominal
50,000 definition limit. Larger anchors can reach that budget sooner.
YAML simple keys retain the language's 1,024-character lookahead bound.
Includes and property interpolation are not enabled.

`max_policy_input_depth` controls runtime policy input/output, not manifests.
`max_manifest_url_bytes` additionally caps fetched bodies. A local source read
stops at `max_merged_manifest_bytes + 1` before parsing, for JSON as well as YAML.
The legacy JSON decoder retains its own recursion limit; the YAML-specific
node/event/depth budgets do not change that decoder's contract.
Text chains intentionally enforce the serialized composed-size cap as well as
each source's cap. Two individually admissible overlays can therefore exceed
`max_merged_manifest_bytes` when combined, including through SDK merge APIs.

Rust callers can use `Manifest::parse_yaml_str_with_limits` (no semantic
validation), `from_yaml_str_with_limits` (validation), or
`from_yaml_chain_with_limits` (composition and validation). The loader uses
`from_path_with_limits`. Existing no-options calls use `Limits::default()`.

Python manifest tooling accepts `limits={"max_manifest_nodes": 200_000}`.
Node's corresponding functions accept a second `Limits` argument. FFI exports
`acs_validate_manifest_with_limits`, `acs_manifest_parse_with_limits` and
`acs_manifest_merge_with_limits`, taking an optional JSON limits object.
.NET supports `AcsManifest.Validate(source, dictionary)` and limits overloads
of `AcsManifestTools.Parse` and `Merge`. The other defaults
remain unchanged when only one field is supplied.

Grammar errors are `ManifestInvalid`; budget exhaustion is
`ResourceLimitExceeded`. Python preserves its ordinary `ValueError` boundary
path (not `ManifestInvalidError`); Node throws a boundary error rather than
returning a grammar verdict; C returns `ACS_MANIFEST_CALL_FAILED`, which .NET
maps to `AgentControlSpecNativeException`. Detailed diagnostic callers likewise
receive boundary failures rather than findings for manifest parsing limits,
including artifact validation. FFI diagnostic functions return null and set
`err_out`; .NET `AcsManifestTools.Diagnostics` and `ValidateArtifacts` throw.
Diagnostic APIs without a limits argument retain the default budgets.
Python and Node parse, validate and merge exceptions retain the
`runtime_error:manifest_invalid:` prefix; structured findings keep the reason
in their separate `code` field. Budget messages name the count and limit field,
without Rust debug variants or repeated anchor locations. Unknown path segments
and the root placeholder are omitted, not literal punctuation in mapping keys.

## Dependency and MSRV evidence

Verified against registry metadata on September 18, 2026:

| Crate | Locked version | Published (UTC) | Declared Rust |
| --- | --- | --- | --- |
| `serde-saphyr` | 1.2.0 | 2026-08-30 11:49:53.652594 | 1.89 |
| `granit-parser` | 1.2.1 | 2026-09-11 09:25:43.624847 | 1.81.0 |
| `serde_path_to_error` | 0.1.20 | 2025-09-15 15:05:54.817744 | 1.61 |

The granit patch was older than seven full days when selected. It fixes colon-tab
separation; the tab leniencies above are pinned by regressions. Both Cargo lockfiles record the
registry checksum. Version 1.3 releases from September 16 were not selected.
The published manifest follows the repository's caret convention; lockfiles,
not an exact published dependency constraint, select the tested parser versions.
Library builds enable only `deserialize`; serialization is a test dependency.

The change replaces an archived upstream and its transpiled libyaml path; it is
not a claim that a new advisory affects the removed locked versions. The two
parser crates forbid unsafe code in their own source, but their dependency tree
is **not** wholly unsafe-free: `arraydeque` and the `encoding_rs_io` /
`encoding_rs` path contain unsafe code. Regorus's separate YAML feature remains
available. No capabilities were disabled to obtain a clean dependency graph.

Registry metadata and upstream source:

- <https://crates.io/api/v1/crates/serde-saphyr/1.2.0>
- <https://crates.io/api/v1/crates/granit-parser/1.2.1>
- <https://crates.io/api/v1/crates/serde_path_to_error/0.1.20>
- <https://github.com/bourumir-wyngs/serde-saphyr>
- <https://github.com/bourumir-wyngs/granit-parser>

The registry `src/` trees and `Cargo.toml.orig` were compared byte-for-byte
against their recorded upstream commits: `serde-saphyr`
`45042059e6905e833516f52d958cba4c16e8cedd` (60 files) and `granit-parser`
`d0c5b42f9c99ded05d305e788e626a037081572f` (13 files). No differences were found.

Both parser crates have a single registry owner, `bourumir-wyngs`, rather than a
team. That remains a supply-chain concentration risk, not a correctness finding.
Their grouped dependency updates need human review and the manifest corpus
tests; a successful resolver update is not parser-compatibility evidence.
The MSRV CI job checks the locked workspace with all features on Rust 1.89.0.
