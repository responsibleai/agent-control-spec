# Tool integrity

**Purpose:** require the actual executable tool artifact to match a trusted
SHA-256 pin. This runnable decision template requires host artifact
measurement and a trustworthy pin distribution process.

**Point:** `pre_tool_call`. **Target:** `$.target`, the invocation arguments.
`$.tool_call.name` identifies the actual selected tool.

## Configure and measure

`config.json` ships with an **empty** `pack.sha256` map. Every call denies
until the operator records real approved hashes. Invented demo hashes must
not become production trust anchors.

```json
{"pack": {"sha256": {"search": "<64 lowercase hexadecimal characters>"}}}
```

The host measures the artifact it is about to execute and supplies the
observed digest at `extensions.policy_packs.tool_sha256`. Both the pin and
measurement must be exactly 64 lowercase hexadecimal characters. A
malformed/missing hash or empty pin map denies with
`tool_integrity_data_invalid`. An unknown tool or a valid but different
digest denies with `tool_integrity_mismatch`.

## Install and bind to execution

Follow the [shared install](../README.md#install-and-run), configure actual
pins and register
`AcsInterceptor("policy/packs/tool-integrity/manifest.yaml")`.
The measurement must cover the agreed artifact identity, such as an
immutable package, container or complete executable bundle. Hashing only
a tool's agent-visible description does not attest its implementation.

Prevent time-of-check/time-of-use replacement. Execute the same immutable
artifact that was measured. A remote tool advertising its own checksum is
not a trusted observation. This pack does not fetch code, measure files,
verify signatures, validate publishers or establish reproducible builds.
An approved hash also does not prove benign behavior.

The goal corresponds to stock `agt.content_hash`, but this pack uses the
new shared extension contract and validates digest types instead of
assuming AGT's old `tool_call.content_hash` shape.

## Cases

Tests inject a synthetic pin into an isolated in-memory bundle, permit
the exact hash, reject a different hash and unknown tool, and reject
missing, uppercase, short and non-string digests. The shipped empty map
is verified to deny. Composition tests prove a pinned tool can still be
blocked for credential disclosure.
