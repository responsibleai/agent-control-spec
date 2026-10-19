# Releasing

One tag releases the runtime packages listed below together. The optional
generator shares their version number and CI consistency checks, but is outside
the tag's publication set. The tag workflow does not publish the generator.

1. Bump the version on every surface (workspace `Cargo.toml`,
   `sdk/python/{Cargo.toml,pyproject.toml}` + `Cargo.lock`,
   `sdk/node/package.json` + `npm/*/package.json` + lockfile,
   `sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj`,
   `generator/pyproject.toml`, `sdk/remote-policy/python/pyproject.toml`) and add a
   `CHANGELOG.md` entry, through a PR. Python's `__version__` is NOT on
   that list and must not be added to it: it is read from the installed
   distribution, and `sdk/python/tests/test_version.py` fails if someone
   writes a literal back. Do NOT regenerate
   `sdk/node/binding.js` for the bump: the napi version-check strings it
   embeds are stamped from `package.json` at publish time
   (`sdk/node/scripts/stamp-binding-version.mjs`, run by the release
   workflow), and the CI drift check compares the file modulo those
   strings. Committing a regenerated copy is harmless but never
   required.
2. Dry-run: Actions → release → Run workflow (`dry_run: true`). Builds
   everything, packs the npm tarballs with the publish-time manifest
   edits, and produces SBOMs; attests and uploads nothing. A manual run
   is always a dry run: the workflow's preflight job refuses
   `dry_run: false` with an error, so the only path to the registries
   is a tag push. The `release` environment admits `main` and `v*`
   tags only, so a dry run from a feature branch stops at that gate.
3. Tag the merged commit and push:

   ```bash
   git tag -s v<version> -m "agent-control-spec <version>"
   git push origin v<version>
   ```

   The tag name must be `v` plus the version every manifest carries.
   The preflight job runs `scripts/check-version-consistency.py` and
   fails the whole run when the tag disagrees with it, or when
   `CHANGELOG.md` has no `## <version>` section (the release notes
   come from that section through `scripts/release-notes.py`).

4. The tag run publishes: crates.io `agent-control-spec`, PyPI
   `agent-control-spec` and optional `agent-control-spec-remote-policy`,
   npm `@responsibleai/agent-control-spec` plus
   four platform packages, NuGet `ResponsibleAI.AgentControlSpec`.
   Each artifact carries the LICENSE text and a build provenance
   attestation; the npm attestation covers the exact tarballs the
   workflow publishes. A final job creates the GitHub Release for the
   tag (pre-release when the version has a hyphen) with the five SBOMs
   attached. All legs are idempotent: already-published versions are
   skipped and an existing release gets its SBOMs re-uploaded, so a
   re-run after a partial failure is safe.

   Before the polling package's first publication, configure its own PyPI
   trusted publisher for this repository, `release.yml` and the `release`
   environment. The base package's publisher does not grant permission to a
   different distribution. Adding this workflow configuration does not create
   that publisher or publish a package.

5. npm dist-tags. The workflow publishes every version under
   `latest`, pre-releases included, so a plain `npm install` gets the
   newest release. For a pre-release it also adds a channel tag from
   the label: `alpha` for `-alpha.N`, `beta` for `-beta.N`, `rc` for
   `-rc.N`, `next` for any other label. Stable versions carry only
   `latest`. The channel tag relies on "Allow npm dist-tag" being enabled on the trusted publisher configuration (npmjs.com > package > Settings > Trusted Publisher) of every package, which it is today for

   - `@responsibleai/agent-control-spec`
   - `@responsibleai/agent-control-spec-linux-x64-gnu`
   - `@responsibleai/agent-control-spec-darwin-x64`
   - `@responsibleai/agent-control-spec-darwin-arm64`
   - `@responsibleai/agent-control-spec-win32-x64-msvc`

   If that setting is ever lost, the dist-tag step fails the release; re-enable it and re-run the tag workflow, or add the tag by hand on the loader and every platform package. Run this from an interactive npm login with 2FA,
   not a stored automation token:

   ```bash
   V=<version>
   TAG=<alpha|beta|rc|next>
   for p in agent-control-spec agent-control-spec-linux-x64-gnu \
            agent-control-spec-darwin-x64 agent-control-spec-darwin-arm64 \
            agent-control-spec-win32-x64-msvc; do
     npm dist-tag add "@responsibleai/$p@$V" "$TAG"
   done
   ```

   The same loop with `latest` moves `latest` back after a withdrawal
   (see below). Check with
   `npm view @responsibleai/agent-control-spec dist-tags`.

## Pinned tooling

The release workflow builds with one Rust toolchain, `RUST_TOOLCHAIN`
in `release.yml`, pinned to the exact version the ci workflow resolves
as `stable` today (1.99.0). When stable moves, CI runs on the new
version first; bump the pin in a PR once CI is green on it, not during
a release. maturin installs by hash from
`.github/requirements/maturin.txt`, and `check-version-consistency.py`
fails when that pin, `[build-system] requires` in
`sdk/python/pyproject.toml` and the `requirements-dev.lock` files under
`sdk/python/` and `sdk/remote-policy/python/` disagree; the header of the
core requirements file says how to regenerate it, and the section on
dependency locks below covers the optional package's. npm is
installed at an exact version in the publish step because the npm
bundled with Node 22 predates trusted publishing. NuGet restores with
`--locked-mode` against the committed
`sdk/dotnet/src/AgentControlSpec/packages.lock.json`; a package
reference change must update that file in the same PR
(`dotnet restore --use-lock-file` from `sdk/dotnet`).

## Partial failure, re-run and yank

The four publish legs run in parallel and one can fail after another
has uploaded. Fix the cause and re-run the failed jobs from the Actions
page; every leg skips a version that already exists on its registry,
and the release job uploads the SBOMs to the release it finds. Do not
re-tag: a tag that moved no longer matches the attestations and the
published artifacts.

When a published version must be withdrawn, mark it on each registry
rather than deleting it. None of these steps removes the files from
consumers who already have them; they stop new resolution and show the
version as withdrawn. Run them from an interactive login with 2FA.

```bash
V=<version>                                   # SemVer spelling
cargo yank --version "$V" agent-control-spec  # crates.io
# PyPI: Manage project -> Releases -> <version> -> Options -> Yank
#       (web interface only; twine has no yank command)
for p in agent-control-spec agent-control-spec-linux-x64-gnu \
         agent-control-spec-darwin-x64 agent-control-spec-darwin-arm64 \
         agent-control-spec-win32-x64-msvc; do
  npm deprecate "@responsibleai/$p@$V" "Withdrawn: <reason>. Use <fixed version>."
done
# NuGet: Manage package -> Listing -> untick "List in search results"
#        for ResponsibleAI.AgentControlSpec <version>
```

Then publish the fixed version under a new tag, add a CHANGELOG entry
that names the withdrawn version and the reason, and move the npm
`latest` dist-tag back if the withdrawn version held it (the loop in
step 5 with `latest`; `npm deprecate` does not move tags).
`cargo yank --undo` and the PyPI and NuGet listing toggles reverse a
mistaken withdrawal; `npm deprecate` with an empty message clears the
deprecation.

## Async adapter contract changes

PR #68 deliberately adds the three `runtime_error:acs_async_*`
admission reasons to the draft specification and its producer inventory.
Section 16's exception is limited to these interceptor-produced denials.
The emitter keeps its `host_error:*` obligations; the scope-allow label
is not a reserved error.

The three reasons ship in specification `0.5.0-alpha.1`. Section 22
requires a minor bump for an added reserved reason; the annotator
dependency change (#78) made that bump. Legacy manifest contract
`0.4.0-alpha.1` stays supported (section 2.1). The test
`reserved_reason_tables_match_inventory` in
`engine/tests/security_conformance.rs` fails when the section 16 tables
and `spec/reserved-reasons.json` disagree.

Runtime package metadata (`0.4.0-beta.1`) and the specification
identifier are separate version surfaces. Neither ships before the
tag. Before tagging, confirm the supported versions, schema,
fixtures and compatibility cases still match section 2.1.

## Generator compatibility

The generator and runtime use lockstep version metadata. The generator's minimum
SDK version is `0.4.0a4`, the first version containing the public Regorus authoring
helper. Keep that floor unless a later generator change needs a newer SDK API.
Before any separate generator publication, the required SDK must be available
from the package registry. Setting version metadata does not publish either package.

The Python binding pins Regorus exactly for its serialized AST. When changing
that pin, update both root and `sdk/python/Cargo.lock` resolutions, update the native AST version marker
and the generator's supported-version gate, and review the AST adapter against
the resolved crate. `sdk/python/tests/test_authoring.py` compares the compiled
marker to both the manifest pin and resolved lockfile, so a stale marker fails CI.
The version consistency check also compares Regorus in both lockfiles, preventing
separate dependency updates from moving Python and the other bindings apart.
The parser remains Python-only authoring tooling; the binding-coverage script
records that decision separately from the runtime's cross-language contract.

Registry credentials: OIDC trusted publishing everywhere; the only
by-hand actions are the one-time "Allow npm dist-tag" setting in step 5
and moving `latest` back after a withdrawal. The one-time
first-publish bootstraps for crates.io and npm are described in the
`release.yml` header. Publish jobs run in the `release` environment.

## Python documentation baseline

The Python CI job runs the documentation examples against both the checkout
build and a published package. The consumer-side pin lives in
`examples/python_composition/requirements.txt`; it deliberately may lag the
version in `pyproject.toml`.

After the new package is available on PyPI, update that pin in a follow-up PR,
run `python -m unittest discover -s examples/python_composition -v` in a clean
environment, and refresh the tested-version statement in the example README.
Do not advance the consumer pin in the pre-publication version bump: CI
cannot install a release that does not exist yet.

When changing `sdk/python/requirements-dev.in`, regenerate its lock with
`uv pip compile requirements-dev.in -o requirements-dev.lock --universal --generate-hashes`
from `sdk/python/`. Core-only contributor environments use that lock; CI uses
the optional lock described next.

The Python CI job installs `sdk/remote-policy/python/requirements-dev.lock`, which
also pins everything in `sdk/python/requirements-dev.in` through
`-r ../../python/requirements-dev.in`. Change either `.in` file, then regenerate
that lock from `sdk/remote-policy/python/` with
`uv pip compile requirements-dev.in -o requirements-dev.lock --universal --generate-hashes --no-annotate --no-header`
and review the diff. The committed file has no header or annotations so no
machine-specific path can enter it; the command above is the one that produces
that format, so run it where the index serves every pin and expect only the pins
you changed to move. Then run `python scripts/check-version-consistency.py`: it
fails if the maturin pins in the two locks, `.github/requirements/maturin.txt`
and `sdk/python/pyproject.toml` disagree.
