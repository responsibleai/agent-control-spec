# Releasing

One tag releases the runtime packages listed below together. The optional
generator shares their version number and CI consistency checks, but is outside
the tag's publication set. The tag workflow does not publish the generator.

1. Bump the version on every surface (workspace `Cargo.toml`,
   `sdk/python/{Cargo.toml,pyproject.toml}` + `Cargo.lock`,
   `sdk/node/package.json` + `npm/*/package.json` + lockfile,
   `sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj`,
   `generator/pyproject.toml`) and add a
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
   `agent-control-spec`, npm `@responsibleai/agent-control-spec` plus
   four platform packages, NuGet `ResponsibleAI.AgentControlSpec`.
   Each artifact carries the LICENSE text and a build provenance
   attestation; the npm attestation covers the exact tarballs the
   workflow publishes. A final job creates the GitHub Release for the
   tag (pre-release when the version has a hyphen) with the four SBOMs
   attached. All legs are idempotent: already-published versions are
   skipped and an existing release gets its SBOMs re-uploaded, so a
   re-run after a partial failure is safe.

5. Pre-release only: move the npm `latest` dist-tag. Skip this step
   for a stable release, which the workflow publishes under `latest`
   itself. The workflow publishes pre-release versions under the
   `alpha` tag and leaves `latest` alone, so `latest` can lag and a
   plain `npm install` may fetch an older build. The workflow does not
   move `latest` for a pre-release today (npm trusted publishing can
   run `npm dist-tag` once "Allow npm dist-tag" is enabled on each
   publisher; wiring that in is still to do). Until then, when the
   version you just published should be the default install, move the
   tag by hand on the loader and every platform package. Run this from
   an interactive npm login with 2FA, not a stored automation token:

   ```bash
   V=<version>
   for p in agent-control-spec agent-control-spec-linux-x64-gnu \
            agent-control-spec-darwin-x64 agent-control-spec-darwin-arm64 \
            agent-control-spec-win32-x64-msvc; do
     npm dist-tag add "@responsibleai/$p@$V" latest
   done
   ```

   Check with `npm view @responsibleai/agent-control-spec dist-tags`.

## Pinned tooling

The release workflow builds with one Rust toolchain, `RUST_TOOLCHAIN`
in `release.yml`, pinned to the exact version the ci workflow resolves
as `stable` today (1.99.0). When stable moves, CI runs on the new
version first; bump the pin in a PR once CI is green on it, not during
a release. maturin installs by hash from
`.github/requirements/maturin.txt`, and `check-version-consistency.py`
fails when that pin, `[build-system] requires` in
`sdk/python/pyproject.toml` and `requirements-dev.lock` disagree; the
header of the requirements file says how to regenerate it. npm is
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
`latest` dist-tag if the withdrawn version held it (step 5 above).
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
by-hand action is the pre-release dist-tag move in step 5. The one-time
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
from `sdk/python/`. The checkout tests use that lock, not the consumer pin.
