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
   strings — committing a regenerated copy is harmless but never
   required.
2. Dry-run: Actions → release → Run workflow (`dry_run: true`). Builds
   and attests everything, uploads nothing.
3. Tag the merged commit and push:

   ```bash
   git tag -s v<version> -m "agent-control-spec <version>"
   git push origin v<version>
   ```

4. The tag run publishes: crates.io `agent-control-spec`, PyPI
   `agent-control-spec`, npm `@responsibleai/agent-control-spec` plus
   four platform packages, NuGet `ResponsibleAI.AgentControlSpec`.
   All legs are idempotent: already-published versions are skipped, so
   a re-run after a partial failure is safe.

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

Registry credentials: OIDC trusted publishing everywhere; the one-time
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
`uv pip compile requirements-dev.in -o requirements-dev.lock --universal`
from `sdk/python/`. The checkout tests use that lock, not the consumer pin.
