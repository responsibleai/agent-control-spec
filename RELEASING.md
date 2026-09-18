# Releasing

One tag releases every package together. Versions must agree across all
manifests (`scripts/check-version-consistency.py`, enforced in CI).

1. Bump the version on every surface (workspace `Cargo.toml`,
   `sdk/python/{Cargo.toml,pyproject.toml}` + `Cargo.lock`,
   `sdk/node/package.json` + `npm/*/package.json` + lockfile,
   `sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj`) and add a
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
