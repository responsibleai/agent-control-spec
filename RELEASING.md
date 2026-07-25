# Releasing

One tag releases every package together. Versions must agree across all
manifests (`scripts/check-version-consistency.py`, enforced in CI).

1. Bump the version on every surface (workspace `Cargo.toml`,
   `sdk/python/{Cargo.toml,pyproject.toml}` + `Cargo.lock`,
   `sdk/node/package.json` + `npm/*/package.json` + lockfile,
   `sdk/dotnet/src/AgentControlSpec/AgentControlSpec.csproj`) and add a
   `CHANGELOG.md` entry, through a PR.
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
