#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Prove a packed ResponsibleAI.AgentControlSpec really works.
#
# The managed assembly reaches the engine through agent_control_spec_ffi.
# A package that omits the native library still restores, still compiles
# against, and still passes any test run from a repository checkout that
# happens to have the library on its loader path. It fails only in a
# consumer's process, on the first call. 0.4.0-alpha.2 shipped that way.
#
# So this builds a throwaway console app outside the repository, restores
# the packed artifact from a local feed, and calls both a plain entry
# point and the streaming session. No LD_LIBRARY_PATH, no engine build,
# nothing from the checkout on the loader path.
#
# Usage: verify-dotnet-package.sh <feed-directory> <package-version>

set -euo pipefail

FEED="${1:?usage: verify-dotnet-package.sh <feed-directory> <package-version>}"
VERSION="${2:?usage: verify-dotnet-package.sh <feed-directory> <package-version>}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/NuGet.config" <<XML
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$FEED" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
  </packageSources>
</configuration>
XML

dotnet new console -o "$WORK/app" >/dev/null
cat >"$WORK/app/Program.cs" <<'CS'
using AgentControlSpec;

// A plain entry point: proves the native library resolved at all.
var versions = AcsManifest.SupportedVersions();
if (versions.Count == 0)
{
    throw new InvalidOperationException("no supported manifest versions");
}

// The streaming session: proves the engine was built with the feature
// its consumers cannot enable for themselves.
using var session = new StreamSession(SafetyLevel.Blocking, responseTasks: ["pii"]);
if (session.ObserveText(StreamSourceType.ModelGenerated, "hello") != 5)
{
    throw new InvalidOperationException("observe_text did not count five runes");
}

session.RecordOutcome("pii", StreamSourceType.ModelGenerated, 0, 5, SegmentOutcome.Cleared);
if (session.Advance(StreamTrack.Response) != 5 || session.SafeOffset(StreamTrack.Response) != 5)
{
    throw new InvalidOperationException("a cleared span did not release");
}

if (!session.Finish().IsClean)
{
    throw new InvalidOperationException("a clean stream did not settle clean");
}

if (session.SafeOffset(StreamTrack.Response) is not null)
{
    throw new InvalidOperationException("a settled session still offered a safe offset");
}

Console.WriteLine("package verified: non-streaming and streaming both reachable");
CS

(
  cd "$WORK/app"
  dotnet add package ResponsibleAI.AgentControlSpec --version "$VERSION" >/dev/null
  dotnet run --nologo
)
