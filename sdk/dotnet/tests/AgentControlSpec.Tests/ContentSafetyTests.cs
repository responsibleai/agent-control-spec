// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Xunit;

namespace AgentControlSpec.Tests;

/// <summary>
/// Runs the content safety and stream session harnesses under the project's
/// test runner.
///
/// <para>The harnesses were written as self checking suites that throw on the
/// first divergence and they are ported unchanged, so this only supplies the
/// entry points. Keeping their bodies untouched means a failure here is a
/// failure of the adapter rather than of a rewrite performed during the
/// port.</para>
/// </summary>
public sealed class ContentSafetyTests
{
    [Fact]
    public Task DecisionOracle() => ContentSafetyDecisionOracle.RunAsync();

    [Fact]
    public Task Fuzz() => ContentSafetyFuzz.RunAsync();

    [Fact]
    public Task Adapter() => ContentSafetyHarness.RunAsync();

    [Fact]
    public Task MessageStreams() => ContentSafetyMessageStreams.RunAsync();

    [Fact]
    public Task PolicyMatrix() => ContentSafetyPolicyMatrix.RunAsync();

    [Fact]
    public Task WireContract() => ContentSafetyWireContract.RunAsync();

    [Fact]
    public Task StreamSessionAccounting() => StreamSessionHarness.RunAsync();

    [Fact]
    public Task StreamSessionMatchesTheCore() => StreamSessionDifferential.RunAsync();
}
