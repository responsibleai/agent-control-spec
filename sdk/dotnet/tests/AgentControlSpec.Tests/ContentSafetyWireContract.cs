// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using AgentControlSpec.ContentSafety;

/// <summary>
/// Pins the adapter's neutral enumerations against the wire contract they copy.
///
/// The package declares its own copies so it builds without a dependency on a
/// non public service. That freedom is also the hazard, because nothing
/// otherwise stops a member being added in the middle and shifting every value
/// after it. A caller translating a payload by numeric value would then route
/// text to the wrong track silently.
///
/// The expected values are committed in tests/conformance/streaming/content-safety/content-safety-wire-enums.json,
/// extracted from the service's own proto.
/// </summary>
internal static class ContentSafetyWireContract
{
    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ContentSafetyWireContract: {message}");
        }
    }

    private static string LocateFixture()
    {
        var directory = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && directory is not null; i++)
        {
            var candidate = Path.Combine(
                directory, "tests", "conformance", "streaming", "content-safety", "content-safety-wire-enums.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = Path.GetDirectoryName(directory);
        }

        throw new FileNotFoundException("content-safety-wire-enums.json not found");
    }

    public static Task RunAsync()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(LocateFixture()));
        var enums = document.RootElement.GetProperty("enums");

        // The wire name each member copies, since the local names are idiomatic.
        var sourceNames = new Dictionary<ContentSafetySource, string>
        {
            [ContentSafetySource.Unknown] = "UNKNOWN",
            [ContentSafetySource.UserRequest] = "USER_REQUEST",
            [ContentSafetySource.ModelGenerated] = "MODEL_GENERATED",
            [ContentSafetySource.ConcatAll] = "CONCAT_ALL",
            [ContentSafetySource.Context] = "CONTEXT",
            [ContentSafetySource.PreToolCall] = "PRE_TOOL_CALL",
            [ContentSafetySource.PostToolCall] = "POST_TOOL_CALL",
            [ContentSafetySource.PreRun] = "PRE_RUN",
            [ContentSafetySource.PostRun] = "POST_RUN",
        };

        var kindNames = new Dictionary<ContentSafetyTextKind, string>
        {
            [ContentSafetyTextKind.Unspecified] = "UNKNOWN",
            [ContentSafetyTextKind.UserRequest] = "USER_REQUEST",
            [ContentSafetyTextKind.ModelGenerated] = "MODEL_GENERATED",
            [ContentSafetyTextKind.ConcatAll] = "CONCAT_ALL",
            [ContentSafetyTextKind.Context] = "CONTEXT",
            [ContentSafetyTextKind.PreToolCall] = "PRE_TOOL_CALL",
            [ContentSafetyTextKind.PostToolCall] = "POST_TOOL_CALL",
            [ContentSafetyTextKind.PreRun] = "PRE_RUN",
            [ContentSafetyTextKind.PostRun] = "POST_RUN",
        };

        Check(enums.GetProperty("SourceType"), sourceNames, "SourceType");
        Check(enums.GetProperty("TextType"), kindNames, "TextType");

        // Every wire member must be represented, so a value added upstream is a
        // failure here rather than an unhandled payload at runtime.
        AssertCoversEveryMember(enums.GetProperty("SourceType"), sourceNames.Count, "SourceType");
        AssertCoversEveryMember(enums.GetProperty("TextType"), kindNames.Count, "TextType");

        // The response action type is a different enumeration from the policy's
        // configured action and its values are deliberately not contiguous.
        // ContentSafetyAction models the configured action, so it is compared by
        // membership rather than by value.
        var responseActions = enums.GetProperty("ResponseActionType");
        foreach (var name in new[] { "ANNOTATE", "BLOCK", "HITL", "RETRY" })
        {
            Assert(
                responseActions.TryGetProperty(name, out _),
                $"the wire response action {name} has no counterpart in ContentSafetyAction");
        }

        Assert(
            responseActions.GetProperty("HITL").GetInt32() == 7
                && responseActions.GetProperty("RETRY").GetInt32() == 8,
            "the wire response action values are not contiguous and must not be assumed to be");

        Console.WriteLine("AgentControlSpec content safety wire contract passed.");
        return Task.CompletedTask;
    }

    private static void Check<TEnum>(
        JsonElement wire,
        Dictionary<TEnum, string> names,
        string label)
        where TEnum : struct, Enum
    {
        foreach (var (member, wireName) in names)
        {
            Assert(
                wire.TryGetProperty(wireName, out var expected),
                $"{label}: {member} claims to copy {wireName}, which the contract does not define");
            var actual = Convert.ToInt32(member, System.Globalization.CultureInfo.InvariantCulture);
            Assert(
                actual == expected.GetInt32(),
                $"{label}: {member} is {actual} but the wire contract says "
                + $"{wireName} is {expected.GetInt32()}");
        }
    }

    private static void AssertCoversEveryMember(JsonElement wire, int localCount, string label)
    {
        var wireCount = 0;
        foreach (var _ in wire.EnumerateObject())
        {
            wireCount++;
        }

        Assert(
            localCount == wireCount,
            $"{label}: the contract defines {wireCount} members but this package declares "
            + $"{localCount}; a member added upstream must be handled here");
    }
}
