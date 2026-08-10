// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using AgentControlSpec;

/// <summary>
/// Replays the traces the Rust core exported and requires identical behavior.
///
/// The release accounting is implemented natively per SDK rather than shared
/// through the C ABI, so nothing structural stops the two implementations from
/// drifting. This replays every recorded operation, compares what this SDK
/// concluded against what the core concluded, and fails on any divergence.
///
/// The comparison is on observable behavior rather than on message text.
/// Whether an operation succeeded, what offset it returned, and which terminal
/// state the session reached are canonical. The wording of a failure is
/// idiomatic per SDK and is recorded as an allowed difference.
/// </summary>
internal static class StreamSessionDifferential
{
    private static readonly string TracePath = LocateTraces();

    private static string Track(StreamTrack track) =>
        track == StreamTrack.Request ? "request" : "response";

    private static string LocateTraces()
    {
        var directory = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && directory is not null; i++)
        {
            var candidate = Path.Combine(directory, "tests", "conformance", "streaming", "stream-session-traces.txt");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = Path.GetDirectoryName(directory);
        }

        throw new FileNotFoundException(
            "stream-session-traces.txt not found; generate it with ACS_WRITE_TRACES=1 cargo test");
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"StreamSessionDifferential: {message}");
        }
    }

    private static StreamSourceType Source(string name) => name switch
    {
        "user_request" => StreamSourceType.UserRequest,
        "model_generated" => StreamSourceType.ModelGenerated,
        _ => throw new InvalidOperationException($"unknown source {name}"),
    };

    private static StreamTrack Track(string name) => name switch
    {
        "request" => StreamTrack.Request,
        "response" => StreamTrack.Response,
        _ => throw new InvalidOperationException($"unknown track {name}"),
    };

    private static SegmentOutcome Outcome(string name) => name switch
    {
        "cleared" => SegmentOutcome.Cleared,
        "transformed" => SegmentOutcome.Transformed,
        "denied" => SegmentOutcome.Denied,
        _ => throw new InvalidOperationException($"unknown outcome {name}"),
    };

    public static Task RunAsync()
    {
        var lines = File.ReadAllLines(TracePath);
        var cases = 0;
        var operations = 0;
        StreamSession? session = null;
        var caseId = 0;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line == "---")
            {
                session = null;
                continue;
            }

            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;

            if (root.TryGetProperty("case", out var caseElement))
            {
                caseId = caseElement.GetInt32();
                var level = StreamMediationExtensions.ParseSafetyLevel(
                    root.GetProperty("level").GetString()!);
                var start = root.GetProperty("start").GetInt32();
                var requestTasks = root.GetProperty("request_tasks")
                    .EnumerateArray().Select(e => e.GetString()!).ToArray();
                var responseTasks = root.GetProperty("response_tasks")
                    .EnumerateArray().Select(e => e.GetString()!).ToArray();
                session = new StreamSession(
                    new StreamSessionConfig(
                        level, start, start, requestTasks, responseTasks));
                cases++;
                continue;
            }

            Assert(session is not null, $"case {caseId}: operation before a case header");
            operations++;
            var op = root.GetProperty("op").GetString();

            switch (op)
            {
                case "observe":
                {
                    var source = Source(root.GetProperty("source").GetString()!);
                    var runes = root.GetProperty("runes").GetInt32();
                    var expected = root.GetProperty("result").GetString()!;
                    string actual;
                    try
                    {
                        actual = session!.Observe(source, runes).ToString();
                    }
                    catch (StreamMediationException)
                    {
                        actual = "error";
                    }

                    var expectedError = expected.StartsWith("error:", StringComparison.Ordinal);
                    Assert(
                        expectedError ? actual == "error" : actual == expected,
                        $"case {caseId} observe: core said {expected}, this SDK said {actual}");
                    break;
                }

                case "record":
                {
                    var source = Source(root.GetProperty("source").GetString()!);
                    var task = root.GetProperty("task").GetString()!;
                    var start = root.GetProperty("start").GetInt32();
                    var end = root.GetProperty("end").GetInt32();
                    var outcome = Outcome(root.GetProperty("outcome").GetString()!);
                    var expected = root.GetProperty("result").GetString()!;

                    var actual = "ok";
                    try
                    {
                        var span = StreamSpan.Create(source, start, end);
                        session!.RecordOutcome(task, span, outcome);
                    }
                    catch (StreamMediationException)
                    {
                        actual = "error";
                    }

                    var expectedError = expected.StartsWith("error:", StringComparison.Ordinal);
                    Assert(
                        expectedError == (actual == "error"),
                        $"case {caseId} record {task} [{start},{end}) {outcome}: "
                        + $"core said {expected}, this SDK said {actual}");
                    break;
                }

                case "advance":
                {
                    var track = Track(root.GetProperty("track").GetString()!);
                    var expectedElement = root.GetProperty("result");
                    var actual = session!.Advance(track);
                    if (expectedElement.ValueKind == JsonValueKind.Null)
                    {
                        Assert(
                            actual is null,
                            $"case {caseId} advance {track}: core said no progress, "
                            + $"this SDK said {actual}");
                    }
                    else
                    {
                        var expected = expectedElement.GetInt32();
                        Assert(
                            actual == expected,
                            $"case {caseId} advance {track}: core said {expected}, "
                            + $"this SDK said {actual}");
                    }

                    break;
                }

                case "end_of_payloads":
                    session!.EndOfPayloads();
                    break;

                case "finish":
                {
                    var expected = root.GetProperty("reason").GetString()!;
                    var expectedTransformed = root.GetProperty("transformed").GetBoolean();
                    var completion = session!.Finish();

                    var actual = completion.Reason switch
                    {
                        StreamEndReason.Complete => "complete",
                        StreamEndReason.Denied denied =>
                            $"denied:{Track(denied.Track)}:{denied.Task}:{denied.Range.Start}:{denied.Range.End}",
                        StreamEndReason.Rewritten rewritten =>
                            $"rewritten:{Track(rewritten.Track)}:{rewritten.Task}:{rewritten.Range.Start}:{rewritten.Range.End}",
                        StreamEndReason.Failed => "failed",
                        _ => "unknown",
                    };

                    // A failure's wording is idiomatic per SDK, so only the
                    // terminal class is compared for that arm.
                    var expectedClass = expected.StartsWith("failed:", StringComparison.Ordinal)
                        ? "failed"
                        : expected;
                    Assert(
                        actual == expectedClass,
                        $"case {caseId} finish: core said {expectedClass}, this SDK said {actual}");
                    Assert(
                        completion.Transformed == expectedTransformed,
                        $"case {caseId} finish: core said transformed={expectedTransformed}, "
                        + $"this SDK said {completion.Transformed}");
                    break;
                }

                default:
                    throw new InvalidOperationException($"case {caseId}: unknown op {op}");
            }
        }

        Assert(cases > 0, "no cases were replayed");
        Console.WriteLine(
            $"AgentControlSpec stream differential replay passed "
            + $"({cases} cases, {operations} operations).");
        return Task.CompletedTask;
    }
}
