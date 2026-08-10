// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentControlSpec;
using AgentControlSpec.ContentSafety;

/// <summary>
/// Property based testing of the adapter's own decision logic.
///
/// The policy matrix walks the configuration space systematically but drives
/// each session with a single segment. The bugs that survived it were in how
/// several tasks with different actions combine over a sequence of segments, so
/// this generates random policies and random observation streams and checks the
/// result against an independent model after every segment.
///
/// The generator is a seeded xorshift, so any failure prints a reproducing seed.
/// </summary>
internal static class ContentSafetyFuzz
{
    private sealed class Rng
    {
        private ulong _state;

        public Rng(ulong seed) => _state = seed | 1;

        public ulong Next()
        {
            var x = _state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            _state = x;
            return x;
        }

        public int Below(int bound) => bound <= 0 ? 0 : (int)(Next() % (ulong)bound);

        public bool Chance(int percent) => Below(100) < percent;

        public T Pick<T>(IReadOnlyList<T> items) => items[Below(items.Count)];
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ContentSafetyFuzz: {message}");
        }
    }

    private static readonly ContentSafetyAction[] Actions =
    {
        ContentSafetyAction.Unspecified,
        ContentSafetyAction.Annotate,
        ContentSafetyAction.Block,
        ContentSafetyAction.Hitl,
        ContentSafetyAction.Retry,
    };

    private static readonly ContentSafetyAppliedSource[] Scopes =
    {
        ContentSafetyAppliedSource.All,
        ContentSafetyAppliedSource.Prompt,
        ContentSafetyAppliedSource.Completion,
        ContentSafetyAppliedSource.PreToolCall,
        ContentSafetyAppliedSource.System,
    };

    /// <summary>Independent model of the precedence order.</summary>
    private static ContentSafetyAction Strongest(IEnumerable<ContentSafetyAction> actions)
    {
        var best = ContentSafetyAction.Annotate;
        var rank = new Dictionary<ContentSafetyAction, int>
        {
            [ContentSafetyAction.Annotate] = 0,
            [ContentSafetyAction.Retry] = 1,
            [ContentSafetyAction.Hitl] = 2,
            [ContentSafetyAction.Block] = 3,
        };
        foreach (var action in actions)
        {
            // An unset action on a matched criterion is a block.
            var effective = action == ContentSafetyAction.Unspecified
                ? ContentSafetyAction.Block
                : action;
            if (rank[effective] > rank[best])
            {
                best = effective;
            }
        }

        return best;
    }

    public static Task RunAsync()
    {
        for (var seed = 1UL; seed <= 3000; seed++)
        {
            RunOne(seed);
        }

        Console.WriteLine("AgentControlSpec content safety fuzz passed (3000 cases).");
        return Task.CompletedTask;
    }

    private static void RunOne(ulong seed)
    {
        var rng = new Rng(seed);

        var taskCount = 1 + rng.Below(5);
        var tasks = new List<ContentSafetyTask>();
        var thresholds = new Dictionary<string, int>(StringComparer.Ordinal);
        var actionsByLabel = new Dictionary<string, ContentSafetyAction>(StringComparer.Ordinal);
        var scopesByLabel = new Dictionary<string, ContentSafetyAppliedSource>(StringComparer.Ordinal);

        for (var i = 0; i < taskCount; i++)
        {
            var label = $"task{i}";
            var threshold = rng.Below(8);
            var action = rng.Pick(Actions);
            var scope = rng.Chance(60) ? ContentSafetyAppliedSource.Completion : rng.Pick(Scopes);
            thresholds[label] = threshold;
            actionsByLabel[label] = action;
            scopesByLabel[label] = scope;
            tasks.Add(new ContentSafetyTask
            {
                Label = label,
                Action = action,
                Criterion = new BlockingCriterion
                {
                    Enabled = true,
                    Kind = BlockingCriterionKind.Severity,
                    AllowedSeverity = threshold,
                },
                AppliesTo = new[] { scope },
            });
        }

        var level = rng.Pick(new[] { SafetyLevel.Blocking, SafetyLevel.Complete, SafetyLevel.Deferred });
        var session = ContentSafetySession.Create(new ContentSafetySessionOptions
        {
            SafetyLevel = level,
            Tasks = tasks,
        });

        var total = 50 + rng.Below(200);
        session.OnPayload(ContentSafetySource.ModelGenerated, total);

        var gating = tasks
            .Where(t => ContentSafetySourceMapping.GatesTrack(
                scopesByLabel[t.Label], StreamTrack.Response))
            .Select(t => t.Label)
            .ToList();

        // Each task carries its own cursor, matching a service whose segmenter
        // state is per runner rather than shared. A task therefore reports its
        // own contiguous spans, and one call carries one task's span.
        var cursors = tasks.ToDictionary(t => t.Label, _ => 0, StringComparer.Ordinal);
        var previousWatermark = 0;
        var ended = false;
        var rounds = 0;

        while (!ended && rounds++ < 200 && cursors.Values.Any(c => c < total))
        {
            var behind = tasks.Where(t => cursors[t.Label] < total).ToList();
            if (behind.Count == 0)
            {
                break;
            }

            // Two legitimate caller shapes. Either one task reports its own
            // span, which is what independent per runner segmenters produce, or
            // several tasks that share a segmentation report one span together.
            var shared = rng.Chance(40);
            var reporting = shared
                ? behind.Where(t => cursors[t.Label] == cursors[behind[0].Label]).ToList()
                : new List<ContentSafetyTask> { rng.Pick(behind) };
            var cursor = cursors[reporting[0].Label];
            var end = Math.Min(total, cursor + 1 + rng.Below(40));

            var observations = new Dictionary<string, TaskObservation>(StringComparer.Ordinal);
            var expectedActions = new List<ContentSafetyAction>();
            var expectedMatched = new List<string>();
            foreach (var reporter in reporting)
            {
                var severity = rng.Below(8);
                observations[reporter.Label] = TaskObservation.Severity(severity);
                if (gating.Contains(reporter.Label) && severity >= thresholds[reporter.Label])
                {
                    expectedMatched.Add(reporter.Label);
                    expectedActions.Add(actionsByLabel[reporter.Label]);
                }
            }

            var outcome = session.RecordSegment(
                ContentSafetySource.ModelGenerated, cursor, end, observations);
            foreach (var reporter in reporting)
            {
                cursors[reporter.Label] = end;
            }

            var expectedAction = Strongest(expectedActions);
            Assert(
                outcome.Action == expectedAction,
                $"seed {seed}: expected {expectedAction}, got {outcome.Action}");
            Assert(
                outcome.MatchedTasks.OrderBy(x => x, StringComparer.Ordinal)
                    .SequenceEqual(expectedMatched.OrderBy(x => x, StringComparer.Ordinal)),
                $"seed {seed}: matched tasks disagreed");

            // Only tasks that gate this track and reported may appear.
            foreach (var evaluated in outcome.EvaluatedTasks)
            {
                Assert(
                    gating.Contains(evaluated) && observations.ContainsKey(evaluated),
                    $"seed {seed}: evaluated names {evaluated}, which did not gate or report");
            }

            if (!outcome.Permits)
            {
                // A refusal must name a task whose own action produced it.
                var denied = session.Stream.EndReason as StreamEndReason.Denied;
                Assert(denied is not null, $"seed {seed}: a refusal did not end the session");
                var namedAction = actionsByLabel[denied!.Task] == ContentSafetyAction.Unspecified
                    ? ContentSafetyAction.Block
                    : actionsByLabel[denied.Task];
                Assert(
                    namedAction == outcome.Action,
                    $"seed {seed}: refusal reported {outcome.Action} but named {denied.Task}, "
                    + $"whose action is {namedAction}");
                ended = true;
                break;
            }

            var watermark = session.TryAdvanceWatermark(StreamTrack.Response);
            if (watermark >= 0)
            {
                Assert(
                    watermark >= previousWatermark,
                    $"seed {seed}: watermark went backwards");
                Assert(
                    watermark <= total,
                    $"seed {seed}: watermark {watermark} passed the observed end {total}");
                previousWatermark = watermark;
            }

            // The watermark may never pass a rune some gating task is still
            // behind, which is the whole point of taking the minimum.
            var slowest = gating.Count == 0 ? 0 : gating.Min(label => cursors[label]);
            Assert(
                session.SafeOffset(StreamTrack.Response) <= slowest,
                $"seed {seed}: safe offset {session.SafeOffset(StreamTrack.Response)} passed "
                + $"the slowest gating task at {slowest}");
        }

        if (!ended)
        {
            session.EndOfPayloads();
            var settlement = session.Finish();
            if (settlement.Clean)
            {
                // Read the watermark rather than the release point. Settlement
                // ended the session, so the release point is withheld by
                // design, while the offset the track reached stays readable
                // for exactly this kind of check.
                Assert(
                    session.Stream.Watermark(StreamTrack.Response).Confirmed == total,
                    $"seed {seed}: settled clean without clearing the whole track");
                Assert(
                    gating.Count > 0,
                    $"seed {seed}: settled clean with no task gating the track");
            }
        }
    }
}
