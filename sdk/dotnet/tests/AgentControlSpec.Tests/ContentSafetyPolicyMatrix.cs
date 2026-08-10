// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentControlSpec;
using AgentControlSpec.ContentSafety;

/// <summary>
/// Exhaustive matrix over policy shape.
///
/// The adapter's behavior depends on four independent dimensions, which are the
/// criterion kind, the configured action, the applicability scope, and the
/// safety level. A test that fixes three and varies one misses the interactions,
/// so this walks the product and checks the decision against an independent
/// model of what each combination should produce.
/// </summary>
internal static class ContentSafetyPolicyMatrix
{
    private const StreamSourceType Res = StreamSourceType.ModelGenerated;

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"ContentSafetyPolicyMatrix: {message}");
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

    private static readonly SafetyLevel[] Levels =
    {
        SafetyLevel.Blocking,
        SafetyLevel.Complete,
        SafetyLevel.Deferred,
    };

    /// <summary>Independent model of what one matched action should produce.</summary>
    private static ContentSafetyAction ExpectedAction(ContentSafetyAction configured, bool matched)
    {
        if (!matched)
        {
            return ContentSafetyAction.Annotate;
        }

        // An unset action on a matched criterion fails closed to a block.
        return configured == ContentSafetyAction.Unspecified ? ContentSafetyAction.Block : configured;
    }

    public static Task RunAsync()
    {
        EveryCriterionKindTimesEveryActionTimesEveryLevel();
        MultiplePoliciesCombineByPrecedenceNotByOrder();
        ARefusalNamesTheTaskWhoseActionDecidedIt();
        ThresholdBoundariesAreInclusiveOnEveryKind();
        ScopeCombinationsGateTheRightTracks();
        ConcurrentReportingAndAdvancingIsSafe();
        Console.WriteLine("AgentControlSpec content safety policy matrix passed.");
        return Task.CompletedTask;
    }

    private static void EveryCriterionKindTimesEveryActionTimesEveryLevel()
    {
        var kinds = new (BlockingCriterionKind Kind, BlockingCriterion Criterion,
            TaskObservation Matching, TaskObservation NotMatching)[]
        {
            (BlockingCriterionKind.Severity,
             new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = 4 },
             TaskObservation.Severity(5), TaskObservation.Severity(3)),
            (BlockingCriterionKind.RiskLevel,
             new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.RiskLevel, AllowedRiskLevel = RiskLevel.Medium },
             TaskObservation.Severity(4), TaskObservation.Severity(3)),
            (BlockingCriterionKind.IsDetected,
             new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.IsDetected },
             TaskObservation.Detected(true), TaskObservation.Detected(false)),
            (BlockingCriterionKind.Score,
             new BlockingCriterion { Enabled = true, Kind = BlockingCriterionKind.Score, AllowedScore = 0.8d },
             TaskObservation.Score(0.9d), TaskObservation.Score(0.5d)),
        };

        var combinations = 0;
        foreach (var (kind, criterion, matching, notMatching) in kinds)
        {
            foreach (var action in Actions)
            {
                foreach (var level in Levels)
                {
                    foreach (var matched in new[] { true, false })
                    {
                        var session = ContentSafetySession.Create(new ContentSafetySessionOptions
                        {
                            SafetyLevel = level,
                            Tasks = new[]
                            {
                                new ContentSafetyTask
                                {
                                    Label = "t",
                                    Action = action,
                                    Criterion = criterion,
                                    AppliesTo = new[] { ContentSafetyAppliedSource.Completion },
                                },
                            },
                        });
                        session.OnPayload(ContentSafetySource.ModelGenerated, 10);
                        var outcome = session.RecordSegment(
                            ContentSafetySource.ModelGenerated, 0, 10,
                            new Dictionary<string, TaskObservation>
                            {
                                ["t"] = matched ? matching : notMatching,
                            });

                        var expected = ExpectedAction(action, matched);
                        Assert(
                            outcome.Action == expected,
                            $"{kind} action={action} level={level} matched={matched}: "
                            + $"expected {expected}, got {outcome.Action}");
                        Assert(
                            outcome.Permits == (expected == ContentSafetyAction.Annotate),
                            $"{kind} action={action} level={level} matched={matched}: "
                            + $"permits disagreed with the action");
                        Assert(
                            outcome.MatchedTasks.Count == (matched ? 1 : 0),
                            $"{kind} action={action} level={level} matched={matched}: "
                            + "matched task list disagreed");
                        combinations++;
                    }
                }
            }
        }

        Assert(combinations == 4 * 5 * 3 * 2, $"expected 120 combinations, ran {combinations}");
    }

    private static void MultiplePoliciesCombineByPrecedenceNotByOrder()
    {
        // Several tasks scoring the same segment must collapse to the strongest
        // action regardless of the order they appear in the configuration.
        var pairs = new (ContentSafetyAction A, ContentSafetyAction B, ContentSafetyAction Expected)[]
        {
            (ContentSafetyAction.Annotate, ContentSafetyAction.Block, ContentSafetyAction.Block),
            (ContentSafetyAction.Block, ContentSafetyAction.Annotate, ContentSafetyAction.Block),
            (ContentSafetyAction.Hitl, ContentSafetyAction.Block, ContentSafetyAction.Block),
            (ContentSafetyAction.Retry, ContentSafetyAction.Hitl, ContentSafetyAction.Hitl),
            (ContentSafetyAction.Annotate, ContentSafetyAction.Retry, ContentSafetyAction.Retry),
            (ContentSafetyAction.Retry, ContentSafetyAction.Annotate, ContentSafetyAction.Retry),
        };

        foreach (var (a, b, expected) in pairs)
        {
            var criterion = new BlockingCriterion
            {
                Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = 4,
            };
            var session = ContentSafetySession.Create(new ContentSafetySessionOptions
            {
                Tasks = new[]
                {
                    new ContentSafetyTask { Label = "first", Action = a, Criterion = criterion },
                    new ContentSafetyTask { Label = "second", Action = b, Criterion = criterion },
                },
            });
            session.OnPayload(ContentSafetySource.ModelGenerated, 10);
            var outcome = session.RecordSegment(
                ContentSafetySource.ModelGenerated, 0, 10,
                new Dictionary<string, TaskObservation>
                {
                    ["first"] = TaskObservation.Severity(6),
                    ["second"] = TaskObservation.Severity(6),
                });
            Assert(
                outcome.Action == expected,
                $"{a} with {b}: expected {expected}, got {outcome.Action}");
            Assert(outcome.MatchedTasks.Count == 2, "both tasks should have matched");
        }
    }

    private static void ARefusalNamesTheTaskWhoseActionDecidedIt()
    {
        // When several tasks match with different actions, the terminal reason
        // must name one whose own action collapsed to the reported decision.
        // Naming any matched task would record a block against a task
        // configured only to annotate, which is a false account of which policy
        // refused and is the audit trail a service reports.
        var criterion = new BlockingCriterion
        {
            Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = 4,
        };

        foreach (var first in Actions)
        {
            foreach (var second in Actions)
            {
                var session = ContentSafetySession.Create(new ContentSafetySessionOptions
                {
                    Tasks = new[]
                    {
                        new ContentSafetyTask { Label = "first", Action = first, Criterion = criterion },
                        new ContentSafetyTask { Label = "second", Action = second, Criterion = criterion },
                    },
                });
                session.OnPayload(ContentSafetySource.ModelGenerated, 10);
                var outcome = session.RecordSegment(
                    ContentSafetySource.ModelGenerated, 0, 10,
                    new Dictionary<string, TaskObservation>
                    {
                        ["first"] = TaskObservation.Severity(6),
                        ["second"] = TaskObservation.Severity(6),
                    });

                Assert(
                    outcome.EvaluatedTasks.Count == 2,
                    $"{first} with {second}: both tasks should be reported as evaluated");

                if (outcome.Permits)
                {
                    continue;
                }

                var denied = session.Stream.EndReason as StreamEndReason.Denied;
                Assert(denied is not null, $"{first} with {second}: refusal did not end the session");

                var namedConfigured = denied!.Task == "first" ? first : second;
                var namedEffective = namedConfigured == ContentSafetyAction.Unspecified
                    ? ContentSafetyAction.Block
                    : namedConfigured;
                Assert(
                    namedEffective == outcome.Action,
                    $"{first} with {second}: reported {outcome.Action} but named {denied.Task}, "
                    + $"whose action is {namedEffective}");
            }
        }
    }

    private static void ThresholdBoundariesAreInclusiveOnEveryKind()
    {
        // Off by one at a threshold is the classic policy bug, so every kind is
        // probed at its boundary and one step either side.
        for (var allowed = 0; allowed <= 7; allowed++)
        {
            var criterion = new BlockingCriterion
            {
                Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = allowed,
            };
            for (var observed = 0; observed <= 7; observed++)
            {
                var expected = observed >= allowed;
                Assert(
                    criterion.Matches(TaskObservation.Severity(observed)) == expected,
                    $"severity allowed={allowed} observed={observed} expected match={expected}");
            }
        }

        foreach (var (allowed, boundary) in new[]
                 {
                     (RiskLevel.Safe, 0), (RiskLevel.Low, 2),
                     (RiskLevel.Medium, 4), (RiskLevel.High, 6),
                 })
        {
            var criterion = new BlockingCriterion
            {
                Enabled = true, Kind = BlockingCriterionKind.RiskLevel, AllowedRiskLevel = allowed,
            };
            for (var observed = 0; observed <= 7; observed++)
            {
                var expected = BlockingCriterion.ToRiskLevel(observed) >= allowed;
                Assert(
                    criterion.Matches(TaskObservation.Severity(observed)) == expected,
                    $"risk allowed={allowed} observed={observed} boundary={boundary}");
            }
        }

        foreach (var allowed in new[] { 0d, 0.5d, 0.8d, 1d })
        {
            var criterion = new BlockingCriterion
            {
                Enabled = true, Kind = BlockingCriterionKind.Score, AllowedScore = allowed,
            };
            foreach (var observed in new[] { 0d, 0.4999d, 0.5d, 0.7999d, 0.8d, 0.9999d, 1d })
            {
                Assert(
                    criterion.Matches(TaskObservation.Score(observed)) == (observed >= allowed),
                    $"score allowed={allowed} observed={observed}");
            }
        }
    }

    private static void ConcurrentReportingAndAdvancingIsSafe()
    {
        // A front door receives classifier results concurrently and emits from
        // another thread. Without internal serialization, advancing enumerates
        // the task map while another thread writes to it and throws.
        const int Total = 2000;
        var labels = new[] { "a", "b", "c", "d" };
        var faults = 0;

        for (var run = 0; run < 25; run++)
        {
            var session = ContentSafetySession.Create(new ContentSafetySessionOptions
            {
                Tasks = labels.Select(label => new ContentSafetyTask
                {
                    Label = label,
                    Action = ContentSafetyAction.Block,
                    Criterion = new BlockingCriterion
                    {
                        Enabled = true,
                        Kind = BlockingCriterionKind.Severity,
                        AllowedSeverity = 4,
                    },
                }).ToArray(),
            });
            session.OnPayload(ContentSafetySource.ModelGenerated, Total);

            var work = labels.Select(label => Task.Run(() =>
            {
                for (var offset = 0; offset < Total; offset += 50)
                {
                    session.RecordSegment(
                        ContentSafetySource.ModelGenerated, offset, offset + 50,
                        new Dictionary<string, TaskObservation>
                        {
                            [label] = TaskObservation.Severity(0),
                        });
                }
            })).ToList();

            work.Add(Task.Run(() =>
            {
                var previous = 0;
                for (var i = 0; i < Total; i++)
                {
                    var safe = session.TryAdvanceWatermark(StreamTrack.Response);
                    if (safe >= 0)
                    {
                        if (safe < previous)
                        {
                            throw new InvalidOperationException(
                                $"watermark went backwards, {previous} then {safe}");
                        }

                        previous = safe;
                    }
                }
            }));

            try
            {
                Task.WaitAll(work.ToArray());
            }
            catch (Exception)
            {
                faults++;
                continue;
            }

            session.TryAdvanceWatermark(StreamTrack.Response);
            Assert(
                session.SafeOffset(StreamTrack.Response) == Total,
                "every task cleared every rune, so the whole track should be releasable");
        }

        Assert(faults == 0, $"{faults} of 25 concurrent runs faulted");
    }

    private static void ScopeCombinationsGateTheRightTracks()
    {
        var scopes = Enum.GetValues<ContentSafetyAppliedSource>();
        foreach (var scope in scopes)
        {
            foreach (var track in new[] { StreamTrack.Request, StreamTrack.Response })
            {
                var expected = scope switch
                {
                    ContentSafetyAppliedSource.All => true,
                    ContentSafetyAppliedSource.Prompt => track == StreamTrack.Request,
                    ContentSafetyAppliedSource.Completion => track == StreamTrack.Response,
                    _ => false,
                };
                Assert(
                    ContentSafetySourceMapping.GatesTrack(scope, track) == expected,
                    $"scope {scope} on {track}: expected {expected}");
            }
        }

        // A task with several scopes gates the union of them.
        var session = ContentSafetySession.Create(new ContentSafetySessionOptions
        {
            Tasks = new[]
            {
                new ContentSafetyTask
                {
                    Label = "both",
                    Action = ContentSafetyAction.Block,
                    Criterion = new BlockingCriterion
                    {
                        Enabled = true, Kind = BlockingCriterionKind.Severity, AllowedSeverity = 4,
                    },
                    AppliesTo = new[]
                    {
                        ContentSafetyAppliedSource.Prompt,
                        ContentSafetyAppliedSource.PreToolCall,
                    },
                },
            },
        });
        session.OnPayload(ContentSafetySource.UserRequest, 5);
        var outcome = session.RecordSegment(
            ContentSafetySource.UserRequest, 0, 5,
            new Dictionary<string, TaskObservation> { ["both"] = TaskObservation.Severity(0) });
        Assert(outcome.Permits, "a prompt scoped task should evaluate request text");
        Assert(
            session.TryAdvanceWatermark(StreamTrack.Request) == 5,
            "and should gate the request track");
    }
}
