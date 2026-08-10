# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Content safety blocking criteria and action precedence.
#
# A content safety service decides whether to act on a task by comparing what a
# model reported against a configured criterion, then combines the actions every
# matched task asked for into one. Both halves are fiddly enough to be worth
# writing once. The comparison has four shapes that are easy to conflate, and
# the combination is a precedence order rather than a last writer wins.
#
# Callers supply a criterion object shaped as the service's own configuration,
# with an enabled flag, a kind, and whichever threshold that kind reads.
package agt.content_safety

import rego.v1

# Severity runs 0 through 7 and buckets into four risk levels, pairing adjacent
# values. A policy expressed against risk levels is comparing these buckets
# rather than the raw number.
risk_level(severity) := "safe" if severity in [0, 1]

risk_level(severity) := "low" if severity in [2, 3]

risk_level(severity) := "medium" if severity in [4, 5]

risk_level(severity) := "high" if severity in [6, 7]

risk_level(severity) := "unspecified" if not severity in [0, 1, 2, 3, 4, 5, 6, 7]

risk_rank := {
	"unspecified": -1,
	"safe": 0,
	"low": 1,
	"medium": 2,
	"high": 3,
}

# Whether a criterion matches an observation.
#
# A criterion that is disabled never matches. A criterion whose threshold is
# absent never matches either, which mirrors the service, where a null
# comparison is false. That is permissive, so `malformed` below exists to catch
# it at configuration time rather than at decision time.
matches(criterion, observation) if {
	criterion.enabled == true
	criterion.kind == "severity"
	observation.severity >= criterion.allowed_severity
}

matches(criterion, observation) if {
	criterion.enabled == true
	criterion.kind == "risk_level"
	risk_rank[risk_level(observation.severity)] >= risk_rank[criterion.allowed_risk_level]
}

matches(criterion, observation) if {
	criterion.enabled == true
	criterion.kind == "is_detected"
	observation.detected == true
}

matches(criterion, observation) if {
	criterion.enabled == true
	criterion.kind == "score"
	observation.score >= criterion.allowed_score
}

# An enabled criterion that can never match, which is almost always a mistake
# rather than an intent to permit everything.
malformed(criterion) if {
	criterion.enabled == true
	criterion.kind == "severity"
	not criterion.allowed_severity
}

malformed(criterion) if {
	criterion.enabled == true
	criterion.kind == "risk_level"
	not criterion.allowed_risk_level
}

malformed(criterion) if {
	criterion.enabled == true
	criterion.kind == "score"
	not criterion.allowed_score
}

malformed(criterion) if {
	criterion.enabled == true
	not criterion.kind in ["severity", "risk_level", "is_detected", "score"]
}

# Action precedence. Block outranks human review, which outranks retry, which
# outranks annotate. An unset or unrecognised action on a matched criterion
# resolves to block, because a task that found something must not be permitted
# by a gap in its own configuration.
#
# These rules are also implemented in C# in ContentSafetyDecision, and both
# answer to the same authority: the service's own expectations, committed at
# tests/conformance/streaming/content-safety/content-safety-decision-oracle.json.
# The .NET tests check against that file. Nothing checks this one against it, so
# a change to the precedence here has to be made in both places by hand.
action_rank := {
	"annotate": 0,
	"retry": 1,
	"hitl": 2,
	"block": 3,
}

effective_action(action) := action if action in ["annotate", "retry", "hitl", "block"]

effective_action(action) := "block" if not action in ["annotate", "retry", "hitl", "block"]

# Collapse the actions of every matched task into the one to report. No matched
# task means annotate, which permits the content.
collapse(actions) := "annotate" if count(actions) == 0

collapse(actions) := strongest if {
	count(actions) > 0
	ranks := [action_rank[effective_action(a)] | some a in actions]
	top := max(ranks)
	some name, rank in action_rank
	rank == top
	strongest := name
}

# Whether an action permits the content to be released.
permits(action) if effective_action(action) == "annotate"
