# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.content_safety_test

import data.agt.content_safety as cs
import rego.v1

severity_criterion(allowed) := {"enabled": true, "kind": "severity", "allowed_severity": allowed}

test_severity_is_inclusive_at_the_threshold if {
	cs.matches(severity_criterion(4), {"severity": 4})
	cs.matches(severity_criterion(4), {"severity": 7})
	not cs.matches(severity_criterion(4), {"severity": 3})
}

test_severity_zero_matches_everything if {
	every s in [0, 1, 2, 3, 4, 5, 6, 7] {
		cs.matches(severity_criterion(0), {"severity": s})
	}
}

test_risk_level_buckets_pair_adjacent_severities if {
	cs.risk_level(0) == "safe"
	cs.risk_level(1) == "safe"
	cs.risk_level(2) == "low"
	cs.risk_level(3) == "low"
	cs.risk_level(4) == "medium"
	cs.risk_level(5) == "medium"
	cs.risk_level(6) == "high"
	cs.risk_level(7) == "high"
	cs.risk_level(9) == "unspecified"
}

test_risk_level_criterion_compares_buckets_not_numbers if {
	criterion := {"enabled": true, "kind": "risk_level", "allowed_risk_level": "medium"}

	# Severity 4 and 5 are both medium, so both match at a medium threshold.
	cs.matches(criterion, {"severity": 4})
	cs.matches(criterion, {"severity": 5})
	cs.matches(criterion, {"severity": 6})

	# Severity 3 is low, which is below medium.
	not cs.matches(criterion, {"severity": 3})
}

test_is_detected_carries_no_threshold if {
	criterion := {"enabled": true, "kind": "is_detected"}
	cs.matches(criterion, {"detected": true})
	not cs.matches(criterion, {"detected": false})
}

test_score_is_inclusive_at_the_threshold if {
	criterion := {"enabled": true, "kind": "score", "allowed_score": 0.8}
	cs.matches(criterion, {"score": 0.8})
	cs.matches(criterion, {"score": 0.95})
	not cs.matches(criterion, {"score": 0.79})
}

test_a_disabled_criterion_never_matches if {
	every kind in ["severity", "risk_level", "is_detected", "score"] {
		not cs.matches(
			{"enabled": false, "kind": kind, "allowed_severity": 0, "allowed_risk_level": "safe", "allowed_score": 0},
			{"severity": 7, "detected": true, "score": 1.0},
		)
	}
}

test_a_missing_threshold_never_matches_and_is_reported_malformed if {
	criterion := {"enabled": true, "kind": "severity"}
	not cs.matches(criterion, {"severity": 7})
	cs.malformed(criterion)
}

test_an_unknown_kind_is_malformed if {
	cs.malformed({"enabled": true, "kind": "vibes"})
}

test_a_disabled_criterion_is_not_malformed if {
	not cs.malformed({"enabled": false, "kind": "severity"})
}

test_collapse_orders_block_above_everything if {
	cs.collapse(["annotate", "retry", "hitl", "block"]) == "block"
	cs.collapse(["annotate", "retry", "hitl"]) == "hitl"
	cs.collapse(["annotate", "retry"]) == "retry"
	cs.collapse(["annotate"]) == "annotate"
	cs.collapse([]) == "annotate"
}

test_collapse_is_order_independent if {
	cs.collapse(["block", "annotate"]) == cs.collapse(["annotate", "block"])
	cs.collapse(["retry", "hitl"]) == cs.collapse(["hitl", "retry"])
}

test_an_unset_action_on_a_match_fails_closed if {
	cs.effective_action("") == "block"
	cs.effective_action("unspecified") == "block"
	cs.collapse(["annotate", ""]) == "block"
}

test_only_annotate_permits_release if {
	cs.permits("annotate")
	not cs.permits("block")
	not cs.permits("hitl")
	not cs.permits("retry")
	not cs.permits("")
}
