package acs.packs.content_safety

import data.acs.packs.common as c
import rego.v1

valid if {
	is_object(data.pack.thresholds)
	count(data.pack.thresholds) > 0
	is_object(input.annotations.content_safety.scores)
	every category, threshold in data.pack.thresholds {
		data.acs.packs.common.nonempty_string(category)
		data.acs.packs.common.natural(threshold)
		threshold <= 7
		score := input.annotations.content_safety.scores[category]
		data.acs.packs.common.natural(score)
		score <= 7
	}
}

blocked if {
	some category, threshold in data.pack.thresholds
	input.annotations.content_safety.scores[category] >= threshold
}

verdict := data.acs.packs.common.deny("content_safety_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("content_safety_threshold") if {
	blocked
} else := c.allow
