package acs.packs.budgets

import data.acs.packs.common as c
import rego.v1

valid if {
	is_object(data.pack.limits)
	count(data.pack.limits) > 0
	every metric, limit in data.pack.limits {
		data.acs.packs.common.nonempty_string(metric)
		data.acs.packs.common.natural(limit)
		data.acs.packs.common.natural(c.host.budget.used[metric])
		data.acs.packs.common.natural(c.host.budget.reserved[metric])
	}
}

exceeded if {
	some metric, limit in data.pack.limits
	c.host.budget.used[metric] + c.host.budget.reserved[metric] > limit
}

verdict := data.acs.packs.common.deny("budget_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("budget_exceeded") if {
	exceeded
} else := c.allow
