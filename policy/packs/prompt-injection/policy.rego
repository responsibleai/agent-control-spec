package acs.packs.prompt_injection

import data.acs.packs.common as c
import rego.v1

valid if {
	is_number(data.pack.deny_at)
	data.pack.deny_at > 0
	data.pack.deny_at <= 1
	is_number(input.annotations.prompt_injection.score)
	input.annotations.prompt_injection.score >= 0
	input.annotations.prompt_injection.score <= 1
}

verdict := data.acs.packs.common.deny("prompt_injection_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("prompt_injection_detected") if {
	input.annotations.prompt_injection.score >= data.pack.deny_at
} else := c.allow
