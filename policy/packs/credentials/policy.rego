package acs.packs.credentials

import data.acs.packs.common as c
import rego.v1

valid if {
	data.acs.packs.common.valid_patterns(data.pack.patterns)
	input.policy_target.value != null
}

detected if {
	walk(input.policy_target.value, [_, value])
	is_string(value)
	data.agt.patterns.matches_any(value, data.pack.patterns)
}

detected if {
	data.agt.patterns.matches_any(json.marshal(input.policy_target.value), data.pack.patterns)
}

verdict := data.acs.packs.common.deny("credential_scan_invalid") if {
	not valid
} else := data.acs.packs.common.deny("credential_detected") if {
	detected
} else := c.allow
