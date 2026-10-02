package acs.packs.tool_integrity

import data.acs.packs.common as c
import rego.v1

digest(value) if {
	is_string(value)
	regex.match("^[0-9a-f]{64}$", value)
}

valid if {
	is_object(data.pack.sha256)
	count(data.pack.sha256) > 0
	every name, value in data.pack.sha256 {
		data.acs.packs.common.nonempty_string(name)
		digest(value)
	}
	data.acs.packs.common.nonempty_string(input.snapshot.tool_call.name)
	digest(c.host.tool_sha256)
}

verdict := data.acs.packs.common.deny("tool_integrity_data_invalid") if {
	not valid
} else := c.allow if {
	c.host.tool_sha256 == data.pack.sha256[input.snapshot.tool_call.name]
} else := data.acs.packs.common.deny("tool_integrity_mismatch")
