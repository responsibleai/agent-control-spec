package acs.packs.tool_permissions

import data.acs.packs.common as c
import rego.v1

valid if {
	data.acs.packs.common.nonempty_string(c.host.subject)
	data.acs.packs.common.strings(c.host.roles)
	data.acs.packs.common.nonempty_strings(input.tool.allowed_roles)
}

permitted if {
	some role in c.host.roles
	role in input.tool.allowed_roles
}

verdict := data.acs.packs.common.deny("tool_permissions_data_invalid") if {
	not valid
} else := c.allow if {
	permitted
} else := data.acs.packs.common.deny("tool_permission_denied")
