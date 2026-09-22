package acs.packs.destinations

import data.acs.packs.common as c
import rego.v1

valid if {
	data.acs.packs.common.nonempty_strings(data.pack.origins)
	data.acs.packs.common.nonempty_strings(data.pack.methods)
	data.acs.packs.common.nonempty_string(c.host.destination.origin)
	data.acs.packs.common.nonempty_string(c.host.destination.method)
	is_boolean(c.host.destination.has_credentials)
}

verdict := data.acs.packs.common.deny("destination_data_invalid") if {
	not valid
} else := c.allow if {
	not c.host.destination.has_credentials
	c.host.destination.origin in data.pack.origins
	c.host.destination.method in data.pack.methods
} else := data.acs.packs.common.deny("destination_denied")
