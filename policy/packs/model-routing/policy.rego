package acs.packs.model_routing

import data.acs.packs.common as c
import rego.v1

route_valid(route) if {
	is_object(route)
	object.keys(route) == {"provider", "deployment", "region"}
	every _, value in route {
		data.acs.packs.common.nonempty_string(value)
	}
}

valid if {
	is_array(data.pack.routes)
	count(data.pack.routes) > 0
	every route in data.pack.routes {
		route_valid(route)
	}
	route_valid(c.host.model_route)
}

verdict := data.acs.packs.common.deny("model_route_data_invalid") if {
	not valid
} else := c.allow if {
	c.host.model_route in data.pack.routes
} else := data.acs.packs.common.deny("model_route_denied")
