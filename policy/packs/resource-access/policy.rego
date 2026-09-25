package acs.packs.resource_access

import data.acs.packs.common as c
import rego.v1

valid if {
	data.acs.packs.common.nonempty_strings(data.pack.operations)
	is_boolean(data.pack.require_same_tenant)
	data.acs.packs.common.nonempty_string(c.host.subject)
	data.acs.packs.common.nonempty_string(c.host.tenant)
	data.acs.packs.common.nonempty_string(c.host.resource.id)
	data.acs.packs.common.nonempty_string(c.host.resource.tenant)
	data.acs.packs.common.nonempty_string(c.host.resource.operation)
	data.acs.packs.common.strings(c.host.resource.allowed_subjects)
}

tenant_allowed if {
	not data.pack.require_same_tenant
}

tenant_allowed if {
	c.host.tenant == c.host.resource.tenant
}

verdict := data.acs.packs.common.deny("resource_access_data_invalid") if {
	not valid
} else := c.allow if {
	c.host.subject in c.host.resource.allowed_subjects
	c.host.resource.operation in data.pack.operations
	tenant_allowed
} else := data.acs.packs.common.deny("resource_access_denied")
