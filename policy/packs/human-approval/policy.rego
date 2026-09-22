package acs.packs.human_approval

import data.acs.packs.common as c
import rego.v1

valid if {
	data.acs.packs.common.nonempty_strings(data.pack.allowed_tools)
	data.acs.packs.common.strings(data.pack.approval_tools)
	every tool in data.pack.approval_tools {
		tool in data.pack.allowed_tools
	}
	data.acs.packs.common.nonempty_string(data.pack.refund_tool)
	data.pack.refund_tool in data.pack.allowed_tools
	data.acs.packs.common.natural(data.pack.refund_limit_minor)
	data.acs.packs.common.nonempty_string(input.snapshot.tool_call.name)
}

valid_amount if {
	data.acs.packs.common.natural(input.policy_target.value.amount_minor)
}

requires_approval if {
	input.snapshot.tool_call.name in data.pack.approval_tools
}

requires_approval if {
	input.snapshot.tool_call.name == data.pack.refund_tool
	input.policy_target.value.amount_minor > data.pack.refund_limit_minor
}

verdict := data.acs.packs.common.deny("approval_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("approval_tool_unknown") if {
	not input.snapshot.tool_call.name in data.pack.allowed_tools
} else := data.acs.packs.common.deny("refund_amount_invalid") if {
	input.snapshot.tool_call.name == data.pack.refund_tool
	not valid_amount
} else := data.agt.approval.escalate_if(true, "human_approval_required") if {
	requires_approval
} else := c.allow
