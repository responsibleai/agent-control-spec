package acs.packs.human_approval

import data.acs.packs.common as c
import rego.v1

rule_valid(rule) if {
	is_object(rule)
	rule.mode in {"allow", "review"}
	object.keys(rule) == {"mode"}
}

rule_valid(rule) if {
	is_object(rule)
	rule.mode == "threshold"
	object.keys(rule) == {"mode", "argument_path", "max_without_approval"}
	data.acs.packs.common.nonempty_strings(rule.argument_path)
	data.acs.packs.common.natural(rule.max_without_approval)
}

valid if {
	is_object(data.pack.tools)
	count(data.pack.tools) > 0
	every name, rule in data.pack.tools {
		data.acs.packs.common.nonempty_string(name)
		rule_valid(rule)
	}
	data.acs.packs.common.nonempty_string(input.snapshot.tool_call.name)
}

rule := data.pack.tools[input.snapshot.tool_call.name]

valid_argument if {
	data.acs.packs.common.natural(object.get(input.policy_target.value, rule.argument_path, null))
}

verdict := data.acs.packs.common.deny("approval_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("approval_tool_unknown") if {
	not rule
} else := data.acs.packs.common.deny("approval_argument_invalid") if {
	rule.mode == "threshold"
	not valid_argument
} else := data.agt.approval.escalate_if(true, "human_approval_required") if {
	rule.mode == "review"
} else := data.agt.approval.escalate_if(true, "human_approval_required") if {
	rule.mode == "threshold"
	object.get(input.policy_target.value, rule.argument_path, null) > rule.max_without_approval
} else := c.allow
