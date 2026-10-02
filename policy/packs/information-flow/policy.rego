package acs.packs.information_flow

import data.acs.packs.common as c
import rego.v1

clearance := input.tool.clearance if {
	input.intervention_point == "pre_tool_call"
} else := data.pack.model_clearance if {
	input.intervention_point == "pre_model_call"
} else := data.pack.output_clearance if {
	input.intervention_point == "output"
}

default verdict := {"decision": "deny", "reason": "ifc_data_invalid"}

verdict := {
	"decision": "allow",
	"result_labels": data.agent_control_specification.lib.ifc.propagated_labels(c.host.source_labels),
} if {
	data.agent_control_specification.lib.ifc.flow_allowed(clearance, c.host.source_labels)
}
