package acs.packs.pii

import data.acs.packs.common as c
import rego.v1

matches(value) if {
	walk(value, [_, leaf])
	is_string(leaf)
	data.agt.patterns.matches_any(leaf, data.pack.patterns)
}

matches(value) if {
	data.agt.patterns.matches_any(json.marshal(value), data.pack.patterns)
}

unredactable_match if {
	is_object(input.policy_target.value)
	matches(object.remove(input.policy_target.value, {"content"}))
}

redactable if {
	is_string(c.text)
	not unredactable_match
}

valid if {
	data.pack.action in {"deny", "redact"}
	data.acs.packs.common.valid_patterns(data.pack.patterns)
	is_string(data.pack.replacement)
}

verdict := data.acs.packs.common.deny("pii_data_invalid") if {
	not valid
} else := c.allow if {
	not matches(input.policy_target.value)
} else := data.acs.packs.common.deny("pii_detected") if {
	data.pack.action == "deny"
} else := data.acs.packs.common.deny("pii_unredactable_fields") if {
	not redactable
} else := data.acs.packs.common.deny("pii_replacement_unsafe") if {
	value := data.agt.redact.apply_patterns(c.text, data.pack.patterns, data.pack.replacement)
	is_string(value)
	data.agt.patterns.matches_any(value, data.pack.patterns)
} else := {
	"decision": "transform",
	"reason": "pii_redacted",
	"transform": {
		"path": c.text_path,
		"value": data.agt.redact.apply_patterns(c.text, data.pack.patterns, data.pack.replacement),
	},
}
