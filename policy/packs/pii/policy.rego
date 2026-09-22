package acs.packs.pii

import data.acs.packs.common as c
import rego.v1

text_target if {
	is_string(input.policy_target.value)
}

text_target if {
	is_object(input.policy_target.value)
	is_string(input.policy_target.value.content)
}

unredactable_match if {
	is_object(input.policy_target.value)
	other := object.remove(input.policy_target.value, {"content"})
	walk(other, [_, value])
	is_string(value)
	data.agt.patterns.matches_any(value, data.pack.patterns)
}

unredactable_match if {
	is_object(input.policy_target.value)
	other := object.remove(input.policy_target.value, {"content"})
	data.agt.patterns.matches_any(json.marshal(other), data.pack.patterns)
}

valid if {
	data.pack.action in {"deny", "redact"}
	data.acs.packs.common.valid_patterns(data.pack.patterns)
	is_string(data.pack.replacement)
	text_target
	is_string(c.text)
}

verdict := data.acs.packs.common.deny("pii_data_invalid") if {
	not valid
} else := data.acs.packs.common.deny("pii_unredactable_fields") if {
	unredactable_match
} else := data.acs.packs.common.deny("pii_detected") if {
	data.agt.patterns.matches_any(c.text, data.pack.patterns)
	data.pack.action == "deny"
} else := data.acs.packs.common.deny("pii_replacement_unsafe") if {
	data.pack.action == "redact"
	sanitized := data.agt.redact.apply_patterns(c.text, data.pack.patterns, data.pack.replacement)
	data.agt.patterns.matches_any(sanitized, data.pack.patterns)
} else := {
	"decision": "transform",
	"reason": "pii_redacted",
	"transform": {
		"path": c.text_path,
		"value": data.agt.redact.apply_patterns(c.text, data.pack.patterns, data.pack.replacement),
	},
} if {
	data.agt.patterns.matches_any(c.text, data.pack.patterns)
	data.pack.action == "redact"
} else := c.allow
