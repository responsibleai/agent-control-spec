package acs.packs.common

import rego.v1

nonempty_string(value) if {
	is_string(value)
	count(value) > 0
}

strings(value) if {
	is_array(value)
	every item in value {
		nonempty_string(item)
	}
}

nonempty_strings(value) if {
	strings(value)
	count(value) > 0
}

natural(value) if {
	is_number(value)
	value >= 0
	value == floor(value)
}

valid_patterns(patterns) if {
	nonempty_strings(patterns)
	every pattern in patterns {
		regex.replace("", pattern, "") == ""
	}
}

text := input.policy_target.value if {
	is_string(input.policy_target.value)
} else := input.policy_target.value.content if {
	is_object(input.policy_target.value)
	is_string(input.policy_target.value.content)
}

text_path := "$target" if {
	is_string(input.policy_target.value)
} else := "$target.content" if {
	is_object(input.policy_target.value)
	is_string(input.policy_target.value.content)
}

host := input.snapshot.extensions.policy_packs

allow := {"decision": "allow"}

deny(reason) := {"decision": "deny", "reason": reason}
