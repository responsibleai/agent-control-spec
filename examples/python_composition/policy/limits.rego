package refund_limits

import rego.v1

default verdict := {"decision": "deny", "reason": "amount_invalid"}

verdict := {
    "decision": "transform",
    "reason": "refund_capped",
    "transform": {"path": "$target.amount", "value": 100},
} if {
    is_number(input.policy_target.value.amount)
    input.policy_target.value.amount > 100
} else := {"decision": "allow"} if {
    is_number(input.policy_target.value.amount)
    input.policy_target.value.amount > 0
    input.policy_target.value.amount <= 100
}
