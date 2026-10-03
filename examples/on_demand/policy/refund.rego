package refund
import rego.v1

valid_request if {
    is_number(input.policy_target.value.amount_cents)
    input.policy_target.value.amount_cents == floor(input.policy_target.value.amount_cents)
    input.policy_target.value.amount_cents > 0
    input.policy_target.value.amount_cents <= 1000000
    is_string(input.policy_target.value.order_id)
    count(input.policy_target.value.order_id) > 0
}

required := input.policy_target.value.amount_cents >= 10000 if valid_request
eligibility := acs.annotate("eligibility", required)

default verdict := {"decision": "deny", "reason": "refund_not_permitted"}

verdict := {"decision": "allow", "reason": "small_refund"} if {
    valid_request
    required == false
    eligibility.status == "not_required"
}

verdict := {"decision": "allow", "reason": "eligibility_confirmed"} if {
    valid_request
    required == true
    eligibility.status == "completed"
    eligibility.value.eligible == true
    is_number(eligibility.value.max_amount_cents)
    input.policy_target.value.amount_cents <= eligibility.value.max_amount_cents
}
