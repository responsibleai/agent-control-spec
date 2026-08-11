package acs

decision := {"decision": "deny", "reason": "unsafe_content"} if {
    input.annotations.content_safety.severity >= 4
} else := {"decision": "allow"}
