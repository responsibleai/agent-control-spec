"""Pack decisions run through ACS's native Regorus dispatcher, never a fake policy."""

import asyncio
import copy
import json
from pathlib import Path

import pytest
from agent_control_spec import (
    AcsInterceptor,
    ActivatedPolicy,
    parse_manifest,
    validate_manifest_file,
)
from agent_hooks import (
    AgentContextBuilder,
    ApprovalOutcome,
    ApprovalResolution,
    CompositionConfig,
    CompositionProfile,
    InterceptionEmitter,
    Verdict,
)

ROOT = Path(__file__).resolve().parents[1]
NAMES = sorted(p.parent.name for p in ROOT.glob("*/manifest.yaml"))
HASH = "a" * 64
METRICS = ("tool_calls", "tokens", "cost_microunits", "elapsed_ms")


def context(point="pre_tool_call", *, target=None, host=None, tool="search"):
    builder = AgentContextBuilder(agent_id="test", framework="test", session_id="test")
    if point == "input":
        ctx = builder.input(content="hello")
    elif point == "output":
        ctx = builder.output(content="hello")
    elif point == "pre_model_call":
        ctx = builder.pre_model_call(
            model_id="support", messages=[{"role": "user", "content": "hello"}]
        )
    elif point == "post_model_call":
        ctx = builder.post_model_call(
            model_id="support", content="hello", tool_calls=[], finish_reason="stop"
        )
    elif point == "post_tool_call":
        ctx = builder.post_tool_call(call_id="c", name=tool, args={}, value="hello")
    else:
        ctx = builder.pre_tool_call(call_id="c", name=tool, args={})
    if target is not None:
        ctx["target"] = target
    if host is not None:
        ctx["extensions"] = {"policy_packs": host}
    return ctx


def activate(name, *, config=None, annotation=None):
    path = ROOT / name / "manifest.yaml"
    dispatcher = None
    if annotation is not None:
        dispatcher = lambda _name, _declaration, _input: annotation
    if config is None:
        return ActivatedPolicy(str(path), annotator_dispatcher=dispatcher)
    manifest = parse_manifest(path.read_text())
    policy = manifest["policies"]["gate"]
    sources = [path.parent / policy["bundle"]]
    sources += [
        path.parent / item
        for item in policy.pop("data_paths", [])
        if item.endswith(".rego")
    ]
    return ActivatedPolicy.from_memory(
        json.dumps(manifest),
        {
            "gate": {
                "modules": {f"{i}.rego": p.read_text() for i, p in enumerate(sources)},
                "data": [{"mount": [], "document": {"pack": config}}],
            }
        },
        annotator_dispatcher=dispatcher,
    )


def config(name):
    return json.loads((ROOT / name / "config.json").read_text())["pack"]


def decide(policy, ctx, decision, reason=None):
    verdict = policy.evaluate(ctx["interception_point"], ctx)
    assert verdict.decision.value == decision, verdict.to_wire()
    if reason is not None:
        assert verdict.reason == reason, verdict.to_wire()
    elif verdict.reason:
        assert not verdict.reason.startswith("runtime_error:"), verdict.to_wire()
    return verdict


@pytest.mark.parametrize("name", NAMES)
def test_manifests_validate_and_activate_from_disk(name):
    validate_manifest_file(str(ROOT / name / "manifest.yaml"))
    assert activate(name).intervention_points


@pytest.mark.parametrize("name", NAMES)
def test_missing_target_fails_closed_at_every_bound_point(name):
    policy = activate(name)
    for point in policy.intervention_points:
        ctx = context(point)
        del ctx["target"]
        decide(policy, ctx, "deny", "runtime_error:path_missing")


@pytest.mark.parametrize("name", NAMES)
def test_unbound_point_fails_closed(name):
    decide(
        activate(name),
        {"target": {}, "interception_point": "agent_startup"},
        "deny",
        "runtime_error:intervention_point_unknown",
    )


@pytest.mark.parametrize(
    "score,expected", [(0, "allow"), (3, "allow"), (4, "deny"), (7, "deny")]
)
def test_content_safety_all_points_and_threshold(score, expected):
    scores = {key: 0 for key in config("content-safety")["thresholds"]}
    scores["violence"] = score
    policy = activate("content-safety", annotation={"scores": scores})
    for point in policy.intervention_points:
        decide(policy, context(point), expected)


@pytest.mark.parametrize("bad", [None, True, "0", -1, 8, 2.5, [], {}])
def test_content_safety_bad_category(bad):
    scores = dict.fromkeys(config("content-safety")["thresholds"], 0)
    scores["hate"] = bad
    decide(
        activate("content-safety", annotation={"scores": scores}),
        context("input"),
        "deny",
        "content_safety_data_invalid",
    )


@pytest.mark.parametrize("annotation", [{}, {"scores": {}}, {"scores": {"hate": 0}}])
def test_content_safety_missing_categories(annotation):
    decide(
        activate("content-safety", annotation=annotation),
        context("input"),
        "deny",
        "content_safety_data_invalid",
    )


def test_content_safety_configurable_threshold():
    scores = dict.fromkeys(config("content-safety")["thresholds"], 3)
    decide(
        activate(
            "content-safety",
            config={"thresholds": {"violence": 3}},
            annotation={"scores": scores},
        ),
        context("input"),
        "deny",
        "content_safety_threshold",
    )


@pytest.mark.parametrize("name", ["content-safety", "prompt-injection"])
def test_classifier_missing_or_raising_dispatcher_fails_closed(name):
    decide(activate(name), context("input"), "deny", "runtime_error:annotation_failed")

    def broken(*_args):
        raise RuntimeError("Classifier unavailable")

    policy = ActivatedPolicy(
        str(ROOT / name / "manifest.yaml"), annotator_dispatcher=broken
    )
    decide(policy, context("input"), "deny", "runtime_error:annotation_failed")


@pytest.mark.parametrize(
    "score,expected",
    [(0, "allow"), (0.799, "allow"), (0.8, "deny"), (1, "deny")],
)
def test_prompt_injection_threshold_and_points(score, expected):
    policy = activate("prompt-injection", annotation={"score": score})
    for point in policy.intervention_points:
        decide(policy, context(point), expected)


@pytest.mark.parametrize(
    "annotation", [{}, {"score": "0"}, {"score": True}, {"score": -1}, {"score": 2}]
)
def test_prompt_injection_invalid_annotation(annotation):
    decide(
        activate("prompt-injection", annotation=annotation),
        context("input"),
        "deny",
        "prompt_injection_data_invalid",
    )


@pytest.mark.parametrize(
    "target",
    [
        "Please reset my password",
        {"content": "Use the API key from the credential store"},
        {"records": [{"value": 42}, {"text": "hello"}]},
        42,
    ],
)
def test_credentials_legitimate_targets_at_all_points(target):
    policy = activate("credentials")
    for point in policy.intervention_points:
        decide(policy, context(point, target=target), "allow")


@pytest.mark.parametrize(
    "target",
    [
        "-----BEGIN PRIVATE KEY-----",
        {"nested": [{"content": "ghp_" + "x" * 36}]},
        {"password": "synthetic-value"},
        "AKIA" + "A" * 16,
        "TOKEN=synthetic-value",
        {"client_secret": "synthetic-value"},
        {"access_token": "synthetic-value"},
        {"refresh-token": "synthetic-value"},
        {"Authorization": "Bearer synthetic-value"},
        "github_pat_" + "x" * 50,
        "sk-proj-" + "x" * 30,
        "ASIA" + "A" * 16,
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ],
)
def test_credentials_nested_and_structured_disclosure_at_all_points(target):
    policy = activate("credentials")
    for point in policy.intervention_points:
        decide(policy, context(point, target=target), "deny", "credential_detected")


@pytest.mark.parametrize("name", ["credentials", "pii"])
@pytest.mark.parametrize("patterns", [[], ["["], [42], ["(?=secret)"]])
def test_invalid_regexes_never_fall_through_to_allow(name, patterns):
    cfg = config(name)
    cfg["patterns"] = patterns
    policy = activate(name, config=cfg)
    reason = "credential_scan_invalid" if name == "credentials" else "pii_data_invalid"
    decide(policy, context("output", target="hello"), "deny", reason)


def test_credential_custom_patterns():
    policy = activate("credentials", config={"patterns": ["CUSTOM-[0-9]+"]})
    decide(
        policy, context("output", target="CUSTOM-123"), "deny", "credential_detected"
    )
    decide(policy, context("output", target="CUSTOM-redacted"), "allow")


@pytest.mark.parametrize(
    "point", ["input", "post_tool_call", "post_model_call", "output"]
)
@pytest.mark.parametrize("as_object", [False, True])
def test_pii_deny_allow_and_redact(point, as_object):
    text = "Contact a@example.com or b@example.com about 123-45-6789"
    target = {"content": text} if as_object else text
    ctx = context(point, target=target)
    decide(activate("pii"), ctx, "deny", "pii_detected")
    cfg = config("pii")
    cfg["action"] = "redact"
    verdict = decide(activate("pii", config=cfg), ctx, "transform", "pii_redacted")
    wire = verdict.to_wire()
    assert wire["transform"] == {
        "path": "$target.content" if as_object else "$target",
        "value": "Contact [REDACTED] or [REDACTED] about [REDACTED]",
    }
    decide(
        activate("pii"),
        context(point, target="A harmless technical explanation"),
        "allow",
    )


@pytest.mark.parametrize(
    "target",
    [[], {}, {"content": []}],
)
def test_pii_allows_structured_targets_without_pattern_matches(target):
    decide(activate("pii"), context("output", target=target), "allow")


def test_pii_config_allows_business_email_while_still_blocking_ssn():
    cfg = config("pii")
    cfg["patterns"] = [cfg["patterns"][0]]
    policy = activate("pii", config=cfg)
    decide(policy, context("output", target="a@example.com"), "allow")
    decide(policy, context("output", target="123-45-6789"), "deny", "pii_detected")


@pytest.mark.parametrize("action", ["deny", "redact"])
@pytest.mark.parametrize(
    "other",
    [
        {"attachment": "a@example.com"},
        {"tool_calls": [{"args": {"email": "a@example.com"}}]},
        {"role": "a@example.com"},
        {"a@example.com": "address in a property name"},
    ],
)
def test_pii_other_fields_are_checked_and_not_partially_redacted(action, other):
    policy = activate("pii", config={**config("pii"), "action": action})
    decide(
        policy,
        context("output", target={"content": "hello", **other}),
        "deny",
        "pii_detected" if action == "deny" else "pii_unredactable_fields",
    )


@pytest.mark.parametrize("action", ["deny", "redact"])
def test_pii_canonical_model_response_remains_usable(action):
    policy = activate("pii", config={**config("pii"), "action": action})
    ctx = context("post_model_call")
    decide(policy, ctx, "allow")
    ctx["target"]["tool_calls"] = [
        {"id": "c", "name": "search", "args": {"q": "hello"}}
    ]
    decide(policy, ctx, "allow")
    ctx["target"]["content"] = "Email a@example.com"
    if action == "deny":
        decide(policy, ctx, "deny", "pii_detected")
    else:
        outcome = asyncio.run(composed(policy).emit(ctx))
        assert outcome.target["content"] == "Email [REDACTED]"
        assert outcome.target["tool_calls"] == [
            {"id": "c", "name": "search", "args": {"q": "hello"}}
        ]
        assert outcome.target["finish_reason"] == "stop"


@pytest.mark.parametrize(
    "tool,roles,decision,reason",
    [
        ("search", ["reader"], "allow", None),
        ("send_email", ["reader"], "deny", "tool_permission_denied"),
        ("send_email", ["operator"], "allow", None),
        ("delete_record", ["administrator"], "allow", None),
        ("search", [], "deny", "tool_permission_denied"),
        ("shell", ["administrator"], "deny", "runtime_error:tool_unknown"),
    ],
)
def test_tool_permissions(tool, roles, decision, reason):
    decide(
        activate("tool-permissions"),
        context(tool=tool, host={"subject": "alice", "roles": roles}),
        decision,
        reason,
    )


@pytest.mark.parametrize(
    "host",
    [{}, {"subject": "a"}, {"roles": ["reader"]}, {"subject": "a", "roles": "reader"}],
)
def test_tool_permissions_missing_or_malformed_identity(host):
    decide(
        activate("tool-permissions"),
        context(host=host),
        "deny",
        "tool_permissions_data_invalid",
    )


def test_agent_claimed_permissions_do_not_authorize():
    decide(
        activate("tool-permissions"),
        context(
            tool="send_email", target={"roles": ["administrator"], "subject": "alice"}
        ),
        "deny",
        "tool_permissions_data_invalid",
    )


@pytest.mark.parametrize(
    "origin,method,credentials,expected",
    [
        ("https://api.example.com:443", "GET", False, "allow"),
        ("https://api.example.com:443", "HEAD", False, "allow"),
        ("https://api.example.com:443", "POST", False, "deny"),
        ("https://api.example.com.evil.test:443", "GET", False, "deny"),
        ("https://api.example.com@evil.test:443", "GET", False, "deny"),
        ("https://api.example.com:444", "GET", False, "deny"),
        ("http://api.example.com:80", "GET", False, "deny"),
        ("https://api.example.com:443", "GET", True, "deny"),
    ],
)
def test_destinations(origin, method, credentials, expected):
    host = {
        "destination": {
            "origin": origin,
            "method": method,
            "has_credentials": credentials,
        }
    }
    decide(activate("destinations"), context(host=host), expected)


@pytest.mark.parametrize(
    "destination",
    [{}, {"origin": "https://api.example.com:443", "method": "GET"}, {"origin": 42}],
)
def test_destination_metadata_missing(destination):
    decide(
        activate("destinations"),
        context(host={"destination": destination}),
        "deny",
        "destination_data_invalid",
    )


@pytest.mark.parametrize(
    "tool,amount,expected,approval",
    [
        ("search", 0, "allow", False),
        ("send_email", 0, "deny", True),
        ("delete_record", 0, "deny", True),
        ("issue_refund", 10000, "allow", False),
        ("issue_refund", 10001, "deny", True),
        ("issue_refund", -1, "deny", False),
        ("issue_refund", True, "deny", False),
        ("issue_refund", "100", "deny", False),
        ("issue_refund", 0.1, "deny", False),
        ("unknown", 0, "deny", False),
    ],
)
def test_approval_boundaries(tool, amount, expected, approval):
    cfg = config("human-approval")
    cfg["tools"]["issue_refund"] = {
        "mode": "threshold",
        "argument_path": ["amount_minor"],
        "max_without_approval": 10000,
    }
    verdict = decide(
        activate("human-approval", config=cfg),
        context(tool=tool, target={"amount_minor": amount, "approved": True}),
        expected,
    )
    assert (verdict.approval is not None) == approval


def test_refund_missing_amount_is_not_approvable():
    cfg = {
        "tools": {
            "issue_refund": {
                "mode": "threshold",
                "argument_path": ["amount_minor"],
                "max_without_approval": 10000,
            }
        }
    }
    verdict = decide(
        activate("human-approval", config=cfg),
        context(tool="issue_refund"),
        "deny",
        "approval_argument_invalid",
    )
    assert verdict.approval is None


def budget_host():
    return {
        "budget": {
            "used": dict.fromkeys(METRICS, 0),
            "reserved": dict.fromkeys(METRICS, 0),
        }
    }


@pytest.mark.parametrize("metric", METRICS)
@pytest.mark.parametrize("point", ["pre_model_call", "pre_tool_call"])
def test_budget_reservations_and_exact_limit(metric, point):
    policy = activate("budgets")
    limit = config("budgets")["limits"][metric]
    host = budget_host()
    host["budget"]["used"][metric] = limit - 1
    host["budget"]["reserved"][metric] = 1
    decide(policy, context(point, host=host), "allow")
    host["budget"]["reserved"][metric] = 2
    decide(policy, context(point, host=host), "deny", "budget_exceeded")


@pytest.mark.parametrize("bad", [None, True, -1, "0", 0.5, {}, []])
@pytest.mark.parametrize("field", ["used", "reserved"])
def test_budget_bad_or_missing_counters(bad, field):
    host = budget_host()
    host["budget"][field]["tokens"] = bad
    decide(activate("budgets"), context(host=host), "deny", "budget_data_invalid")
    del host["budget"][field]["tokens"]
    decide(activate("budgets"), context(host=host), "deny", "budget_data_invalid")


@pytest.mark.parametrize(
    "labels,tool,expected",
    [
        (["public"], "send_email", "allow"),
        (["public", "confidential"], "archive", "allow"),
        (["confidential"], "send_email", "deny"),
        (["secret"], "archive", "deny"),
        ([], "archive", "deny"),
        (["public", "unknown"], "archive", "deny"),
        ("public", "archive", "deny"),
        (None, "archive", "deny"),
    ],
)
def test_information_flow(labels, tool, expected):
    verdict = decide(
        activate("information-flow"),
        context(tool=tool, host={"source_labels": labels}),
        expected,
    )
    if expected == "allow":
        assert verdict.to_wire()["result_labels"] == [labels[-1]]
    else:
        assert not verdict.to_wire().get("result_labels")


@pytest.mark.parametrize("point", ["pre_model_call", "output"])
def test_information_flow_other_sinks_and_host_propagation(point):
    policy = activate("information-flow")
    verdict = decide(
        policy,
        context(tool="archive", host={"source_labels": ["public", "confidential"]}),
        "allow",
    )
    decide(
        policy,
        context(point, host={"source_labels": verdict.to_wire()["result_labels"]}),
        "deny",
        "ifc_data_invalid",
    )
    decide(policy, context(point, host={"source_labels": ["public"]}), "allow")


def test_model_route_exact_tuple():
    policy = activate("model-routing")
    route = config("model-routing")["routes"][0]
    decide(policy, context("pre_model_call", host={"model_route": route}), "allow")
    for key in route:
        changed = {**route, key: "unapproved"}
        decide(
            policy,
            context("pre_model_call", host={"model_route": changed}),
            "deny",
            "model_route_denied",
        )
        missing = {k: v for k, v in route.items() if k != key}
        decide(
            policy,
            context("pre_model_call", host={"model_route": missing}),
            "deny",
            "model_route_data_invalid",
        )


def test_tool_integrity_requires_pinning_and_actual_digest():
    cfg = {"sha256": {"search": HASH}}
    policy = activate("tool-integrity", config=cfg)
    decide(
        activate("tool-integrity"),
        context(host={"tool_sha256": HASH}),
        "deny",
        "tool_integrity_data_invalid",
    )
    decide(policy, context(host={"tool_sha256": HASH}), "allow")
    decide(
        policy,
        context(host={"tool_sha256": "b" * 64}),
        "deny",
        "tool_integrity_mismatch",
    )
    decide(
        policy,
        context(tool="shell", host={"tool_sha256": HASH}),
        "deny",
        "tool_integrity_mismatch",
    )
    for bad in (None, 42, "a" * 63, "A" * 64):
        decide(
            policy,
            context(host={"tool_sha256": bad}),
            "deny",
            "tool_integrity_data_invalid",
        )


def resource_host():
    return {
        "subject": "alice",
        "tenant": "tenant-a",
        "resource": {
            "id": "record-42",
            "tenant": "tenant-a",
            "operation": "read",
            "allowed_subjects": ["alice"],
        },
    }


def test_resource_access_subject_tenant_operation_and_missing_data():
    policy = activate("resource-access")
    host = resource_host()
    decide(policy, context(host=host), "allow")
    for key, value in [("tenant", "tenant-b"), ("subject", "bob")]:
        decide(
            policy, context(host={**host, key: value}), "deny", "resource_access_denied"
        )
    for key, value in [("operation", "write"), ("allowed_subjects", [])]:
        changed = copy.deepcopy(host)
        changed["resource"][key] = value
        decide(policy, context(host=changed), "deny", "resource_access_denied")
    for key in host["resource"]:
        changed = copy.deepcopy(host)
        del changed["resource"][key]
        decide(policy, context(host=changed), "deny", "resource_access_data_invalid")


@pytest.mark.parametrize(
    "name",
    [
        "tool-permissions",
        "destinations",
        "budgets",
        "information-flow",
        "model-routing",
        "tool-integrity",
        "resource-access",
    ],
)
@pytest.mark.parametrize("host", [None, {}, [], "trusted", True])
def test_host_dependent_packs_fail_closed_without_trusted_metadata(name, host):
    policy = activate(name)
    for point in policy.intervention_points:
        ctx = context(point, host=host, tool="send_email")
        decide(policy, ctx, "deny")


@pytest.mark.parametrize("name", [n for n in NAMES if n != "tool-permissions"])
def test_empty_configuration_fails_closed(name):
    annotation = {
        "score": 0,
        "scores": dict.fromkeys(["hate", "self_harm", "sexual", "violence"], 0),
    }
    policy = activate(name, config={}, annotation=annotation)
    _, valid_context = passing_case(name)
    for point in policy.intervention_points:
        if name == "information-flow" and point == "pre_tool_call":
            # Tool clearance comes from the catalog, not config.json.
            continue
        ctx = copy.deepcopy(valid_context)
        ctx["interception_point"] = point
        decide(policy, ctx, "deny")


class PolicyInterceptor:
    """Test the ActivatedPolicy interface through the real agent-hooks host."""

    def __init__(self, policy):
        self.policy = policy

    def intercept(self, ctx):
        return self.policy.evaluate(ctx["interception_point"], ctx)


def composed(*policies):
    emitter = InterceptionEmitter(
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL)
    )
    for policy in policies:
        emitter.register(PolicyInterceptor(policy))
    return emitter


@pytest.mark.parametrize("name", NAMES)
def test_every_pack_composes_with_a_credential_hard_deny(name):
    policy = activate(
        name,
        annotation={
            "score": 0,
            "scores": dict.fromkeys(["hate", "self_harm", "sexual", "violence"], 0),
        },
    )
    shared = set(policy.intervention_points) & set(
        activate("credentials").intervention_points
    )
    point = min(shared)
    ctx = context(
        point,
        tool="send_email",
        target={"content": "TOKEN=synthetic-value"},
        host={"subject": "alice", "roles": ["operator"], "source_labels": ["public"]},
    )
    record = asyncio.run(composed(policy, activate("credentials")).emit_unchecked(ctx))
    assert not record.proceeds
    assert any(v.reason == "credential_detected" for v in record.verdicts)


def test_plain_deny_beats_approval_without_resolver():
    ctx = context(tool="send_email", host={"subject": "alice", "roles": ["reader"]})
    record = asyncio.run(
        composed(
            activate("human-approval"), activate("tool-permissions")
        ).emit_unchecked(ctx)
    )
    assert not record.proceeds


def test_pii_transform_then_credentials_checks_effective_target():
    cfg = {**config("pii"), "action": "redact"}
    emitter = composed(activate("pii", config=cfg), activate("credentials"))
    ctx = context("output", target={"content": "Email a@example.com"})
    outcome = asyncio.run(emitter.emit(ctx))
    assert outcome.target == {"content": "Email [REDACTED]"}
    blocked = context(
        "output", target={"content": "Email a@example.com TOKEN=synthetic-value"}
    )
    assert not asyncio.run(emitter.emit_unchecked(blocked)).proceeds


def test_native_interceptor_loads_the_same_disk_pack():
    interceptor = AcsInterceptor(str(ROOT / "credentials" / "manifest.yaml"))
    verdict = interceptor.intercept(
        context("output", target={"content": "TOKEN=synthetic-value"})
    )
    assert verdict.reason == "credential_detected"


class Approver:
    def __init__(self, identity_matches=True):
        self.calls = 0
        self.identity_matches = identity_matches

    def resolve(self, request):
        self.calls += 1
        return ApprovalResolution(
            ApprovalOutcome.APPROVE,
            request.context_identity if self.identity_matches else "wrong-identity",
            Verdict.allow(),
        )


@pytest.mark.parametrize("identity_matches", [True, False])
def test_approval_requires_identity_bound_host_resolution(identity_matches):
    resolver = Approver(identity_matches)
    emitter = InterceptionEmitter(
        resolver=resolver,
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL),
    )
    emitter.register(PolicyInterceptor(activate("human-approval")))
    record = asyncio.run(emitter.emit_unchecked(context(tool="send_email")))
    assert resolver.calls == 1
    assert record.proceeds == identity_matches


@pytest.mark.parametrize("approval_first", [True, False])
def test_approver_cannot_lift_other_pack_hard_deny(approval_first):
    resolver = Approver()
    emitter = InterceptionEmitter(
        resolver=resolver,
        composition=CompositionConfig(profile=CompositionProfile.SEQUENTIAL_RUN_ALL),
    )
    names = ["human-approval", "tool-permissions"]
    for name in names if approval_first else reversed(names):
        emitter.register(PolicyInterceptor(activate(name)))
    denied = context(tool="send_email", host={"subject": "alice", "roles": ["reader"]})
    record = asyncio.run(emitter.emit_unchecked(denied))
    assert not record.proceeds
    assert any(v.reason == "tool_permission_denied" for v in record.verdicts)


def passing_case(name):
    point, tool, target, host, cfg, annotation = (
        "pre_tool_call",
        "search",
        {},
        {},
        None,
        None,
    )
    if name == "content-safety":
        point = "output"
        annotation = {"scores": dict.fromkeys(config(name)["thresholds"], 0)}
    elif name == "prompt-injection":
        point = "post_tool_call"
        annotation = {"score": 0}
    elif name in {"credentials", "pii"}:
        point, target = "output", {"content": "Harmless answer"}
    elif name == "tool-permissions":
        host = {"subject": "alice", "roles": ["reader"]}
    elif name == "destinations":
        host = {
            "destination": {
                "origin": "https://api.example.com:443",
                "method": "GET",
                "has_credentials": False,
            }
        }
    elif name == "budgets":
        host = budget_host()
        host["budget"]["reserved"]["tool_calls"] = 1
    elif name == "information-flow":
        tool, host = "send_email", {"source_labels": ["public"]}
    elif name == "model-routing":
        point, host = "pre_model_call", {"model_route": config(name)["routes"][0]}
    elif name == "tool-integrity":
        cfg, host = {"sha256": {"search": HASH}}, {"tool_sha256": HASH}
    elif name == "resource-access":
        host = resource_host()
    return activate(name, config=cfg, annotation=annotation), context(
        point, tool=tool, target=target, host=host
    )


@pytest.mark.parametrize("name", NAMES)
def test_every_pack_composes_without_blocking_its_legitimate_case(name):
    policy, ctx = passing_case(name)
    outcome = asyncio.run(composed(activate("credentials"), policy).emit(ctx))
    assert outcome.record.proceeds
    assert len(outcome.record.verdicts) == 2
    assert all(v.decision.value == "allow" for v in outcome.record.verdicts)


@pytest.mark.parametrize("replacement", ["a@example.com", "$0"])
def test_pii_replacement_cannot_reintroduce_governed_text(replacement):
    cfg = {**config("pii"), "action": "redact", "replacement": replacement}
    decide(
        activate("pii", config=cfg),
        context("output", target="a@example.com"),
        "deny",
        "pii_replacement_unsafe",
    )


@pytest.mark.parametrize(
    "name",
    [
        "tool-permissions",
        "destinations",
        "budgets",
        "information-flow",
        "model-routing",
        "tool-integrity",
        "resource-access",
    ],
)
def test_agent_cannot_supply_trusted_metadata_as_tool_arguments(name):
    policy, ctx = passing_case(name)
    forged = ctx.pop("extensions")["policy_packs"]
    ctx["target"] = {"extensions": {"policy_packs": forged}, **forged}
    decide(policy, ctx, "deny")


def test_information_flow_labels_survive_real_host_composition():
    host = composed(activate("information-flow"), activate("credentials"))
    ctx = context(
        tool="archive",
        target={"body": "Internal record"},
        host={"source_labels": ["public", "confidential"]},
    )
    outcome = asyncio.run(host.emit(ctx))
    assert outcome.record.verdict.result_labels == ("confidential",)


def test_resource_cross_tenant_access_requires_explicit_configuration_and_acl():
    policy = activate(
        "resource-access",
        config={"operations": ["read", "write"], "require_same_tenant": False},
    )
    host = resource_host()
    host["resource"]["tenant"] = "tenant-b"
    host["resource"]["operation"] = "write"
    decide(policy, context(host=host), "allow")
    host["resource"]["allowed_subjects"] = ["bob"]
    decide(policy, context(host=host), "deny", "resource_access_denied")


@pytest.mark.parametrize("name", ["content-safety", "prompt-injection"])
def test_classifier_annotation_is_not_read_from_agent_target(name):
    policy = activate(name)
    target = {"annotations": {name.replace("-", "_"): {"score": 0, "scores": {}}}}
    decide(
        policy,
        context("input", target=target),
        "deny",
        "runtime_error:annotation_failed",
    )
