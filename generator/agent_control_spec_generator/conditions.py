# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Inspect condition bodies with the same Regorus parser used by ACS."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .text import is_control


class ConditionError(ValueError):
    """A condition cannot be checked within the supported authoring subset."""


def condition_source(conditions: tuple[str, ...]) -> str:
    """The exact bytes both inspection and rendering use, separated only by LF."""
    source = "\n".join(conditions)
    for char in source:
        if char != "\n" and is_control(char):
            raise ConditionError(
                f"condition contains forbidden character U+{ord(char):04X}"
            )
    for line in source.split("\n"):
        first = line.lstrip(" ")
        if not first or first.startswith("#"):
            continue
        if first.startswith("-"):
            # Regorus continues arithmetic across LF. Otherwise this unary
            # expression can attach to the renderer's preceding point guard.
            raise ConditionError(
                "condition body cannot start with '-'; write '0 - ...' explicitly"
            )
        break
    return source


def require_regorus_ast() -> Callable[[str], list[dict[str, Any]]]:
    try:
        from agent_control_spec.authoring import REGORUS_AST_VERSION, parse_rego_ast
    except (ImportError, AttributeError):
        raise RuntimeError(
            "this generator requires the authoring-enabled ACS SDK; install SDK and "
            "generator from the same checkout"
        ) from None

    if REGORUS_AST_VERSION != "0.12.0" or not callable(parse_rego_ast):
        raise RuntimeError(
            "this generator requires ACS's Regorus 0.12.0 authoring support; "
            "install the SDK and generator from the same checkout with "
            "'python -m pip install ./sdk/python ./generator'"
        )
    return parse_rego_ast


@lru_cache(maxsize=128)
def _parse(body: str) -> dict[str, Any]:
    source = (
        f"package acs_generator_conditions\nimport rego.v1\ncheck if {{\n{body}\n}}\n"
    )
    parser = require_regorus_ast()
    try:
        policies = parser(source)
    except ValueError as exc:
        raise ConditionError("invalid Rego conditions: " + str(exc)[:2000]) from exc
    if len(policies) != 1 or policies[0].get("version") != 1:
        raise ConditionError("unsupported Regorus AST envelope")
    document = policies[0]["ast"]
    rules = document.get("rules", [])
    imports = document.get("imports", [])
    if (
        _ref(_expression(document["package"]["refr"])) != ("acs_generator_conditions",)
        or not document.get("rego_v1")
        or len(imports) != 1
        or "as" in imports[0]
        or _ref(_expression(imports[0]["refr"])) != ("rego", "v1")
        or len(rules) != 1
    ):
        raise ConditionError("conditions must be a rule body, not additional rules")
    rule = rules[0].get("Spec", {})
    head = rule.get("head", {}).get("Compr", {})
    bodies = rule.get("bodies", [])
    if (
        not head
        or head.get("assign") is not None
        or _ref(_expression(head["refr"])) != ("check",)
        or len(bodies) != 1
        or bodies[0].get("assign") is not None
        or bodies[0].get("is_else")
    ):
        raise ConditionError("conditions must be a rule body, not additional rules")
    return {"body": [_statement(stmt) for stmt in bodies[0]["query"]["stmts"]]}


_OPERATORS = {
    "AssignExpr": {"ColEq": "assign", "Eq": "eq"},
    "BoolExpr": {
        "Eq": "equal",
        "Ne": "neq",
        "Lt": "lt",
        "Le": "lte",
        "Gt": "gt",
        "Ge": "gte",
    },
    "ArithExpr": {
        "Add": "plus",
        "Sub": "minus",
        "Mul": "mul",
        "Div": "div",
        "Mod": "rem",
    },
    "BinExpr": {"Intersection": "and", "Union": "or"},
}
_SCALARS = {
    "Var": "var",
    "String": "string",
    "RawString": "string",
    "Number": "number",
    "Bool": "boolean",
    "Null": "null",
}


def _call(name: str, args: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "call", "value": [{"type": "var", "value": name}, *args]}


def _membership(value: dict[str, Any]) -> dict[str, Any]:
    args = [_expression(value["value"]), _expression(value["collection"])]
    if value["key"] is not None:
        args.insert(0, _expression(value["key"]))
    return _call(f"internal.member_{len(args)}", args)


def _statement(stmt: dict[str, Any]) -> dict[str, Any]:
    if stmt.get("with_mods"):
        raise ConditionError(
            "conditions must not replace input or builtins with 'with'"
        )
    kind, value = next(iter(stmt["literal"].items()))
    if kind in {"Expr", "NotExpr"}:
        return {"terms": _expression(value["expr"]), "negated": kind == "NotExpr"}
    if kind == "SomeIn":
        return {"terms": _membership(value), "iteration": True}
    if kind == "SomeVars":
        return {"terms": {"symbols": []}}
    if kind == "Every":
        raise ConditionError(
            "nested condition scopes are not supported; use top-level some"
        )
    raise ConditionError(f"unsupported Regorus statement '{kind}'")


def _expression(expr: dict[str, Any]) -> dict[str, Any]:
    """Normalize parsed expressions for the existing dependency checks.

    This is not a parser or an OPA AST emulator. Only Regorus variants handled
    explicitly here enter the inspection representation; unknown variants fail.
    """
    if len(expr) != 1:
        raise ConditionError("unsupported Regorus expression shape")
    kind, value = next(iter(expr.items()))
    if kind in _SCALARS:
        term = {"type": _SCALARS[kind], "value": value["value"]}
        if kind == "Var" and value["value"] in {"input", "data"}:
            return {"type": "ref", "value": [term]}
        return term
    if kind in {"Array", "Set"}:
        return {
            "type": kind.lower(),
            "value": [_expression(item) for item in value["items"]],
        }
    if kind == "Object":
        return {
            "type": "object",
            "value": [
                [_expression(key), _expression(item)]
                for _span, key, item in value["fields"]
            ],
        }
    if kind in {"ArrayCompr", "SetCompr", "ObjectCompr"}:
        raise ConditionError(
            "nested condition scopes are not supported; use top-level some"
        )
    if kind in {"RefDot", "RefBrack"}:
        base = _expression(value["refr"])
        parts = base["value"] if base["type"] == "ref" else [base]
        index = (
            _expression(value["index"])
            if kind == "RefBrack"
            else {"type": "string", "value": value["field"][1]}
        )
        return {"type": "ref", "value": [*parts, index]}
    if kind == "Call":
        return {
            "type": "call",
            "value": [
                _expression(value["fcn"]),
                *(_expression(arg) for arg in value["params"]),
            ],
        }
    if kind in _OPERATORS:
        operator = _OPERATORS[kind].get(value["op"])
        if operator is None:
            raise ConditionError(f"unsupported Regorus operator '{value['op']}'")
        return _call(operator, [_expression(value["lhs"]), _expression(value["rhs"])])
    if kind == "Membership":
        return _membership(value)
    if kind == "UnaryExpr":
        # Regorus represents unary numeric negation explicitly, including on
        # variables. Preserve the operand so nested references/calls are checked.
        return _call(
            "minus", [{"type": "number", "value": 0}, _expression(value["expr"])]
        )
    raise ConditionError(f"unsupported Regorus expression '{kind}'")


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _ref(term: dict[str, Any]) -> tuple[Any, ...]:
    if term.get("type") == "var":
        return (term["value"],)
    if term.get("type") != "ref":
        return ()
    return tuple(
        part["value"]
        if part.get("type") in {"string", "number"}
        or index == 0
        and part.get("type") == "var"
        else None
        for index, part in enumerate(term["value"])
    )


def _calls(node: Any) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    for entry in _walk(node):
        terms = entry.get("terms")
        if entry.get("type") == "call":
            terms = entry["value"]
        if isinstance(terms, list) and terms:
            ref = _ref(terms[0])
            if not ref or not all(isinstance(part, str) for part in ref):
                raise ConditionError("dynamic function calls are not supported")
            yield ".".join(ref), terms[1:]


@dataclass(frozen=True)
class ConditionInfo:
    patterns: tuple[str, ...]
    annotators: frozenset[str]
    tools: frozenset[str]
    uses_tool: bool
    warnings: tuple[str, ...] = ()


# Keep authoring evaluation free of network, host/environment introspection,
# clocks, random values and diagnostic output. Unknown functions require review.
_CALLS = frozenset(
    [
        "assign",
        "eq",
        "equal",
        "neq",
        "gt",
        "gte",
        "lt",
        "lte",
        "plus",
        "minus",
        "mul",
        "div",
        "rem",
        "and",
        "or",
        "xor",
        "internal.member_2",
        "internal.member_3",
        "contains",
        "startswith",
        "endswith",
        "lower",
        "upper",
        "trim",
        "trim_space",
        "trim_prefix",
        "trim_suffix",
        "split",
        "concat",
        "substring",
        "replace",
        "sprintf",
        "count",
        "sum",
        "max",
        "min",
        "sort",
        "is_string",
        "is_number",
        "is_boolean",
        "is_array",
        "is_object",
        "is_set",
        "is_null",
        "object.get",
        "object.keys",
        "object.values",
        "object.union",
        "object.remove",
        "object.filter",
        "array.concat",
        "array.slice",
        "array.reverse",
        "regex.match",
        "regex.replace",
        "regex.split",
        "regex.find_n",
        "regex.find_all_string_submatch_n",
        "regex.is_valid",
        "to_number",
        "to_string",
        "json.marshal",
        "json.unmarshal",
    ]
)
_REGEX_ARGS = {
    "regex.match": 0,
    "regex.split": 0,
    "regex.find_n": 0,
    "regex.find_all_string_submatch_n": 0,
    "regex.replace": 1,
}
_ROOTS = {"intervention_point", "policy_target", "snapshot", "annotations", "tool"}
_OBJECT_MEMBERS = {
    "agent_startup": {"tools_registered"},
    "input": {"content", "role"},
    "post_model_call": {"content", "tool_calls", "finish_reason"},
    "output": {"content"},
    "agent_shutdown": {"reason"},
}


def inspect_conditions(conditions: tuple[str, ...], point: str) -> ConditionInfo:
    if not conditions:
        return ConditionInfo((), frozenset(), frozenset(), False)
    tree = _parse(condition_source(conditions))
    nodes = list(_walk(tree))
    # Literal/alias inference below is single-scope. Flattening bindings from
    # comprehensions or every blocks would let a local literal certify an
    # unrelated request-controlled variable with the same name.
    if any(
        node.get("type")
        in {
            "arraycomprehension",
            "setcomprehension",
            "objectcomprehension",
        }
        or "domain" in node
        for node in nodes
    ):
        raise ConditionError(
            "nested condition scopes are not supported; use top-level some statements "
            "instead of comprehensions or every blocks"
        )
    calls = list(_calls(tree))
    if any(
        _ref(expr.get("terms", {})) == ("input",)
        for expr in tree["body"]
        if isinstance(expr.get("terms"), dict)
    ):
        raise ConditionError(
            "bare input selects every request; use a request-specific condition"
        )
    if any("with" in node for node in nodes):
        raise ConditionError(
            "conditions must not replace input or builtins with 'with'"
        )
    for name, _ in calls:
        if name not in _CALLS:
            raise ConditionError(f"unsupported condition function '{name}'")

    bindings: dict[str, list[dict[str, Any]]] = {}
    for name, args in calls:
        if name in {"assign", "eq"} and len(args) == 2:
            left, right = args
            if left.get("type") == "var":
                bindings.setdefault(left["value"], []).append(right)
            if name == "eq" and right.get("type") == "var":
                bindings.setdefault(right["value"], []).append(left)
        if (
            name == "internal.member_2"
            and len(args) >= 2
            and args[0].get("type") == "var"
            and args[1].get("type") in {"array", "set"}
        ):
            bindings.setdefault(args[0]["value"], []).extend(args[1]["value"])

    def literals(term: dict[str, Any], seen: tuple[str, ...] = ()) -> list[str]:
        if term.get("type") == "string":
            return [term["value"]]
        ref = _ref(term)
        if len(ref) == 1 and ref[0] in bindings and ref[0] not in seen:
            values = [literals(value, (*seen, ref[0])) for value in bindings[ref[0]]]
            if values and all(values):
                return [literal for value in values for literal in value]
        return []

    def resolved(term: dict[str, Any], seen: tuple[str, ...] = ()) -> tuple[Any, ...]:
        ref = _ref(term)
        if not ref:
            return ()
        if ref[0] in bindings and ref[0] not in seen:
            candidates = {
                resolved(value, (*seen, ref[0])) for value in bindings[ref[0]]
            }
            candidates.discard(())
            if len(candidates) > 1:
                raise ConditionError(
                    "ambiguous input aliases; use direct input references"
                )
            if candidates:
                return (*next(iter(candidates)), *ref[1:])
        return ref

    patterns: list[str] = []
    annotators: set[str] = set()
    tools: set[str] = set()
    references = [resolved(node) for node in nodes if node.get("type") == "ref"]
    # object.get is also an input read; resolve its literal key before checking
    # the five-member policy input and discovering annotation dependencies.
    for name, args in calls:
        if name == "object.get" and len(args) == 3:
            root = resolved(args[0])
            keys = literals(args[1])
            if root and root[0] == "input":
                if root in {("input",), ("input", "annotations")} and not keys:
                    raise ConditionError(
                        "object.get needs a literal key at the input/annotation root"
                    )
                references.extend((*root, key) for key in keys)
        if name in _REGEX_ARGS:
            index = _REGEX_ARGS[name]
            values = literals(args[index]) if len(args) > index else []
            if not values:
                raise ConditionError(
                    "regex patterns must be literals or variables bound to literal strings; "
                    "computed patterns cannot be validated"
                )
            patterns.extend(values)
        if name in {"eq", "equal", "internal.member_2"} and len(args) == 2:
            for left, right in (args, list(reversed(args))):
                if resolved(left) in {
                    ("input", "tool", "id"),
                    ("input", "tool", "name"),
                }:
                    if right.get("type") in {"array", "set"}:
                        tools.update(
                            v for item in right["value"] for v in literals(item)
                        )
                    else:
                        tools.update(literals(right))

    uses_input = False
    uses_tool = False
    for ref in references:
        if not ref:
            continue
        if ref[0] == "data":
            raise ConditionError(
                "external data references are not supported in generated conditions"
            )
        if ref[0] != "input":
            continue
        uses_input = True
        if len(ref) > 1 and ref[1] not in _ROOTS:
            raise ConditionError(f"unknown or removed policy-input member {ref[1]!r}")
        if len(ref) > 1 and ref[1] == "tool":
            uses_tool = True
            if point not in {"pre_tool_call", "post_tool_call"}:
                raise ConditionError(f"input.tool is null at '{point}'")
        if len(ref) > 2 and ref[1] == "annotations":
            if not isinstance(ref[2], str):
                raise ConditionError(
                    "annotation names must be literal; use input.annotations.name"
                )
            annotators.add(ref[2])
        if (
            ref[:2] == ("input", "policy_target")
            and len(ref) > 2
            and ref[2] not in {"value", "kind", "path"}
        ):
            raise ConditionError(f"unknown policy_target member {ref[2]!r}")
        if ref[:3] == ("input", "policy_target", "value") and len(ref) > 3:
            if point == "pre_model_call" and isinstance(ref[3], str):
                raise ConditionError(
                    "pre_model_call target is an array; iterate over messages"
                )
            members = _OBJECT_MEMBERS.get(point)
            if members is not None and ref[3] not in members:
                raise ConditionError(
                    f"unsupported target member {ref[3]!r} at '{point}'"
                )
    if ("input", "annotations") in references and not annotators:
        raise ConditionError("annotation dependencies must name specific annotators")
    if not uses_input:
        raise ConditionError(
            "a constant body selects every request or none; conditions must read input"
        )
    iterations: list[tuple[Any, ...]] = []
    bound_variables = {
        args[0]["value"]
        for name, args in calls
        if name == "assign" and args and args[0].get("type") == "var"
    }
    for statement in tree["body"]:
        if statement.get("iteration"):
            args = statement["terms"]["value"][1:]
            iterations.append(resolved(args[-1]) or ("computed collection",))
            bound_variables.update(
                arg["value"] for arg in args[:-1] if arg.get("type") == "var"
            )

    def bound_index(term: dict[str, Any], seen: tuple[str, ...] = ()) -> bool:
        if term.get("type") != "var":
            # Any enumeration within a compound RHS is counted at its own ref.
            return True
        name = term["value"]
        if name == "_":
            return False
        if name in bound_variables:
            return True
        if name in seen:
            return False
        return any(bound_index(rhs, (*seen, name)) for rhs in bindings.get(name, []))

    seen_indices: set[str] = set()
    for node in nodes:
        if node.get("type") != "ref":
            continue
        parts = node["value"]
        for index, selector in enumerate(parts[1:], 1):
            if selector.get("type") != "var" or bound_index(selector):
                continue
            name = selector["value"]
            if name != "_" and name in seen_indices:
                continue
            # A wildcard is a fresh dimension on every occurrence; a named
            # unbound index enumerates once and subsequent uses join on it.
            collection = resolved({"type": "ref", "value": parts[:index]})
            iterations.append(collection or ("computed collection",))
            seen_indices.add(name)
    warnings = ()
    if len(iterations) > 1:
        collections = ", ".join(
            dict.fromkeys(
                ".".join("[*]" if part is None else str(part) for part in collection)
                for collection in iterations
            )
        )
        warnings = (
            (
                f"{len(iterations)} iteration clauses at {point} over {collections} "
                "can form a Cartesian product; test realistic input sizes"
            ),
        )
    return ConditionInfo(
        tuple(dict.fromkeys(patterns)),
        frozenset(annotators),
        frozenset(tools),
        uses_tool,
        warnings,
    )
