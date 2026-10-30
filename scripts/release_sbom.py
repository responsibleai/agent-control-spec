#!/usr/bin/env python3
# Copyright (c) Microsoft. All rights reserved.

"""Bind source/build inventories to release bytes; never claim exact linked contents."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
from urllib.parse import quote

ROOTS = {
    "rust": "agent-control-spec",
    "node": "agent-control-spec-node",
    "dotnet": "agent-control-spec-ffi",
}


def argv(command):
    value = command.get("argv") if isinstance(command, dict) else command
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError("Missing actual command argv")
    return value


def option(command, flag):
    values = argv(command)
    if values.count(flag) != 1 or values.index(flag) + 1 >= len(values):
        raise ValueError("Missing or ambiguous command option " + flag)
    return values[values.index(flag) + 1]


def metadata_binding(command, target):
    values = argv(command)
    if (
        len(values) < 2
        or values[1] != "metadata"
        or option(command, "--filter-platform") != target
        or not any(x in values for x in ("--locked", "--frozen"))
    ):
        raise ValueError("Metadata filter/locking receipt mismatch")


def build_binding(command, sdk, target):
    values = argv(command)
    if len(values) == 5 and values[1] == "-c" and values[3] == "sbom-node":
        tokens = shlex.split(values[2].replace("\\\n", " "))
        expected = [
            "exec",
            "npx",
            "napi",
            "build",
            "--release",
            "--platform",
            "--target",
            "$1",
            "--manifest-path",
            "native/Cargo.toml",
            "--cwd",
            ".",
            "--output-dir",
            ".",
            "--",
            "--message-format=json-render-diagnostics",
        ]
        if sdk != "node" or tokens != expected or values[4] != target:
            raise ValueError("Node command/target binding mismatch")
        return [ROOTS["node"]]
    if (
        len(values) < 2
        or values[1] != "build"
        or "--release" not in values
        or option(command, "--target") != target
    ):
        raise ValueError("Native command/target/release binding mismatch")
    if any(
        x in values
        for x in ("--features", "--no-default-features", "--all-features", "--profile")
    ):
        raise ValueError("Unsupported non-default root feature/profile command")
    roots = [
        values[i + 1] for i, x in enumerate(values[:-1]) if x in ("-p", "--package")
    ]
    if ROOTS[sdk] not in roots or not set(roots) <= {ROOTS["node"], ROOTS["dotnet"]}:
        raise ValueError("Native command package-root mismatch")
    return roots


def required_graph(metadata, root_names, host_metadata=None, overrides=None):
    """Resolve declared features/optional dependencies independently of compiler coverage.

    Metadata edges are platform-filtered; host build/proc-macro edges use
    separately filtered host metadata when the producer cross-compiles.
    Dev edges are excluded from native release builds. Cargo resolver-2
    host/target feature contexts are retained separately.
    """
    host_metadata = host_metadata or metadata
    packages = {p["id"]: p for p in metadata["packages"]}
    packages.update({p["id"]: p for p in host_metadata["packages"]})
    node_sets = {
        "target": {n["id"]: n for n in metadata["resolve"]["nodes"]},
        "host": {n["id"]: n for n in host_metadata["resolve"]["nodes"]},
    }
    required = {}
    for p in packages.values():
        if p["name"] in root_names:
            required[(p["id"], "target")] = (
                {"default"} if "default" in p["features"] else set()
            )
    if len(required) != len(set(root_names)):
        raise ValueError("Missing independent resolver roots")
    changed = True
    while changed:
        changed = False
        for (ident, role), requested in list(required.items()):
            p = packages[ident]
            if overrides:
                extra = overrides.get((ident, role), set())
                if not extra <= requested:
                    requested.update(extra)
                    changed = True
            nodes = node_sets[role]
            edges = nodes[ident]["deps"]
            eligible = []
            for dep in p["dependencies"]:
                if dep["kind"] == "dev":
                    continue
                alias = (dep.get("rename") or dep["name"]).replace("-", "_")
                edge = next(
                    (
                        edge
                        for edge in edges
                        if packages[edge["pkg"]]["name"] == dep["name"]
                        and (not dep.get("rename") or edge["name"] == alias)
                        and any(
                            k["kind"] == dep["kind"] and k["target"] == dep["target"]
                            for k in edge["dep_kinds"]
                        )
                    ),
                    None,
                )
                if edge:
                    eligible.append((dep, alias, edge["pkg"]))
            active = {alias for dep, alias, _ in eligible if not dep["optional"]}
            dep_features, local, weak = {}, set(), []
            todo = list(requested)
            while todo:
                feature = todo.pop()
                if feature in local:
                    continue
                if feature not in p["features"]:
                    raise ValueError(
                        "Unknown resolver feature " + p["name"] + "/" + feature
                    )
                local.add(feature)
                for token in p["features"][feature]:
                    if token.startswith("dep:"):
                        active.add(token[4:].replace("-", "_"))
                    elif "/" in token:
                        alias, child_feature = token.split("/", 1)
                        optional = alias.endswith("?")
                        implicit_feature = alias.rstrip("?")
                        alias = alias.rstrip("?").replace("-", "_")
                        if optional:
                            weak.append((alias, child_feature))
                        else:
                            active.add(alias)
                            if (
                                implicit_feature in p["features"]
                                and "dep:" + implicit_feature
                                in p["features"][implicit_feature]
                            ):
                                todo.append(implicit_feature)
                            dep_features.setdefault(alias, set()).add(child_feature)
                    else:
                        todo.append(token)
            for alias, feature in weak:
                if alias in active:
                    dep_features.setdefault(alias, set()).add(feature)
            if not local <= requested:
                requested.update(local)
                changed = True
            for dep, alias, child in eligible:
                if dep["optional"] and alias not in active:
                    continue
                child_package = packages[child]
                features = set(dep["features"]) | dep_features.get(alias, set())
                if (
                    dep["uses_default_features"]
                    and "default" in child_package["features"]
                ):
                    features.add("default")
                child_role = (
                    "host"
                    if (
                        role == "host"
                        or dep["kind"] == "build"
                        or any(
                            "proc-macro" in t["kind"] for t in child_package["targets"]
                        )
                    )
                    else "target"
                )
                key = (child, child_role)
                if key not in required:
                    required[key] = set()
                    changed = True
                if not features <= required[key]:
                    required[key].update(features)
                    changed = True
    return required


def normalized_parts(path):
    return str(path).replace("\\", "/").split("/")


def independent_inventory(context):
    evidence = context.get("resolver_evidence", {})
    metadata = evidence.get("metadata")
    if not metadata:
        raise ValueError("Missing independent resolver evidence")
    producer_root = context.get("producer_root")
    if not producer_root or normalized_parts(producer_root) != normalized_parts(
        metadata.get("workspace_root", "")
    ):
        raise ValueError("Resolver/producer source-root mismatch")
    if isinstance(evidence.get("command"), dict) and normalized_parts(
        evidence["command"].get("cwd", "")
    ) != normalized_parts(producer_root):
        raise ValueError("Metadata command source-root mismatch")
    metadata_binding(evidence.get("command"), context["target"])
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root_ids = [
        p["id"] for p in packages.values() if p["name"] == ROOTS[context["sdk"]]
    ]
    if len(root_ids) != 1 or packages[root_ids[0]]["version"] != context["version"]:
        raise ValueError("Independent resolver root/version mismatch")
    if context["sdk"] == "rust":
        seen, todo = set(), root_ids[:]
        while todo:
            ident = todo.pop()
            if ident in seen:
                continue
            seen.add(ident)
            todo.extend(d["pkg"] for d in nodes[ident]["deps"])
        return [
            {
                "name": packages[i]["name"],
                "version": packages[i]["version"],
                "source": packages[i]["source"],
                "features": nodes[i]["features"],
                "kinds": ["resolved-source-including-dev"],
                "scope": "resolved-source",
            }
            for i in sorted(seen)
        ]
    roots = build_binding(context["command"], context["sdk"], context["target"])
    host = evidence.get("host")
    if not host:
        raise ValueError("Missing compiler host identity")
    host_metadata = metadata
    if host != context["target"]:
        host_metadata = evidence.get("host_metadata")
        if not host_metadata:
            raise ValueError("Missing independent host-filtered resolver evidence")
        metadata_binding(evidence.get("host_command"), host)
        if normalized_parts(
            host_metadata.get("workspace_root", "")
        ) != normalized_parts(producer_root):
            raise ValueError("Host resolver source-root mismatch")
        for package in host_metadata["packages"]:
            if package["id"] in packages and any(
                packages[package["id"]][field] != package[field]
                for field in ("features", "dependencies", "version")
            ):
                raise ValueError("Host/target resolver manifest mismatch")
            packages[package["id"]] = package
    global_features = required_graph(metadata, roots, host_metadata)
    required = required_graph(
        metadata, [ROOTS[context["sdk"]]], host_metadata, global_features
    )
    records = context.get("compiler_evidence", [])
    if not any(
        m.get("reason") == "build-finished" and m.get("success") is True
        for m in records
    ):
        raise ValueError("Missing successful compiler evidence")
    selected = []
    for ident in sorted({ident for ident, _ in required}):
        p = packages[ident]
        contexts = []
        for (package_id, role), features in required.items():
            if package_id != ident:
                continue
            matching = []
            for message in records:
                if (
                    message.get("reason") != "compiler-artifact"
                    or message.get("package_id") != ident
                ):
                    continue
                if "custom-build" in message["target"]["kind"]:
                    continue
                actual_role = (
                    "target"
                    if any(
                        context["target"] in normalized_parts(f)
                        for f in message["filenames"]
                    )
                    else "host"
                )
                if actual_role != role:
                    continue
                actual_features = set(message["features"])
                if not actual_features <= p["features"].keys():
                    raise ValueError("Fabricated compiler features")
                if features == actual_features:
                    matching.append(message)
            if not matching:
                raise ValueError(
                    "Required compiler coverage/features absent: "
                    + p["name"]
                    + "/"
                    + role
                )
            contexts.extend(
                {
                    "role": role,
                    "features": m["features"],
                    "required_features": sorted(features),
                    "target_kind": m["target"]["kind"],
                    "profile": m["profile"],
                }
                for m in matching
            )
        selected.append(
            {
                "name": p["name"],
                "version": p["version"],
                "source": p["source"],
                "features": sorted({f for c in contexts for f in c["features"]}),
                "kinds": sorted({c["role"] for c in contexts}),
                "scope": "compiler-selected",
                "compiler_contexts": contexts,
                "dependency_edges": [
                    detail
                    for parent in nodes.values()
                    for dep in parent["deps"]
                    if dep["pkg"] == ident
                    for detail in dep["dep_kinds"]
                ],
            }
        )
    binding = context.get("binding_evidence", {})
    root_messages = [
        m
        for m in records
        if m.get("reason") == "compiler-artifact"
        and m.get("package_id") == root_ids[0]
        and "cdylib" in m["target"]["kind"]
        and m["profile"].get("opt_level") == "3"
        and not m["profile"].get("test")
    ]
    filename = binding.get("compiler_output", "")
    parts = normalized_parts(filename)
    if (
        not any(filename in m["filenames"] for m in root_messages)
        or context["target"] not in parts
        or "release" not in parts
        or binding.get("sha256") != context["artifact"]["sha256"]
    ):
        raise ValueError(
            "Native root compiler/target/profile/artifact binding mismatch"
        )
    logical = normalized_parts(context["artifact"]["path"])
    target = context["target"]
    rid = {
        "x86_64-unknown-linux-gnu": "linux-x64",
        "aarch64-unknown-linux-gnu": "linux-arm64",
        "x86_64-apple-darwin": "osx-x64",
        "aarch64-apple-darwin": "osx-arm64",
        "x86_64-pc-windows-msvc": "win-x64",
    }.get(target)
    local_layout = (
        len(logical) == 4
        and logical[:3] == ["target", target, "release"]
        and logical[-1] == parts[-1]
    )
    prefix = (
        "node-binding-" + target
        if context["sdk"] == "node"
        else "dotnet-native-" + str(rid)
    )
    transport_layout = len(logical) == 2 and logical[0] == prefix
    if not local_layout and not transport_layout:
        raise ValueError("Native per-target logical layout mismatch")
    return selected


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def purls(package):
    return [
        r["referenceLocator"]
        for r in package.get("externalRefs", [])
        if r.get("referenceType") == "purl"
    ]


def cargo_purl(name, version):
    return "pkg:cargo/" + quote(name, safe="") + "@" + quote(version, safe="")


def identities(report):
    return {
        (p.get("name"), p.get("versionInfo"), url)
        for p in report["packages"]
        for url in (purls(p) or [None])
    }


def structure(report):
    if not isinstance(report, dict) or report.get("spdxVersion") not in (
        "SPDX-2.2",
        "SPDX-2.3",
    ):
        raise ValueError("Malformed SPDX document")
    packages = report.get("packages")
    if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
        raise ValueError("Malformed SPDX packages")
    ids = [p.get("SPDXID") for p in packages]
    ids += [f.get("SPDXID") for f in report.get("files", [])]
    ids += [s.get("SPDXID") for s in report.get("snippets", [])]
    if None in ids or len(ids) != len(set(ids)):
        raise ValueError("Missing or duplicate SPDX IDs")
    allowed = set(ids) | {report.get("SPDXID"), "NONE", "NOASSERTION"}
    if not report.get("SPDXID"):
        raise ValueError("Missing document ID")
    for relation in report.get("relationships", []):
        if (
            relation.get("spdxElementId") not in allowed
            or relation.get("relatedSpdxElement") not in allowed
        ):
            raise ValueError("Dangling SPDX relationship")


def generate(baseline, source_inventory, provenances):
    structure(baseline)
    structure(source_inventory)
    output = copy.deepcopy(baseline)
    wanted = {
        cargo_purl(p["name"], p["version"])
        for ctx in provenances
        for p in ctx["packages"]
    }
    present = {url for p in output["packages"] for url in purls(p)}
    candidates = {}
    for package in source_inventory["packages"]:
        for url in purls(package):
            candidates.setdefault(url, package)
        # Syft omits purls for unpublished workspace entries. Their real
        # root-lock record and Cargo metadata still identify name/version.
        if package.get("sourceInfo", "").endswith(": /Cargo.lock"):
            url = cargo_purl(package["name"], package["versionInfo"])
            candidates.setdefault(url, package)
    missing = wanted - present - candidates.keys()
    if missing:
        raise ValueError(
            "Real scanner omitted required Cargo identities: " + str(sorted(missing))
        )
    used = {p["SPDXID"] for p in output["packages"]} | {
        f["SPDXID"] for f in output.get("files", [])
    }
    for url in sorted(wanted - present):
        package = copy.deepcopy(candidates[url])
        if url not in purls(package):
            package.setdefault("externalRefs", []).append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": url,
                }
            )
        # Copy package inventory, not unrelated scanner file references.
        for key in ("hasFiles", "packageVerificationCode"):
            package.pop(key, None)
        package["filesAnalyzed"] = False
        new_id = "SPDXRef-native-" + hashlib.sha256(url.encode()).hexdigest()
        if new_id in used:
            raise ValueError("SPDX native ID collision")
        used.add(new_id)
        package["SPDXID"] = new_id
        output["packages"].append(package)
        output.setdefault("relationships", []).append(
            {
                "spdxElementId": output["SPDXID"],
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": new_id,
            }
        )
    # Standard document annotation survives Syft SPDX round trips.
    output.setdefault("annotations", []).append(
        {
            "annotationType": "OTHER",
            "annotator": "Tool: agent-control-spec-release-sbom",
            "annotationDate": baseline.get("creationInfo", {}).get(
                "created", "1970-01-01T00:00:00Z"
            ),
            "comment": "ACS_RELEASE_PROVENANCE="
            + json.dumps(provenances, sort_keys=True, separators=(",", ":")),
        }
    )
    structure(output)
    return output


def verify(
    report,
    baseline,
    provenances,
    artifacts,
    *,
    source,
    lock,
    expected_sdk,
    targets,
    version,
):
    structure(report)
    structure(baseline)
    annotations = [a.get("comment", "") for a in report.get("annotations", [])]
    expected = "ACS_RELEASE_PROVENANCE=" + json.dumps(
        provenances, sort_keys=True, separators=(",", ":")
    )
    if expected not in annotations:
        raise ValueError("Missing or changed provenance annotation")
    if not identities(baseline) <= identities(report):
        raise ValueError("Baseline package identity loss")
    if {p.get("target") for p in provenances} != set(targets):
        raise ValueError("Missing or wrong target set")
    if len(provenances) != len(set(targets)) or len(
        {p["artifact"]["path"] for p in provenances}
    ) != len(provenances):
        raise ValueError("Duplicate producer target/artifact binding")
    present = identities(report)
    for ctx in provenances:
        if (
            ctx.get("schema") != 1
            or ctx.get("sdk") != expected_sdk
            or ctx.get("source") != source
            or ctx.get("lock_sha256") != lock
            or ctx.get("version") != version
            or ctx.get("profile") != "release"
            or not re.fullmatch(r"[0-9a-f]{40}", source)
            or not re.fullmatch(r"[0-9a-f]{64}", lock)
        ):
            raise ValueError("Provenance context mismatch")
        if ctx.get("packages") != independent_inventory(ctx):
            raise ValueError(
                "Sidecar inventory/features differ from independent resolver/compiler evidence"
            )
        artifact = ctx.get("artifact", {})
        sha = artifact.get("sha256")
        if (
            not isinstance(sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha)
            or sha == "0" * 64
        ):
            raise ValueError("Missing or zero artifact hash")
        path = Path(artifact.get("path", ""))
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("Invalid logical artifact path")
        candidate = (Path(artifacts) / path).resolve()
        if (
            not candidate.is_relative_to(Path(artifacts).resolve())
            or digest(candidate) != sha
        ):
            raise ValueError("Artifact byte mismatch")
        if not ctx.get("packages"):
            raise ValueError("No native identities")
        if ctx.get("root_package") != ROOTS[expected_sdk] or not any(
            p.get("name") == ROOTS[expected_sdk] and p.get("version") == version
            for p in ctx["packages"]
        ):
            raise ValueError("Wrong SDK package root")
        for package in ctx["packages"]:
            if not isinstance(package.get("features"), list) or not package.get(
                "kinds"
            ):
                raise ValueError("Missing native feature/dependency scope")
            identity = (
                package["name"],
                package["version"],
                cargo_purl(package["name"], package["version"]),
            )
            if identity not in present:
                raise ValueError("Missing or changed native identity: " + str(identity))


def check_conversion_inventory(original, converted):
    """Permit only Syft's known directory-root addition, never inventory repair."""
    before, after = identities(original), identities(converted)
    if before - after:
        raise ValueError("Converted inventory lost or changed original identities")

    def cargo(values):
        return {item for item in values if item[2] and item[2].startswith("pkg:cargo/")}

    if cargo(before) != cargo(after):
        raise ValueError("Converted Cargo identity mismatch")
    extra = after - before
    if not extra:
        return
    if extra != {("unknown", None, None)}:
        raise ValueError("Arbitrary converted package addition")
    roots = [
        p
        for p in converted["packages"]
        if p.get("name") == "unknown" and not p.get("versionInfo") and not purls(p)
    ]
    if len(roots) != 1:
        raise ValueError("Ambiguous converted source root")
    root = roots[0]
    if (
        root.get("SPDXID") != "SPDXRef-DocumentRoot-Directory-unknown"
        or root.get("primaryPackagePurpose") != "FILE"
        or root.get("filesAnalyzed") is not False
        or root.get("downloadLocation") != "NOASSERTION"
    ):
        raise ValueError("Unknown package is not the documented Syft source root")
    relations = converted.get("relationships", [])
    if not any(
        r.get("spdxElementId") == converted["SPDXID"]
        and r.get("relationshipType") == "DESCRIBES"
        and r.get("relatedSpdxElement") == root["SPDXID"]
        for r in relations
    ):
        raise ValueError("Missing converted document/source relationship")
    if not any(
        r.get("spdxElementId") == root["SPDXID"]
        and r.get("relationshipType") == "CONTAINS"
        for r in relations
    ):
        raise ValueError("Missing converted source contents")


def rebind_roundtrip(original, converted, baseline, contexts, artifacts, **expected):
    """Syft drops document annotations; rebind trusted context only after strict checks.

    Keep raw conversion unchanged. This does not repair missing packages or
    relationships: the converted inventory must independently pass verification.
    """
    verify(original, baseline, contexts, artifacts, **expected)
    check_conversion_inventory(original, converted)
    output = copy.deepcopy(converted)
    # Syft 1.54 SPDX encoding can emit a file's internal hash ID as a
    # relationship endpoint. Resolve only unique aliases for unchanged
    # named/checksummed files; refuse arbitrary missing references.
    originals = {
        (f.get("fileName"), json.dumps(f.get("checksums", []), sort_keys=True))
        for f in original.get("files", [])
    }
    aliases = {}
    for file in output.get("files", []):
        identity = (
            file.get("fileName"),
            json.dumps(file.get("checksums", []), sort_keys=True),
        )
        if identity not in originals:
            raise ValueError("Converted file identity mismatch")
        alias = "SPDXRef-" + file["SPDXID"].rsplit("-", 1)[-1]
        if alias in aliases:
            raise ValueError("Ambiguous converted file alias")
        aliases[alias] = file["SPDXID"]
    for relation in output.get("relationships", []):
        for key in ("spdxElementId", "relatedSpdxElement"):
            relation[key] = aliases.get(relation[key], relation[key])
    output.setdefault("annotations", []).extend(
        copy.deepcopy(original.get("annotations", []))
    )
    verify(output, baseline, contexts, artifacts, **expected)
    return output


def capture(command, log):
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("Missing capture command")
    Path(log).parent.mkdir(parents=True, exist_ok=True)
    write(str(log) + ".command.json", {"argv": command, "cwd": str(Path.cwd())})
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
    with Path(log).open("w") as stream:
        for line in process.stdout:
            print(line, end="", flush=True)
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("reason"):
                stream.write(json.dumps(item) + "\n")
    return process.wait()


def provenance(
    metadata,
    messages,
    sdk,
    target,
    artifact,
    logical_path,
    root,
    command,
    metadata_command=None,
    host_metadata=None,
    host_metadata_command=None,
):
    if Path(metadata.get("workspace_root", "")).resolve() != Path(root).resolve():
        raise ValueError("Metadata was not resolved from the producer checkout")
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = [p for p in packages.values() if p["name"] == ROOTS[sdk]]
    if len(roots) != 1:
        raise ValueError("Ambiguous package root")
    package_root = roots[0]
    compiled = {}
    if sdk != "rust":
        if not any(
            m.get("reason") == "build-finished" and m.get("success") is True
            for m in messages
        ):
            raise ValueError("No successful compiler receipt")
        for m in messages:
            if m.get("reason") == "compiler-artifact":
                compiled.setdefault(m["package_id"], []).append(m)
        root_outputs = compiled.get(package_root["id"], [])
        matching = [
            m
            for m in root_outputs
            if "cdylib" in m["target"]["kind"]
            and m["profile"]["opt_level"] == "3"
            and not m["profile"]["test"]
        ]
        # napi copies the native output; check actual bytes instead of assuming its rename.
        if not any(
            digest(p) == digest(artifact) and target in Path(p).parts
            for m in matching
            for p in m["filenames"]
            if Path(p).is_file() and Path(p).suffix in (".so", ".dll", ".dylib")
        ):
            raise ValueError(
                "Artifact is not the recorded root target/release compiler output"
            )
    seen = {}
    todo = [(package_root["id"], "normal")]
    while todo:
        ident, kind = todo.pop()
        if kind in seen.setdefault(ident, set()):
            continue
        seen[ident].add(kind)
        for dep in nodes[ident]["deps"]:
            for detail in dep["dep_kinds"]:
                child_kind = detail["kind"] or "normal"
                if sdk != "rust" and child_kind == "dev":
                    continue
                todo.append(
                    (dep["pkg"], child_kind if child_kind != "normal" else kind)
                )
    selected = []
    for ident, kinds in sorted(seen.items()):
        if sdk != "rust" and ident not in compiled:
            continue
        package = packages[ident]
        features = (
            sorted({f for m in compiled.get(ident, []) for f in m["features"]})
            if compiled
            else nodes[ident]["features"]
        )
        selected.append(
            {
                "name": package["name"],
                "version": package["version"],
                "source": package["source"],
                "features": features,
                "kinds": sorted(kinds),
                "scope": "resolved-source" if sdk == "rust" else "compiler-selected",
                "compiler_targets": [
                    m["target"]["kind"] for m in compiled.get(ident, [])
                ],
                "compiler_contexts": [
                    {
                        "target_kind": m["target"]["kind"],
                        "profile": m["profile"],
                        "features": m["features"],
                        "host_output": not any(
                            target in Path(f).parts for f in m["filenames"]
                        ),
                    }
                    for m in compiled.get(ident, [])
                ],
                "dependency_targets": [
                    detail
                    for parent in seen
                    for dep in nodes[parent]["deps"]
                    if dep["pkg"] == ident
                    for detail in dep["dep_kinds"]
                ],
            }
        )
    context = {
        "schema": 1,
        "sdk": sdk,
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "lock_sha256": digest(Path(root) / "Cargo.lock"),
        "target": target,
        "profile": "release",
        "version": package_root["version"],
        "producer_root": str(Path(root).resolve()),
        "root_package": ROOTS[sdk],
        "command": command,
        "compiler": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "producer_path": str(Path(artifact).resolve().relative_to(Path(root).resolve()))
        if Path(artifact).resolve().is_relative_to(Path(root).resolve())
        else str(Path(artifact).resolve()),
        "scope": "resolved source/archive inventory"
        if sdk == "rust"
        else "build-selected compiler inventory; not exact linked contents",
        "artifact": {"path": logical_path, "sha256": digest(artifact)},
        "packages": selected,
    }
    host_line = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(
        line.split(": ", 1)[1]
        for line in host_line.splitlines()
        if line.startswith("host: ")
    )
    context["resolver_evidence"] = {
        "metadata": metadata,
        "command": metadata_command,
        "host": host,
        "host_metadata": host_metadata,
        "host_command": host_metadata_command,
    }
    context["compiler_evidence"] = [
        m
        for m in messages
        if m.get("reason") in ("compiler-artifact", "build-finished")
    ]
    if sdk != "rust":
        native_outputs = [
            f
            for m in compiled[package_root["id"]]
            if "cdylib" in m["target"]["kind"]
            for f in m["filenames"]
            if Path(f).suffix in (".dylib", ".dll", ".so")
            and Path(f).is_file()
            and digest(f) == digest(artifact)
        ]
        if len(native_outputs) != 1:
            raise ValueError("Ambiguous root native output binding")
        context["binding_evidence"] = {
            "compiler_output": native_outputs[0],
            "sha256": digest(artifact),
        }
    context["packages"] = independent_inventory(context)
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    cap = sub.add_parser("capture")
    cap.add_argument("--log", required=True)
    cap.add_argument("command", nargs=argparse.REMAINDER)
    prov = sub.add_parser("provenance")
    for name in (
        "metadata",
        "sdk",
        "target",
        "artifact",
        "logical-path",
        "root",
        "output",
    ):
        prov.add_argument("--" + name, required=True)
    prov.add_argument("--compiler")
    prov.add_argument("--command", default="")
    prov.add_argument("--metadata-command", required=True)
    prov.add_argument("--host-metadata")
    prov.add_argument("--host-metadata-command")
    gen = sub.add_parser("generate")
    for name in (
        "baseline",
        "source-inventory",
        "artifacts",
        "source",
        "lock",
        "sdk",
        "version",
        "output",
    ):
        gen.add_argument("--" + name, required=True)
    gen.add_argument("--provenance", nargs="+", required=True)
    gen.add_argument("--targets", nargs="+", required=True)
    args = parser.parse_args()
    if args.operation == "capture":
        return capture(args.command, args.log)
    if args.operation == "provenance":
        messages = (
            [json.loads(line) for line in Path(args.compiler).read_text().splitlines()]
            if args.compiler
            else []
        )
        command = (
            read(str(args.compiler) + ".command.json")
            if args.compiler
            else args.command
        )
        write(
            args.output,
            provenance(
                read(args.metadata),
                messages,
                args.sdk,
                args.target,
                args.artifact,
                args.logical_path,
                args.root,
                command,
                read(args.metadata_command),
                read(args.host_metadata) if args.host_metadata else None,
                read(args.host_metadata_command)
                if args.host_metadata_command
                else None,
            ),
        )
    else:
        contexts = [read(p) for p in args.provenance]
        baseline = read(args.baseline)
        report = generate(baseline, read(args.source_inventory), contexts)
        verify(
            report,
            baseline,
            contexts,
            args.artifacts,
            source=args.source,
            lock=args.lock,
            expected_sdk=args.sdk,
            targets=args.targets,
            version=args.version,
        )
        write(args.output, report)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"release SBOM refused: {error}", file=sys.stderr)
        sys.exit(1)
