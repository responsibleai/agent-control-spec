#!/usr/bin/env python3
# Copyright (c) Microsoft. All rights reserved.

"""Offline verifier controls. Minimal synthetic SPDX is deliberately test data."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).with_name("release_sbom.py")


class ReleaseSbomTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("release_sbom", MODULE)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "node-binding-aarch64-apple-darwin/binding.node"
        self.artifact.parent.mkdir()
        self.artifact.write_bytes(b"synthetic-byte-control-not-a-library")
        self.provenance = {
            "schema": 1,
            "sdk": "node",
            "source": "a" * 40,
            "lock_sha256": "b" * 64,
            "target": "aarch64-apple-darwin",
            "profile": "release",
            "version": "1.0.0",
            "root_package": "agent-control-spec-node",
            "producer_root": "/producer",
            "artifact": {
                "path": "node-binding-aarch64-apple-darwin/binding.node",
                "sha256": self.mod.digest(self.artifact),
            },
            "scope": "build-selected compiler inventory; not exact linked contents",
            "packages": [
                {
                    "name": "agent-control-spec-node",
                    "version": "1.0.0",
                    "features": [],
                    "kinds": ["normal"],
                }
            ],
        }
        self.baseline = self.document([self.package("npm", "loader", "1.0.0")])
        self.native = self.document(
            [self.package("cargo", "agent-control-spec-node", "1.0.0")]
        )
        # Minimal independent resolver/compiler fixtures, never an SDK stub.
        dep = {
            "name": "agent-control-spec",
            "rename": None,
            "kind": None,
            "target": None,
            "optional": False,
            "uses_default_features": True,
            "features": [],
        }
        packages = [
            {
                "id": "node",
                "name": "agent-control-spec-node",
                "version": "1.0.0",
                "source": None,
                "features": {},
                "dependencies": [dep],
                "targets": [{"kind": ["cdylib"]}],
            },
            {
                "id": "core",
                "name": "agent-control-spec",
                "version": "1.0.0",
                "source": None,
                "features": {"default": []},
                "dependencies": [],
                "targets": [{"kind": ["lib"]}],
            },
        ]
        metadata = {
            "workspace_root": "/producer",
            "packages": packages,
            "resolve": {
                "nodes": [
                    {
                        "id": "node",
                        "features": [],
                        "deps": [
                            {
                                "name": "agent_control_spec",
                                "pkg": "core",
                                "dep_kinds": [{"kind": None, "target": None}],
                            }
                        ],
                    },
                    {"id": "core", "features": ["default"], "deps": []},
                ]
            },
        }
        output = "/producer/target/aarch64-apple-darwin/release/libagent_control_spec_node.dylib"
        self.provenance["resolver_evidence"] = {
            "metadata": metadata,
            "command": [
                "cargo",
                "metadata",
                "--locked",
                "--filter-platform",
                "aarch64-apple-darwin",
            ],
            "host": "aarch64-apple-darwin",
        }
        self.provenance["command"] = [
            "cargo",
            "build",
            "--release",
            "--target",
            "aarch64-apple-darwin",
            "-p",
            "agent-control-spec-node",
        ]
        profile = {"opt_level": "3", "test": False}
        self.provenance["compiler_evidence"] = [
            {
                "reason": "compiler-artifact",
                "package_id": "node",
                "target": {"kind": ["cdylib"]},
                "profile": profile,
                "features": [],
                "filenames": [output],
            },
            {
                "reason": "compiler-artifact",
                "package_id": "core",
                "target": {"kind": ["lib"]},
                "profile": profile,
                "features": ["default"],
                "filenames": [output.replace("_node.dylib", ".rlib")],
            },
            {"reason": "build-finished", "success": True},
        ]
        self.provenance["binding_evidence"] = {
            "compiler_output": output,
            "sha256": self.mod.digest(self.artifact),
        }
        self.provenance["packages"] = self.mod.independent_inventory(self.provenance)
        self.native = self.document(
            [self.package("cargo", p["name"], p["version"]) for p in packages]
        )

    @staticmethod
    def package(ecosystem, name, version):
        return {
            "SPDXID": "SPDXRef-" + ecosystem + "-" + name,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:{ecosystem}/{name}@{version}",
                }
            ],
        }

    @staticmethod
    def document(packages):
        return {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": packages,
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": p["SPDXID"],
                }
                for p in packages
            ],
        }

    def generate(self):
        return self.mod.generate(self.baseline, self.native, [self.provenance])

    def validate(self, report, provenance=None):
        self.mod.verify(
            report,
            self.baseline,
            [provenance or self.provenance],
            self.root,
            source="a" * 40,
            lock="b" * 64,
            expected_sdk="node",
            targets=["aarch64-apple-darwin"],
            version="1.0.0",
        )

    def test_complete_report_and_id_collision(self):
        report = self.generate()
        self.validate(report)
        self.assertEqual(len(report["packages"]), 3)
        self.assertEqual(len({p["SPDXID"] for p in report["packages"]}), 3)

    def test_byte_mutation(self):
        report = self.generate()
        self.artifact.write_bytes(self.artifact.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_missing_component(self):
        report = self.generate()
        report["packages"] = report["packages"][:1]
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_changed_version(self):
        report = self.generate()
        report["packages"][-1]["versionInfo"] = "wrong"
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_wrong_context(self):
        for key, value in [
            ("source", "c" * 40),
            ("target", "wrong"),
            ("sdk", "dotnet"),
            ("version", "2"),
            ("lock_sha256", "d" * 64),
            ("profile", "debug"),
        ]:
            with self.subTest(key=key):
                p = copy.deepcopy(self.provenance)
                p[key] = value
                with self.assertRaises(ValueError):
                    self.validate(self.generate(), p)

    def test_missing_and_zero_hash(self):
        for value in [None, "0" * 64, "bad"]:
            p = copy.deepcopy(self.provenance)
            p["artifact"]["sha256"] = value
            with self.assertRaises(ValueError):
                self.validate(self.generate(), p)

    def test_wrong_artifact_path(self):
        p = copy.deepcopy(self.provenance)
        p["artifact"]["path"] = "../outside"
        with self.assertRaises(ValueError):
            self.validate(self.generate(), p)

    def test_non_rust_identity_preservation(self):
        report = self.generate()
        report["packages"] = report["packages"][1:]
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_dangling_relationship(self):
        report = self.generate()
        report["relationships"][0]["relatedSpdxElement"] = "SPDXRef-absent"
        with self.assertRaises(ValueError):
            self.validate(report)

    def test_roundtrip_file_alias_rebind_requires_real_file_identity(self):
        original = self.generate()
        original["files"] = [
            {
                "SPDXID": "SPDXRef-File-lock-abc",
                "fileName": "lock",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "c" * 64}],
            }
        ]
        converted = copy.deepcopy(original)
        converted.pop("annotations")
        converted["relationships"].append(
            {
                "spdxElementId": "SPDXRef-cargo",
                "relationshipType": "OTHER",
                "relatedSpdxElement": "SPDXRef-abc",
            }
        )
        # Use the actual generated native package ID, not its source ID.
        converted["relationships"][-1]["spdxElementId"] = converted["packages"][-1][
            "SPDXID"
        ]
        result = self.mod.rebind_roundtrip(
            original,
            converted,
            self.baseline,
            [self.provenance],
            self.root,
            source="a" * 40,
            lock="b" * 64,
            expected_sdk="node",
            targets=["aarch64-apple-darwin"],
            version="1.0.0",
        )
        self.assertEqual(
            result["relationships"][-1]["relatedSpdxElement"], "SPDXRef-File-lock-abc"
        )

    def test_roundtrip_allows_only_known_source_root_addition(self):
        original = self.generate()
        converted = copy.deepcopy(original)
        root = {
            "name": "unknown",
            "SPDXID": "SPDXRef-DocumentRoot-Directory-unknown",
            "primaryPackagePurpose": "FILE",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION",
        }
        converted["packages"].append(root)
        converted["relationships"].append(
            {
                "spdxElementId": converted["SPDXID"],
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": root["SPDXID"],
            }
        )
        converted["relationships"].append(
            {
                "spdxElementId": root["SPDXID"],
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": converted["packages"][0]["SPDXID"],
            }
        )
        self.mod.check_conversion_inventory(original, converted)
        for mutation in ["name", "version", "purl", "cargo", "loss"]:
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(converted)
                if mutation == "name":
                    bad["packages"][-1]["name"] = "arbitrary"
                elif mutation == "version":
                    bad["packages"][-1]["versionInfo"] = "1"
                elif mutation == "purl":
                    bad["packages"][-1]["externalRefs"] = self.package(
                        "npm", "extra", "1"
                    )["externalRefs"]
                elif mutation == "cargo":
                    bad["packages"].append(self.package("cargo", "extra", "1"))
                else:
                    bad["packages"] = bad["packages"][1:]
                with self.assertRaises(ValueError):
                    self.mod.check_conversion_inventory(original, bad)

    def test_malformed_document(self):
        for report in [{}, {"spdxVersion": "SPDX-2.3", "packages": "bad"}]:
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_missing_independent_evidence_rejected(self):
        context = copy.deepcopy(self.provenance)
        context.pop("resolver_evidence")
        report = self.mod.generate(self.baseline, self.native, [context])
        with self.assertRaises(ValueError):
            self.validate(report, context)

    def test_truncated_sidecar_and_compiler_features_rejected(self):
        for mutation in ["list", "compiler", "features", "contexts"]:
            with self.subTest(mutation=mutation):
                context = copy.deepcopy(self.provenance)
                if mutation == "list":
                    context["packages"] = context["packages"][:1]
                elif mutation == "compiler":
                    context["compiler_evidence"] = [
                        m
                        for m in context["compiler_evidence"]
                        if m.get("package_id") != "core"
                    ]
                elif mutation == "features":
                    context["packages"][0]["features"] = ["fabricated"]
                else:
                    context["packages"][0]["compiler_contexts"] = []
                report = self.mod.generate(self.baseline, self.native, [context])
                with self.assertRaises(ValueError):
                    self.validate(report, context)

    def test_target_label_cannot_replace_command_or_metadata(self):
        for mutation in ["label", "command", "metadata", "output", "layout"]:
            with self.subTest(mutation=mutation):
                context = copy.deepcopy(self.provenance)
                if mutation == "label":
                    context["target"] = "x86_64-unknown-linux-gnu"
                elif mutation == "command":
                    context["command"][4] = "wrong"
                elif mutation == "metadata":
                    context["resolver_evidence"]["command"][-1] = "wrong"
                elif mutation == "output":
                    context["binding_evidence"]["compiler_output"] = "wrong"
                else:
                    context["artifact"]["path"] = "binding.node"
                report = self.mod.generate(self.baseline, self.native, [context])
                with self.assertRaises(ValueError):
                    self.validate(report, context)

    def test_five_relabelled_copies_and_duplicate_binding_rejected(self):
        targets = [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ]
        contexts = []
        for target in targets:
            context = copy.deepcopy(self.provenance)
            context["target"] = target
            contexts.append(context)
        report = self.mod.generate(self.baseline, self.native, contexts)
        with self.assertRaises(ValueError):
            self.mod.verify(
                report,
                self.baseline,
                contexts,
                self.root,
                source="a" * 40,
                lock="b" * 64,
                expected_sdk="node",
                targets=targets,
                version="1.0.0",
            )

    def test_declared_optional_features_and_host_scope_are_independent(self):
        metadata = copy.deepcopy(self.provenance["resolver_evidence"]["metadata"])
        core = metadata["packages"][1]
        core["features"] = {"default": ["with-extra"], "with-extra": ["dep:extra"]}
        dep = {
            "name": "extra",
            "rename": None,
            "kind": None,
            "target": None,
            "optional": True,
            "uses_default_features": True,
            "features": [],
        }
        core["dependencies"].append(dep)
        metadata["packages"].append(
            {
                "id": "extra",
                "name": "extra",
                "version": "1",
                "source": None,
                "features": {"default": []},
                "dependencies": [],
                "targets": [{"kind": ["proc-macro"]}],
            }
        )
        metadata["resolve"]["nodes"][1]["deps"].append(
            {
                "name": "extra",
                "pkg": "extra",
                "dep_kinds": [{"kind": None, "target": None}],
            }
        )
        metadata["resolve"]["nodes"].append({"id": "extra", "features": [], "deps": []})
        graph = self.mod.required_graph(metadata, ["agent-control-spec-node"])
        self.assertEqual(graph[("extra", "host")], {"default"})
        self.assertNotIn(("extra", "target"), graph)

    def test_cross_host_requires_independent_host_filter_receipt(self):
        context = copy.deepcopy(self.provenance)
        context["resolver_evidence"]["host"] = "x86_64-apple-darwin"
        with self.assertRaises(ValueError):
            self.mod.independent_inventory(context)

    def test_capture_preserves_exit_and_compiler_stream(self):
        log = self.root / "compiler.jsonl"
        command = [
            sys.executable,
            str(MODULE),
            "capture",
            "--log",
            str(log),
            "--",
            sys.executable,
            "-c",
            'import json,sys;print("cli log");print(json.dumps({"reason":"build-finished","success":False}));sys.exit(7)',
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(json.loads(log.read_text())["success"], False)
        self.assertIn("cli log", result.stdout)
        self.assertEqual(
            json.loads(Path(str(log) + ".command.json").read_text())["argv"],
            command[6:],
        )

    def test_capture_preserves_existing_bash_command(self):
        log = self.root / "bash.jsonl"
        code = 'import json,sys;print(json.dumps({"reason":"build-finished","success":False}));sys.exit(11)'
        result = subprocess.run(
            [
                sys.executable,
                str(MODULE),
                "capture",
                "--log",
                str(log),
                "--",
                "/bin/bash",
                "-c",
                'exec "$@"',
                "capture-test",
                sys.executable,
                "-c",
                code,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 11)
        self.assertFalse(json.loads(log.read_text())["success"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
