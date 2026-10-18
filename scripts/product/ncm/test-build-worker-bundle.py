#!/usr/bin/env python3
"""Tests for NCM worker bundle manifest generation and merging."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import stat
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build-worker-bundle.py")
spec = importlib.util.spec_from_file_location("ncm_build_worker_bundle", SCRIPT)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = MODULE
spec.loader.exec_module(MODULE)

HEADER = MODULE.manifest_header(
    json.loads(MODULE.REFERENCE_WORKER_MANIFEST.read_text(encoding="utf-8"))
)


def per_target_manifest(triple: str, payload: bytes) -> dict[str, object]:
    return dict(HEADER, targets=[MODULE.worker_pin(triple, payload)])


class BuildWorkerBundleTest(unittest.TestCase):
    def test_header_is_copied_from_the_checked_in_trust_root(self) -> None:
        reference = json.loads(MODULE.REFERENCE_WORKER_MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(reference["targets"], [])
        self.assertEqual(
            HEADER,
            {
                "schema_version": 1,
                "worker": "tracedecay-ncm-worker",
                "protocol_version": 1,
                "protocol_identity": "tracedecay.ncm.worker.v1",
            },
        )

    def test_host_target_is_parsed_from_rustc(self) -> None:
        output = "rustc 1.97.1\nbinary: rustc\nhost: aarch64-unknown-linux-gnu\nrelease: 1.97.1\n"
        self.assertEqual(MODULE.host_target(output), "aarch64-unknown-linux-gnu")
        with self.assertRaises(MODULE.BundleError):
            MODULE.host_target("rustc 1.97.1\n")

    def test_pins_carry_rust_platform_constants_for_every_release_target(self) -> None:
        expected = {
            "aarch64-apple-darwin": ("macos", "aarch64", "unix", "tracedecay-ncm-worker"),
            "x86_64-apple-darwin": ("macos", "x86_64", "unix", "tracedecay-ncm-worker"),
            "aarch64-unknown-linux-gnu": ("linux", "aarch64", "unix", "tracedecay-ncm-worker"),
            "x86_64-unknown-linux-gnu": ("linux", "x86_64", "unix", "tracedecay-ncm-worker"),
            "aarch64-pc-windows-msvc": ("windows", "aarch64", "windows", "tracedecay-ncm-worker.exe"),
            "x86_64-pc-windows-msvc": ("windows", "x86_64", "windows", "tracedecay-ncm-worker.exe"),
        }
        payload = b"worker bytes"
        for triple, (os_name, arch, family, file_name) in expected.items():
            pin = MODULE.worker_pin(triple, payload)
            self.assertEqual(
                pin,
                {
                    "triple": triple,
                    "os": os_name,
                    "arch": arch,
                    "family": family,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            )
            self.assertEqual(MODULE.worker_executable_name(triple), file_name)
        with self.assertRaises(MODULE.BundleError):
            MODULE.worker_pin("wasm32-unknown-unknown", payload)
        with self.assertRaises(MODULE.BundleError):
            MODULE.worker_pin("x86_64-unknown-linux-gnu", b"")

    def test_merge_combines_targets_and_rejects_conflicts(self) -> None:
        linux = per_target_manifest("aarch64-unknown-linux-gnu", b"linux")
        windows = per_target_manifest("x86_64-pc-windows-msvc", b"windows")
        merged = MODULE.merge_manifests([windows, linux], header=HEADER)
        self.assertEqual(
            [entry["triple"] for entry in merged["targets"]],
            ["aarch64-unknown-linux-gnu", "x86_64-pc-windows-msvc"],
        )
        self.assertEqual({key: merged[key] for key in HEADER}, HEADER)

        rebuilt = per_target_manifest("aarch64-unknown-linux-gnu", b"rebuilt linux")
        with self.assertRaisesRegex(MODULE.BundleError, "repeat target"):
            MODULE.merge_manifests([linux, rebuilt], header=HEADER)
        other_protocol = dict(windows, protocol_identity="tracedecay.ncm.worker.v2")
        with self.assertRaisesRegex(MODULE.BundleError, "protocol_identity"):
            MODULE.merge_manifests([linux, other_protocol], header=HEADER)
        foreign = per_target_manifest("x86_64-pc-windows-msvc", b"windows")
        foreign["targets"][0]["family"] = "unix"
        with self.assertRaisesRegex(MODULE.BundleError, "platform metadata"):
            MODULE.merge_manifests([foreign], header=HEADER)
        with self.assertRaises(MODULE.BundleError):
            MODULE.merge_manifests([], header=HEADER)

    def test_self_referential_worker_is_rejected(self) -> None:
        digest = hashlib.sha256(b"pinned worker").hexdigest()
        MODULE.ensure_not_self_referential(b"independent worker", digest)
        for embedded in (digest.encode("ascii"), bytes.fromhex(digest)):
            with self.assertRaisesRegex(MODULE.BundleError, "own pinned digest"):
                MODULE.ensure_not_self_referential(b"prefix" + embedded + b"suffix", digest)

    def test_bundle_pins_exactly_the_written_worker(self) -> None:
        payload = b"\x7fELF fixture worker"
        model_manifest = MODULE.MODEL_ACQUISITION_MANIFEST.read_bytes()
        with tempfile.TemporaryDirectory(prefix="ncm-bundle-") as directory:
            output = Path(directory) / "bundle"
            manifest_path = MODULE.write_bundle(
                output,
                triple="x86_64-pc-windows-msvc",
                payload=payload,
                header=HEADER,
                model_manifest=model_manifest,
            )
            self.assertEqual(manifest_path, output / "worker-manifest.json")
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                [
                    "model-acquisition-manifest.json",
                    "tracedecay-ncm-worker.exe",
                    "worker-manifest.json",
                ],
            )
            worker = output / "tracedecay-ncm-worker.exe"
            self.assertEqual(worker.read_bytes(), payload)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(worker.stat().st_mode), 0o755)
            self.assertEqual(
                (output / "model-acquisition-manifest.json").read_bytes(), model_manifest
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest, per_target_manifest("x86_64-pc-windows-msvc", payload)
            )

            # Rewriting replaces the bundle in place and keeps no prior copy.
            MODULE.write_bundle(
                output,
                triple="x86_64-pc-windows-msvc",
                payload=b"rebuilt worker",
                header=HEADER,
                model_manifest=model_manifest,
            )
            self.assertEqual(len(list(output.iterdir())), 3)
            self.assertEqual(
                json.loads(manifest_path.read_text(encoding="utf-8"))["targets"][0]["bytes"],
                len(b"rebuilt worker"),
            )

    def test_merge_cli_writes_the_manifest_and_prints_the_trust_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ncm-merge-") as directory:
            root = Path(directory)
            inputs = []
            for triple, payload in (
                ("aarch64-apple-darwin", b"mac"),
                ("x86_64-unknown-linux-gnu", b"linux"),
            ):
                path = root / f"{triple}.json"
                path.write_bytes(MODULE.encode_manifest(per_target_manifest(triple, payload)))
                inputs.append(str(path))
            output = root / "merged" / "worker-manifest.json"

            captured = io.StringIO()
            with redirect_stdout(captured):
                status = MODULE.main(["--merge", *inputs, "-o", str(output)])
            self.assertEqual(status, 0)
            self.assertEqual(
                captured.getvalue().strip(),
                f"TRACEDECAY_NCM_WORKER_MANIFEST={output.as_posix()}",
            )
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(merged["targets"]), 2)
            self.assertEqual(MODULE.main(["--merge", inputs[0], inputs[0], "-o", str(output)]), 2)

    def test_printed_paths_use_forward_slashes_on_windows(self) -> None:
        bundle = PureWindowsPath(r"D:\a\repo\target\ncm-bundle\x86_64-pc-windows-msvc")
        self.assertEqual(
            MODULE.assignment(
                "TRACEDECAY_NCM_WORKER",
                bundle / MODULE.worker_executable_name("x86_64-pc-windows-msvc"),
            ),
            "TRACEDECAY_NCM_WORKER="
            "D:/a/repo/target/ncm-bundle/x86_64-pc-windows-msvc/tracedecay-ncm-worker.exe",
        )

    @unittest.skipUnless(os.name == "posix", "the fake cargo is a POSIX script")
    def test_build_cli_bundles_the_target_worker_and_prints_both_assignments(self) -> None:
        triple = "aarch64-pc-windows-msvc"
        with tempfile.TemporaryDirectory(prefix="ncm-build-") as directory:
            root = Path(directory)
            target_directory = root / "target"
            record = root / "cargo-calls.json"
            cargo = root / "fake-cargo"
            cargo.write_text(
                f"""#!{sys.executable}
import json, os, pathlib, sys
arguments = sys.argv[1:]
record = pathlib.Path({str(record)!r})
calls = json.loads(record.read_text()) if record.exists() else []
calls.append({{
    "arguments": arguments,
    "manifest_env": os.environ.get("TRACEDECAY_NCM_WORKER_MANIFEST"),
    "ort_lib_location": os.environ.get("ORT_LIB_LOCATION"),
}})
record.write_text(json.dumps(calls))
target_directory = pathlib.Path({str(target_directory)!r})
if arguments[0] == "build":
    triple = arguments[arguments.index("--target") + 1]
    release = target_directory / triple / "release"
    release.mkdir(parents=True, exist_ok=True)
    (release / "tracedecay-ncm-worker.exe").write_bytes(b"MZ fixture worker")
elif arguments[0] == "metadata":
    print(json.dumps({{"target_directory": str(target_directory)}}))
""",
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            output = root / "bundle"
            captured = io.StringIO()
            environment = {
                "TRACEDECAY_NCM_WORKER_MANIFEST": "/stale/worker-manifest.json",
                "ORT_LIB_LOCATION": "/opt/onnxruntime/lib",
            }
            saved = {key: os.environ.get(key) for key in environment}
            os.environ.update(environment)
            try:
                with redirect_stdout(captured):
                    status = MODULE.main(
                        ["--target", triple, "--output", str(output), "--cargo", str(cargo)]
                    )
            finally:
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(status, 0)
            self.assertEqual(
                captured.getvalue().splitlines(),
                [
                    f"TRACEDECAY_NCM_WORKER={(output / 'tracedecay-ncm-worker.exe').as_posix()}",
                    f"TRACEDECAY_NCM_WORKER_MANIFEST={(output / 'worker-manifest.json').as_posix()}",
                ],
            )
            self.assertEqual(
                (output / "tracedecay-ncm-worker.exe").read_bytes(), b"MZ fixture worker"
            )
            manifest = json.loads((output / "worker-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest, per_target_manifest(triple, b"MZ fixture worker"))
            calls = json.loads(record.read_text(encoding="utf-8"))
            build = calls[0]
            self.assertEqual(build["arguments"][0], "build")
            self.assertEqual(
                build["arguments"][build["arguments"].index("--target") + 1], triple
            )
            self.assertIn("--locked", build["arguments"])
            # A stale pin never reaches the worker build; ORT linkage does.
            self.assertTrue(all(call["manifest_env"] is None for call in calls))
            self.assertEqual(build["ort_lib_location"], "/opt/onnxruntime/lib")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BuildWorkerBundleTest)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
