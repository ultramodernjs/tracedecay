#!/usr/bin/env python3
"""Focused tests for exact release artifact coverage."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).with_name("check-release-artifacts.py")
ROOT = SCRIPT.resolve().parents[1]
POLICY = ROOT / "product/ncm/reference/worker-platforms.json"
TAG = "v1.2.3"


def fixture_manifest() -> dict:
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    runners = {
        "aarch64-macos": ("macos-14", "tar.gz"),
        "x86_64-linux": ("ubuntu-22.04", "tar.gz"),
        "aarch64-linux": ("ubuntu-22.04-arm", "tar.gz"),
        "x86_64-windows": ("windows-latest", "zip"),
    }
    targets = []
    for entry in policy["release_targets"]:
        runner, archive = runners[entry["name"]]
        target = dict(entry, runner=runner, archive=archive)
        if target["ncm"] == "supported":
            target["sidecar"] = {
                "worker": policy["worker"],
                "manifest": Path(policy["worker_manifest"]).name,
                "model_manifest": Path(policy["model_acquisition_manifest"]).name,
            }
        targets.append(target)
    return {"include": targets}


def write_manifest(root: Path, manifest: dict) -> None:
    (root / "targets.json").write_text(json.dumps(manifest), encoding="utf-8")


def run(
    root: Path,
    profile: str = "stable",
    *,
    allow_missing: bool = False,
    include_workers: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "-S",
        "-B",
        str(SCRIPT),
        "--manifest",
        str(root / "targets.json"),
        "--worker-platforms",
        str(POLICY),
        "--tag",
        TAG,
        "--profile",
        profile,
        "--binaries",
        str(root / "binaries"),
        "--mcpbs",
        str(root / "mcpbs"),
    ]
    if include_workers:
        command.extend(("--ncm-workers", str(root / "ncm-workers")))
    if allow_missing:
        command.append("--allow-missing-targets")
    return subprocess.run(command, capture_output=True, text=True)


def expect(
    root: Path,
    status: int,
    message: str,
    profile: str = "stable",
    *,
    allow_missing: bool = False,
    include_workers: bool = True,
) -> None:
    """Success reports on stdout and a refusal on stderr, each as one line."""
    completed = run(
        root, profile, allow_missing=allow_missing, include_workers=include_workers
    )
    output = completed.stdout if status == 0 else completed.stderr
    if completed.returncode != status or output != f"{message}\n":
        raise AssertionError(completed.stdout + completed.stderr)


def worker_name(profile: str) -> str:
    if profile == "beta":
        return "tracedecay-ncm-worker-beta-v1.2.3-aarch64-macos.tar.gz"
    return "tracedecay-ncm-worker-v1.2.3-aarch64-macos.tar.gz"


def write_worker(root: Path, profile: str) -> None:
    name = worker_name(profile)
    payload = b"NCM worker archive"
    (root / "ncm-workers" / name).write_bytes(payload)
    (root / "ncm-workers" / f"{name}.sha256").write_text(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n", encoding="ascii"
    )


def populate(root: Path, manifest: dict, profile: str) -> None:
    for child in ("binaries", "mcpbs", "ncm-workers"):
        for item in (root / child).iterdir():
            item.unlink()
    prefix = "tracedecay-beta" if profile == "beta" else "tracedecay"
    for target in manifest["include"]:
        (root / "binaries" / (
            f"{prefix}-{TAG}-{target['name']}.{target['archive']}"
        )).write_bytes(b"CLI archive")
        (root / "mcpbs" / f"{prefix}-{TAG}-{target['name']}.mcpb").write_bytes(b"MCPB")
    write_worker(root, profile)


def checker_module():
    spec = importlib.util.spec_from_file_location("release_artifact_checker_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load release artifact checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = fixture_manifest()
        write_manifest(root, manifest)
        for child in ("binaries", "mcpbs", "ncm-workers"):
            (root / child).mkdir()

        checker = checker_module()
        targets = checker.target_matrix(root / "targets.json", POLICY)
        assert checker.target_matrix(root / "targets.json") == targets
        for profile in ("stable", "beta"):
            prefix = "tracedecay-beta" if profile == "beta" else "tracedecay"
            assert checker.target_assets(targets[0], TAG, profile) == (
                f"{prefix}-v1.2.3-aarch64-macos.tar.gz",
                f"{prefix}-v1.2.3-aarch64-macos.mcpb",
                worker_name(profile),
                f"{worker_name(profile)}.sha256",
            )
            assert checker.target_assets(targets[-1], TAG, profile) == (
                f"{prefix}-v1.2.3-x86_64-windows.zip",
                f"{prefix}-v1.2.3-x86_64-windows.mcpb",
            )
            populate(root, manifest, profile)
            expect(root, 0, "release artifact coverage matches target manifest", profile)
            expect(root, 0, "release artifact coverage matches target manifest", profile,
                   allow_missing=True)

            archive = f"{prefix}-{TAG}-aarch64-macos.tar.gz"
            mcpb = f"{prefix}-{TAG}-aarch64-macos.mcpb"
            worker = worker_name(profile)
            checksum = f"{worker}.sha256"

            # Every member of the supported target is required in both modes.
            for child, name, kind, presence in (
                ("binaries", archive, "binary", "archive=missing, mcpb=present, worker=present, checksum=present"),
                ("mcpbs", mcpb, "MCPB", "archive=present, mcpb=missing, worker=present, checksum=present"),
                ("ncm-workers", worker, "NCM worker", "archive=present, mcpb=present, worker=missing, checksum=present"),
                ("ncm-workers", checksum, "NCM worker", "archive=present, mcpb=present, worker=present, checksum=missing"),
            ):
                path = root / child / name
                payload = path.read_bytes()
                path.unlink()
                expect(root, 1, f"{kind} coverage mismatch: missing {name}", profile)
                expect(root, 1, f"release target aarch64-macos is half built: {presence}",
                       profile, allow_missing=True)
                path.write_bytes(payload)

            for child, name in (("binaries", archive), ("mcpbs", mcpb),
                                ("ncm-workers", worker), ("ncm-workers", checksum)):
                (root / child / name).unlink()
            expect(root, 0, "release artifact coverage is partial; missing targets: aarch64-macos",
                   profile, allow_missing=True)
            expect(root, 1, f"binary coverage mismatch: missing {archive}", profile)
            populate(root, manifest, profile)

            # Unpublished or native-only worker assets are foreign, even with valid bytes.
            for unexpected in (
                "unexpected.zip",
                f"tracedecay-ncm-worker-{TAG}-x86_64-linux.tar.gz",
                f"{worker}.extra.sha256",
                worker_name("beta" if profile == "stable" else "stable"),
            ):
                path = root / "ncm-workers" / unexpected
                path.write_bytes(b"foreign worker")
                expect(root, 1, f"NCM worker coverage mismatch: unexpected {unexpected}", profile)
                expect(root, 1, f"unexpected release artifacts: {unexpected}", profile,
                       allow_missing=True)
                path.unlink()

            # Generic binary and MCPB separation remains exact.
            (root / "binaries" / mcpb).write_bytes(b"misplaced MCPB")
            expect(root, 1, f"binary coverage mismatch: unexpected {mcpb}", profile)
            expect(root, 1, f"unexpected release artifacts: {mcpb}", profile, allow_missing=True)
            (root / "binaries" / mcpb).unlink()

            checksum_path = root / "ncm-workers" / checksum
            digest = hashlib.sha256((root / "ncm-workers" / worker).read_bytes()).hexdigest()
            for malformed in (
                f"{digest}  ../{worker}\n",
                f"{digest}  other.tar.gz\n",
                f"{digest}  {worker}\n{digest}  {worker}\n",
                f"{digest} {worker}\n",
            ):
                checksum_path.write_text(malformed, encoding="ascii")
                for allow_missing in (False, True):
                    expect(root, 1, f"invalid NCM worker checksum: {checksum}", profile,
                           allow_missing=allow_missing)
            checksum_path.write_text(f"{'0' * 64}  {worker}\n", encoding="ascii")
            for allow_missing in (False, True):
                expect(root, 1, f"NCM worker checksum mismatch: {worker}", profile,
                       allow_missing=allow_missing)
            checksum_path.write_text(f"{digest} *{worker}\n", encoding="ascii")
            expect(root, 0, "release artifact coverage matches target manifest", profile)
            (root / "ncm-workers" / worker).write_bytes(b"changed worker archive")
            expect(root, 1, f"NCM worker checksum mismatch: {worker}", profile)
            write_worker(root, profile)

            for allow_missing in (False, True):
                (root / "ncm-workers" / worker).write_bytes(b"")
                expect(root, 1, f"empty release artifacts: {worker}", profile,
                       allow_missing=allow_missing)
            write_worker(root, profile)

            # A missing native-only row retains the previous whole-target rule.
            windows_archive = f"{prefix}-{TAG}-x86_64-windows.zip"
            windows_mcpb = f"{prefix}-{TAG}-x86_64-windows.mcpb"
            (root / "binaries" / windows_archive).unlink()
            expect(root, 1, "release target x86_64-windows is half built: archive=missing, mcpb=present",
                   profile, allow_missing=True)
            (root / "mcpbs" / windows_mcpb).unlink()
            expect(root, 0, "release artifact coverage is partial; missing targets: x86_64-windows",
                   profile, allow_missing=True)
            for child in ("binaries", "mcpbs", "ncm-workers"):
                for item in (root / child).iterdir():
                    item.unlink()
            expect(root, 1, "no release target is complete; nothing to publish", profile,
                   allow_missing=True)

        populate(root, manifest, "stable")
        expect(root, 1, "release validation requires an NCM worker directory", include_workers=False)
        invalid = fixture_manifest()
        del invalid["include"][0]["ncm"]
        write_manifest(root, invalid)
        expect(root, 1, "release target is missing required string fields")
        invalid = fixture_manifest()
        invalid["include"][0]["ncm"] = "native-only"
        write_manifest(root, invalid)
        expect(root, 1, "invalid release NCM policy: release target aarch64-macos NCM status differs between manifests")
        invalid = fixture_manifest()
        del invalid["include"][0]["sidecar"]
        write_manifest(root, invalid)
        expect(root, 1, "invalid release NCM policy: supported release target aarch64-macos must carry sidecar metadata")
        invalid = fixture_manifest()
        invalid["include"][1]["sidecar"] = manifest["include"][0]["sidecar"]
        write_manifest(root, invalid)
        expect(root, 1, "invalid release NCM policy: native-only release target x86_64-linux must not carry NCM sidecar metadata")
        invalid = fixture_manifest()
        invalid["include"][0]["target"] = "x86_64-apple-darwin"
        write_manifest(root, invalid)
        expect(root, 1, "invalid release NCM policy: release target aarch64-macos target differs between manifests")
    print("release artifact validator tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
