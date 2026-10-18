#!/usr/bin/env python3
"""Behavioral tests for immutable release recovery planning."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("plan-release-recovery.py")
TARGETS = {
    "include": [
        {
            "name": "aarch64-macos",
            "runner": "macos-14",
            "target": "aarch64-apple-darwin",
            "archive": "tar.gz",
            "ncm": "supported",
            "sidecar": {
                "worker": "tracedecay-ncm-worker",
                "manifest": "worker-manifest.json",
                "model_manifest": "model-acquisition-manifest.json",
            },
        },
        {
            "name": "x86_64-linux",
            "runner": "ubuntu-22.04",
            "target": "x86_64-unknown-linux-gnu",
            "archive": "tar.gz",
            "ncm": "native-only",
        },
        {
            "name": "aarch64-linux",
            "runner": "ubuntu-22.04-arm",
            "target": "aarch64-unknown-linux-gnu",
            "archive": "tar.gz",
            "ncm": "native-only",
        },
        {
            "name": "x86_64-windows",
            "runner": "windows-latest",
            "target": "x86_64-pc-windows-msvc",
            "archive": "zip",
            "ncm": "native-only",
        },
    ]
}


def invoke(
    root: Path, assets: tuple[str, ...], profile: str
) -> subprocess.CompletedProcess[str]:
    (root / "assets").write_text("\n".join(assets), encoding="utf-8")
    for output in ("github-output", "retained"):
        (root / output).unlink(missing_ok=True)
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--manifest",
            str(root / "targets.json"),
            "--tag",
            "v1.2.3",
            "--profile",
            profile,
            "--asset-names",
            str(root / "assets"),
            "--retained-output",
            str(root / "retained"),
            "--github-output",
            str(root / "github-output"),
        ],
        capture_output=True,
        text=True,
    )


def run(
    root: Path, assets: tuple[str, ...], profile: str = "stable"
) -> tuple[str, dict[str, object], list[str]]:
    completed = invoke(root, assets, profile)
    if completed.returncode != 0:
        raise AssertionError(completed.stdout + completed.stderr)
    outputs = dict(
        line.split("=", 1)
        for line in (root / "github-output").read_text(encoding="utf-8").splitlines()
    )
    retained = (root / "retained").read_text(encoding="utf-8").splitlines()
    return outputs["build_required"], json.loads(outputs["matrix"]), retained


def refuses(root: Path, assets: tuple[str, ...], reason: str, profile: str) -> None:
    completed = invoke(root, assets, profile)
    if completed.returncode != 1 or completed.stderr != f"{reason}\n":
        raise AssertionError(completed.stdout + completed.stderr)
    if (root / "github-output").exists() or (root / "retained").exists():
        raise AssertionError("a refused plan still wrote release outputs")


def premature_metadata(asset: str) -> str:
    return (
        f"final release metadata exists before all immutable artifacts ({asset}); "
        "refusing destructive recovery"
    )


def check_profile(root: Path, profile: str) -> None:
    cli_prefix = "tracedecay-beta" if profile == "beta" else "tracedecay"
    worker_prefix = (
        "tracedecay-ncm-worker-beta" if profile == "beta" else "tracedecay-ncm-worker"
    )
    macos_binary = f"{cli_prefix}-v1.2.3-aarch64-macos.tar.gz"
    macos_mcpb = f"{cli_prefix}-v1.2.3-aarch64-macos.mcpb"
    macos_worker = f"{worker_prefix}-v1.2.3-aarch64-macos.tar.gz"
    macos_checksum = f"{macos_worker}.sha256"
    native_assets = (
        f"{cli_prefix}-v1.2.3-x86_64-linux.tar.gz",
        f"{cli_prefix}-v1.2.3-x86_64-linux.mcpb",
        f"{cli_prefix}-v1.2.3-aarch64-linux.tar.gz",
        f"{cli_prefix}-v1.2.3-aarch64-linux.mcpb",
        f"{cli_prefix}-v1.2.3-x86_64-windows.zip",
        f"{cli_prefix}-v1.2.3-x86_64-windows.mcpb",
    )
    complete_macos = (macos_binary, macos_mcpb, macos_worker, macos_checksum)
    all_assets = complete_macos + native_assets

    build_required, matrix, retained = run(root, (), profile)
    assert build_required == "true"
    assert matrix == TARGETS
    assert retained == []

    # A CLI pair cannot satisfy a target whose worker sidecar is required.
    build_required, matrix, retained = run(root, (macos_binary, macos_mcpb), profile)
    assert build_required == "true"
    assert matrix == TARGETS
    assert retained == sorted((macos_binary, macos_mcpb))

    # Recovery keeps both already-published worker bytes and their checksum.
    build_required, matrix, retained = run(root, complete_macos, profile)
    assert build_required == "true"
    assert matrix == {"include": TARGETS["include"][1:]}
    assert retained == sorted(complete_macos)

    for absent in (macos_binary, macos_mcpb, macos_worker, macos_checksum):
        partial = tuple(asset for asset in all_assets if asset != absent)
        build_required, matrix, retained = run(root, partial, profile)
        assert build_required == "true"
        assert matrix == {"include": [TARGETS["include"][0]]}
        assert retained == sorted(partial)
        for metadata in ("SHA256SUMS", "install.sh"):
            refuses(root, partial + (metadata,), premature_metadata(metadata), profile)

    build_required, matrix, retained = run(
        root, all_assets + ("SHA256SUMS", "install.sh"), profile
    )
    assert build_required == "false"
    assert matrix == {"include": []}
    assert retained == sorted(all_assets)

    foreign_worker = f"{worker_prefix}-v1.2.3-x86_64-linux.tar.gz"
    refuses(
        root,
        (foreign_worker,),
        "unexpected existing release assets: " + foreign_worker,
        profile,
    )
    refuses(
        root,
        ("unexpected.tar.gz",),
        "unexpected existing release assets: unexpected.tar.gz",
        profile,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "targets.json").write_text(json.dumps(TARGETS), encoding="utf-8")
        check_profile(root, "stable")
        check_profile(root, "beta")

        # Source fixtures carry the same mandatory participation policy as releases.
        missing_policy = json.loads(json.dumps(TARGETS))
        del missing_policy["include"][0]["ncm"]
        (root / "targets.json").write_text(json.dumps(missing_policy), encoding="utf-8")
        completed = invoke(root, (), "stable")
        assert completed.returncode == 1
        assert completed.stderr == "release target is missing required string fields\n"
        assert not (root / "github-output").exists()
        assert not (root / "retained").exists()

    print("release recovery planner tests passed")


if __name__ == "__main__":
    main()
