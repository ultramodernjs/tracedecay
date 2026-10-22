#!/usr/bin/env python3
"""Validate exact release asset coverage from the release target manifest."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from typing import Any


def target_matrix(
    path: Path, worker_platforms_path: Path | None = None
) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid release target manifest: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit("release target manifest must be an object")
    targets = value.get("include")
    if not isinstance(targets, list) or not targets:
        raise SystemExit("release target manifest has no targets")
    names: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise SystemExit("release target must be an object")
        required = ("name", "runner", "target", "archive", "ncm")
        if any(not isinstance(target.get(field), str) or not target[field] for field in required):
            raise SystemExit("release target is missing required string fields")
        if target["archive"] not in {"tar.gz", "zip"}:
            raise SystemExit(f"unsupported release archive: {target['archive']}")
        if target["name"] in names:
            raise SystemExit(f"duplicate release target: {target['name']}")
        names.add(target["name"])

    module_path = Path(__file__).with_name("product") / "ncm" / "worker_platform_policy.py"
    spec = importlib.util.spec_from_file_location("release_worker_platform_policy", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit("NCM worker platform policy validator cannot be loaded")
    policy_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy_module)
    policy_path = worker_platforms_path or (
        Path(__file__).resolve().parents[1] / "product/ncm/reference/worker-platforms.json"
    )
    try:
        policy_module.validate_worker_platform_policy(
            policy_path,
            worker_manifest_path=(
                Path(__file__).resolve().parents[1]
                / "product/ncm/reference/worker-manifest.json"
            ),
            release_target_manifest_path=path,
        )
    except policy_module.WorkerPlatformPolicyError as error:
        raise SystemExit(f"invalid release NCM policy: {error}") from error
    return targets


def target_assets(target: dict[str, Any], tag: str, profile: str) -> tuple[str, ...]:
    """Return the complete immutable asset inventory for an admitted target."""
    if profile not in {"stable", "beta"}:
        raise SystemExit(f"unsupported release profile: {profile}")
    prefix = "tracedecay-beta" if profile == "beta" else "tracedecay"
    assets = (
        f"{prefix}-{tag}-{target['name']}.{target['archive']}",
        f"{prefix}-{tag}-{target['name']}.mcpb",
    )
    if target["ncm"] == "supported":
        worker_prefix = target["sidecar"]["worker"]
        if profile == "beta":
            worker_prefix += "-beta"
        worker = f"{worker_prefix}-{tag}-{target['name']}.tar.gz"
        return (*assets, worker, f"{worker}.sha256")
    if target["ncm"] != "native-only":
        raise SystemExit(f"unsupported release NCM status: {target['ncm']}")
    return assets


def target_inventory(target: dict[str, Any], tag: str, profile: str) -> str:
    prefix = "tracedecay-beta" if profile == "beta" else "tracedecay"
    return f"{prefix}-{tag}-{target['name']}.spdx.json"


def files(path: Path) -> set[str]:
    if not path.is_dir():
        raise SystemExit(f"release artifact directory is missing: {path}")
    result = {item.name for item in path.iterdir() if item.is_file() and item.stat().st_size}
    empty = sorted(item.name for item in path.iterdir() if item.is_file() and not item.stat().st_size)
    if empty:
        raise SystemExit("empty release artifacts: " + ", ".join(empty))
    return result


def require_exact(kind: str, actual: set[str], expected: set[str]) -> None:
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise SystemExit(f"{kind} coverage mismatch: {'; '.join(details)}")


def require_whole_targets(
    targets: list[dict[str, Any]],
    binaries: set[str],
    mcpbs: set[str],
    workers: set[str],
    assets: dict[str, tuple[str, ...]],
    inventories: set[str] | None,
    inventory_names: dict[str, str],
) -> list[str]:
    """Partial coverage: every present target is whole, nothing is foreign.

    A publish job that lost one build target still ships the others; the
    recovery planner rebuilds only what is missing. What it must never ship
    is an incomplete target, including its required NCM worker and checksum,
    or a file the manifest does not name.
    """
    extra = sorted(binaries - {names[0] for names in assets.values()}) + sorted(
        mcpbs - {names[1] for names in assets.values()}
    ) + sorted(
        workers - {name for names in assets.values() for name in names[2:]}
    )
    if inventories is not None:
        extra.extend(sorted(inventories - set(inventory_names.values())))
    if extra:
        raise SystemExit("unexpected release artifacts: " + ", ".join(extra))
    missing = []
    for target in targets:
        names = assets[target["name"]]
        present = [names[0] in binaries, names[1] in mcpbs]
        labels = ["archive", "mcpb"]
        if len(names) > 2:
            present.extend(name in workers for name in names[2:])
            labels.extend(("worker", "checksum"))
        if inventories is not None:
            present.append(inventory_names[target["name"]] in inventories)
            labels.append("inventory")
        if any(present) and not all(present):
            raise SystemExit(
                f"release target {target['name']} is half built: "
                + ", ".join(
                    f"{label}={'present' if exists else 'missing'}"
                    for label, exists in zip(labels, present)
                )
            )
        if not any(present):
            missing.append(target["name"])
    if len(missing) == len(targets):
        raise SystemExit("no release target is complete; nothing to publish")
    return missing


def verify_worker_checksums(directory: Path, worker_names: set[str]) -> None:
    for worker in sorted(worker_names):
        checksum_name = f"{worker}.sha256"
        try:
            checksum = (directory / checksum_name).read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise SystemExit(f"invalid NCM worker checksum: {checksum_name}") from error
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([^\r\n]+)\n?", checksum)
        if match is None or match.group(2) != worker:
            raise SystemExit(f"invalid NCM worker checksum: {checksum_name}")
        digest = hashlib.sha256()
        with (directory / worker).open("rb") as archive:
            for chunk in iter(lambda: archive.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != match.group(1).lower():
            raise SystemExit(f"NCM worker checksum mismatch: {worker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--worker-platforms", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--profile", choices=("stable", "beta"), default="stable")
    parser.add_argument("--mcpbs", type=Path)
    parser.add_argument("--ncm-workers", type=Path)
    parser.add_argument(
        "--allow-missing-targets",
        action="store_true",
        help="accept a subset of targets as long as each present target is whole",
    )
    parser.add_argument("--inventories", type=Path)
    arguments = parser.parse_args()
    targets = target_matrix(arguments.manifest, arguments.worker_platforms)
    assets = {
        target["name"]: target_assets(target, arguments.tag, arguments.profile)
        for target in targets
    }
    inventory_name = {
        target["name"]: target_inventory(target, arguments.tag, arguments.profile)
        for target in targets
    }
    if arguments.mcpbs is None:
        raise SystemExit("release validation requires an MCPB directory")
    if arguments.ncm_workers is None:
        raise SystemExit("release validation requires an NCM worker directory")
    binaries = files(arguments.binaries)
    mcpbs = files(arguments.mcpbs)
    workers = files(arguments.ncm_workers)
    worker_archives = {names[2] for names in assets.values() if len(names) > 2}

    inventories = files(arguments.inventories) if arguments.inventories is not None else None
    if arguments.allow_missing_targets:
        missing = require_whole_targets(
            targets, binaries, mcpbs, workers, assets, inventories, inventory_name
        )
        verify_worker_checksums(arguments.ncm_workers, worker_archives & workers)
        if missing:
            print(
                "release artifact coverage is partial; missing targets: "
                + ", ".join(missing)
            )
        else:
            print("release artifact coverage matches target manifest")
        return 0

    require_exact("binary", binaries, {names[0] for names in assets.values()})
    require_exact("MCPB", mcpbs, {names[1] for names in assets.values()})
    require_exact("NCM worker", workers, {
        name for names in assets.values() for name in names[2:]
    })
    verify_worker_checksums(arguments.ncm_workers, worker_archives)
    if inventories is not None:
        require_exact("component inventory", inventories, set(inventory_name.values()))
    print("release artifact coverage matches target manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
