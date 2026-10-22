#!/usr/bin/env python3
"""Plan release work without rebuilding already-published immutable artifacts."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from typing import Any


def artifact_checker() -> Any:
    """Reuse the release checker's admitted targets and exact asset inventory."""
    path = Path(__file__).with_name("check-release-artifacts.py")
    spec = importlib.util.spec_from_file_location("release_artifact_checker", path)
    if spec is None or spec.loader is None:
        raise SystemExit("release artifact checker cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def plan(
    targets: list[dict[str, Any]],
    tag: str,
    profile: str,
    existing: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    checker = artifact_checker()
    packages = {
        target["name"]: checker.target_assets(target, tag, profile)
        for target in targets
    }
    inventories = {
        target["name"]: checker.target_inventory(target, tag, profile)
        for target in targets
    }
    expected_mutable = {
        asset for names in packages.values() for asset in names
    } | set(inventories.values())
    # Both profiles publish the installer beside the archives, so `install.sh`
    # is immutable release metadata on a prerelease exactly as it is on a
    # stable release. While it counted as unexpected under `beta`, uploading
    # it to a prerelease would have made every later recovery run for that tag
    # abort.
    fixed = {"SHA256SUMS", "install.sh"}
    unexpected = sorted(existing - expected_mutable - fixed)
    if unexpected:
        raise SystemExit(
            "unexpected existing release assets: " + ", ".join(unexpected)
        )

    missing_packages = {
        name: any(asset not in existing for asset in names)
        for name, names in packages.items()
    }
    missing_targets = [
        {
            **target,
            **(
                {"inventory_only": True}
                if not missing_packages[target["name"]]
                else {}
            ),
        }
        for target in targets
        if missing_packages[target["name"]]
        or inventories[target["name"]] not in existing
    ]
    finalized = sorted(existing & fixed)
    if finalized and any(missing_packages[target["name"]] for target in missing_targets):
        raise SystemExit(
            "final release metadata exists before all immutable artifacts "
            f"({', '.join(finalized)}); refusing destructive recovery"
        )
    retained = sorted(existing & expected_mutable)
    return missing_targets, retained


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--worker-platforms", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--profile", choices=("stable", "beta"), default="stable")
    parser.add_argument("--asset-names", type=Path, required=True)
    parser.add_argument("--retained-output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    arguments = parser.parse_args()

    targets = artifact_checker().target_matrix(
        arguments.manifest, arguments.worker_platforms
    )
    existing = {
        line
        for line in arguments.asset_names.read_text(encoding="utf-8").splitlines()
        if line
    }
    missing, retained = plan(targets, arguments.tag, arguments.profile, existing)
    arguments.retained_output.write_text(
        "".join(f"{asset}\n" for asset in retained),
        encoding="utf-8",
    )
    matrix = json.dumps({"include": missing}, separators=(",", ":"))
    package_build_required = any(
        not target.get("inventory_only", False) for target in missing
    )
    with arguments.github_output.open("a", encoding="utf-8") as output:
        output.write(f"matrix={matrix}\n")
        output.write(f"build_required={'true' if missing else 'false'}\n")
        output.write(
            f"package_build_required={'true' if package_build_required else 'false'}\n"
        )


if __name__ == "__main__":
    main()
