#!/usr/bin/env python3
"""Package a Bazel-built NCM worker, or merge per-target worker manifests.

Package mode consumes an executable, its explicit Rust target triple, and an
output directory. The Bazel ``//product/ncm:worker_bundle`` target supplies
these inputs and writes:

* the worker executable (``tracedecay-ncm-worker``, ``.exe`` on Windows);
* ``worker-manifest.json``, which pins exactly those executable bytes; and
* ``model-acquisition-manifest.json``, the target-independent model descriptor.

The checked-in ``product/ncm/reference/worker-manifest.json`` pins no worker,
so host binaries only admit a worker when their build embeds a pinned manifest.
Bazel passes the generated manifest to the host runtime as a declared build
input. This script also prints the absolute release trust-root assignment,
using forward slashes so POSIX shells preserve Windows paths.
For a multi-platform release, build one bundle per target,
merge their manifests with ``--merge a.json b.json ... -o merged.json``, build
every host binary with the merged manifest, and ship the merged manifest as the
``worker-manifest.json`` of every sidecar: the runtime requires the sidecar
manifest to equal the embedded trust root.

The worker's Bazel target embeds the unpinned reference manifest, so its bytes
never depend on the generated bundle that pins them. This writer runs no build
commands.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePath
import sys
import tempfile
from typing import Any


REPO = Path(__file__).resolve().parents[3]
REFERENCE_WORKER_MANIFEST = REPO / "product/ncm/reference/worker-manifest.json"
MODEL_ACQUISITION_MANIFEST = REPO / "product/ncm/release/model-acquisition-manifest.json"
WORKER_NAME = "tracedecay-ncm-worker"
WORKER_MANIFEST_NAME = "worker-manifest.json"
MODEL_ACQUISITION_MANIFEST_NAME = "model-acquisition-manifest.json"
WORKER_MANIFEST_ENV = "TRACEDECAY_NCM_WORKER_MANIFEST"
HEADER_FIELDS = ("schema_version", "worker", "protocol_version", "protocol_identity")
TARGET_FIELDS = {"triple", "os", "arch", "family", "bytes", "sha256"}


class BundleError(RuntimeError):
    """The worker bundle could not be built, validated, or merged."""


def target_platform(triple: str) -> tuple[str, str, str]:
    """Return Rust's ``(OS, ARCH, FAMILY)`` constants for a worker target triple.

    The Rust verifier compares these against ``std::env::consts`` of the
    running host, so a pin with different metadata can never be admitted.
    """

    parts = triple.split("-")
    if len(parts) < 3 or not all(parts):
        raise BundleError(f"invalid Rust target triple: {triple!r}")
    arch = parts[0]
    if triple.endswith("-apple-darwin"):
        return "macos", arch, "unix"
    if "-pc-windows-" in triple:
        return "windows", arch, "windows"
    if "-linux-" in triple:
        return "linux", arch, "unix"
    raise BundleError(f"unsupported NCM worker target: {triple}")


def worker_executable_name(triple: str) -> str:
    """Return the worker file name for ``triple``, including its EXE suffix."""

    return WORKER_NAME + (".exe" if target_platform(triple)[2] == "windows" else "")


def manifest_header(reference: dict[str, Any]) -> dict[str, Any]:
    """Return the protocol header shared by every pinned worker manifest."""

    missing = [field for field in HEADER_FIELDS if field not in reference]
    if missing:
        raise BundleError(f"reference worker manifest lacks {', '.join(missing)}")
    if reference["worker"] != WORKER_NAME:
        raise BundleError(f"reference worker manifest names {reference['worker']!r}")
    return {field: reference[field] for field in HEADER_FIELDS}


def worker_pin(triple: str, payload: bytes) -> dict[str, Any]:
    """Pin one worker executable for one target."""

    if not payload:
        raise BundleError(f"worker executable for {triple} is empty")
    os_name, arch, family = target_platform(triple)
    return {
        "triple": triple,
        "os": os_name,
        "arch": arch,
        "family": family,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def validate_manifest(manifest: dict[str, Any], *, header: dict[str, Any]) -> None:
    """Apply the rules `worker_artifact.rs` enforces on a trusted manifest."""

    if set(manifest) != set(HEADER_FIELDS) | {"targets"}:
        raise BundleError("worker manifest has unexpected or missing fields")
    for field in HEADER_FIELDS:
        if manifest[field] != header[field]:
            raise BundleError(
                f"worker manifest {field} {manifest[field]!r} differs from {header[field]!r}"
            )
    targets = manifest["targets"]
    if not isinstance(targets, list):
        raise BundleError("worker manifest targets must be a list")
    seen: set[str] = set()
    for entry in targets:
        if not isinstance(entry, dict) or set(entry) != TARGET_FIELDS:
            raise BundleError("worker manifest target has unexpected or missing fields")
        triple = entry["triple"]
        if not isinstance(triple, str) or triple in seen:
            raise BundleError(f"worker manifest repeats target {triple}")
        seen.add(triple)
        if (entry["os"], entry["arch"], entry["family"]) != target_platform(triple):
            raise BundleError(f"worker manifest platform metadata does not match {triple}")
        size = entry["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise BundleError(f"worker manifest target {triple} has an invalid byte count")
        digest = entry["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise BundleError(f"worker manifest target {triple} has an invalid sha256")


def ensure_not_self_referential(payload: bytes, pin_sha256: str) -> None:
    """Reject a worker whose bytes embed the digest that pins them.

    Such a worker would have been built against its own pin, so rebuilding it
    from the same source could never reproduce the pinned bytes.
    """

    if pin_sha256.encode("ascii") in payload or bytes.fromhex(pin_sha256) in payload:
        raise BundleError("worker executable embeds its own pinned digest")


def merge_manifests(manifests: list[dict[str, Any]], *, header: dict[str, Any]) -> dict[str, Any]:
    """Merge per-target manifests into one multi-target trust root."""

    if not manifests:
        raise BundleError("--merge needs at least one worker manifest")
    targets: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        validate_manifest(manifest, header=header)
        for entry in manifest["targets"]:
            if entry["triple"] in targets:
                raise BundleError(f"merged manifests repeat target {entry['triple']}")
            targets[entry["triple"]] = entry
    merged = dict(header, targets=[targets[triple] for triple in sorted(targets)])
    validate_manifest(merged, header=header)
    return merged


def assignment(variable: str, path: PurePath) -> str:
    """Render a path assignment without shell-sensitive Windows backslashes."""

    return f"{variable}={path.as_posix()}"


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2) + "\n").encode("utf-8")


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError(f"read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"{label} {path} must be a JSON object")
    return value


def _replace_file(directory: Path, name: str, payload: bytes, mode: int) -> Path:
    """Atomically publish one bundle file without leaving a prior copy."""

    destination = directory / name
    descriptor, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return destination


def write_bundle(
    output: Path,
    *,
    triple: str,
    payload: bytes,
    header: dict[str, Any],
    model_manifest: bytes,
) -> Path:
    """Write the bundle for one target and return its worker manifest path."""

    manifest = dict(header, targets=[worker_pin(triple, payload)])
    validate_manifest(manifest, header=header)
    ensure_not_self_referential(payload, manifest["targets"][0]["sha256"])
    executable_name = worker_executable_name(triple)
    for other_name in {WORKER_NAME, WORKER_NAME + ".exe"} - {executable_name}:
        other_worker = output / other_name
        if other_worker.exists() or other_worker.is_symlink():
            raise BundleError(f"bundle output already contains another target's worker: {other_worker}")
    output.mkdir(parents=True, exist_ok=True)
    _replace_file(output, executable_name, payload, 0o755)
    _replace_file(output, MODEL_ACQUISITION_MANIFEST_NAME, model_manifest, 0o644)
    return _replace_file(output, WORKER_MANIFEST_NAME, encode_manifest(manifest), 0o644)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", help="Rust target triple of the supplied executable")
    parser.add_argument(
        "--output",
        type=Path,
        help="bundle output directory",
    )
    parser.add_argument(
        "--reference-manifest",
        type=Path,
        default=REFERENCE_WORKER_MANIFEST,
        help="canonical reference worker manifest",
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        default=MODEL_ACQUISITION_MANIFEST,
        help="canonical model acquisition manifest",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--worker", type=Path, help="Bazel-built worker executable to package")
    mode.add_argument(
        "--merge",
        nargs="+",
        type=Path,
        metavar="MANIFEST",
        help="merge per-target worker manifests instead of packaging",
    )
    parser.add_argument("-o", "--merge-output", type=Path, help="merged manifest path")
    arguments = parser.parse_args(argv)
    try:
        header = manifest_header(
            _load_json(arguments.reference_manifest, "reference worker manifest")
        )
        if arguments.merge is not None:
            if arguments.target is not None or arguments.output is not None:
                raise BundleError("--merge cannot be combined with --target or --output")
            if arguments.merge_output is None:
                raise BundleError("--merge requires -o/--merge-output")
            merged = merge_manifests(
                [_load_json(path, "worker manifest") for path in arguments.merge],
                header=header,
            )
            output = arguments.merge_output.absolute()
            output.parent.mkdir(parents=True, exist_ok=True)
            manifest_path = _replace_file(output.parent, output.name, encode_manifest(merged), 0o644)
        else:
            if arguments.target is None or arguments.output is None:
                raise BundleError("--worker requires --target and --output")
            if arguments.merge_output is not None:
                raise BundleError("--merge-output requires --merge")
            triple, worker = arguments.target, arguments.worker
            try:
                payload = worker.read_bytes()
            except OSError as error:
                raise BundleError(f"read built worker {worker}: {error}") from error
            output = arguments.output.absolute()
            manifest_path = write_bundle(
                output,
                triple=triple,
                payload=payload,
                header=header,
                model_manifest=arguments.model_manifest.read_bytes(),
            )
    except (BundleError, OSError, json.JSONDecodeError) as error:
        print(f"NCM worker bundle failed: {error}", file=sys.stderr)
        return 2
    print(assignment(WORKER_MANIFEST_ENV, manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
