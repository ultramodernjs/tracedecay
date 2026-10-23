#!/usr/bin/env python3
"""Validate source feature ownership and the NCM release contract.

Unpublished-crate distribution acceptance was retired upstream. Keep the
fork's source-contract and NCM guards independent of that build pipeline:
optional dependencies stay feature-wired and public `lang-*` aliases match
the extraction owner. Explicit --*-packaged paths may still be supplied to
compare normalized manifests, but no packaging or compilation runs here.

When the source manifest is this checkout's production manifest, the gate also
validates the explicit NCM distribution matrix: arm64 macOS V2 is the only
target allowed to claim the verified worker sidecar and pinned model contract;
all other current release targets must remain Native-only.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tomllib
from typing import Any


REQUIRED_ROOT_FEATURES = {
    "full",
    "token-counting",
    "test-transport",
}
REQUIRED_CLI_FEATURE_MEMBERS = {
    "production": {"tracedecay/production"},
}

# The NCM worker is deliberately a much smaller distribution surface than the
# native providers. Keep this matrix in the distribution gate so a new release
# target cannot accidentally inherit the host's NCM capability claim.
NCM_SUPPORTED_TARGET = "aarch64-apple-darwin"
NCM_RUNTIME_POLICY = {
    "provider_package": "tracedecay-memory-provider-ncm",
    "provider_feature": "rust-backend",
    "runtime_package": "tracedecay-memory-ncm-runtime",
    "runtime_feature": "real-encoder",
    "worker_distribution": "separate-sidecar",
    "worker_manifest": "product/ncm/reference/worker-manifest.json",
    "model_manifest": "product/ncm/reference/embedding-manifest.json",
    "model_acquisition_manifest": "product/ncm/release/model-acquisition-manifest.json",
}
NCM_MODEL_CONTRACT = {
    "model": "paraphrase-multilingual-MiniLM-L12-v2",
    "repository": "Xenova/paraphrase-multilingual-MiniLM-L12-v2",
    "revision": "2c4055b12046f11709e9df2c122e59ffbdc2f900",
    "max_length": 128,
    "pooling": "mean",
    "normalize": True,
}
NCM_MODEL_REVISION_PROVENANCE = (
    "product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
    "#/identities/model/revision"
)
NCM_MODEL_REVISION_RECEIPT_PATH = (
    "product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
)
NCM_MODEL_FILES = {
    "onnx/model.onnx",
    "tokenizer.json",
    "config.json",
    "special_tokens_map.json",
    "tokenizer_config.json",
}
NCM_RELEASE_WORKFLOW_SNIPPETS = (
    "uses: ./.github/actions/build-cli",
    "ncm-worker: ${{ matrix.ncm == 'supported' }}",
    'worker="target/${{ matrix.target }}/release/ncm-worker/tracedecay-ncm-worker"',
    'manifest="target/${{ matrix.target }}/release/ncm-worker/worker-manifest.json"',
    'test -x "$worker"',
    'test -s "$manifest"',
    "--format tar.gz",
    "--entry-name tracedecay-ncm-worker",
    '--companion "$manifest=worker-manifest.json"',
    'model_manifest="target/${{ matrix.target }}/release/ncm-worker/model-acquisition-manifest.json"',
    '--companion "$model_manifest=model-acquisition-manifest.json"',
    "test -x verify-ncm-worker/tracedecay-ncm-worker",
    'cmp "$manifest" verify-ncm-worker/worker-manifest.json',
    'cmp "$model_manifest" verify-ncm-worker/model-acquisition-manifest.json',
    'shasum -a 256 "$archive" > "$archive.sha256"',
    "python3 scripts/product/ncm/verify-installed.py",
    '--worker-manifest "$manifest"',
    '--manifest "$model_manifest"',
    "--binary-archive",
    "--expected-version",
    "--expected-source-sha",
    "--expected-archive-sha256",
    "--expected-binary-sha256",
    '--binary "$binary"',
    "--revision-receipt product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json",
    "--operation install",
    "--installed-e2e",
    "scripts/verify-retained-release-assets.sh",
    "--download-dir retained-assets",
    "isDraft,isPrerelease",
    '--worker-archive "$archive"',
    "--ncm-workers",
)


def load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"distribution acceptance: invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"distribution acceptance: {label} must be a JSON object")
    return value


def optional_dependencies(manifest: dict) -> set[str]:
    names: set[str] = set()

    def collect(table: object) -> None:
        if not isinstance(table, dict):
            return
        dependencies = table.get("dependencies")
        if isinstance(dependencies, dict):
            for name, spec in dependencies.items():
                if isinstance(spec, dict) and spec.get("optional") is True:
                    names.add(name)

    collect(manifest)
    for target in manifest.get("target", {}).values():
        collect(target)
    return names


def dependency_package_names(manifest: dict) -> set[str]:
    names: set[str] = set()

    def collect(table: object) -> None:
        if not isinstance(table, dict):
            return
        dependencies = table.get("dependencies")
        if isinstance(dependencies, dict):
            for name, spec in dependencies.items():
                package = spec.get("package") if isinstance(spec, dict) else None
                names.add(package if isinstance(package, str) else name)

    collect(manifest)
    for target in manifest.get("target", {}).values():
        collect(target)
    return names


def require_matching_features(name: str, source: dict, packaged: dict) -> dict:
    source_features = source.get("features", {})
    packaged_features = packaged.get("features", {})
    if source_features != packaged_features:
        raise SystemExit(
            f"distribution acceptance: packaged {name} feature wiring differs from Cargo.toml"
        )
    return packaged_features


def require_optional_dependencies_wired(name: str, manifest: dict, features: dict) -> None:
    references = {
        item
        for members in features.values()
        for item in members
        if isinstance(item, str)
    }
    unwired = sorted(
        dependency
        for dependency in optional_dependencies(manifest)
        if f"dep:{dependency}" not in references and dependency not in features
    )
    if unwired:
        raise SystemExit(
            f"distribution acceptance: {name} optional dependencies are not feature-wired: "
            + ", ".join(unwired)
        )


def language_feature_names(features: dict) -> set[str]:
    return {name for name in features if name.startswith("lang-")}


def require_language_surface(
    name: str,
    features: dict,
    authority_features: set[str],
) -> None:
    """The public `lang-*` surface must advertise exactly the owner's languages."""
    actual_features = language_feature_names(features)
    if actual_features != authority_features:
        missing = sorted(authority_features - actual_features)
        extra = sorted(actual_features - authority_features)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        raise SystemExit(
            f"distribution acceptance: {name} language features differ from "
            "tracedecay-code-extraction: " + "; ".join(details)
        )


def _ncm_failure(message: str) -> None:
    raise SystemExit(f"distribution acceptance: NCM {message}")


def _load_worker_platform_policy_module() -> Any:
    """Load the shared NCM platform-policy validator without package imports."""
    module_path = Path(__file__).with_name("product") / "ncm" / "worker_platform_policy.py"
    spec = importlib.util.spec_from_file_location(
        "tracedecay_distribution_worker_platform_policy", module_path
    )
    if spec is None or spec.loader is None:
        _ncm_failure(f"worker platform policy validator is unavailable: {module_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        _ncm_failure(f"worker platform policy validator could not load: {error}")
    return module


def expand_local_features(
    features: dict[str, list[str]], selected: list[str]
) -> set[str]:
    """Traverse local aliases; dependency feature edges remain Cargo's job.

    Retained from the retired release-source-profile resolver so the NCM
    guard does not depend on unpublished-crate distribution tooling.
    """
    resolved: set[str] = set()
    pending = list(selected)
    while pending:
        feature = pending.pop()
        if feature in resolved:
            continue
        resolved.add(feature)
        for member in features.get(feature, []):
            if member in features:
                pending.append(member)
    return resolved


def _ncm_feature_members(manifest: dict[str, Any], feature: str, label: str) -> set[str]:
    features = manifest.get("features")
    if not isinstance(features, dict):
        _ncm_failure(f"{label} has no feature table")
    members = features.get(feature)
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        _ncm_failure(f"{label} feature {feature!r} must be a list of feature members")
    return set(members)


def _ncm_required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _ncm_failure(f"{label} must be a non-empty string")
    return value


def _ncm_required_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _ncm_failure(f"{label} must be a positive integer")
    return value


def _require_ncm_runtime_policy(policy: dict[str, Any]) -> dict[str, Any]:
    runtime_policy = policy.get("runtime_policy")
    if not isinstance(runtime_policy, dict):
        _ncm_failure(
            "supported host capability has no runtime_policy for its encoder and artifacts"
        )
    for key, expected in NCM_RUNTIME_POLICY.items():
        if runtime_policy.get(key) != expected:
            _ncm_failure(
                f"runtime_policy.{key} must be {expected!r} for the verified arm64 macOS sidecar"
            )
    if policy.get("worker_manifest") != runtime_policy["worker_manifest"]:
        _ncm_failure("runtime_policy.worker_manifest differs from worker_manifest")
    if policy.get("model_acquisition_manifest") != runtime_policy["model_acquisition_manifest"]:
        _ncm_failure(
            "runtime_policy.model_acquisition_manifest differs from the release model descriptor"
        )
    packaging = policy.get("packaging")
    if not isinstance(packaging, dict):
        _ncm_failure("packaging must describe the worker artifact")
    if packaging.get("worker_distribution") != runtime_policy["worker_distribution"]:
        _ncm_failure(
            "packaging.worker_distribution must match runtime_policy.worker_distribution"
        )
    if packaging.get("model_acquisition_manifest_sidecar_required") is not True:
        _ncm_failure(
            "packaging must require the target-bound model acquisition manifest sidecar"
        )
    return runtime_policy


def _require_ncm_target_matrix(
    policy: dict[str, Any], release_target_manifest: dict[str, Any]
) -> None:
    supported = policy.get("supported_targets")
    if not isinstance(supported, list) or not supported:
        _ncm_failure("distribution matrix must list the NCM-supported worker targets")
    supported_targets: set[str] = set()
    for index, entry in enumerate(supported):
        if not isinstance(entry, dict) or set(entry) != {"target", "status"}:
            _ncm_failure(
                f"supported_targets[{index}] must be exactly a target and status; "
                "worker pins are selected at build time"
            )
        if entry["status"] != "supported":
            _ncm_failure(f"supported_targets[{index}].status must be 'supported'")
        supported_targets.add(
            _ncm_required_string(entry["target"], f"supported_targets[{index}].target")
        )
    if NCM_SUPPORTED_TARGET not in supported_targets:
        _ncm_failure(
            f"supported_targets must include {NCM_SUPPORTED_TARGET}, the release "
            "target that publishes the verified arm64 macOS sidecar"
        )

    release_entries = policy.get("release_targets")
    if not isinstance(release_entries, list) or not release_entries:
        _ncm_failure("release_targets must be a non-empty list")
    release_by_target: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(release_entries):
        if not isinstance(entry, dict):
            _ncm_failure(f"release_targets[{index}] must be an object")
        target = _ncm_required_string(entry.get("target"), f"release_targets[{index}].target")
        if target in release_by_target:
            _ncm_failure(f"release_targets contains duplicate target {target}")
        release_by_target[target] = entry
        expected_status = (
            "supported" if target == NCM_SUPPORTED_TARGET else "native-only"
        )
        if entry.get("ncm") != expected_status:
            _ncm_failure(
                f"release target {target} must declare NCM {expected_status!r}; "
                "only arm64 macOS V2 has a verified worker sidecar"
            )
    if NCM_SUPPORTED_TARGET not in release_by_target:
        _ncm_failure("the supported arm64 macOS target is missing from release_targets")

    include = release_target_manifest.get("include")
    if not isinstance(include, list) or not include:
        _ncm_failure("release target manifest.include must be a non-empty list")
    current_targets: set[str] = set()
    for index, entry in enumerate(include):
        if not isinstance(entry, dict):
            _ncm_failure(f"release target manifest.include[{index}] must be an object")
        target = _ncm_required_string(
            entry.get("target"), f"release target manifest.include[{index}].target"
        )
        if target in current_targets:
            _ncm_failure(f"release target manifest contains duplicate target {target}")
        current_targets.add(target)
        if target not in release_by_target:
            _ncm_failure(
                f"current release target {target} has no explicit Native/NCM policy row"
            )
    policy_targets = set(release_by_target)
    if policy_targets != current_targets:
        missing = sorted(current_targets - policy_targets)
        extra = sorted(policy_targets - current_targets)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        _ncm_failure(
            "release target policy must cover exactly the current release matrix: "
            + "; ".join(details)
        )


def _require_ncm_worker_artifact(
    policy: dict[str, Any], worker_manifest: dict[str, Any]
) -> None:
    worker_name = policy.get("worker")
    if worker_name != "tracedecay-ncm-worker":
        _ncm_failure("worker policy must name tracedecay-ncm-worker")
    # The checked-in manifest is the source trust root and pins no worker.
    # Release builds embed a pinned manifest through
    # TRACEDECAY_NCM_WORKER_MANIFEST (scripts/product/ncm/build-worker-bundle.py).
    if worker_manifest.get("targets") != []:
        _ncm_failure(
            "checked-in worker manifest must pin no worker; release pins are "
            "selected at build time through TRACEDECAY_NCM_WORKER_MANIFEST"
        )


def _require_ncm_release_workflow(path: Path) -> None:
    try:
        workflow = path.read_text(encoding="utf-8")
    except OSError as error:
        _ncm_failure(f"release workflow cannot be read ({path}): {error}")
    missing = [snippet for snippet in NCM_RELEASE_WORKFLOW_SNIPPETS if snippet not in workflow]
    if missing:
        _ncm_failure(
            f"release workflow {path.name} does not implement the verified "
            "sidecar/archive/checksum contract: "
            + "; ".join(missing)
        )
    # The artifact verifier checks worker bytes and digests against the
    # generated manifest. This gate checks that release orchestration reaches
    # that authority with the staged sidecar, only on the declared target.
    for step in ("Package NCM worker sidecar", "Verify installed NCM release"):
        match = re.search(
            rf"(?ms)^      - name: {re.escape(step)}\n(.*?)(?=^      - |\Z)",
            workflow,
        )
        # Recovery jobs only rebuild inventory and have no CLI/worker to
        # package. Accept that additional restriction, never an OR that could
        # admit Native-only targets or an arbitrary replacement condition.
        guard = None if match is None else re.search(r"(?m)^        if: (.+)$", match[1])
        if guard is None or guard[1] not in {
            "matrix.ncm == 'supported'",
            "matrix.ncm == 'supported' && matrix.inventory_only != true",
        }:
            _ncm_failure(
                f"release workflow {path.name} must guard {step!r} with the "
                "supported sidecar target"
            )


def _require_ncm_model_contract(
    model_manifest: dict[str, Any], source_manifest: dict[str, Any] | None
) -> None:
    for key, expected in NCM_MODEL_CONTRACT.items():
        if model_manifest.get(key) != expected:
            _ncm_failure(
                f"pinned model contract field {key} must be {expected!r}"
            )


    provenance = model_manifest.get("revision_provenance")
    if not isinstance(provenance, str) or not provenance.startswith("product/ncm/receipts/"):
        _ncm_failure("pinned model contract must include a receipt-backed revision provenance")

    files = model_manifest.get("files")
    if not isinstance(files, list) or not files:
        _ncm_failure("pinned model contract files must be a non-empty list")
    files_by_path: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            _ncm_failure(f"pinned model contract files[{index}] must be an object")
        path = _ncm_required_string(entry.get("path"), f"pinned model contract files[{index}].path")
        if path in files_by_path:
            _ncm_failure(f"pinned model contract contains duplicate file {path}")
        files_by_path[path] = entry
        _ncm_required_positive_int(
            entry.get("bytes"), f"pinned model contract files[{index}].bytes"
        )
        digest = _ncm_required_string(
            entry.get("sha256"), f"pinned model contract files[{index}].sha256"
        )
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _ncm_failure(
                f"pinned model contract files[{index}].sha256 must be lowercase hexadecimal"
            )
    if set(files_by_path) != NCM_MODEL_FILES:
        missing = sorted(NCM_MODEL_FILES - set(files_by_path))
        extra = sorted(set(files_by_path) - NCM_MODEL_FILES)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("extra " + ", ".join(extra))
        _ncm_failure("pinned model contract file set drift: " + "; ".join(details))

    if source_manifest is None:
        return
    source_model = source_manifest.get("model")
    if not isinstance(source_model, dict):
        _ncm_failure("source-manifest.json has no model contract")
    source_matches = {
        "rust_repository": model_manifest["repository"],
        "rust_revision": model_manifest["revision"],
        "artifact_sha256": files_by_path["onnx/model.onnx"]["sha256"],
        "max_seq_length": model_manifest["max_length"],
        "pooling": model_manifest["pooling"],
        "normalize": model_manifest["normalize"],
    }
    for key, expected in source_matches.items():
        if source_model.get(key) != expected:
            _ncm_failure(
                f"source-manifest.json model field {key} differs from the pinned model contract"
            )


def _require_ncm_model_acquisition_contract(
    acquisition_manifest: dict[str, Any],
    embedding_manifest: dict[str, Any],
    embedding_manifest_path: Path,
    model_revision_receipt_path: Path | None = None,
) -> None:
    """Keep the target-independent release descriptor tied to the model pin."""
    if "target" in acquisition_manifest or "release_name" in acquisition_manifest:
        _ncm_failure("model acquisition manifest must be target-independent")
    expected = {
        "schema_version": 1,
        "manifest_type": "ncm-model-acquisition",
        "provider_id": "ncm",
        "worker": "tracedecay-ncm-worker",
        "embedding_manifest": "product/ncm/reference/embedding-manifest.json",
        "model_root": "models",
        "cache_repository": "models--Xenova--paraphrase-multilingual-MiniLM-L12-v2",
        "model": NCM_MODEL_CONTRACT["model"],
        "repository": NCM_MODEL_CONTRACT["repository"],
        "revision": NCM_MODEL_CONTRACT["revision"],
        "revision_provenance": NCM_MODEL_REVISION_PROVENANCE,
        "max_length": NCM_MODEL_CONTRACT["max_length"],
        "pooling": NCM_MODEL_CONTRACT["pooling"],
        "normalize": NCM_MODEL_CONTRACT["normalize"],
        "transport": "https",
    }
    for key, value in expected.items():
        if acquisition_manifest.get(key) != value:
            _ncm_failure(f"model acquisition manifest field {key} must be {value!r}")
    receipt_digest = acquisition_manifest.get("revision_provenance_sha256")
    if not isinstance(receipt_digest, str) or re.fullmatch(r"[0-9a-f]{64}", receipt_digest) is None:
        _ncm_failure(
            "model acquisition manifest revision_provenance_sha256 must be lowercase hexadecimal"
        )
    try:
        raw_embedding = embedding_manifest_path.read_bytes()
    except OSError as error:
        _ncm_failure(f"cannot read trusted embedding manifest for acquisition validation: {error}")
    if acquisition_manifest.get("embedding_manifest_sha256") != hashlib.sha256(raw_embedding).hexdigest():
        _ncm_failure(
            "model acquisition manifest embedding_manifest_sha256 differs from the trusted embedding manifest"
        )
    files = acquisition_manifest.get("files")
    if not isinstance(files, list) or len(files) != len(NCM_MODEL_FILES):
        _ncm_failure("model acquisition manifest must pin exactly the required model files")
    embedding_files = {
        entry.get("path"): entry
        for entry in embedding_manifest.get("files", [])
        if isinstance(entry, dict)
    }
    seen: set[str] = set()
    base_url = acquisition_manifest.get("base_url")
    expected_base_url = (
        "https://huggingface.co/Xenova/paraphrase-multilingual-MiniLM-L12-v2/resolve/"
        f"{NCM_MODEL_CONTRACT['revision']}/"
    )
    if base_url != expected_base_url:
        _ncm_failure(
            "model acquisition manifest base_url must use the pinned HTTPS model host and revision"
        )
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            _ncm_failure(f"model acquisition manifest files[{index}] must be an object")
        path = entry.get("path")
        if path not in NCM_MODEL_FILES or path in seen:
            _ncm_failure(f"model acquisition manifest files[{index}] has an invalid or duplicate path")
        seen.add(path)
        byte_count = entry.get("bytes")
        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count <= 0:
            _ncm_failure(f"model acquisition manifest files[{index}].bytes must be positive")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            _ncm_failure(f"model acquisition manifest files[{index}].sha256 must be lowercase hexadecimal")
        trusted = embedding_files.get(path)
        if not isinstance(trusted, dict) or trusted.get("bytes") != byte_count or trusted.get("sha256") != digest:
            _ncm_failure(f"model acquisition manifest file pin differs from embedding manifest for {path}")
        if entry.get("url") != f"{base_url}{path}":
            _ncm_failure(f"model acquisition manifest URL is not revision-bound for {path}")
    if seen != NCM_MODEL_FILES:
        _ncm_failure("model acquisition manifest file set differs from the embedding manifest")
    transaction = acquisition_manifest.get("transaction")
    if (
        not isinstance(transaction, dict)
        or transaction.get("version") != 1
        or transaction.get("publication") != "atomic-directory-swap"
        or transaction.get("journal") != "ncm-model-lifecycle-v1.json"
        or transaction.get("staging_prefix") != ".ncm-model-staging-"
        or transaction.get("backup_prefix") != ".ncm-model-backup-"
    ):
        _ncm_failure("model acquisition manifest does not require atomic publication")
    receipt = acquisition_manifest.get("receipt")
    required_receipt_fields = {
        "schema_version",
        "operation_id",
        "operation",
        "outcome",
        "model",
        "repository",
        "revision",
        "manifest_sha256",
        "revision_provenance_sha256",
        "files",
        "created_at_unix",
    }
    receipt_fields = receipt.get("required_fields") if isinstance(receipt, dict) else None
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema_version") != 1
        or receipt.get("relative_path") != "receipts/ncm-model-acquisition-v1.json"
        or not isinstance(receipt_fields, list)
        or not all(isinstance(field, str) for field in receipt_fields)
        or not required_receipt_fields.issubset(set(receipt_fields))
    ):
        _ncm_failure("model acquisition manifest does not name the pinned receipt")

    if model_revision_receipt_path is None:
        _ncm_failure(
            "supported NCM distribution has no canonical model revision receipt"
        )
    if model_revision_receipt_path.name != Path(NCM_MODEL_REVISION_RECEIPT_PATH).name:
        _ncm_failure(
            "supported NCM distribution must use the canonical model revision receipt"
        )
    try:
        receipt_bytes = model_revision_receipt_path.read_bytes()
    except OSError as error:
        _ncm_failure(f"cannot read the pinned model revision receipt: {error}")
    if hashlib.sha256(receipt_bytes).hexdigest() != receipt_digest:
        _ncm_failure(
            "model acquisition manifest revision_provenance_sha256 differs from the pinned receipt"
        )
    try:
        revision_receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _ncm_failure(f"pinned model revision receipt is not valid JSON: {error}")
    if not isinstance(revision_receipt, dict):
        _ncm_failure("pinned model revision receipt must be an object")
    identities = revision_receipt.get("identities")
    model_identity = identities.get("model") if isinstance(identities, dict) else None
    if not isinstance(model_identity, dict):
        _ncm_failure("pinned model revision receipt has no model identity")
    if model_identity.get("model") != NCM_MODEL_CONTRACT["model"]:
        _ncm_failure("pinned model revision receipt model identity drifted")
    if model_identity.get("revision") != NCM_MODEL_CONTRACT["revision"]:
        _ncm_failure("pinned model revision receipt revision identity drifted")
    artifact_digest = model_identity.get("artifact_sha256")
    onnx_digest = next(
        entry["sha256"]
        for entry in acquisition_manifest["files"]
        if isinstance(entry, dict) and entry.get("path") == "onnx/model.onnx"
    )
    if artifact_digest != onnx_digest:
        _ncm_failure("pinned model revision receipt artifact digest drifted")
    receipt_manifest_digest = model_identity.get("manifest_sha256")
    if not isinstance(receipt_manifest_digest, str) or re.fullmatch(
        r"[0-9a-f]{64}", receipt_manifest_digest
    ) is None:
        _ncm_failure("pinned model revision receipt manifest digest is invalid")
    if receipt_manifest_digest != acquisition_manifest["embedding_manifest_sha256"]:
        _ncm_failure(
            "pinned model revision receipt manifest digest differs from the trusted model manifest"
        )
    receipt_files = model_identity.get("files")
    if not isinstance(receipt_files, list):
        _ncm_failure("pinned model revision receipt has no model file identities")
    receipt_files_by_path = {
        entry.get("path"): entry
        for entry in receipt_files
        if isinstance(entry, dict)
    }
    if set(receipt_files_by_path) != set(NCM_MODEL_FILES) or len(receipt_files_by_path) != len(receipt_files):
        _ncm_failure("pinned model revision receipt file identities drifted")
    for entry in acquisition_manifest["files"]:
        receipt_entry = receipt_files_by_path.get(entry["path"])
        if not isinstance(receipt_entry, dict) or receipt_entry.get("bytes") != entry.get("bytes") or receipt_entry.get("sha256") != entry.get("sha256"):
            _ncm_failure(
                f"pinned model revision receipt file identity differs for {entry['path']}"
            )


def _require_ncm_runtime_features(
    root_manifest: dict[str, Any],
    provider_manifest: dict[str, Any],
    runtime_manifest: dict[str, Any],
    runtime_policy: dict[str, Any],
) -> None:
    provider_package = runtime_policy["provider_package"]
    provider_feature = runtime_policy["provider_feature"]
    runtime_package = runtime_policy["runtime_package"]
    runtime_feature = runtime_policy["runtime_feature"]

    root_features = _ncm_feature_members(
        root_manifest, "memory-provider-host", "root manifest"
    )
    if f"dep:{provider_package}" not in root_features:
        _ncm_failure(
            "host capability claims NCM but memory-provider-host does not mount "
            f"dep:{provider_package}"
        )
    root_dependencies = root_manifest.get("dependencies")
    root_dependency = (
        root_dependencies.get(provider_package)
        if isinstance(root_dependencies, dict)
        else None
    )
    if not isinstance(root_dependency, dict) or root_dependency.get("optional") is not True:
        _ncm_failure(
            "host capability claims NCM but its provider dependency is not optional"
        )
    root_provider_features = root_dependency.get("features")
    if (
        not isinstance(root_provider_features, list)
        or provider_feature not in root_provider_features
    ):
        _ncm_failure(
            "host capability claims NCM but the provider dependency does not enable "
            f"{provider_feature!r}"
        )

    if provider_manifest.get("package", {}).get("name") != provider_package:
        _ncm_failure("provider manifest package name differs from runtime_policy.provider_package")
    provider_feature_members = _ncm_feature_members(
        provider_manifest, provider_feature, "NCM provider manifest"
    )
    runtime_edges = {
        f"{runtime_package}/{runtime_feature}",
        f"{runtime_package}?/{runtime_feature}",
    }
    if not provider_feature_members & runtime_edges:
        _ncm_failure(
            "host capability claims NCM but "
            f"{provider_package}/{provider_feature} does not enable "
            f"{runtime_package}/{runtime_feature}"
        )
    provider_dependencies = provider_manifest.get("dependencies")
    runtime_dependency = (
        provider_dependencies.get(runtime_package)
        if isinstance(provider_dependencies, dict)
        else None
    )
    if not isinstance(runtime_dependency, dict):
        _ncm_failure(
            f"NCM provider manifest has no optional {runtime_package} dependency"
        )
    if runtime_dependency.get("optional") is not True:
        _ncm_failure(f"NCM provider dependency {runtime_package} must remain optional")
    if runtime_dependency.get("default-features") is not False:
        _ncm_failure(
            f"NCM provider dependency {runtime_package} must disable default features"
        )

    if runtime_manifest.get("package", {}).get("name") != runtime_package:
        _ncm_failure("runtime manifest package name differs from runtime_policy.runtime_package")
    encoder_members = _ncm_feature_members(
        runtime_manifest, runtime_feature, "NCM runtime manifest"
    )
    if "dep:fastembed" not in encoder_members:
        _ncm_failure(
            "host capability claims NCM but the runtime encoder feature does not "
            "enable dep:fastembed"
        )
    runtime_dependencies = runtime_manifest.get("dependencies")
    fastembed = (
        runtime_dependencies.get("fastembed")
        if isinstance(runtime_dependencies, dict)
        else None
    )
    if not isinstance(fastembed, dict) or fastembed.get("optional") is not True:
        _ncm_failure("NCM runtime encoder dependency fastembed must be optional")
    if fastembed.get("default-features") is not False:
        _ncm_failure("NCM runtime encoder dependency fastembed must disable default features")


def _require_ncm_release_profile(
    root_manifest: dict[str, Any], cli_manifest: dict[str, Any]
) -> None:
    """Validate the source feature profiles consumed by the Bazel CLI build.

    The library's production profile stays Native-only. The CLI includes the
    provider host so operators can opt into NCM; target availability is owned
    by the sidecar matrix and generated worker manifest, not feature selection.
    """
    root_features = root_manifest.get("features")
    if not isinstance(root_features, dict):
        _ncm_failure("root manifest has no feature table for release profile validation")
    _ncm_feature_members(root_manifest, "production", "root manifest")
    root_production = expand_local_features(root_features, ["production"])
    forbidden = root_production & {"memory-provider-host", "test-transport"}
    if forbidden:
        _ncm_failure(
            "library production must exclude " + ", ".join(sorted(forbidden))
        )

    cli_features = cli_manifest.get("features")
    if not isinstance(cli_features, dict):
        _ncm_failure("CLI manifest has no feature table for release profile validation")
    defaults = _ncm_feature_members(cli_manifest, "default", "CLI manifest")
    cli_defaults = expand_local_features(cli_features, sorted(defaults))
    missing = {"production", "memory-provider-host"} - cli_defaults
    if missing:
        _ncm_failure("CLI default must enable " + ", ".join(sorted(missing)))
    default_members: set[str] = set()
    for feature in cli_defaults:
        default_members.update(_ncm_feature_members(cli_manifest, feature, "CLI manifest"))
    if "test-transport" in cli_defaults or default_members & {
        "tracedecay/test-transport",
        "tracedecay?/test-transport",
    }:
        _ncm_failure("CLI default must exclude test-transport")
    host_members: set[str] = set()
    for feature in expand_local_features(cli_features, ["memory-provider-host"]):
        host_members.update(_ncm_feature_members(cli_manifest, feature, "CLI manifest"))
    required_host_members = {
        "tracedecay/memory-provider-host",
        "tracedecay-memory-ncm-runtime/real-encoder",
    }
    missing_host_members = required_host_members - host_members
    if missing_host_members:
        _ncm_failure(
            "CLI memory-provider-host must enable "
            + ", ".join(sorted(missing_host_members))
        )


def validate_ncm_distribution_matrix(
    policy_path: Path,
    *,
    worker_manifest_path: Path,
    model_manifest_path: Path,
    release_target_manifest_path: Path,
    root_manifest_path: Path,
    cli_manifest_path: Path,
    provider_manifest_path: Path,
    runtime_manifest_path: Path,
    source_manifest_path: Path | None = None,
    model_acquisition_manifest_path: Path | None = None,
    model_revision_receipt_path: Path | None = None,
    release_workflow_paths: list[Path] | None = None,
) -> None:
    """Validate NCM's explicit sidecar/native-only distribution matrix.

    The platform-policy checker owns the general worker policy rules. This
    gate adds the release-specific V2 contract: exactly arm64 macOS may claim
    the verified sidecar, its model pin must be present, and the host feature
    must reach the real encoder runtime feature.
    """
    policy_module = _load_worker_platform_policy_module()
    try:
        policy_module.validate_worker_platform_policy(
            policy_path,
            worker_manifest_path=worker_manifest_path,
            release_target_manifest_path=release_target_manifest_path,
        )
    except Exception as error:
        _ncm_failure(f"worker platform policy is invalid: {error}")

    policy = load_json(policy_path, "NCM worker platform policy")
    worker_manifest = load_json(worker_manifest_path, "NCM worker manifest")
    model_manifest = load_json(model_manifest_path, "NCM model manifest")
    release_target_manifest = load_json(
        release_target_manifest_path, "release target manifest"
    )
    root_manifest = load(root_manifest_path)
    provider_manifest = load(provider_manifest_path)
    runtime_manifest = load(runtime_manifest_path)
    source_manifest = (
        load_json(source_manifest_path, "NCM source manifest")
        if source_manifest_path is not None
        else None
    )

    runtime_policy = _require_ncm_runtime_policy(policy)
    _require_ncm_target_matrix(policy, release_target_manifest)
    _require_ncm_worker_artifact(policy, worker_manifest)
    _require_ncm_model_contract(model_manifest, source_manifest)
    if model_acquisition_manifest_path is None:
        _ncm_failure("supported NCM distribution has no model acquisition manifest")
    acquisition_manifest = load_json(
        model_acquisition_manifest_path, "NCM model acquisition manifest"
    )
    _require_ncm_model_acquisition_contract(
        acquisition_manifest,
        model_manifest,
        model_manifest_path,
        model_revision_receipt_path,
    )
    _require_ncm_runtime_features(
        root_manifest, provider_manifest, runtime_manifest, runtime_policy
    )
    _require_ncm_release_profile(root_manifest, load(cli_manifest_path))
    for workflow_path in release_workflow_paths or []:
        _require_ncm_release_workflow(workflow_path)


def validate(
    root_source: dict,
    root_packaged: dict,
    code_index_source: dict,
    code_index_packaged: dict,
    extraction_source: dict,
    extraction_packaged: dict,
    cli_source: dict,
    cli_packaged: dict,
) -> None:
    root_features = require_matching_features("root", root_source, root_packaged)
    missing = sorted(REQUIRED_ROOT_FEATURES - root_features.keys())
    if missing:
        raise SystemExit(
            "distribution acceptance: source manifest is missing required features: "
            + ", ".join(missing)
        )
    require_optional_dependencies_wired("root", root_packaged, root_features)

    require_matching_features(
        "tracedecay-code-index", code_index_source, code_index_packaged
    )
    extraction_features = require_matching_features(
        "tracedecay-code-extraction", extraction_source, extraction_packaged
    )
    require_language_surface(
        "root", root_features, language_feature_names(extraction_features)
    )
    require_optional_dependencies_wired(
        "tracedecay-code-extraction", extraction_packaged, extraction_features
    )

    cli_features = require_matching_features(
        "tracedecay-cli", cli_source, cli_packaged
    )
    missing_cli = sorted(
        REQUIRED_CLI_FEATURE_MEMBERS.keys() - cli_features.keys()
    )
    if missing_cli:
        raise SystemExit(
            "distribution acceptance: tracedecay-cli is missing required features: "
            + ", ".join(missing_cli)
        )
    for feature, expected in REQUIRED_CLI_FEATURE_MEMBERS.items():
        members = cli_features.get(feature)
        # Extra crate passthroughs are allowed; the contract is the required
        # release members, not an exhaustive crate inventory.
        if not isinstance(members, list) or not expected.issubset(members):
            raise SystemExit(
                f"distribution acceptance: tracedecay-cli {feature} must enable "
                + ", ".join(sorted(expected))
            )
    require_optional_dependencies_wired(
        "tracedecay-cli", cli_packaged, cli_features
    )


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    root_manifest = repo / "crates/tracedecay/Cargo.toml"
    code_index_manifest = repo / "crates/tracedecay-code-index/Cargo.toml"
    extraction_manifest = repo / "crates/tracedecay-code-extraction/Cargo.toml"
    cli_manifest = repo / "crates/tracedecay-cli/Cargo.toml"
    ncm_policy = repo / "product/ncm/reference/worker-platforms.json"
    ncm_worker_manifest = repo / "product/ncm/reference/worker-manifest.json"
    ncm_model_manifest = repo / "product/ncm/reference/embedding-manifest.json"
    ncm_model_acquisition_manifest = (
        repo / "product/ncm/release/model-acquisition-manifest.json"
    )
    ncm_release_targets = repo / ".github/release-targets.json"
    ncm_provider_manifest = repo / "crates/tracedecay-memory-provider-ncm/Cargo.toml"
    ncm_runtime_manifest = repo / "crates/tracedecay-memory-ncm-runtime/Cargo.toml"
    ncm_source_manifest = repo / "product/ncm/reference/source-manifest.json"
    ncm_release_workflows = [
        repo / ".github/workflows/release.yml",
        repo / ".github/workflows/release-beta.yml",
    ]
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Default to source-contract validation, not package verification. Optional
    # normalized manifests retain the comparison API used by regression fixtures.
    parser.add_argument("--root-source", type=Path, default=root_manifest)
    parser.add_argument("--root-packaged", type=Path)
    parser.add_argument("--code-index-source", type=Path, default=code_index_manifest)
    parser.add_argument("--code-index-packaged", type=Path)
    parser.add_argument("--extraction-source", type=Path, default=extraction_manifest)
    parser.add_argument("--extraction-packaged", type=Path)
    parser.add_argument("--cli-source", type=Path, default=cli_manifest)
    parser.add_argument("--cli-packaged", type=Path)
    parser.add_argument("--ncm-platform-policy", type=Path)
    parser.add_argument("--ncm-worker-manifest", type=Path)
    parser.add_argument("--ncm-model-manifest", type=Path)
    parser.add_argument("--ncm-model-acquisition-manifest", type=Path)
    parser.add_argument("--ncm-model-revision-receipt", type=Path)
    parser.add_argument("--ncm-release-targets", type=Path)
    parser.add_argument("--ncm-provider-manifest", type=Path)
    parser.add_argument("--ncm-runtime-manifest", type=Path)
    parser.add_argument("--ncm-source-manifest", type=Path)
    parser.add_argument("--ncm-release-workflow", type=Path, action="append")
    arguments = parser.parse_args()
    root_source = load(arguments.root_source)
    extraction_packaged = load(arguments.extraction_packaged or arguments.extraction_source)
    validate(
        root_source,
        load(arguments.root_packaged or arguments.root_source),
        load(arguments.code_index_source),
        load(arguments.code_index_packaged or arguments.code_index_source),
        load(arguments.extraction_source),
        extraction_packaged,
        load(arguments.cli_source),
        load(arguments.cli_packaged or arguments.cli_source),
    )
    # Production source checks always validate NCM. Temporary fixture roots
    # opt in explicitly so generic feature fixtures need no release assets.
    ncm_policy_path = arguments.ncm_platform_policy
    if ncm_policy_path is None and arguments.root_source.resolve() == root_manifest.resolve():
        ncm_policy_path = ncm_policy
    if ncm_policy_path is not None:
        validate_ncm_distribution_matrix(
            ncm_policy_path,
            worker_manifest_path=arguments.ncm_worker_manifest or ncm_worker_manifest,
            model_manifest_path=arguments.ncm_model_manifest or ncm_model_manifest,
            release_target_manifest_path=arguments.ncm_release_targets or ncm_release_targets,
            root_manifest_path=arguments.root_source,
            cli_manifest_path=arguments.cli_source,
            provider_manifest_path=arguments.ncm_provider_manifest or ncm_provider_manifest,
            runtime_manifest_path=arguments.ncm_runtime_manifest or ncm_runtime_manifest,
            source_manifest_path=(
                arguments.ncm_source_manifest
                if arguments.ncm_source_manifest is not None
                else ncm_source_manifest
                if ncm_policy_path.resolve() == ncm_policy.resolve()
                and ncm_source_manifest.exists()
                else None
            ),
            model_acquisition_manifest_path=(
                arguments.ncm_model_acquisition_manifest
                if arguments.ncm_model_acquisition_manifest is not None
                else ncm_model_acquisition_manifest
                if ncm_policy_path.resolve() == ncm_policy.resolve()
                and ncm_model_acquisition_manifest.exists()
                else None
            ),
            model_revision_receipt_path=(
                arguments.ncm_model_revision_receipt
                if arguments.ncm_model_revision_receipt is not None
                else repo / NCM_MODEL_REVISION_RECEIPT_PATH
                if ncm_policy_path.resolve() == ncm_policy.resolve()
                and (repo / NCM_MODEL_REVISION_RECEIPT_PATH).exists()
                else None
            ),
            release_workflow_paths=(
                arguments.ncm_release_workflow
                if arguments.ncm_release_workflow is not None
                else ncm_release_workflows
                if ncm_policy_path.resolve() == ncm_policy.resolve()
                else None
            ),
        )
    print("source feature wiring and NCM release contracts are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
