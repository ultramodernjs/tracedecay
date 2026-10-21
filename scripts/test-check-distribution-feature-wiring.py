#!/usr/bin/env python3
"""Regression tests for source features and NCM release contract validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


VALIDATOR = Path(__file__).with_name("check-distribution-feature-wiring.py")

ROOT_MANIFEST = """[package]
name = "tracedecay"
version = "0.1.0-beta.34"

[dependencies]
tracedecay-code-index = { version = "0.1.0" }
tracedecay-application = { version = "0.1.0" }

[features]
lite = ["tracedecay-code-index/lite", "tracedecay-code-index-runtime/lite"]
medium = ["tracedecay-code-index/medium"]
full = ["tracedecay-code-index/full", "tracedecay-code-index-runtime/full"]
lang-dart = ["tracedecay-code-index/lang-dart"]
lang-markdown = ["tracedecay-code-index/lang-markdown"]
token-counting = []
test-transport = []
"""

CODE_INDEX_MANIFEST = """[package]
name = "tracedecay-code-index"
version = "0.1.0"

[dependencies]
tracedecay-code-extraction = { version = "0.1.0" }

[features]
lite = ["tracedecay-code-extraction/lite", "lang-markdown"]
medium = ["tracedecay-code-extraction/medium"]
full = ["tracedecay-code-extraction/full", "lang-markdown"]
lang-dart = ["tracedecay-code-extraction/lang-dart"]
lang-markdown = ["tracedecay-code-extraction/lang-markdown"]
"""

EXTRACTION_MANIFEST = """[package]
name = "tracedecay-code-extraction"
version = "0.1.0"

[features]
lite = ["lang-markdown"]
medium = ["lang-dart"]
full = ["medium", "lang-markdown"]
lang-dart = []
lang-markdown = []
"""

CLI_MANIFEST = """[package]
name = "tracedecay-cli"
version = "0.1.0"

[dependencies]
tracedecay = { version = "0.1.0" }

[features]
default = ["production"]
production = ["tracedecay/production"]
"""

NCM_ROOT_MANIFEST = ROOT_MANIFEST.replace(
    "[dependencies]\n",
    "[dependencies]\n"
    'tracedecay-memory-provider-ncm = { version = "0.1.0", optional = true, '
    'features = ["rust-backend"] }\n',
).replace(
    "[features]\n",
    '[features]\ndefault = ["production"]\n'
    'production = ["token-counting", "lite", "full"]\n'
    'memory-provider-host = ["dep:tracedecay-memory-provider-ncm"]\n',
)

NCM_CLI_MANIFEST = CLI_MANIFEST.replace(
    'tracedecay = { version = "0.1.0" }',
    'tracedecay = { version = "0.1.0" }\n'
    'tracedecay-memory-ncm-runtime = { version = "0.1.0", default-features = false }',
).replace(
    'default = ["production"]',
    'default = ["production", "memory-provider-host"]',
).replace(
    'production = ["tracedecay/production"]',
    'production = ["tracedecay/production"]\n'
    'memory-provider-host = ["tracedecay/memory-provider-host", '
    '"tracedecay-memory-ncm-runtime/real-encoder"]',
)

NCM_PROVIDER_MANIFEST = """[package]
name = "tracedecay-memory-provider-ncm"
version = "0.1.0"

[features]
default = []
rust-backend = [
    "dep:tracedecay-memory-ncm-runtime",
    "tracedecay-memory-ncm-runtime/real-encoder",
]

[dependencies]
tracedecay-memory-ncm-runtime = { path = "../tracedecay-memory-ncm-runtime", optional = true, default-features = false }
"""

NCM_RUNTIME_MANIFEST = """[package]
name = "tracedecay-memory-ncm-runtime"
version = "0.1.0"

[features]
default = []
real-encoder = ["dep:fastembed"]

[dependencies]
fastembed = { version = "1", optional = true, default-features = false }
"""

NCM_POLICY = {
    "schema_version": 1,
    "provider_id": "ncm",
    "worker": "tracedecay-ncm-worker",
    "policy": "pinned-artifact-only",
    "worker_manifest": "product/ncm/reference/worker-manifest.json",
    "model_acquisition_manifest": "product/ncm/release/model-acquisition-manifest.json",
    "release_target_manifest": ".github/release-targets.json",
    "fallback": "native-only",
    "runtime_policy": {
        "provider_package": "tracedecay-memory-provider-ncm",
        "provider_feature": "rust-backend",
        "runtime_package": "tracedecay-memory-ncm-runtime",
        "runtime_feature": "real-encoder",
        "worker_distribution": "separate-sidecar",
        "worker_manifest": "product/ncm/reference/worker-manifest.json",
        "model_manifest": "product/ncm/reference/embedding-manifest.json",
        "model_acquisition_manifest": "product/ncm/release/model-acquisition-manifest.json",
    },
    "packaging": {
        "worker_distribution": "separate-sidecar",
        "standard_cli_archive_includes_worker": False,
        "manifest_sidecar_required": True,
        "model_acquisition_manifest_sidecar_required": True,
    },
    "supported_targets": [
        {"target": target, "status": "supported"}
        for target in (
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            "aarch64-pc-windows-msvc",
            "x86_64-pc-windows-msvc",
        )
    ],
    "unsupported_targets": [
        {"target": "x86_64-unknown-linux-musl", "reason": "no-prebuilt-onnxruntime"},
    ],
    "release_targets": [
        {
            "name": "aarch64-macos",
            "target": "aarch64-apple-darwin",
            "ncm": "supported",
        },
        {
            "name": "x86_64-linux",
            "target": "x86_64-unknown-linux-gnu",
            "ncm": "native-only",
        },
        {
            "name": "aarch64-linux",
            "target": "aarch64-unknown-linux-gnu",
            "ncm": "native-only",
        },
        {
            "name": "x86_64-windows",
            "target": "x86_64-pc-windows-msvc",
            "ncm": "native-only",
        },
    ],
}

NCM_WORKER_MANIFEST = {
    "schema_version": 1,
    "worker": "tracedecay-ncm-worker",
    "protocol_version": 1,
    "protocol_identity": "tracedecay.ncm.worker.v1",
    "targets": [],
}

NCM_MODEL_MANIFEST = {
    "model": "paraphrase-multilingual-MiniLM-L12-v2",
    "repository": "Xenova/paraphrase-multilingual-MiniLM-L12-v2",
    "revision": "2c4055b12046f11709e9df2c122e59ffbdc2f900",
    "revision_provenance": (
        "product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
        "#/identities/model/revision"
    ),
    "files": [
        {"path": path, "sha256": "b" * 64, "bytes": 1}
        for path in (
            "onnx/model.onnx",
            "tokenizer.json",
            "config.json",
            "special_tokens_map.json",
            "tokenizer_config.json",
        )
    ],
    "max_length": 128,
    "pooling": "mean",
    "normalize": True,
}

NCM_MODEL_ACQUISITION_MANIFEST = {
    "schema_version": 1,
    "manifest_type": "ncm-model-acquisition",
    "provider_id": "ncm",
    "worker": "tracedecay-ncm-worker",
    "embedding_manifest": "product/ncm/reference/embedding-manifest.json",
    "embedding_manifest_sha256": hashlib.sha256(
        json.dumps(NCM_MODEL_MANIFEST).encode("utf-8")
    ).hexdigest(),
    "model_root": "models",
    "cache_repository": "models--Xenova--paraphrase-multilingual-MiniLM-L12-v2",
    "model": "paraphrase-multilingual-MiniLM-L12-v2",
    "repository": "Xenova/paraphrase-multilingual-MiniLM-L12-v2",
    "revision": "2c4055b12046f11709e9df2c122e59ffbdc2f900",
    "revision_provenance": NCM_MODEL_MANIFEST["revision_provenance"],
    "revision_provenance_sha256": "c" * 64,
    "max_length": 128,
    "pooling": "mean",
    "normalize": True,
    "transport": "https",
    "base_url": (
        "https://huggingface.co/Xenova/paraphrase-multilingual-MiniLM-L12-v2/resolve/"
        "2c4055b12046f11709e9df2c122e59ffbdc2f900/"
    ),
    "files": [
        {
            **entry,
            "url": (
                "https://huggingface.co/Xenova/paraphrase-multilingual-MiniLM-L12-v2/resolve/"
                f"2c4055b12046f11709e9df2c122e59ffbdc2f900/{entry['path']}"
            ),
        }
        for entry in NCM_MODEL_MANIFEST["files"]
    ],
    "transaction": {
        "version": 1,
        "publication": "atomic-directory-swap",
        "journal": "ncm-model-lifecycle-v1.json",
        "staging_prefix": ".ncm-model-staging-",
        "backup_prefix": ".ncm-model-backup-",
    },
    "receipt": {
        "schema_version": 1,
        "relative_path": "receipts/ncm-model-acquisition-v1.json",
        "required_fields": [
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
        ],
    },
}

NCM_RELEASE_TARGETS = {
    "include": [
        {
            "name": "aarch64-macos",
            "runner": "macos-14",
            "target": "aarch64-apple-darwin",
            "archive": "tar.gz",
            "ncm": "supported",
            "sidecar": {
                "worker": "tracedecay-ncm-worker",
                "archive": "tar.gz",
                "manifest": "worker-manifest.json",
                "model_manifest": "model-acquisition-manifest.json",
                "checksum": "sha256",
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


def ncm_revision_receipt() -> dict[str, object]:
    files = [
        {
            "path": entry["path"],
            "bytes": entry["bytes"],
            "sha256": entry["sha256"],
        }
        for entry in NCM_MODEL_MANIFEST["files"]
    ]
    return {
        "schema_version": 1,
        "identities": {
            "model": {
                "model": NCM_MODEL_MANIFEST["model"],
                "revision": NCM_MODEL_MANIFEST["revision"],
                "artifact_sha256": files[0]["sha256"],
                "manifest_sha256": hashlib.sha256(
                    json.dumps(NCM_MODEL_MANIFEST).encode("utf-8")
                ).hexdigest(),
                "files": files,
            }
        },
    }


def ncm_fixture() -> dict[str, object]:
    receipt = ncm_revision_receipt()
    acquisition = json.loads(json.dumps(NCM_MODEL_ACQUISITION_MANIFEST))
    acquisition["revision_provenance_sha256"] = hashlib.sha256(
        json.dumps(receipt).encode("utf-8")
    ).hexdigest()
    return {
        "policy.json": json.loads(json.dumps(NCM_POLICY)),
        "worker.json": json.loads(json.dumps(NCM_WORKER_MANIFEST)),
        "model.json": json.loads(json.dumps(NCM_MODEL_MANIFEST)),
        "model-acquisition.json": acquisition,
        "2fc72f1d81f543224d8e7d8ef19195b026ba855f.json": receipt,
        "release-targets.json": json.loads(json.dumps(NCM_RELEASE_TARGETS)),
        "provider.toml": NCM_PROVIDER_MANIFEST,
        "runtime.toml": NCM_RUNTIME_MANIFEST,
    }


@dataclass(frozen=True)
class FixtureResult:
    returncode: int
    stdout: str
    stderr: str


def run_fixture(
    root_source: str = ROOT_MANIFEST,
    root_packaged: str = ROOT_MANIFEST,
    code_index_source: str = CODE_INDEX_MANIFEST,
    code_index_packaged: str = CODE_INDEX_MANIFEST,
    extraction_source: str = EXTRACTION_MANIFEST,
    extraction_packaged: str = EXTRACTION_MANIFEST,
    cli_source: str | None = None,
    cli_packaged: str | None = None,
    source_only: bool = False,
    ncm_files: dict[str, object] | None = None,
    ncm_workflows: list[Path] | None = None,
) -> FixtureResult:
    default_cli_manifest = NCM_CLI_MANIFEST if ncm_files is not None else CLI_MANIFEST
    if cli_source is None:
        cli_source = default_cli_manifest
    if cli_packaged is None:
        cli_packaged = default_cli_manifest
    with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary_directory:
        root = Path(temporary_directory)
        manifests = {
            "root-source.toml": root_source,
            "root-packaged.toml": root_packaged,
            "code-index-source.toml": code_index_source,
            "code-index-packaged.toml": code_index_packaged,
            "extraction-source.toml": extraction_source,
            "extraction-packaged.toml": extraction_packaged,
            "cli-source.toml": cli_source,
            "cli-packaged.toml": cli_packaged,
        }
        for name, contents in manifests.items():
            root.joinpath(name).write_text(contents, encoding="utf-8")
        command = [
            sys.executable,
            "-B",
            str(VALIDATOR),
            "--root-source",
            str(root / "root-source.toml"),
            "--root-packaged",
            str(root / "root-packaged.toml"),
            "--code-index-source",
            str(root / "code-index-source.toml"),
            "--code-index-packaged",
            str(root / "code-index-packaged.toml"),
            "--extraction-source",
            str(root / "extraction-source.toml"),
            "--extraction-packaged",
            str(root / "extraction-packaged.toml"),
            "--cli-source",
            str(root / "cli-source.toml"),
            "--cli-packaged",
            str(root / "cli-packaged.toml"),
        ]
        if ncm_files is not None:
            for name, contents in ncm_files.items():
                path = root / name
                if isinstance(contents, str):
                    text = contents
                else:
                    text = json.dumps(contents)
                path.write_text(text, encoding="utf-8")
            command.extend(
                [
                    "--ncm-platform-policy",
                    str(root / "policy.json"),
                    "--ncm-worker-manifest",
                    str(root / "worker.json"),
                    "--ncm-model-manifest",
                    str(root / "model.json"),
                    "--ncm-model-acquisition-manifest",
                    str(root / "model-acquisition.json"),
                    "--ncm-model-revision-receipt",
                    str(root / "2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"),
                    "--ncm-release-targets",
                    str(root / "release-targets.json"),
                    "--ncm-provider-manifest",
                    str(root / "provider.toml"),
                    "--ncm-runtime-manifest",
                    str(root / "runtime.toml"),
                ]
            )
            for workflow in ncm_workflows or []:
                command.extend(["--ncm-release-workflow", str(workflow)])
        if source_only:
            for option in ("--root-packaged", "--code-index-packaged", "--extraction-packaged", "--cli-packaged"):
                index = command.index(option)
                del command[index:index + 2]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
        return FixtureResult(completed.returncode, completed.stdout, completed.stderr)


def check_ncm_release_profiles() -> None:
    for cli in [
        NCM_CLI_MANIFEST,
        NCM_CLI_MANIFEST.replace(
            'memory-provider-host = ["tracedecay/memory-provider-host", '
            '"tracedecay-memory-ncm-runtime/real-encoder"]',
            'memory-provider-host = ["provider-forwarding"]\n'
            'provider-forwarding = ["tracedecay/memory-provider-host", '
            '"tracedecay-memory-ncm-runtime/real-encoder"]',
        ),
    ]:
        valid = run_fixture(
            root_source=NCM_ROOT_MANIFEST,
            root_packaged=NCM_ROOT_MANIFEST,
            cli_source=cli,
            cli_packaged=cli,
            ncm_files=ncm_fixture(),
        )
        if valid.returncode != 0:
            raise SystemExit("valid NCM CLI release profile was rejected: " + valid.stderr)

    cases = [
        (
            "library production reaching the provider host indirectly",
            NCM_ROOT_MANIFEST.replace(
                'full = ["tracedecay-code-index/full", "tracedecay-code-index-runtime/full"]',
                'full = ["tracedecay-code-index/full", "tracedecay-code-index-runtime/full", "memory-provider-host"]',
            ),
            NCM_CLI_MANIFEST,
            "library production must exclude memory-provider-host",
        ),
        (
            "library production enabling test transport",
            NCM_ROOT_MANIFEST.replace(
                'production = ["token-counting", "lite", "full"]',
                'production = ["token-counting", "lite", "full", "test-transport"]',
            ),
            NCM_CLI_MANIFEST,
            "library production must exclude test-transport",
        ),
        (
            "CLI default omitting the provider host",
            NCM_ROOT_MANIFEST,
            NCM_CLI_MANIFEST.replace(
                'default = ["production", "memory-provider-host"]',
                'default = ["production"]',
            ),
            "CLI default must enable memory-provider-host",
        ),
        (
            "CLI default omitting production",
            NCM_ROOT_MANIFEST,
            NCM_CLI_MANIFEST.replace(
                'default = ["production", "memory-provider-host"]',
                'default = ["memory-provider-host"]',
            ),
            "CLI default must enable production",
        ),
        (
            "CLI host omitting the real encoder",
            NCM_ROOT_MANIFEST,
            NCM_CLI_MANIFEST.replace(
                ', "tracedecay-memory-ncm-runtime/real-encoder"', ""
            ),
            "CLI memory-provider-host must enable tracedecay-memory-ncm-runtime/real-encoder",
        ),
        (
            "CLI default reaching test transport through a local alias",
            NCM_ROOT_MANIFEST,
            NCM_CLI_MANIFEST.replace(
                'production = ["tracedecay/production"]',
                'production = ["tracedecay/production", "transport-alias"]\n'
                'transport-alias = ["test-transport"]\n'
                'test-transport = ["tracedecay/test-transport"]',
            ),
            "CLI default must exclude test-transport",
        ),
        (
            "CLI default forwarding test transport directly",
            NCM_ROOT_MANIFEST,
            NCM_CLI_MANIFEST.replace(
                'production = ["tracedecay/production"]',
                'production = ["tracedecay/production", "tracedecay/test-transport"]',
            ),
            "CLI default must exclude test-transport",
        ),
    ]
    for label, root, cli, expected_failure in cases:
        result = run_fixture(
            root_source=root,
            root_packaged=root,
            cli_source=cli,
            cli_packaged=cli,
            ncm_files=ncm_fixture(),
        )
        if result.returncode == 0:
            raise SystemExit(f"{label} was accepted")
        if expected_failure not in result.stderr:
            raise SystemExit(f"{label} failed for an unexpected reason: {result.stderr}")


def main() -> int:
    source_contract = run_fixture(source_only=True)
    if source_contract.returncode != 0:
        raise SystemExit("source-only feature contract was rejected: " + source_contract.stderr)
    ncm_source_contract = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        ncm_files=ncm_fixture(),
        source_only=True,
    )
    if ncm_source_contract.returncode != 0:
        raise SystemExit("source-only NCM contract was rejected: " + ncm_source_contract.stderr)
    source_without_host = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        cli_source=NCM_CLI_MANIFEST.replace(
            'default = ["production", "memory-provider-host"]',
            'default = ["production"]',
        ),
        ncm_files=ncm_fixture(),
        source_only=True,
    )
    if source_without_host.returncode == 0 or "CLI default must enable memory-provider-host" not in source_without_host.stderr:
        raise SystemExit("source-only NCM check did not reject a missing host: " + source_without_host.stderr)

    extracted_owner = run_fixture()
    if extracted_owner.returncode != 0:
        raise SystemExit(extracted_owner.stderr)

    cli_without_production = CLI_MANIFEST.replace(
        'production = ["tracedecay/production"]\n',
        "",
    )
    missing_cli_production = run_fixture(
        cli_source=cli_without_production,
        cli_packaged=cli_without_production,
    )
    if missing_cli_production.returncode == 0:
        raise SystemExit("CLI without the production release feature was accepted")
    if (
        "tracedecay-cli is missing required features"
        not in missing_cli_production.stderr
    ):
        raise SystemExit("missing CLI production feature failed for an unexpected reason")

    cli_with_miswired_production = CLI_MANIFEST.replace(
        'production = ["tracedecay/production"]',
        'production = []',
    )
    miswired_cli_production = run_fixture(
        cli_source=cli_with_miswired_production,
        cli_packaged=cli_with_miswired_production,
    )
    if miswired_cli_production.returncode == 0:
        raise SystemExit("CLI with a mountless production feature was accepted")
    if (
        "tracedecay-cli production must enable"
        not in miswired_cli_production.stderr
    ):
        raise SystemExit("miswired CLI production feature failed for an unexpected reason")

    # Internal forwarding topology is not a contract: rerouting a tier through
    # a different intermediate edge, forwarding a language alias through the
    # runtime crate, and adding a local tier member are all accepted without
    # touching this validator.
    rewired_root = ROOT_MANIFEST.replace(
        'lite = ["tracedecay-code-index/lite", "tracedecay-code-index-runtime/lite"]',
        'lite = ["tracedecay-code-index-runtime/lite"]',
    ).replace(
        'lang-dart = ["tracedecay-code-index/lang-dart"]',
        'lang-dart = ["tracedecay-code-index-runtime/lang-dart"]',
    ).replace(
        'full = ["tracedecay-code-index/full", "tracedecay-code-index-runtime/full"]',
        'full = ["tracedecay-code-index/full", "tracedecay-code-index-runtime/full", "lang-markdown"]',
    )
    rewired_code_index = CODE_INDEX_MANIFEST.replace(
        'lang-dart = ["tracedecay-code-extraction/lang-dart"]\n', ""
    )
    rewired = run_fixture(
        root_source=rewired_root,
        root_packaged=rewired_root,
        code_index_source=rewired_code_index,
        code_index_packaged=rewired_code_index,
    )
    if rewired.returncode != 0:
        raise SystemExit(
            "behavior-preserving forwarding change was rejected: " + rewired.stderr
        )

    packaged_root_drift = run_fixture(
        root_packaged=ROOT_MANIFEST.replace('lang-dart = ["tracedecay-code-index/lang-dart"]\n', "")
    )
    if packaged_root_drift.returncode == 0:
        raise SystemExit("packaged root manifest dropping a feature was accepted")
    if "packaged root feature wiring differs" not in packaged_root_drift.stderr:
        raise SystemExit("packaged root drift failed for an unexpected reason")

    extraction_with_new_language = EXTRACTION_MANIFEST.replace(
        "lang-markdown = []\n", "lang-markdown = []\nlang-rustdoc = []\n"
    )
    unforwarded_language = run_fixture(
        extraction_source=extraction_with_new_language,
        extraction_packaged=extraction_with_new_language,
    )
    if unforwarded_language.returncode == 0:
        raise SystemExit("new extraction language without public aliases was accepted")
    if "root language features differ" not in unforwarded_language.stderr:
        raise SystemExit("unforwarded language failed for an unexpected reason")

    check_ncm_release_profiles()

    ncm_valid = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_fixture(),
        ncm_workflows=[
            VALIDATOR.parent.parent / ".github/workflows/release.yml",
            VALIDATOR.parent.parent / ".github/workflows/release-beta.yml",
        ],
    )
    if ncm_valid.returncode != 0:
        raise SystemExit("valid NCM distribution matrix was rejected: " + ncm_valid.stderr)

    ncm_without_receipt_digest = ncm_fixture()
    acquisition_without_receipt_digest = ncm_without_receipt_digest["model-acquisition.json"]
    assert isinstance(acquisition_without_receipt_digest, dict)
    acquisition_without_receipt_digest["revision_provenance_sha256"] = "0" * 64
    missing_receipt_digest = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_without_receipt_digest,
    )
    if missing_receipt_digest.returncode == 0:
        raise SystemExit("NCM acquisition manifest with a stale receipt digest was accepted")
    if "revision_provenance_sha256 differs" not in missing_receipt_digest.stderr:
        raise SystemExit(
            "stale NCM receipt digest failed for an unexpected reason: "
            + missing_receipt_digest.stderr
        )

    ncm_with_stale_receipt = ncm_fixture()
    stale_receipt = ncm_with_stale_receipt[
        "2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
    ]
    assert isinstance(stale_receipt, dict)
    stale_receipt["identities"]["model"]["revision"] = "0" * 40
    stale_acquisition = ncm_with_stale_receipt["model-acquisition.json"]
    assert isinstance(stale_acquisition, dict)
    stale_acquisition["revision_provenance_sha256"] = hashlib.sha256(
        json.dumps(stale_receipt).encode("utf-8")
    ).hexdigest()
    stale_receipt_check = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_with_stale_receipt,
    )
    if stale_receipt_check.returncode == 0:
        raise SystemExit("NCM acquisition manifest with stale receipt identity was accepted")
    if "receipt revision identity drifted" not in stale_receipt_check.stderr:
        raise SystemExit(
            "stale NCM receipt identity failed for an unexpected reason: "
            + stale_receipt_check.stderr
        )

    ncm_without_runtime_feature = ncm_fixture()
    ncm_without_runtime_feature["provider.toml"] = NCM_PROVIDER_MANIFEST.replace(
        '    "tracedecay-memory-ncm-runtime/real-encoder",\n', ""
    )
    missing_runtime_feature = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_without_runtime_feature,
    )
    if missing_runtime_feature.returncode == 0:
        raise SystemExit("NCM host without the real encoder feature was accepted")
    if (
        "does not enable tracedecay-memory-ncm-runtime/real-encoder"
        not in missing_runtime_feature.stderr
    ):
        raise SystemExit(
            "missing NCM runtime feature failed for an unexpected reason: "
            + missing_runtime_feature.stderr
        )

    ncm_with_extra_supported_target = ncm_fixture()
    extra_supported_policy = ncm_with_extra_supported_target["policy.json"]
    assert isinstance(extra_supported_policy, dict)
    extra_supported_policy["release_targets"][1]["ncm"] = "supported"
    extra_supported_release = ncm_with_extra_supported_target["release-targets.json"]
    assert isinstance(extra_supported_release, dict)
    extra_supported_release["include"][1]["ncm"] = "supported"
    extra_supported_release["include"][1]["sidecar"] = dict(
        extra_supported_release["include"][0]["sidecar"]
    )
    extra_supported_target = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_with_extra_supported_target,
    )
    if extra_supported_target.returncode == 0:
        raise SystemExit("non-macOS release target claiming NCM was accepted")
    if "must declare NCM 'native-only'" not in extra_supported_target.stderr:
        raise SystemExit(
            "extra NCM target failed for an unexpected reason: "
            + extra_supported_target.stderr
        )

    ncm_with_checked_in_pin = ncm_fixture()
    pinned_worker = ncm_with_checked_in_pin["worker.json"]
    assert isinstance(pinned_worker, dict)
    pinned_worker["targets"] = [
        {
            "triple": "aarch64-apple-darwin",
            "os": "macos",
            "arch": "aarch64",
            "family": "unix",
            "bytes": 1,
            "sha256": "a" * 64,
        }
    ]
    checked_in_pin = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_with_checked_in_pin,
    )
    if checked_in_pin.returncode == 0:
        raise SystemExit("a checked-in worker pin was accepted as the source trust root")
    if "must pin no worker" not in checked_in_pin.stderr:
        raise SystemExit(
            "checked-in worker pin failed for an unexpected reason: " + checked_in_pin.stderr
        )

    ncm_with_target_bound_model = ncm_fixture()
    target_bound_model = ncm_with_target_bound_model["model-acquisition.json"]
    assert isinstance(target_bound_model, dict)
    target_bound_model["target"] = "aarch64-apple-darwin"
    target_bound = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_with_target_bound_model,
    )
    if target_bound.returncode == 0:
        raise SystemExit("a target-bound model acquisition manifest was accepted")
    if "target-independent" not in target_bound.stderr:
        raise SystemExit(
            "target-bound model acquisition failed for an unexpected reason: "
            + target_bound.stderr
        )

    ncm_without_artifact_policy = ncm_fixture()
    artifact_policy = ncm_without_artifact_policy["policy.json"]
    assert isinstance(artifact_policy, dict)
    del artifact_policy["runtime_policy"]
    missing_artifact_policy = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_without_artifact_policy,
    )
    if missing_artifact_policy.returncode == 0:
        raise SystemExit("NCM policy without runtime/artifact policy was accepted")
    if "worker platform policy.runtime_policy must be an object" not in missing_artifact_policy.stderr:
        raise SystemExit(
            "missing NCM runtime/artifact policy failed for an unexpected reason: "
            + missing_artifact_policy.stderr
        )

    ncm_model_drift = ncm_fixture()
    model_drift = ncm_model_drift["model.json"]
    assert isinstance(model_drift, dict)
    model_drift["revision"] = "0" * 40
    drifted_model = run_fixture(
        root_source=NCM_ROOT_MANIFEST,
        root_packaged=NCM_ROOT_MANIFEST,
        ncm_files=ncm_model_drift,
    )
    if drifted_model.returncode == 0:
        raise SystemExit("drifted NCM model revision was accepted")
    if "pinned model contract field revision" not in drifted_model.stderr:
        raise SystemExit(
            "drifted NCM model failed for an unexpected reason: " + drifted_model.stderr
        )

    with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as workflow_directory:
        broken_workflow = Path(workflow_directory) / "release.yml"
        broken_workflow.write_text(
            (VALIDATOR.parent.parent / ".github/workflows/release.yml")
            .read_text(encoding="utf-8")
            .replace('--companion "$manifest=worker-manifest.json"', ""),
            encoding="utf-8",
        )
        missing_archive_companion = run_fixture(
            root_source=NCM_ROOT_MANIFEST,
            root_packaged=NCM_ROOT_MANIFEST,
            ncm_files=ncm_fixture(),
            ncm_workflows=[broken_workflow],
        )
    if missing_archive_companion.returncode == 0:
        raise SystemExit("NCM sidecar workflow without the manifest companion was accepted")
    if "sidecar/archive/checksum contract" not in missing_archive_companion.stderr:
        raise SystemExit(
            "missing NCM archive companion failed for an unexpected reason: "
            + missing_archive_companion.stderr
        )

    print("source feature wiring and NCM release contract fixtures passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
