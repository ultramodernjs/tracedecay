# NCM Rust release lifecycle

NCM is an independent Rust implementation of the Biomem based `ncm-biomem-rs.v1`
contract. It is not an official OpenTechLab product and it does not claim to
move memory into a decoder's hidden state. Native is enabled and selected by
default. Enabling NCM and selecting it for recall are explicit opt-ins; NCM
requires a pinned worker artifact for the target.

The worker trust root is chosen when the host binaries are built. The
checked-in `product/ncm/reference/worker-manifest.json` pins no worker, so a
plain source build reports NCM as unsupported on every target. A release
builds the worker for each target with
`scripts/product/ncm/build-worker-bundle.py`, which writes a bundle containing
the worker executable, a `worker-manifest.json` that pins exactly those bytes,
and the model acquisition manifest. Per-target manifests are combined with
`--merge`, and the host binaries are then built with
`TRACEDECAY_NCM_WORKER_MANIFEST=<absolute path of that manifest>`. NCM may be
pinned for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
`aarch64-pc-windows-msvc`, and `x86_64-pc-windows-msvc`; any target the
embedded manifest does not pin is Native-only.

The normal CLI archive contains the CLI alone. A worker sidecar is named
`tracedecay-ncm-worker-<tag>-<release-name>.tar.gz` and contains exactly:

* `tracedecay-ncm-worker` (`tracedecay-ncm-worker.exe` on Windows), the
  executable worker;
* `worker-manifest.json`, the exact trust root the host binaries embed, which
  pins the worker protocol and each target's size and SHA-256; and
* `model-acquisition-manifest.json`, which binds the exact MiniLM revision and
  the five model file digests. It is the same for every target.

A worker copied from another archive, a manifest that differs from the
embedded trust root, or a sidecar without the model acquisition manifest is
rejected. The source of truth for the targets that may carry a pin is
[`product/ncm/reference/worker-platforms.json`](../../product/ncm/reference/worker-platforms.json),
and the release descriptor is
[`product/ncm/release/model-acquisition-manifest.json`](../../product/ncm/release/model-acquisition-manifest.json).
The descriptor's revision digest is bound to the canonical backend receipt at
`product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json`.

## Memory namespaces

The `memory.provider_ncm_observer.v1` setting accepts two namespace modes:

```json
{
  "mode": "enabled",
  "worker_binary": "/absolute/path/to/tracedecay-ncm-worker",
  "state_root": "/absolute/path/to/ncm-state",
  "namespace_binding": "checkout_observations_v1"
}
```

`checkout_observations_v1` shares ordinary observations across agent sessions
of the same profile, project, repository, worktree and branch. Each observation
keeps its canonical source identity. Recall reads current canonical content and
dispositions from the host; this mode does not grant access to original session
history or bypass existing source controls. New `ncm install` configurations
explicitly select this mode. NCM participation and recall routing still require
their existing opt-ins.

`exact_session_v1` retains the original namespace hash, state directories and
receipts, including the agent session and scope resolution identity. Existing
enabled documents that omit `namespace_binding` select this mode, and worker
updates preserve the configured choice. To select legacy session namespaces,
omit `namespace_binding`; explicitly writing `"exact_session_v1"` is rejected
as noncanonical because the canonical serializer omits this default field.
Changing modes requires a daemon restart and selects a separate namespace; it does not migrate, rename or delete previous memory.
Existing snapshots and journals must keep their original namespace identities.

## Installed release verification

Run the portable regression gate from a checkout of the release source:

```bash
python3 scripts/product/ncm/verify-installed.py
```

The gate checks the target-independent release descriptor, the unpinned source
worker trust root, the embedding manifest, and the transaction and receipt schema without contacting
the network. Given release assets, it safely extracts and smokes the CLI, then
verifies the worker sidecar and its archive checksum:

```bash
python3 scripts/product/ncm/verify-installed.py \
  --binary-archive tracedecay-v<version>-aarch64-macos.tar.gz \
  --worker-archive tracedecay-ncm-worker-v<version>-aarch64-macos.tar.gz \
  --target aarch64-apple-darwin \
  --expected-version <version> \
  --expected-source-sha <40-hex-commit> \
  --expected-archive-sha256 <64-hex-digest> \
  --manifest product/ncm/release/model-acquisition-manifest.json \
  --worker-manifest <the TRACEDECAY_NCM_WORKER_MANIFEST used for the release build> \
  --revision-receipt product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json
```

Archive and installed-binary smoke requires the trusted release version,
source commit, and archive or binary digest. It also checks the executable
format and target before launching it, so a script that merely prints a
version cannot satisfy the release gate.

The release binary is still installed through the normal archive path. NCM
model acquisition is an explicit operation under the chosen absolute state
root. The release verifier can exercise the same operation with an offline
fixture source (the regression tests use this mode; production uses the HTTPS
URLs pinned in the descriptor):

```bash
python3 scripts/product/ncm/verify-installed.py \
  --manifest product/ncm/release/model-acquisition-manifest.json \
  --revision-receipt product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json \
  --model-root "$PWD/.local/ncm-state" \
  --operation install
```

The model transaction performs these steps:

1. refuse a pending lifecycle journal and validate the repository,
   immutable revision, URL and every expected size/digest;
2. download into a private same-filesystem staging directory, hashing each
   file as it is written;
3. materialize the exact runtime layout under
   `models/models--Xenova--paraphrase-multilingual-MiniLM-L12-v2/`, including
   `refs/main`, the immutable revision snapshot and
   `ncm-encoder-manifest.json`;
4. fsync the candidate, move the previous `models` directory to a private
   backup, and atomically publish the verified candidate; and
5. verify the published tree before writing
   `receipts/ncm-model-acquisition-v1.json`.

An install against an already verified tree records `already_present` without
redownloading. An update records `committed` only after the new tree and all
digests verify. A failed download or publication removes only its private
staging state and restores the previous model tree; the journal can be
replayed with `--operation recover`. Other state-root entries, including the
provider namespace, are not part of this transaction.

The receipt records the operation id, model/repository
identity, immutable revision, embedding-manifest digest, acquisition-manifest
digest, complete file digest list, published tree digest and creation time.
It is the evidence required before an installed worker may be considered ready.
The Rust owner uses the same `ncm-model-lifecycle-v1.json` journal name for
atomic publication but emits no release acquisition receipt; the Python
release verifier owns and validates `ncm-model-acquisition-v1.json`. A
published journal is retained after a crash until that schema-valid receipt
matches the journal operation id, model revision, manifest and tree digest.
Missing or mismatched model artifacts remain unavailable; they are never
silently replaced from an ambient Hugging Face cache or environment override.

The release matrix in `.github/release-targets.json` currently publishes a
sidecar only for `aarch64-macos`; `x86_64-linux`, `aarch64-linux`, and
`x86_64-windows` stay `native-only` there until their release builds embed a
manifest that pins their worker. A successful portable Rust build alone does
not widen that claim: without a pin the embedded trust root reports the target
unsupported.

## Release checks

The two release workflows package and compare both sidecar manifests after
extraction. The arm64 macOS build then runs the installed CLI E2E gate: it
acquires the pinned model, installs the sidecar through `ncm install`, restarts
the managed daemon, checks status and performs a production worker handshake.
Their portable validation list runs
`scripts/product/ncm/test-verify-installed.py`, which covers clean model
installation, an already-installed profile, transactional update failure and
success, sidecar target binding, archive checksums and CLI smoke. The broader
artifact checks remain in `scripts/check-release-artifacts.py`; the feature and
platform matrix checks remain in `scripts/check-distribution-feature-wiring.py`
and `scripts/product/ncm/check-worker-platform.py`.
