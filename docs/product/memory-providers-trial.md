# Memory providers: isolated real-world trial

`scripts/product/ncm/trial.sh` runs the memory-provider host and NCM on a
developer machine, with arm64 macOS as the primary target. It follows the CI
workflow `.github/workflows/memory-providers-real-world.yml`. It builds a pinned
NCM worker for the host target and embeds that worker's trust root in a release
CLI. It then installs the pinned model, runs the same acceptance suites, and
drives an isolated V2 daemon through the shipped CLI and hook commands.

## Isolation

Every mutable path lives under the trial root. The default root is
`$HOME/tracedecay-v2-trial`, and you can override it with
`TRACEDECAY_TRIAL_ROOT`.

| Path under the trial root | Contents |
| --- | --- |
| `profile/` | V2 profile (`TRACEDECAY_DATA_DIR`), `global.db`, `daemon.sock`, NCM control bundle |
| `ncm-state/` | NCM state root: pinned model, receipts, provider namespaces |
| `home/` | host home the daemon and hooks see (default `--host-home isolated`) |
| `bundle/<triple>/` | pinned worker bundle (worker, `worker-manifest.json`, model acquisition manifest) |
| `project/` | fixture git repository used by `up` when no project is given |
| `bin/tracedecay` | guarded shim that runs the trial binary against the trial profile |
| `tmp/` | `TMPDIR` for `test` (journey temp profiles hard-link the installed model) |
| `daemon.log`, `daemon.pid`, `trial.state`, `env.sh` | daemon log, recorded pid, kit state, shell exports |

The kit starts the daemon as `tracedecay daemon run --profile-root <trial>/profile --socket <trial>/profile/daemon.sock`
in the background and stops it only through the pid it recorded. It verifies
that pid's command line first. It never runs
`daemon install-service|start|stop|restart`, `install`, `reinstall`,
`update-plugin`, `uninstall`, `upgrade`, or `update`, and the `bin/tracedecay`
shim refuses those commands.

The kit does not modify an installed V1 service, `~/.tracedecay`,
`~/.claude`, or `~/.codex`. It also refuses a project whose git directory
already carries a `tracedecay-project.json` identity marker, which is usually
written by an installed V1. Running `init` there would bind the repository to
the trial profile. Clone that repository under the trial root instead.

Three environment variables change how NCM loads its model:

* `HF_HOME`
* `HF_ENDPOINT`
* `FASTEMBED_CACHE_DIR`

NCM refuses to run when any of them is set. The kit unsets all three for every
process it starts.

## Prerequisites (macOS, Apple Silicon)

* A native arm64 terminal, not Rosetta. `build` refuses a translated shell,
  because `x86_64-apple-darwin` has no ONNX Runtime prebuilt.
* The Xcode Command Line Tools: `xcode-select --install`. Local macOS links go
  through `scripts/macos-sign-linker.sh`, and `build` also sets
  `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER=scripts/macos-rustc-wrapper.sh`, as the
  macOS CI lanes do.
* rustup (<https://rustup.rs>). `rust-toolchain.toml` pins the toolchain
  (1.97.1), and `build` runs `rustup toolchain install` in the checkout.
* Node 22, and pnpm through corepack: `corepack enable`. `package.json` pins
  `pnpm@12.6.0`. The CLI build script runs pnpm for the embedded dashboard.
* Python 3.12 (`python3`, or set `PYTHON`) and `jq`. Run `brew install jq` if
  `jq` is missing.
* Network access for the first run:
  * crates;
  * the ONNX Runtime prebuilt, which `ort-sys` downloads through fastembed's
    `ort-download-binaries-rustls-tls` feature while the worker builds;
  * the model: about 487 MB from `huggingface.co`, pinned to revision
    `2c4055b1…` by `product/ncm/release/model-acquisition-manifest.json`.
* Ample free disk: the release build and the debug test build of this
  workspace are large, and the model is stored twice (about 0.5 GB each),
  because `test` downloads it once more into `tmp/` for the real-encoder test.

## Step sequence

Run the following from the checkout of `feat/pluggable-memory-providers-v2`.

```bash
pnpm install --frozen-lockfile        # vendors Cargo sources into .pnpm/crates
scripts/product/ncm/trial.sh build    # pinned worker bundle + release CLI
scripts/product/ncm/trial.sh model    # pinned model into <trial>/ncm-state
scripts/product/ncm/trial.sh test     # CI acceptance suites (long)
scripts/product/ncm/trial.sh up       # isolated daemon, NCM active
scripts/product/ncm/trial.sh smoke    # hooks -> NCM recall -> rollback to Native
scripts/product/ncm/trial.sh status
scripts/product/ncm/trial.sh down
```

Each step fails with a clear message if its predecessor has not run.

### What each step proves

**`build`**
* Runs `build-worker-bundle.py --target <rustc host>` and writes the bundle under
  `bundle/<triple>/`. The bundle's `worker-manifest.json` pins exactly the
  worker bytes that were built.
* Builds `cargo build --locked --release -p tracedecay-cli --bin tracedecay --features memory-provider-host`
  with `TRACEDECAY_NCM_WORKER_MANIFEST` set to that manifest, so the host embeds
  the matching trust root.
* Records the path and SHA-256 of `target/release/tracedecay`. Later steps
  refuse the binary if another `cargo build` replaces it.
* Expected output ends with the `TRACEDECAY_NCM_WORKER=` and
  `TRACEDECAY_NCM_WORKER_MANIFEST=` paths and the binary version.
* The worker's dynamic linkage goes to `worker-linkage.txt`, from `otool -L` on
  macOS. On arm64 macOS the worker must not depend on Homebrew's
  `libonnxruntime`.

**`model`**
* Runs `verify-installed.py --operation install --model-root <trial>/ncm-state`.
  The script downloads the model with per-file size and digest checks,
  publishes it atomically, and writes `receipts/ncm-model-acquisition-v1.json`.
* Then runs `--operation verify`, which checks the tree against the receipt.
* The receipt binds the state root's physical absolute path. `ncm install`
  later uses exactly that path, with symlinks resolved; on macOS, for example,
  `/tmp` resolves to `/private/tmp`.
* A rerun records `already_present` and downloads nothing.

**`test`** (`all`, or one of `runtime`, `lifecycle`, `journeys`) runs these
suites with `TRACEDECAY_NCM_WORKER`, `TRACEDECAY_NCM_REAL_MODEL_ROOT`,
`TRACEDECAY_NCM_WORKER_MANIFEST`, and `TMPDIR=<trial>/tmp`:

| Suite | Command | What it proves |
| --- | --- | --- |
| `runtime` | `cargo test -p tracedecay-memory-ncm-runtime --test real_embeddings --test model_lifecycle`, then `--features test-transport --test worker` | Real encoder install, open, and inference; model lifecycle transactions; worker protocol |
| `lifecycle` | `cargo test -p tracedecay-cli --features memory-provider-host,test-transport --test host_journeys_suite -- ncm_lifecycle_cli_acceptance:: --include-ignored` | `ncm install/update/recover/uninstall` through the shipped CLI. The pinned-worker case runs only on arm64 macOS. |
| `journeys` | `cargo test -p tracedecay-cli --features memory-provider-host,test-transport --test product_memory_provider_claude_host_journey -- --include-ignored --skip host_comparison_fixture_entry --test-threads 2` | Native selected, NCM observer, NCM active across sessions, and NCM-to-Native rollback, for Claude Code and Codex hooks, with the real worker and model |

The expected output is a `PASS` line for each suite and `RESULT: PASS`.

**`up [PROJECT] [--provider ncm|native] [--host-home isolated|real]`**
1. Starts the isolated daemon.
2. Runs `tracedecay init` in the project, retrying only during the typed
   `code_index_scheduler_unavailable` warm-up. The default project is a fresh
   fixture repository.
3. Commits `memory.provider_native_enabled.v1`.
4. Runs `tracedecay --yes ncm install --path <project> --worker <bundle worker> --state-root <trial>/ncm-state --json`.
   This command verifies the worker against the embedded trust root, copies the
   worker into `profile/ncm/worker/`, and enables the observer.
5. Commits `memory.provider_recall_routing.v1` with
   `tracedecay tool tracedecay_configuration_set`, using revision CAS through
   `tracedecay_configuration_observed_state`. The value is canonical JSON text
   (sorted keys, compact, every field present), for example
   `{"active_provider":"ncm","degradation":{"allowed_causes":["partial","stale"],"policy_id":"policy.trial.history.v1","policy_revision":1},"fallback":null}`.
   This is the journeys' routing policy.
6. Restarts the daemon, because provider settings take effect only at
   `DaemonRestart`.

Native participates only when it is routed, as in the journeys. `up` then checks
two things:
* `ncm status --json` reports `enabled`, `worker_present`, `manifest_present`,
  and `encoder_ready`, with no pending recovery.
* `tracedecay_context` carries an NCM advisory lane when NCM is routed, and no
  provider lane when Native is routed.

`up` finishes by printing the exports for manual use.

**`smoke`** requires `--host-home isolated`. It drives one Claude Code session
through the shipped hook processes, using the payload shapes the journey uses:
1. Writes an empty transcript at
   `<trial>/home/.claude/projects/<slug>/<session>.jsonl`, then runs
   `hook-claude-session-start`.
2. Appends a turn and runs `hook-stop`.
3. Polls `tracedecay_context` until the NCM advisory lane recalls that turn.
   The NCM journal must exist.
4. Appends a long reply that ends in a per-run tail sentinel, runs `hook-stop`,
   and waits until NCM recalls the whole message. The lane must be
   `provider_id=ncm` and `state=answered`, and every candidate must carry
   `canonical_observations` evidence. Upstream `tracedecay_message_search` must
   also recall the session.
5. Runs `route native`, which restarts the daemon. Context must still answer
   with no provider lane, message search must still recall the session, no
   Native journal may exist, and the NCM journal must be retained, because NCM
   stays installed as an observer.

The expected output is 15 `PASS` lines and `RESULT: PASS`. Artifacts go to
`smoke/<run>/`. After `smoke`, recall is routed to Native; to go back, run
`trial.sh route ncm`.

`smoke` does not pass `_meta.session_id`: like the current journey, each
`tracedecay tool` call is its own MCP connection, and NCM answers from the
project's checkout memory.

**`route ncm|native`** is the operator rollback path. For `ncm` it commits the
routing first and then disables Native. For `native` it enables Native first and
then commits the routing, because routing is admitted only to a constructible
provider. Either way it restarts the isolated daemon and probes the lane.

**`status`** prints the build, the recorded pid and the daemon authority,
`ncm status --json`, the effective values of the three provider settings, and
the provider journals that exist. **`down`** stops only the recorded trial
daemon.

## Manual testing

Point a shell at the isolated profile with `source <trial>/env.sh`, in bash or
zsh. `env.sh` sets:

* `TRACEDECAY_DATA_DIR`
* `TRACEDECAY_GLOBAL_DB`
* `TRACEDECAY_DAEMON_SOCKET`

It also puts `<trial>/bin` first on `PATH`. Then, for example:

```bash
tracedecay ncm status --path ~/tracedecay-v2-trial/project
tracedecay tool --project ~/tracedecay-v2-trial/project tracedecay_context \
  --args '{"task":"what did the retry budget change record?","format":"json"}' --json
```

`trial.sh env` prints these exports again. Use a separate shell for this, and
close it afterwards.

### Real Claude Code and Codex hooks

`tracedecay install --agent claude` (and `reinstall`, `update-plugin`, or
`uninstall`) writes the global Claude Code integration and replaces the
installed V1 integration:
* the plugin marketplace under `~/.claude/plugins/marketplaces/tracedecay/`;
* `claude plugin install tracedecay@tracedecay`;
* `enabledPlugins` in `~/.claude/settings.json`.

The Codex integration also lives in the user's Codex configuration. Do not run
these commands with the trial binary; the shim refuses them. For Codex, use
only the scripted paths: the `journeys` suite covers the Codex hooks.

A manual Claude Code session is optional and unverified by this kit. It needs
`up --host-home real`, which lets the daemon read your real `~/.claude/projects`
and `~/.codex/sessions` for the trial project. The daemon may also sweep
unregistered sessions into the trial profile. In that mode `up` writes two
files and prints the command that uses them:
* `<trial>/claude/settings.json` holds the shipped hook list from
  `plugin/hooks/hooks-claude.json`, with the trial shim as the command, and sets
  `"enabledPlugins": {"tracedecay@tracedecay": false}`.
* `<trial>/claude/mcp.json` holds a `tracedecay-v2` stdio server running
  `<trial>/bin/tracedecay serve`.

```bash
cd ~/tracedecay-v2-trial/project
claude --settings ~/tracedecay-v2-trial/claude/settings.json \
       --mcp-config ~/tracedecay-v2-trial/claude/mcp.json
```

These are Claude Code flags, not TraceDecay commands; check them with
`claude --help`.

In the session, `/hooks` must list only commands under `<trial>/bin`, and
`/plugin` must show `tracedecay@tracedecay` disabled. Otherwise, V1 hooks would
run in the trial project and may register it with V1. If either check fails,
or if `up` warns that `~/.claude/settings.json` itself registers `tracedecay`
hooks, quit the session and use only `smoke`.

## Troubleshooting

* **`daemon socket path is N bytes`.** `sun_path` allows 103 usable bytes on
  macOS. Use a shorter root, for example `TRACEDECAY_TRIAL_ROOT=$HOME/td-trial`.
* **`vendored Cargo sources are missing`.** Run `pnpm install --frozen-lockfile`
  again. Also rerun it after `Cargo.lock` changes.
* **`--locked` fails.** `Cargo.lock` is out of date with the checkout; pull the
  branch rather than updating the lock locally.
* **`binary ... changed since build`, or `platform_supported: false`.** A plain
  `cargo build --release` replaced `target/release/tracedecay` with a binary
  whose trust root pins no worker. Rerun `trial.sh build`.
* **Model download fails partway.** Rerun `trial.sh model`. A failed
  transaction removes only its own staging directory. If the process was killed
  and the rerun refuses a pending lifecycle journal, replay it first:
  `python3 scripts/product/ncm/verify-installed.py --manifest product/ncm/release/model-acquisition-manifest.json --revision-receipt product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json --model-root <trial>/ncm-state --operation recover`.
* **`ambient HF_HOME override is forbidden`.** Something outside the kit starts
  the worker with `HF_HOME`, `HF_ENDPOINT`, or `FASTEMBED_CACHE_DIR` set; unset
  them.
* **ONNX Runtime download fails during `build`.** The prebuilt comes from the
  `ort-sys` build script, so retry with network access. x86_64 macOS is not a
  supported trial target: it needs Homebrew `onnxruntime`,
  `ORT_LIB_LOCATION`, and `ORT_PREFER_DYNAMIC_LINK=1`, as in the CI lane.
* **`up` or `smoke` fails.** Read `<trial>/daemon.log`,
  `<trial>/last-tool.stderr`, `<trial>/ncm-status.json`, and
  `<trial>/smoke/<run>/`. To rerun from clean, run `down`, then
  `up <trial>/project2`, which gives a new project, or remove the trial root.
* **Smoke recall times out.** Raise `TRIAL_SETTLE_SECS` (the default is 180),
  and check the daemon log for worker errors.

## Cleanup

```bash
scripts/product/ncm/trial.sh down
rm -rf ~/tracedecay-v2-trial     # or your TRACEDECAY_TRIAL_ROOT
```

The build outputs stay in the checkout's `target/` directory: the host binary
in `target/release/` and the worker in `target/<triple>/release/`. Run
`cargo clean` to remove them. Nothing outside the trial root and `target/`
needs cleanup.
