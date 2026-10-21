#!/usr/bin/env bash
# Cheap CI checks that run on a developer machine in seconds, shared by the
# Git hooks in .githooks/ and by the Repository gates CI job so the two lists
# cannot drift. Nothing here compiles the Rust workspace.
#
#   scripts/local-gates.sh rustfmt-range <base> <head>  rustfmt-check .rs files changed in base..head
#   scripts/local-gates.sh whitespace-range <base> <head>
#   scripts/local-gates.sh repo                         repository-wide policy scripts and their tests
#   scripts/local-gates.sh resolve-rustfmt              print the rustfmt the hooks would use
#   scripts/local-gates.sh pre-push                     everything above, reading refs from stdin
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Git exports repository-scoped variables (GIT_DIR, GIT_INDEX_FILE, ...) to
# hooks. Tests that build their own fixture repositories would otherwise
# operate on this checkout instead, so drop them once the root is known.
while IFS= read -r variable; do
    unset "$variable"
done < <(git rev-parse --local-env-vars)

fail() {
    echo "local-gates: $*" >&2
    exit 1
}

# Prints the absolute path of a working rustfmt. Prefers the toolchain pinned
# in rust-toolchain.toml, then any installed toolchain, then PATH. Never asks
# rustup to download anything, and fails instead of passing when none works.
resolve_rustfmt() {
    if [[ -n "${TRACEDECAY_RUSTFMT:-}" ]]; then
        "$TRACEDECAY_RUSTFMT" --version >/dev/null 2>&1 \
            || fail "TRACEDECAY_RUSTFMT=$TRACEDECAY_RUSTFMT does not run"
        printf '%s\n' "$TRACEDECAY_RUSTFMT"
        return
    fi
    local pinned rustup_home candidate
    pinned="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
    rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
    local candidates=()
    if [[ -d "$rustup_home/toolchains" ]]; then
        for candidate in "$rustup_home/toolchains/$pinned"-*/bin/rustfmt; do
            candidates+=("$candidate")
        done
        # Newest numbered release first, then stable, then anything else.
        while IFS= read -r candidate; do
            candidates+=("$candidate")
        done < <(
            ls -d "$rustup_home"/toolchains/[0-9]*/bin/rustfmt 2>/dev/null | sort -rV
            ls -d "$rustup_home"/toolchains/stable-*/bin/rustfmt 2>/dev/null
            ls -d "$rustup_home"/toolchains/[!0-9s]*/bin/rustfmt 2>/dev/null | sort -rV
        )
    fi
    if candidate="$(command -v rustfmt 2>/dev/null)"; then
        candidates+=("$candidate")
    fi
    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]] && RUSTUP_AUTO_INSTALL=0 RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-$pinned}" \
            "$candidate" --version >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    fail "no working rustfmt found (pinned toolchain $pinned). Install it with:
  rustup toolchain install $pinned --component rustfmt
or point TRACEDECAY_RUSTFMT at a rustfmt binary."
}

rustfmt_bin=""
rustfmt_init() {
    [[ -n "$rustfmt_bin" ]] && return
    rustfmt_bin="$(resolve_rustfmt)"
    local version
    version="$(RUSTUP_AUTO_INSTALL=0 "$rustfmt_bin" --version 2>/dev/null)"
    echo "local-gates: using $rustfmt_bin ($version)" >&2
    local pinned
    pinned="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
    if [[ "$version" != *"$pinned"* && "$rustfmt_bin" != *"/toolchains/$pinned-"* ]]; then
        echo "local-gates: note: pinned toolchain $pinned rustfmt unavailable; CI uses $pinned" >&2
    fi
}

# rustfmt the given blob specs (e.g. ":path" for the index, "<sha>:path") and
# list the paths whose formatted output differs. rustfmt --check exits 0 on
# stdin even when it prints a diff, so compare the output instead.
rustfmt_unformatted() {
    local spec
    for spec in "$@"; do
        if ! cmp -s <(git show "$spec") \
            <(git show "$spec" | RUSTUP_AUTO_INSTALL=0 "$rustfmt_bin" --edition 2024 \
                --config-path rustfmt.toml --emit stdout 2>/dev/null); then
            printf '%s\n' "${spec#*:}"
        fi
    done
}

rustfmt_range() {
    local base="$1" head="$2" files unformatted
    mapfile -t files < <(git diff --name-only --diff-filter=ACMR "$base" "$head" -- '*.rs')
    [[ ${#files[@]} -eq 0 ]] && return 0
    rustfmt_init
    mapfile -t unformatted < <(rustfmt_unformatted "${files[@]/#/$head:}")
    if [[ ${#unformatted[@]} -gt 0 ]]; then
        echo "local-gates: these Rust files are not rustfmt-clean (CI //:rustfmt_check would fail):" >&2
        printf '  %s\n' "${unformatted[@]}" >&2
        echo "fix with:  $rustfmt_bin --edition 2024 --config-path rustfmt.toml ${unformatted[*]}" >&2
        echo "then amend or add a commit." >&2
        return 1
    fi
}

whitespace_range() {
    if ! git diff --check "$1" "$2"; then
        echo "local-gates: whitespace errors above; fix them and amend or add a commit." >&2
        return 1
    fi
}

# Runs a Python script that needs PyYAML, using uv to supply the CI-pinned
# version when the local interpreter lacks it.
python_yaml() {
    if python3 -c 'import yaml; yaml.YAMLError' >/dev/null 2>&1; then
        python3 "$@"
    elif command -v uv >/dev/null 2>&1; then
        uv run --quiet --no-project --with pyyaml==6.0.2 python "$@"
    else
        fail "PyYAML is unavailable for $1. Install it with: python3 -m pip install pyyaml==6.0.2 (or install uv)"
    fi
}

run_step() {
    echo "local-gates: $*" >&2
    "$@" >/dev/null 2>"$step_log" || {
        cat "$step_log" >&2
        fail "failed: $*"
    }
}

# Keep each step in seconds. Slower Repository gates steps
# (test-lint-commit-range, test-worktree-gc, test-bench-hot-paths,
# test-neutralize-release-pr-closing-keywords) and anything that needs cargo
# or Bazel stay CI-only.
repo_gates() {
    step_log="$(mktemp)"
    trap 'rm -f "$step_log"' RETURN
    run_step python3 scripts/test-checkout-bytes.py
    run_step python3 scripts/test-bazel-workspace-status.py
    run_step python3 scripts/test-gen-builds-default-alias.py
    run_step python3 scripts/test-measure-unused-tool-context.py
    run_step python3 -m unittest discover -s dashboard/hermes-wrapper -p 'test_*.py'
    run_step python3 scripts/test-prune-superseded-actions-caches.py
    run_step python3 scripts/test-rust-cache-lineage.py
    run_step python3 scripts/check-rust-cache-lineage.py
    run_step python3 scripts/test-check-packaged-lsp-bridge.py
    run_step python3 scripts/test-build-mcpb.py
    # Preserve the NCM release contract after upstream retired crate acceptance.
    run_step python3 -B scripts/test-check-distribution-feature-wiring.py
    run_step python3 -B scripts/check-distribution-feature-wiring.py
    run_step python3 scripts/test-package-release-archive.py
    run_step python3 scripts/test-check-release-artifacts.py
    run_step python3 scripts/test-check-dev-skill-mirrors.py
    run_step python3 scripts/check-dev-skill-mirrors.py check
    run_step python_yaml scripts/test-check-sdk-publish-workflow.py
    run_step python_yaml scripts/check-sdk-publish-workflow.py
    run_step python_yaml scripts/test-check-github-hosted-runners.py
    run_step python_yaml scripts/check-github-hosted-runners.py
    if command -v actionlint >/dev/null 2>&1; then
        run_step actionlint .github/workflows/*.yml
    elif [[ -n "${CI:-}" ]]; then
        echo "local-gates: actionlint not on PATH in CI; the sdk-conformance job runs it" >&2
    else
        fail "actionlint is not installed (brew install actionlint, or go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12)"
    fi
}

pre_push() {
    local zero='0000000000000000000000000000000000000000' status=0
    local local_ref local_sha remote_ref remote_sha base
    local pushed=0
    while read -r local_ref local_sha remote_ref remote_sha; do
        [[ "$local_sha" == "$zero" ]] && continue
        if [[ "$remote_sha" == "$zero" ]] || ! git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
            base="$(git merge-base "$local_sha" origin/master 2>/dev/null || git rev-list --max-parents=0 "$local_sha" | tail -1)"
        else
            base="$remote_sha"
        fi
        echo "local-gates: checking $local_ref (${base:0:10}..${local_sha:0:10})" >&2
        rustfmt_range "$base" "$local_sha" || status=1
        whitespace_range "$base" "$local_sha" || status=1
        pushed=1
    done
    [[ $status -eq 0 ]] || exit 1
    [[ $pushed -eq 1 ]] && repo_gates
    echo "local-gates: pre-push checks passed" >&2
}

case "${1:-}" in
    rustfmt-range) rustfmt_range "$2" "$3" ;;
    whitespace-range) whitespace_range "$2" "$3" ;;
    repo) repo_gates; echo "local-gates: repository gates passed" >&2 ;;
    resolve-rustfmt) rustfmt_init; printf '%s\n' "$rustfmt_bin" ;;
    pre-push) pre_push ;;
    *) fail "usage: $0 {rustfmt-range BASE HEAD|whitespace-range BASE HEAD|repo|resolve-rustfmt|pre-push}" ;;
esac
