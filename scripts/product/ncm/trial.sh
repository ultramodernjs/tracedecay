#!/usr/bin/env bash
# Turnkey, isolated real-world trial of the memory-provider host and NCM.
#
# Mirrors .github/workflows/memory-providers-real-world.yml on a developer
# machine (arm64 macOS is the primary target): build a pinned NCM worker
# bundle for the host target, embed its trust root in a release CLI, install
# the pinned model, run the acceptance suites, and drive an ISOLATED V2 daemon
# through the shipped CLI and hook commands.
#
# Safety contract:
#   * every mutable path lives under the trial root
#     (${TRACEDECAY_TRIAL_ROOT:-$HOME/tracedecay-v2-trial});
#   * the daemon is a foreground `tracedecay daemon run` started in the
#     background with its own profile and socket, and is stopped only by the
#     pid this script recorded; `daemon install-service/start/stop/restart`
#     and host lifecycle commands (`install`, `update-plugin`, ...) are never
#     run, so an installed V1 service, ~/.tracedecay, ~/.claude and ~/.codex
#     are not touched;
#   * the default host home for the daemon and hooks is <trial-root>/home.
#
# Bash 3.2 compatible (the macOS system bash).

set -euo pipefail

SCRIPT_DIR=$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SELF=$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")
REPO=$(cd -P "$SCRIPT_DIR/../../.." && pwd -P)

MODEL_MANIFEST_REL="product/ncm/release/model-acquisition-manifest.json"
REVISION_RECEIPT_REL="product/ncm/receipts/backend/2fc72f1d81f543224d8e7d8ef19195b026ba855f.json"
MODEL_RECEIPT_REL="receipts/ncm-model-acquisition-v1.json"
NCM_JOURNAL_FILE="memory-observation-ncm-journal-v1.sqlite3"
NATIVE_JOURNAL_FILE="memory-observation-journal-v1.sqlite3"
KEY_NATIVE="memory.provider_native_enabled.v1"
KEY_NCM="memory.provider_ncm_observer.v1"
KEY_ROUTING="memory.provider_recall_routing.v1"
# The journeys' routing policy: the selected provider, plus the typed
# history degradations a multi-session recall legitimately reports.
ROUTING_POLICY_ID="policy.trial.history.v1"
# sockaddr_un.sun_path is 104 bytes on macOS (103 usable), 108 on Linux.
SOCKET_MAX_BYTES=103
READY_BUDGET_SECS=180
SETTLE_BUDGET_SECS=${TRIAL_SETTLE_SECS:-180}
TAB=$(printf '\t')
NL='
'

usage() {
  cat <<'EOF'
Usage: scripts/product/ncm/trial.sh <command> [options]

Isolated real-world trial of the memory-provider host + NCM. Every mutable
path lives under the trial root (default $HOME/tracedecay-v2-trial, override
with TRACEDECAY_TRIAL_ROOT). Never touches ~/.tracedecay, an installed daemon
service, or host (Claude Code / Codex) configuration.

Commands:
  build                 Build the pinned NCM worker bundle for the host target,
                        then the release CLI (memory-provider-host) that embeds
                        its trust root.
  model                 Install and verify the pinned MiniLM model (~490 MB)
                        into <trial-root>/ncm-state.
  test [SUITE]          Run the acceptance suites the CI workflow runs. SUITE is
                        all (default), runtime, lifecycle, or journeys.
  up [PROJECT] [--provider ncm|native] [--host-home isolated|real]
                        Start the isolated V2 daemon, init PROJECT (default: a
                        fixture git repo at <trial-root>/project), enable Native
                        and NCM, route recall (default ncm), restart.
                        --host-home real lets the daemon read your real
                        ~/.claude and ~/.codex transcripts (read-only) for
                        a manual Claude Code session; see the trial doc.
  route ncm|native      Switch recall routing (native is the rollback path) and
                        restart the isolated daemon.
  status                NCM status, daemon/profile info, provider settings.
  smoke                 Scripted real-world check against the running daemon:
                        Claude hooks -> NCM delivery -> NCM advisory recall,
                        then rollback to Native. Requires --host-home isolated.
  down                  Stop only the daemon started by `up` (recorded pid).
  env                   Print the shell exports for manual use.
  help                  Show this help.

Environment:
  TRACEDECAY_TRIAL_ROOT   trial root (default $HOME/tracedecay-v2-trial)
  PYTHON                  python interpreter (default python3)
  TRIAL_RUST_LOG          daemon RUST_LOG (default warn)
  TRIAL_SETTLE_SECS       smoke wait budget per step (default 180)
EOF
}

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

RESULTS=""
FAILURES=0
record() {
  # record PASS|FAIL|WARN <step description>
  local verdict=$1
  shift
  printf '%-4s  %s\n' "$verdict" "$*" >&2
  RESULTS="${RESULTS}${verdict}  $*
"
  if [ "$verdict" = "FAIL" ]; then
    FAILURES=$((FAILURES + 1))
  fi
}

print_results() {
  printf '\n==== %s summary ====\n%s' "$1" "$RESULTS"
  if [ "$FAILURES" -eq 0 ]; then
    printf 'RESULT: PASS\n'
  else
    printf 'RESULT: FAIL (%s failed step(s))\n' "$FAILURES"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not on PATH${2:+ ($2)}"
}

PYTHON=${PYTHON:-python3}

# ---------------------------------------------------------------------------
# Trial root, paths, and state
# ---------------------------------------------------------------------------

init_paths() {
  local requested=${TRACEDECAY_TRIAL_ROOT:-${HOME:?HOME is unset}/tracedecay-v2-trial}
  case $requested in
    /*) ;;
    *) die "TRACEDECAY_TRIAL_ROOT must be absolute: $requested" ;;
  esac
  mkdir -p "$requested"
  # Physical spelling (e.g. /tmp -> /private/tmp on macOS): the NCM state
  # root must contain no symlink components, and the model receipt binds the
  # exact absolute path later passed to `ncm install --state-root`.
  ROOT=$(cd -P "$requested" && pwd -P)
  local home_physical=""
  home_physical=$(cd -P "$HOME" 2>/dev/null && pwd -P) || true
  if [ "$ROOT" = "/" ] || [ "$ROOT" = "$home_physical" ] || [ "$ROOT" = "$REPO" ]; then
    die "refusing trial root $ROOT; pick a dedicated directory"
  fi
  case "$ROOT/" in
    "$home_physical/.tracedecay/"*) die "the trial root must not live inside ~/.tracedecay" ;;
  esac
  case $ROOT in
    *[[:space:]]*) die "the trial root must not contain whitespace: $ROOT" ;;
  esac
  PROFILE=$ROOT/profile
  SOCKET=$PROFILE/daemon.sock
  NCM_STATE=$ROOT/ncm-state
  TRIAL_HOME=$ROOT/home
  BIN_DIR=$ROOT/bin
  TRIAL_TMP=$ROOT/tmp
  DAEMON_LOG=$ROOT/daemon.log
  PID_FILE=$ROOT/daemon.pid
  STATE=$ROOT/trial.state
  BUNDLE_ROOT=$ROOT/bundle
  DEFAULT_PROJECT=$ROOT/project
  ENV_FILE=$ROOT/env.sh
  SHIM=$BIN_DIR/tracedecay
  if [ -d "$HOME/.tracedecay" ]; then
    local v1_profile
    v1_profile=$(cd -P "$HOME/.tracedecay" && pwd -P)
    [ "$PROFILE" != "$v1_profile" ] || die "trial profile resolves to ~/.tracedecay"
  fi
}

state_get() {
  [ -f "$STATE" ] || return 0
  awk -F'\t' -v key="$1" '$1 == key { value = substr($0, length(key) + 2) } END { if (value != "") print value }' "$STATE"
}

state_set() {
  case $2 in
    *"$TAB"* | *"$NL"*) die "state value for $1 contains a tab or newline" ;;
  esac
  local tmp
  tmp=$(mktemp "$ROOT/.trial.state.XXXXXX")
  if [ -f "$STATE" ]; then
    awk -F'\t' -v key="$1" '$1 != key' "$STATE" >"$tmp"
  fi
  printf '%s\t%s\n' "$1" "$2" >>"$tmp"
  mv "$tmp" "$STATE"
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

check_socket_length() {
  local bytes
  bytes=$(printf '%s' "$SOCKET" | wc -c | tr -d ' ')
  if [ "$bytes" -gt "$SOCKET_MAX_BYTES" ]; then
    die "daemon socket path is $bytes bytes (> $SOCKET_MAX_BYTES, the macOS sun_path limit): $SOCKET
Set TRACEDECAY_TRIAL_ROOT to a shorter directory, e.g. TRACEDECAY_TRIAL_ROOT=\$HOME/td-trial"
  fi
}

require_build() {
  BIN=$(state_get BIN)
  WORKER=$(state_get WORKER)
  WORKER_MANIFEST=$(state_get WORKER_MANIFEST)
  [ -n "$BIN" ] && [ -n "$WORKER" ] && [ -n "$WORKER_MANIFEST" ] ||
    die "no trial build recorded under $ROOT; run: $0 build"
  [ -x "$BIN" ] || die "trial binary $BIN is missing; run: $0 build"
  [ -f "$WORKER" ] && [ -f "$WORKER_MANIFEST" ] || die "worker bundle is missing; run: $0 build"
  local recorded actual
  recorded=$(state_get BIN_SHA256)
  actual=$(sha256_of "$BIN")
  [ "$recorded" = "$actual" ] ||
    die "$BIN changed since '$0 build' (another cargo build replaced it, possibly without the pinned worker manifest); rerun: $0 build"
}

require_model() {
  [ "$(state_get MODEL_ROOT)" = "$NCM_STATE" ] && [ -f "$NCM_STATE/$MODEL_RECEIPT_REL" ] ||
    die "the pinned NCM model is not installed under $NCM_STATE; run: $0 model"
}

darwin_checks() {
  [ "$(uname -s)" = "Darwin" ] || return 0
  if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
    die "this shell runs under Rosetta (x86_64 emulation); open a native arm64 terminal"
  fi
  xcode-select -p >/dev/null 2>&1 || die "Xcode Command Line Tools are missing; run: xcode-select --install"
  # Same wrapper the macOS CI lanes use: re-signs the stripped release binary.
  export CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="$REPO/scripts/macos-rustc-wrapper.sh"
}

# NCM refuses ambient model overrides; never let them reach any process here.
unset HF_HOME HF_ENDPOINT FASTEMBED_CACHE_DIR

# ---------------------------------------------------------------------------
# Isolated environment
# ---------------------------------------------------------------------------

host_home_mode() {
  local mode
  mode=$(state_get HOST_HOME_MODE)
  printf '%s' "${mode:-isolated}"
}

# Run the trial binary with the isolated profile environment. In isolated
# host-home mode HOME also points at <trial-root>/home, exactly like the
# journeys' fixture, so the daemon's transcript sweep and the hooks never see
# the real ~/.claude or ~/.codex.
td() {
  if [ "$(host_home_mode)" = "isolated" ]; then
    env TRACEDECAY_DATA_DIR="$PROFILE" \
      TRACEDECAY_GLOBAL_DB="$PROFILE/global.db" \
      TRACEDECAY_DAEMON_SOCKET="$SOCKET" \
      HOME="$TRIAL_HOME" \
      XDG_CONFIG_HOME="$TRIAL_HOME/.config" \
      PATH="$BIN_DIR:$PATH" \
      "$BIN" "$@"
  else
    env TRACEDECAY_DATA_DIR="$PROFILE" \
      TRACEDECAY_GLOBAL_DB="$PROFILE/global.db" \
      TRACEDECAY_DAEMON_SOCKET="$SOCKET" \
      PATH="$BIN_DIR:$PATH" \
      "$BIN" "$@"
  fi
}

td_in_project() {
  (cd "$PROJECT" && td "$@")
}

# The generated files are shell source; their `$` references are literal.
# shellcheck disable=SC2016
write_shim_and_env() {
  mkdir -p "$BIN_DIR"
  local tmp
  tmp=$(mktemp "$BIN_DIR/.tracedecay.XXXXXX")
  {
    cat <<'SHIM'
#!/usr/bin/env bash
# Generated by scripts/product/ncm/trial.sh. Runs the V2 trial binary against
# the isolated trial profile only, and refuses commands that would change host
# (Claude Code/Codex) configuration, a daemon service, or the installed binary.
set -euo pipefail
refuse() {
  printf 'trial shim: refusing "tracedecay %s"; the trial never changes host config, services, or installs.\n' "$*" >&2
  exit 64
}
sub=""
next=""
skip_value=0
for arg in "$@"; do
  if [ "$skip_value" = 1 ]; then
    skip_value=0
    continue
  fi
  case $arg in
    --component) skip_value=1 ;;
    --component=* | --yes | --dry-run | --adopt) ;;
    *) if [ -z "$sub" ]; then sub=$arg; elif [ -z "$next" ]; then next=$arg; fi ;;
  esac
done
case $sub in
  install | reinstall | update-plugin | uninstall | upgrade | update | post-update | package-hook | channel | wipe | feedback-rollback) refuse "$*" ;;
  daemon) case $next in status) ;; *) refuse "$*" ;; esac ;;
esac
unset HF_HOME HF_ENDPOINT FASTEMBED_CACHE_DIR
SHIM
    printf 'export TRACEDECAY_DATA_DIR=%q\n' "$PROFILE"
    printf 'export TRACEDECAY_GLOBAL_DB=%q\n' "$PROFILE/global.db"
    printf 'export TRACEDECAY_DAEMON_SOCKET=%q\n' "$SOCKET"
    printf 'exec %q "$@"\n' "$BIN"
  } >"$tmp"
  chmod 0755 "$tmp"
  mv "$tmp" "$SHIM"

  tmp=$(mktemp "$ROOT/.env.sh.XXXXXX")
  {
    printf '# Generated by scripts/product/ncm/trial.sh. Source in bash or zsh:\n'
    printf '#   source %q\n' "$ENV_FILE"
    printf '# `tracedecay` then resolves to the guarded V2 trial shim.\n'
    printf 'export TRACEDECAY_DATA_DIR=%q\n' "$PROFILE"
    printf 'export TRACEDECAY_GLOBAL_DB=%q\n' "$PROFILE/global.db"
    printf 'export TRACEDECAY_DAEMON_SOCKET=%q\n' "$SOCKET"
    printf 'export TRACEDECAY_TRIAL_ROOT=%q\n' "$ROOT"
    printf 'export PATH=%q:"$PATH"\n' "$BIN_DIR"
    printf 'unset HF_HOME HF_ENDPOINT FASTEMBED_CACHE_DIR\n'
    printf 'hash -r 2>/dev/null || true\n'
  } >"$tmp"
  mv "$tmp" "$ENV_FILE"
}

# Claude Code settings/MCP files for an optional manual session in real
# host-home mode. Generated from the shipped plugin hook list, with the
# guarded trial shim as the command, and the installed plugin disabled for
# that session only (flag settings; nothing under ~/.claude is written).
write_claude_session_files() {
  mkdir -p "$ROOT/claude"
  jq --arg bin "$SHIM" '
    del(.description)
    | .enabledPlugins = {"tracedecay@tracedecay": false}
    | .hooks |= with_entries(.value |= map(.hooks |= map(
        {type: "command", command: ($bin + " " + (.args | join(" ")))}
        + (if .timeout then {timeout: .timeout} else {} end))))
  ' "$REPO/plugin/hooks/hooks-claude.json" >"$ROOT/claude/settings.json"
  jq -n --arg bin "$SHIM" '{mcpServers: {"tracedecay-v2": {type: "stdio", command: $bin, args: ["serve"], env: {TRACEDECAY_ENABLE_GLOBAL_DB: "1"}}}}' \
    >"$ROOT/claude/mcp.json"
}

print_env_instructions() {
  local home_note
  home_note=$(host_home_mode)
  if [ "$home_note" = isolated ]; then
    home_note="isolated ($TRIAL_HOME)"
  else
    home_note="real ($HOME: the daemon reads your Claude/Codex transcripts)"
  fi
  cat <<EOF

Isolated V2 profile
  trial root : $ROOT
  profile    : $PROFILE
  socket     : $SOCKET
  project    : ${PROJECT:-<none>}
  daemon log : $DAEMON_LOG
  host home  : $home_note

Point a shell at it (bash or zsh):
  source $ENV_FILE
  tracedecay ncm status --path "${PROJECT:-<project>}"
  tracedecay tool --project "${PROJECT:-<project>}" tracedecay_context --args '{"task":"...","format":"json"}' --json

Equivalent explicit exports:
  export TRACEDECAY_DATA_DIR=$PROFILE
  export TRACEDECAY_GLOBAL_DB=$PROFILE/global.db
  export TRACEDECAY_DAEMON_SOCKET=$SOCKET
  export PATH=$BIN_DIR:\$PATH

Do NOT run 'tracedecay install/update-plugin/uninstall/upgrade/daemon start|stop|restart|install-service'
with the trial binary (the shim refuses them). Stop the trial with: $0 down
EOF
  if [ "$(host_home_mode)" = "real" ] && [ -f "$ROOT/claude/settings.json" ]; then
    cat <<EOF

Manual Claude Code session against the trial (real host-home mode):
  cd "${PROJECT:-<project>}"
  claude --settings $ROOT/claude/settings.json --mcp-config $ROOT/claude/mcp.json
  Inside the session, check /hooks lists only commands under $BIN_DIR.
EOF
  fi
}

# ---------------------------------------------------------------------------
# Tool calls and configuration (revision CAS, canonical JSON)
# ---------------------------------------------------------------------------

# jq helpers: `payload` decodes a compatibility MCP result's content text into
# the tool's own JSON payload, as the journeys' join_content_text does.
# shellcheck disable=SC2016
JQ_LIB='
def strip_metrics:
  split("\n") as $l
  | ([$l | to_entries[] | select(.value | test("^\\s*tracedecay_metrics:")) | .key] | first) as $cut
  | $l[0:($cut // ($l | length))] | join("\n");
def payload:
  if type == "object" then
    if (.content | type) == "array" then
      ([.content[] | (.text? // empty) | select(type == "string") | strip_metrics | select(test("\\S"))]) as $texts
      | ([$texts[] | (try fromjson catch null) | select(type == "object")]) as $objects
      | if ($objects | length) == 1 then $objects[0]
        elif ($texts | length) > 0 then ($texts | join("\n\n"))
        else . end
    else . end
  else . end;
'

TOOL_STDERR=""
# tool_raw NAME ARGS_JSON: the daemon result object verbatim (exit != 0 on refusal).
tool_raw() {
  TOOL_STDERR=$ROOT/last-tool.stderr
  td_in_project tool --project "$PROJECT" "$1" --args "$2" --json 2>"$TOOL_STDERR"
}

tool_payload() {
  local raw
  raw=$(tool_raw "$1" "$2") || return 1
  jq "$JQ_LIB payload" <<<"$raw"
}

config_revision() {
  local raw revisions count
  raw=$(tool_raw tracedecay_configuration_observed_state '{}') ||
    die "tracedecay_configuration_observed_state failed: $(cat "$TOOL_STDERR")"
  revisions=$(jq -c "$JQ_LIB"'[(., payload) | .. | objects | (.desired_revision_id? // empty) | strings] | unique' <<<"$raw")
  count=$(jq 'length' <<<"$revisions")
  [ "$count" = "1" ] || die "configuration components do not agree on one desired revision: $revisions"
  jq -r '.[0]' <<<"$revisions"
}

config_effective() {
  local raw
  raw=$(tool_raw tracedecay_configuration_get "$(jq -nc --arg key "$1" '{key: $key}')") || return 1
  jq -cS "$JQ_LIB"'[(., payload) | .. | objects | select(has("effective_value")) | .effective_value] | first' <<<"$raw"
}

config_set() {
  local key=$1 value=$2 purpose=$3 revision args
  revision=$(config_revision)
  args=$(jq -nc --arg project_id "$PROJECT_ID" --arg key "$key" --argjson value "$value" \
    --arg revision "$revision" --arg idem "configuration.idempotency.trial-$purpose-$(date +%s)-$$" \
    '{layer: {kind: "project", project_id: $project_id}, key: $key, value: $value, expected_revision: $revision, idempotency_key: $idem}')
  tool_raw tracedecay_configuration_set "$args" >"$ROOT/last-config-set.json" ||
    die "tracedecay_configuration_set $key failed: $(cat "$TOOL_STDERR")"
  log "committed $key = $(jq -c . <<<"$value")"
}

# ensure_setting KEY VALUE_JSON PURPOSE: write only when the effective value differs.
ensure_setting() {
  local current wanted
  wanted=$(jq -cS . <<<"$2")
  current=$(config_effective "$1" 2>/dev/null || true)
  if [ -n "$current" ] && [ "$current" = "$wanted" ]; then
    log "$1 already $(jq -c . <<<"$2")"
    return 0
  fi
  config_set "$1" "$2" "$3"
}

bool_value() { jq -nc --argjson v "$1" '{kind: "boolean", value: $v}'; }

provider_id_for() {
  case $1 in
    ncm) printf 'ncm' ;;
    native) printf 'tracedecay.native' ;;
    *) die "unknown provider '$1' (expected ncm or native)" ;;
  esac
}

# Canonical JSON text (sorted keys, compact, every field present) of
# MemoryProviderRecallRoutingV1, stored as a text setting.
routing_value() {
  local text
  text=$(jq -ncS --arg p "$(provider_id_for "$1")" --arg policy "$ROUTING_POLICY_ID" \
    '{active_provider: $p, fallback: null, degradation: {policy_id: $policy, policy_revision: 1, allowed_causes: ["partial", "stale"]}}')
  jq -nc --arg text "$text" '{kind: "text", value: $text}'
}

# ---------------------------------------------------------------------------
# Isolated daemon lifecycle (never an installed service)
# ---------------------------------------------------------------------------

recorded_daemon_pid() {
  [ -f "$PID_FILE" ] || return 1
  local pid command
  pid=$(tr -cd '0-9' <"$PID_FILE")
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  command=$(ps -p "$pid" -o command= 2>/dev/null || true)
  case $command in
    *"daemon run"*"--profile-root $PROFILE"*) printf '%s' "$pid" ;;
    *) return 1 ;;
  esac
}

socket_connectable() {
  "$PYTHON" - "$1" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1.0)
s.connect(sys.argv[1])
s.close()
PY
}

start_daemon() {
  check_socket_length
  if recorded_daemon_pid >/dev/null; then
    die "the trial daemon is already running (pid $(recorded_daemon_pid)); use '$0 down' first"
  fi
  mkdir -p "$PROFILE"
  [ "$(host_home_mode)" = "isolated" ] && mkdir -p "$TRIAL_HOME/.config"
  printf '\n===== %s daemon start (%s) =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(host_home_mode) host home" >>"$DAEMON_LOG"
  RUST_LOG=${TRIAL_RUST_LOG:-warn} nohup "$SELF" __daemon-exec >>"$DAEMON_LOG" 2>&1 </dev/null &
  local pid=$!
  printf '%s\n' "$pid" >"$PID_FILE"
  local authority=$PROFILE/daemon-authority.json deadline endpoint
  deadline=$(($(date +%s) + READY_BUDGET_SECS))
  log "waiting for the isolated daemon (pid $pid) to publish its authority"
  while :; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$PID_FILE"
      tail -n 40 "$DAEMON_LOG" >&2 || true
      die "the isolated daemon exited during startup; see $DAEMON_LOG"
    fi
    if [ -f "$authority" ] && [ "$(jq -r '.pid // empty' "$authority" 2>/dev/null)" = "$pid" ]; then
      endpoint=$(jq -r '.endpoint.address // empty' "$authority")
      if [ -n "$endpoint" ] && socket_connectable "$endpoint"; then
        break
      fi
    fi
    [ "$(date +%s)" -lt "$deadline" ] || die "daemon did not publish its authority within ${READY_BUDGET_SECS}s; see $DAEMON_LOG"
    sleep 0.2
  done
  log "isolated daemon up (pid $pid, socket $endpoint)"
}

# Re-exec target for the background daemon: `exec` keeps the recorded pid.
daemon_exec() {
  require_build
  cd "$PROFILE"
  if [ "$(host_home_mode)" = "isolated" ]; then
    exec env TRACEDECAY_DATA_DIR="$PROFILE" TRACEDECAY_GLOBAL_DB="$PROFILE/global.db" \
      TRACEDECAY_DAEMON_SOCKET="$SOCKET" HOME="$TRIAL_HOME" XDG_CONFIG_HOME="$TRIAL_HOME/.config" \
      PATH="$BIN_DIR:$PATH" "$BIN" daemon run --profile-root "$PROFILE" --socket "$SOCKET"
  fi
  exec env TRACEDECAY_DATA_DIR="$PROFILE" TRACEDECAY_GLOBAL_DB="$PROFILE/global.db" \
    TRACEDECAY_DAEMON_SOCKET="$SOCKET" PATH="$BIN_DIR:$PATH" \
    "$BIN" daemon run --profile-root "$PROFILE" --socket "$SOCKET"
}

stop_daemon() {
  local pid
  if ! pid=$(recorded_daemon_pid); then
    if [ -f "$PID_FILE" ]; then
      log "recorded daemon pid is not a live trial daemon; clearing $PID_FILE"
      rm -f "$PID_FILE"
    fi
    return 0
  fi
  log "stopping the isolated trial daemon (pid $pid)"
  kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge 60 ]; then
      warn "daemon ignored SIGTERM for 60s; sending SIGKILL"
      kill -KILL "$pid" 2>/dev/null || true
    fi
    sleep 0.5
    waited=$((waited + 1))
    [ "$waited" -lt 200 ] || die "daemon pid $pid did not exit"
  done
  rm -f "$PID_FILE"
}

wait_ready() {
  local deadline
  deadline=$(($(date +%s) + READY_BUDGET_SECS))
  until tool_raw tracedecay_configuration_observed_state '{}' >/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || die "daemon did not answer tool calls within ${READY_BUDGET_SECS}s: $(cat "$TOOL_STDERR")"
    sleep 0.5
  done
}

restart_daemon() {
  stop_daemon
  start_daemon
  wait_ready
}

load_project() {
  PROJECT=$(state_get PROJECT)
  PROJECT_ID=$(state_get PROJECT_ID)
  [ -n "$PROJECT" ] && [ -n "$PROJECT_ID" ] || die "no trial project recorded; run: $0 up"
}

require_running() {
  recorded_daemon_pid >/dev/null || die "the isolated trial daemon is not running; run: $0 up"
}

# ---------------------------------------------------------------------------
# Project selection
# ---------------------------------------------------------------------------

create_fixture_project() {
  local project=$1
  log "creating fixture git project at $project"
  mkdir -p "$project/src"
  git -C "$project" init --quiet -b main
  git -C "$project" config user.email trial@example.com
  git -C "$project" config user.name "TraceDecay Trial"
  printf '[package]\nname = "tracedecay-trial-fixture"\nversion = "0.0.0"\nedition = "2024"\n' >"$project/Cargo.toml"
  printf '/// Quicksilver transport probe.\npub fn quicksilver_probe() -> u8 { 7 }\n' >"$project/src/lib.rs"
  git -C "$project" add .
  git -C "$project" commit --quiet -m initial
}

select_project() {
  local requested=$1
  if [ ! -e "$requested" ]; then
    case $requested in
      "$ROOT"/*) create_fixture_project "$requested" ;;
      *) die "project $requested does not exist" ;;
    esac
  fi
  PROJECT=$(cd -P "$requested" && pwd -P)
  git -C "$PROJECT" rev-parse --verify HEAD >/dev/null 2>&1 ||
    die "$PROJECT must be a git work tree with at least one commit"
  local common marker
  common=$(cd "$PROJECT" && cd -P "$(git rev-parse --git-common-dir)" && pwd -P)
  marker=$common/tracedecay-project.json
  if [ -f "$marker" ] && [ "$(state_get PROJECT)" != "$PROJECT" ]; then
    die "$PROJECT already carries a TraceDecay identity marker ($marker), most likely from your installed V1.
'init' would bind this repository to the trial profile. Clone it under the trial root instead, e.g.
  git clone $PROJECT $ROOT/projects/$(basename "$PROJECT")"
  fi
  case $PROJECT in
    "$ROOT"/*) ;;
    *) warn "$PROJECT is outside the trial root; 'init' writes $marker into that repository's git directory" ;;
  esac
}

init_project() {
  local deadline output
  deadline=$(($(date +%s) + READY_BUDGET_SECS))
  log "tracedecay init $PROJECT"
  while :; do
    if output=$(td_in_project init 2>&1); then
      break
    fi
    case $output in
      *code_index_scheduler_unavailable*) ;;
      *) printf '%s\n' "$output" >&2 && die "tracedecay init failed" ;;
    esac
    [ "$(date +%s)" -lt "$deadline" ] || die "the daemon's code-index scheduler never became available"
    sleep 0.2
  done
  PROJECT_ID=$(td_in_project projects context "$PROJECT" --json | jq -r '.project.project_id // empty')
  [ -n "$PROJECT_ID" ] || die "could not read the registered project id"
  state_set PROJECT "$PROJECT"
  state_set PROJECT_ID "$PROJECT_ID"
  log "project id $PROJECT_ID"
}

# ---------------------------------------------------------------------------
# NCM enablement and routing
# ---------------------------------------------------------------------------

ncm_status_json() {
  td_in_project ncm status --path "$PROJECT" --json
}

enable_ncm() {
  local status enabled supported configured_root configured_sha bundle_sha
  status=$(ncm_status_json) || die "tracedecay ncm status failed"
  supported=$(jq -r '.platform_supported' <<<"$status")
  [ "$supported" = "true" ] ||
    die "this binary's embedded worker trust root does not pin $(jq -r '.platform_target' <<<"$status"); rerun: $0 build"
  enabled=$(jq -r '.enabled' <<<"$status")
  bundle_sha=$(sha256_of "$WORKER")
  if [ "$enabled" = "true" ]; then
    configured_root=$(jq -r '.state_root // empty' <<<"$status")
    configured_sha=$(jq -r '.worker_sha256 // empty' <<<"$status")
    [ "$configured_root" = "$NCM_STATE" ] ||
      die "NCM is already enabled with state root $configured_root (expected $NCM_STATE)"
    if [ "$configured_sha" = "$bundle_sha" ]; then
      log "NCM already enabled with this bundle's worker"
      return 0
    fi
    log "tracedecay --yes ncm update (worker changed since the last up)"
    td_in_project --yes ncm update --path "$PROJECT" --worker "$WORKER" --state-root "$NCM_STATE" --json \
      >"$ROOT/ncm-update.json" || die "tracedecay ncm update failed"
    return 0
  fi
  log "tracedecay --yes ncm install --worker $WORKER --state-root $NCM_STATE"
  td_in_project --yes ncm install --path "$PROJECT" --worker "$WORKER" --state-root "$NCM_STATE" --json \
    >"$ROOT/ncm-install.json" || die "tracedecay ncm install failed"
  log "NCM install receipt: $ROOT/ncm-install.json ($(jq -r '.outcome // "?"' "$ROOT/ncm-install.json"))"
}

# Route recall. Routing is admitted only when its target is constructible, so
# Native is enabled before a Native route and disabled only after an NCM route,
# matching the journeys (Native participates only when selected).
apply_route() {
  case $1 in
    ncm)
      ensure_setting "$KEY_ROUTING" "$(routing_value ncm)" routing-ncm
      ensure_setting "$KEY_NATIVE" "$(bool_value false)" native-disable
      ;;
    native)
      ensure_setting "$KEY_NATIVE" "$(bool_value true)" native-enable
      ensure_setting "$KEY_ROUTING" "$(routing_value native)" routing-native
      ;;
  esac
}

context_probe() {
  local provider=$1 answer lane
  answer=$(tool_payload tracedecay_context '{"task":"trial readiness probe","format":"json"}') || {
    record FAIL "tracedecay_context answers: $(cat "$TOOL_STDERR")"
    return 0
  }
  lane=$(jq -c 'if type == "object" then (.advisory_provider_memory // null) else null end' <<<"$answer")
  if [ "$provider" = "ncm" ]; then
    if [ "$(jq -r '.provider_id? // empty' <<<"$lane")" = "ncm" ]; then
      record PASS "NCM route mounts the advisory lane (state $(jq -r '.state? // "?"' <<<"$lane"))"
    else
      record FAIL "NCM route: tracedecay_context has no NCM advisory lane: $lane"
    fi
  elif [ "$lane" = "null" ]; then
    record PASS "Native route: tracedecay_context carries no provider lane (upstream memory)"
  else
    record FAIL "Native route: unexpected advisory lane: $lane"
  fi
}

ncm_readiness() {
  local status
  status=$(ncm_status_json) || {
    record FAIL "tracedecay ncm status"
    return 0
  }
  printf '%s\n' "$status" >"$ROOT/ncm-status.json"
  if [ "$(jq -r '.enabled and .worker_present and .manifest_present and .encoder_ready and (.pending_recovery | not)' <<<"$status")" = "true" ]; then
    record PASS "ncm status: enabled, worker verified, encoder ready, no pending recovery"
  else
    record FAIL "ncm status not ready: $(jq -c '{enabled, worker_present, manifest_present, model_manifest_present, encoder_ready, pending_recovery}' <<<"$status")"
  fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_build() {
  need_cmd cargo "install rustup: https://rustup.rs"
  need_cmd rustc
  need_cmd git
  need_cmd jq
  need_cmd "$PYTHON"
  need_cmd node "install Node.js 22"
  need_cmd pnpm "run: corepack enable"
  darwin_checks
  [ -d "$REPO/.pnpm/crates/crates-io" ] ||
    die "vendored Cargo sources are missing; run 'pnpm install --frozen-lockfile' in $REPO"
  if command -v rustup >/dev/null 2>&1; then
    # Installs the toolchain rust-toolchain.toml pins (as the CI lanes do).
    (cd "$REPO" && rustup toolchain install) || (cd "$REPO" && rustup show active-toolchain)
  fi
  local host
  host=$(cd "$REPO" && rustc -vV | sed -n 's/^host: //p')
  case $host in
    aarch64-apple-darwin | x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu) ;;
    x86_64-apple-darwin)
      [ -n "${ORT_LIB_LOCATION:-}" ] ||
        die "x86_64 macOS has no ONNX Runtime prebuilt; set ORT_LIB_LOCATION and ORT_PREFER_DYNAMIC_LINK=1 (see the CI workflow)"
      ;;
    *) die "unsupported trial host target: $host" ;;
  esac
  mkdir -p "$BUNDLE_ROOT"
  local out=$ROOT/bundle.out
  log "building the pinned NCM worker bundle for $host"
  (cd "$REPO" && env -u TRACEDECAY_NCM_WORKER_MANIFEST "$PYTHON" scripts/product/ncm/build-worker-bundle.py \
    --target "$host" --output "$BUNDLE_ROOT/$host") | tee "$out"
  local manifest worker
  manifest=$(sed -n 's/^TRACEDECAY_NCM_WORKER_MANIFEST=//p' "$out" | tail -n 1)
  worker=$(sed -n 's/^TRACEDECAY_NCM_WORKER=//p' "$out" | tail -n 1)
  # Older bundle scripts print only the manifest assignment.
  [ -n "$worker" ] || worker=$(dirname "$manifest")/tracedecay-ncm-worker
  [ -f "$manifest" ] && [ -f "$worker" ] || die "the bundle script did not report its manifest and worker"
  [ "$worker" = "$BUNDLE_ROOT/$host/tracedecay-ncm-worker" ] || die "unexpected bundle worker path $worker"
  if [ "$(uname -s)" = "Darwin" ]; then
    otool -L "$worker" >"$ROOT/worker-linkage.txt"
  else
    ldd "$worker" >"$ROOT/worker-linkage.txt" 2>&1 || true
  fi
  log "building the release CLI with the embedded worker trust root"
  (cd "$REPO" && TRACEDECAY_NCM_WORKER_MANIFEST="$manifest" cargo build --locked --release \
    -p tracedecay-cli --bin tracedecay --features memory-provider-host)
  local target_dir bin
  target_dir=$(cd "$REPO" && cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')
  bin=$target_dir/release/tracedecay
  [ -x "$bin" ] || die "release binary $bin is missing"
  "$bin" --version
  "$bin" ncm --help >/dev/null
  state_set REPO "$REPO"
  state_set TARGET "$host"
  state_set BIN "$bin"
  state_set BIN_SHA256 "$(sha256_of "$bin")"
  state_set WORKER "$worker"
  state_set WORKER_MANIFEST "$manifest"
  state_set WORKER_SHA256 "$(sha256_of "$worker")"
  state_set BUILT_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat <<EOF

Build recorded in $STATE
  TRACEDECAY_NCM_WORKER=$worker
  TRACEDECAY_NCM_WORKER_MANIFEST=$manifest
  binary=$bin
Next: $0 model
EOF
}

cmd_model() {
  need_cmd "$PYTHON"
  need_cmd jq
  mkdir -p "$NCM_STATE"
  local physical
  physical=$(cd -P "$NCM_STATE" && pwd -P)
  [ "$physical" = "$NCM_STATE" ] || die "NCM state root has symlink components: $NCM_STATE -> $physical"
  log "installing the pinned NCM model into $NCM_STATE (~490 MB download on first run)"
  (cd "$REPO" && "$PYTHON" scripts/product/ncm/verify-installed.py \
    --manifest "$MODEL_MANIFEST_REL" --revision-receipt "$REVISION_RECEIPT_REL" \
    --model-root "$NCM_STATE" --operation install) >"$ROOT/model-install.json"
  log "verifying the installed model tree and its acquisition receipt"
  (cd "$REPO" && "$PYTHON" scripts/product/ncm/verify-installed.py \
    --manifest "$MODEL_MANIFEST_REL" --revision-receipt "$REVISION_RECEIPT_REL" \
    --model-root "$NCM_STATE" --operation verify) >"$ROOT/model-verify.json"
  [ -f "$NCM_STATE/$MODEL_RECEIPT_REL" ] || die "model acquisition receipt is missing after install"
  state_set MODEL_ROOT "$NCM_STATE"
  printf 'Model installed and verified under %s\n  install result: %s\n  verify result:  %s\nNext: %s test   (or: %s up)\n' \
    "$NCM_STATE" "$ROOT/model-install.json" "$ROOT/model-verify.json" "$0" "$0"
}

run_step() {
  local name=$1
  shift
  log "$name: $*"
  if (cd "$REPO" && "$@"); then
    record PASS "$name"
  else
    record FAIL "$name"
  fi
}

cmd_test() {
  local suite=${1:-all}
  case $suite in
    all | runtime | lifecycle | journeys) ;;
    *) die "unknown test suite '$suite' (all, runtime, lifecycle, journeys)" ;;
  esac
  need_cmd cargo
  require_build
  require_model
  darwin_checks
  mkdir -p "$TRIAL_TMP"
  # Same variables the CI workflow exports. TMPDIR keeps the journeys' temp
  # profiles on the model's filesystem so they hard-link the installed model.
  export TRACEDECAY_NCM_WORKER_MANIFEST="$WORKER_MANIFEST"
  export TRACEDECAY_NCM_WORKER="$WORKER"
  export TRACEDECAY_NCM_REAL_MODEL_ROOT="$NCM_STATE"
  export TMPDIR="$TRIAL_TMP"
  unset TRACEDECAY_DAEMON_SOCKET TRACEDECAY_GLOBAL_DB TRACEDECAY_DATA_DIR
  if [ "$suite" = all ] || [ "$suite" = runtime ]; then
    run_step "NCM runtime: real encoder + model lifecycle" \
      cargo test --locked -p tracedecay-memory-ncm-runtime --test real_embeddings --test model_lifecycle
    run_step "NCM runtime: worker protocol" \
      cargo test --locked -p tracedecay-memory-ncm-runtime --features test-transport --test worker
  fi
  if [ "$suite" = all ] || [ "$suite" = lifecycle ]; then
    run_step "NCM lifecycle through the shipped CLI" \
      cargo test --locked -p tracedecay-cli --features memory-provider-host,test-transport \
      --test host_journeys_suite -- ncm_lifecycle_cli_acceptance:: --include-ignored
  fi
  if [ "$suite" = all ] || [ "$suite" = journeys ]; then
    run_step "Provider host journeys (Native, NCM observer, NCM active, rollback)" \
      cargo test --locked -p tracedecay-cli --features memory-provider-host,test-transport \
      --test product_memory_provider_claude_host_journey -- \
      --include-ignored --skip host_comparison_fixture_entry --test-threads 2
  fi
  print_results "test"
  [ "$FAILURES" -eq 0 ]
}

cmd_up() {
  local project="" provider=ncm mode=isolated
  while [ $# -gt 0 ]; do
    case $1 in
      --provider) provider=${2:?--provider needs ncm or native}; shift 2 ;;
      --provider=*) provider=${1#--provider=}; shift ;;
      --host-home) mode=${2:?--host-home needs isolated or real}; shift 2 ;;
      --host-home=*) mode=${1#--host-home=}; shift ;;
      -*) die "unknown option $1" ;;
      *) [ -z "$project" ] || die "only one project path may be given"; project=$1; shift ;;
    esac
  done
  provider_id_for "$provider" >/dev/null
  case $mode in isolated | real) ;; *) die "--host-home must be isolated or real" ;; esac
  need_cmd jq
  need_cmd git
  need_cmd "$PYTHON"
  require_build
  require_model
  check_socket_length
  recorded_daemon_pid >/dev/null && die "the trial daemon is already running; use '$0 route' or '$0 down'"
  select_project "${project:-$DEFAULT_PROJECT}"
  state_set HOST_HOME_MODE "$mode"
  write_shim_and_env
  if [ "$mode" = real ]; then
    write_claude_session_files
    if [ -f "$HOME/.claude/settings.json" ] &&
      jq -e '[.hooks? // {} | .. | strings | select(test("tracedecay"))] | length > 0' "$HOME/.claude/settings.json" >/dev/null 2>&1; then
      warn "$HOME/.claude/settings.json itself registers tracedecay hooks; those would also run in a manual session. Use only '$0 smoke' (isolated) instead."
    fi
  fi
  start_daemon
  init_project
  log "enabling providers for route '$provider'"
  ensure_setting "$KEY_NATIVE" "$(bool_value "$([ "$provider" = native ] && echo true || echo false)")" native-gate
  enable_ncm
  ensure_setting "$KEY_ROUTING" "$(routing_value "$provider")" "routing-$provider"
  log "restarting the isolated daemon so the DaemonRestart provider settings take effect"
  restart_daemon
  state_set PROVIDER "$provider"
  ncm_readiness
  context_probe "$provider"
  print_env_instructions
  print_results "up"
  [ "$FAILURES" -eq 0 ]
}

do_route() {
  local provider=$1
  provider_id_for "$provider" >/dev/null
  if [ "$provider" = ncm ]; then
    [ "$(ncm_status_json | jq -r '.enabled')" = "true" ] || die "NCM is not enabled; run '$0 up' first"
  fi
  log "routing recall to $provider"
  apply_route "$provider"
  log "restarting the isolated daemon"
  restart_daemon
  state_set PROVIDER "$provider"
}

cmd_route() {
  local provider=${1:-}
  [ -n "$provider" ] || die "usage: $0 route ncm|native"
  require_build
  load_project
  require_running
  do_route "$provider"
  context_probe "$provider"
  print_results "route $provider"
  [ "$FAILURES" -eq 0 ]
}

cmd_status() {
  printf 'Trial root   : %s\n' "$ROOT"
  printf 'Built        : %s (%s)\n' "$(state_get BUILT_AT)" "$(state_get TARGET)"
  printf 'Binary       : %s\n' "$(state_get BIN)"
  printf 'Worker       : %s\n' "$(state_get WORKER)"
  printf 'Model root   : %s\n' "$(state_get MODEL_ROOT)"
  printf 'Project      : %s (%s)\n' "$(state_get PROJECT)" "$(state_get PROJECT_ID)"
  printf 'Host home    : %s\n' "$(host_home_mode)"
  printf 'Route        : %s\n' "$(state_get PROVIDER)"
  local pid
  if pid=$(recorded_daemon_pid); then
    printf 'Daemon       : running (pid %s, socket %s)\n' "$pid" "$SOCKET"
    if [ -f "$PROFILE/daemon-authority.json" ]; then
      printf 'Authority    : %s\n' "$(jq -c '{pid, version, endpoint}' "$PROFILE/daemon-authority.json" 2>/dev/null || echo unreadable)"
    fi
  else
    printf 'Daemon       : not running\n'
    return 0
  fi
  require_build
  load_project
  printf '\n-- tracedecay ncm status --json\n'
  ncm_status_json || warn "ncm status failed"
  printf '\n-- provider settings (effective values)\n'
  local key
  for key in "$KEY_NATIVE" "$KEY_NCM" "$KEY_ROUTING"; do
    printf '%s = %s\n' "$key" "$(config_effective "$key" 2>/dev/null || echo '<unavailable>')"
  done
  printf '\n-- provider journals under the profile\n'
  find "$PROFILE" -name 'memory-observation-*journal*.sqlite3' -print 2>/dev/null || true
}

cmd_down() {
  stop_daemon
  printf 'Isolated trial daemon stopped. Trial data remains under %s.\n' "$ROOT"
}

cmd_env() {
  [ -f "$ENV_FILE" ] || die "no env file yet; run: $0 up"
  PROJECT=$(state_get PROJECT)
  print_env_instructions
}

# --- smoke -----------------------------------------------------------------

run_hook() {
  # run_hook SUBCOMMAND PAYLOAD LABEL
  local output=$SMOKE_DIR/$3.out
  if (cd "$PROJECT" && printf '%s' "$2" | td "$1") >"$output" 2>&1; then
    record PASS "shipped hook '$1' ($3) exits 0"
  else
    record FAIL "shipped hook '$1' ($3) failed; see $output"
  fi
}

claude_turn() {
  # claude_turn N USER_TEXT ASSISTANT_TEXT -> two JSONL rows in Claude Code's transcript shape
  local user_uuid="trial-smoke-uuid-$SMOKE_RUN-$1" assistant_uuid="trial-smoke-uuid-$SMOKE_RUN-$(($1 + 1))"
  local now
  now=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
  jq -nc --arg cwd "$PROJECT" --arg session "$SMOKE_SESSION" --arg uuid "$user_uuid" --arg ts "$now" --arg text "$2" \
    '{type: "user", cwd: $cwd, sessionId: $session, uuid: $uuid, timestamp: $ts, message: {role: "user", content: $text}}'
  jq -nc --arg cwd "$PROJECT" --arg session "$SMOKE_SESSION" --arg uuid "$assistant_uuid" --arg parent "$user_uuid" \
    --arg ts "$now" --arg text "$3" --arg id "msg_trial_smoke_${SMOKE_RUN}_$(($1 + 1))" \
    '{type: "assistant", cwd: $cwd, sessionId: $session, uuid: $uuid, parentUuid: $parent, timestamp: $ts,
      message: {id: $id, role: "assistant", model: "claude-opus-4-8", content: [{type: "text", text: $text}]}}'
}

# Poll tracedecay_context until the NCM lane returns a candidate containing
# every given marker. Prints the last lane on stdout.
await_ncm_recall() {
  local task=$1 first=$2 second=${3:-} deadline args answer lane found
  deadline=$(($(date +%s) + SETTLE_BUDGET_SECS))
  args=$(jq -nc --arg task "$task" '{task: $task, format: "json"}')
  while :; do
    lane=null
    if answer=$(tool_payload tracedecay_context "$args"); then
      lane=$(jq -c 'if type == "object" then (.advisory_provider_memory // null) else null end' <<<"$answer")
      found=$(jq -r --arg a "$first" --arg b "$second" \
        '[.candidates[]? | (.content? // "") | tostring | select(contains($a) and contains($b))] | length > 0' <<<"$lane" 2>/dev/null || echo false)
      if [ "$found" = "true" ]; then
        printf '%s\n' "$lane"
        return 0
      fi
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      printf '%s\n' "$lane"
      return 1
    fi
    sleep 1
  done
}

message_search_finds() {
  local args payload
  args=$(jq -nc --arg query "$1 retry budget" '{query: $query, format: "json"}')
  payload=$(tool_payload tracedecay_message_search "$args") || return 1
  [ "$(jq -r --arg t "$1" 'if type == "object" then (.outcome.value.payload // .) else {} end
    | [.results[]? | (.message.text? // "") | tostring | select(contains($t))] | length > 0' <<<"$payload")" = "true" ]
}

cmd_smoke() {
  require_build
  load_project
  require_running
  [ "$(host_home_mode)" = "isolated" ] ||
    die "smoke writes a fixture transcript under the daemon's host home; it runs only with 'up --host-home isolated'"
  SMOKE_RUN=$(date +%s)
  SMOKE_SESSION=$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')
  SMOKE_DIR=$ROOT/smoke/$SMOKE_RUN
  mkdir -p "$SMOKE_DIR"
  local term="quicksilver$SMOKE_RUN" sentinel="obsidian-ledger-tail-$SMOKE_RUN"
  local slug transcript
  slug=$(printf '%s' "$PROJECT" | tr '/.' '--')
  transcript=$TRIAL_HOME/.claude/projects/$slug/$SMOKE_SESSION.jsonl
  log "smoke run $SMOKE_RUN, Claude session $SMOKE_SESSION"

  if [ "$(state_get PROVIDER)" != ncm ]; then
    do_route ncm
  fi

  # 1. NCM active: the lane is mounted before any hook.
  context_probe ncm

  # 2. SessionStart on an empty transcript establishes the live baseline.
  mkdir -p "$(dirname "$transcript")"
  : >"$transcript"
  run_hook hook-claude-session-start \
    "$(jq -nc --arg s "$SMOKE_SESSION" --arg t "$transcript" --arg cwd "$PROJECT" \
      '{session_id: $s, transcript_path: $t, cwd: $cwd, hook_event_name: "SessionStart", source: "startup"}')" \
    session-start
  local stop_payload
  stop_payload=$(jq -nc --arg s "$SMOKE_SESSION" --arg t "$transcript" --arg cwd "$PROJECT" \
    '{session_id: $s, transcript_path: $t, cwd: $cwd, hook_event_name: "Stop", stop_hook_active: false}')

  # 3. First turn, committed by the shipped Stop hook, then recalled by NCM.
  claude_turn 1 "how does the $term transport probe decide its retry budget?" \
    "the $term transport probe reads its retry budget from the pinned deadline" >>"$transcript"
  run_hook hook-stop "$stop_payload" stop-turn-1
  local lane
  if lane=$(await_ncm_recall "how does the $term transport probe decide its retry budget?" "$term"); then
    record PASS "NCM journal delivery: the advisory lane recalls the first turn"
  else
    record FAIL "NCM never recalled the first turn within ${SETTLE_BUDGET_SECS}s; last lane: $lane"
  fi
  if [ -n "$(find "$PROFILE" -name "$NCM_JOURNAL_FILE" -print 2>/dev/null | sed -n 1p)" ]; then
    record PASS "NCM observation journal exists under the trial profile"
  else
    record FAIL "no $NCM_JOURNAL_FILE under $PROFILE"
  fi

  # 4. Mid-session turn with a long reply: recall must return it whole.
  claude_turn 3 "what did the $term retry budget change actually record?" \
    "the $term transport probe records its retry budget change in three places: the pinned deadline it reads at construction, the attempt ledger it advances on every refused delivery, and the operator-visible note the session leaves behind, which ends with $sentinel" \
    >>"$transcript"
  run_hook hook-stop "$stop_payload" stop-turn-2
  if lane=$(await_ncm_recall "what did the $term retry budget change record, down to the $sentinel note?" "$term" "$sentinel"); then
    record PASS "NCM advisory lane recalls the mid-session message whole (tail sentinel present)"
  else
    record FAIL "NCM did not recall the whole mid-session message; last lane: $lane"
  fi
  printf '%s\n' "$lane" >"$SMOKE_DIR/ncm-lane.json"
  if [ "$(jq -r '.provider_id? // empty' <<<"$lane")" = "ncm" ] && [ "$(jq -r '.state? // empty' <<<"$lane")" = "answered" ]; then
    record PASS "lane provider_id=ncm, state=answered, degradation=$(jq -c '.degradation? // null' <<<"$lane")"
  else
    record FAIL "lane is not an answered NCM lane: $(jq -c '{provider_id, state, degradation}?' <<<"$lane" 2>/dev/null || printf '%s' "$lane")"
  fi
  if [ "$(jq -r '[.candidates[]? | .provenance_evidence.kind? // ""] | (length > 0) and all(. == "canonical_observations")' <<<"$lane" 2>/dev/null || echo false)" = "true" ]; then
    record PASS "every NCM candidate carries host-confirmed canonical observation evidence"
  else
    record FAIL "NCM candidates lack canonical observation evidence (see $SMOKE_DIR/ncm-lane.json)"
  fi
  if message_search_finds "$term"; then
    record PASS "upstream message search recalls the hook-committed messages"
  else
    record FAIL "tracedecay_message_search did not find '$term'"
  fi

  # 5. Rollback: route to Native, restart, Native answers as upstream memory.
  do_route native
  local answer lane_after
  if answer=$(tool_payload tracedecay_context "$(jq -nc --arg task "how does the $term transport probe decide its retry budget?" '{task: $task, format: "json"}')"); then
    record PASS "after rollback tracedecay_context answers"
    printf '%s\n' "$answer" >"$SMOKE_DIR/native-context.json"
    lane_after=$(jq -c 'if type == "object" then (.advisory_provider_memory // null) else null end' <<<"$answer")
    if [ "$lane_after" = "null" ]; then
      record PASS "Native answers as upstream memory: no advisory provider lane"
    else
      record FAIL "Native-routed context still carries a provider lane: $lane_after"
    fi
  else
    record FAIL "after rollback tracedecay_context failed: $(cat "$TOOL_STDERR")"
  fi
  if message_search_finds "$term"; then
    record PASS "after rollback upstream message search still recalls the session"
  else
    record FAIL "after rollback tracedecay_message_search did not find '$term'"
  fi
  if [ -z "$(find "$PROFILE" -name "$NATIVE_JOURNAL_FILE" -print 2>/dev/null | sed -n 1p)" ]; then
    record PASS "Native mounts no observation journal"
  else
    record FAIL "a Native observation journal ($NATIVE_JOURNAL_FILE) exists"
  fi
  if [ -n "$(find "$PROFILE" -name "$NCM_JOURNAL_FILE" -print 2>/dev/null | sed -n 1p)" ]; then
    record PASS "NCM stays installed as an observer after rollback (journal retained)"
  else
    record FAIL "the NCM journal disappeared after rollback"
  fi

  print_results "smoke $SMOKE_RUN"
  printf 'Artifacts: %s\nRecall is now routed to Native; return to NCM with: %s route ncm\n' "$SMOKE_DIR" "$0"
  [ "$FAILURES" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

main() {
  local command=${1:-help}
  [ $# -eq 0 ] || shift
  case $command in
    help | -h | --help)
      usage
      return 0
      ;;
  esac
  init_paths
  case $command in
    build) cmd_build "$@" ;;
    model) cmd_model "$@" ;;
    test) cmd_test "$@" ;;
    up) cmd_up "$@" ;;
    route) cmd_route "$@" ;;
    status) cmd_status "$@" ;;
    smoke) cmd_smoke "$@" ;;
    down) cmd_down "$@" ;;
    env) cmd_env "$@" ;;
    __daemon-exec) daemon_exec ;;
    *)
      usage >&2
      die "unknown command '$command'"
      ;;
  esac
}

main "$@"
