#!/usr/bin/env python3
r"""Controlled source-edit rebuilds with hot third-party dependencies, not clean builds.

Example small 2x2 screen, then run a separate thread screen on the chosen profile:
  bazel run //scripts:measure_builds -- --output-dir /tmp/build-screen \
    --bazel-startup-option=--output_base=/path/to/private/base \
    --candidate dev:false:1 --candidate dev:true:1 \
    --candidate perf:false:1 --candidate perf:true:1 \
    --invalidate-source crates/tracedecay-domain/src/lib.rs \
    //crates/tracedecay-domain:tracedecay-domain

Candidates are PROFILE:PIPELINE:THREADS. Use explicit targets and owned Rust roots.
Warm dependencies beforehand in the same output base. Every repetition shuffles
all candidates into a paired block. The first candidate is the comparison baseline.
There are no automatic warmups, source backups, cache removals, or winner selection.
Execution logs can be large. All generated logs and results stay in --output-dir.
Execution evidence is by source root, not every target label sharing that root.
Recorded --test compilations do not mean the tests ran.
Workspace response files are captured per sample; opaque arguments stay unknown.
"""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import random
import re
import signal
import subprocess
import sys
import time
import uuid


class SourceConflict(RuntimeError):
    """A source no longer has the bytes this process is allowed to replace."""


class MeasurementInterrupted(BaseException):
    def __init__(self, signum):
        self.signum = signum
        super().__init__(f"received signal {signum}")


@contextmanager
def invalidate(originals, token):
    """Append markers, then remove only our complete or partially written suffix."""
    changed = {}
    try:
        for path, original in originals.items():
            if path.read_bytes() != original:
                raise SourceConflict(f"source changed before invalidation: {path}")
            marker = f"\n// tracedecay build measurement {token}\n".encode()
            # Windows CRT text mode translates LF even for os.write(bytes).
            # Cleanup must see the exact marker bytes, including partial writes.
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
            changed[path] = [marker, False]
            try:
                pending = marker
                while pending:
                    count = os.write(descriptor, pending)
                    if count <= 0:
                        raise OSError(f"marker append made no progress: {path}")
                    pending = pending[count:]
                changed[path][1] = True
            finally:
                os.close(descriptor)
        yield
    finally:
        conflicts = []
        for path, (marker, complete) in changed.items():
            try:
                # r+b never creates or truncates on open. Read and truncate the
                # same descriptor, and never rewrite any of the original bytes.
                with path.open("r+b", buffering=0) as source:
                    current, original = source.read(), originals[path]
                    suffix = current[len(original):]
                    owned = (current.startswith(original)
                             and (suffix == marker if complete else marker.startswith(suffix)))
                    if not owned:
                        conflicts.append(f"unexpected edit: {path}")
                    elif suffix:
                        os.ftruncate(source.fileno(), len(original))
            except OSError as error:
                conflicts.append(f"restoration error: {path}: {error}")
        if conflicts:
            raise SourceConflict(
                "source cleanup failed; original bytes were not rewritten; inspect: "
                + "; ".join(conflicts)
            )


def json_objects(path):
    """Read Bazel's concatenated, possibly pretty-printed protobuf JSON objects."""
    text = path.read_text()
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        obj, offset = decoder.raw_decode(text, offset)
        yield obj


def parse_bep(path):
    summary, finished, timings = None, None, None
    for event in json_objects(path):
        if "buildMetrics" in event:
            metrics = event["buildMetrics"]
            summary = metrics.get("actionSummary")
            timings = metrics.get("timingMetrics")
        if "finished" in event:
            finished = event["finished"]
    if summary is None or finished is None:
        raise ValueError("BEP has no final action summary or build-finished event")
    runners = {r["name"]: int(r.get("count", 0))
               for r in summary.get("runnerCount", [])}
    cache = summary.get("actionCacheStatistics", {})
    return {
        # Bazel's actionsExecuted includes disk-cache hits and internal actions.
        "actions_executed": int(summary.get("actionsExecuted", 0)),
        "actions_created": int(summary.get("actionsCreated", 0)),
        "actions_by_mnemonic": {
            a["mnemonic"]: int(a.get("actionsExecuted", 0))
            for a in summary.get("actionData", [])
        },
        "process_counts": runners,
        "cache_hit_processes": sum(n for name, n in runners.items()
                                   if "cache hit" in name),
        "internal_processes": runners.get("internal", 0),
        "actual_processes": sum(n for name, n in runners.items()
                                if name not in ("total", "internal")
                                and "cache hit" not in name),
        "local_action_cache_hits": (
            int(cache.get("hits", 0)) if "actionCacheStatistics" in summary else None
        ),
        "timing_metrics": timings,
        "finished": finished,
    }


def source_roots(args):
    return {a for a in args if a.startswith("crates/") and a.endswith(".rs")}


def expand_params(args, contents, execroot, capture_dir, captured, digests, stack=()):
    """Rustc response files contain one literal argument per line, not shell words."""
    expanded = []
    for arg in args:
        if not arg.startswith("@"):
            expanded.append(arg)
            continue
        name = arg[1:]
        if name in stack:
            raise ValueError(f"response-file cycle: {name}")
        data = contents.get(name)
        if data is None:
            relative = Path(name)
            if (execroot is None or relative.is_absolute() or ".." in relative.parts
                    or not relative.parts or relative.parts[0] != "bazel-out"):
                raise ValueError(f"response file unavailable: {name}")
            data = (execroot / relative).read_bytes()
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, bytes):
            raise ValueError(f"response contents must be bytes or text: {name}")
        contents[name] = data
        if capture_dir is not None and name not in captured:
            capture_dir.mkdir(exist_ok=True)
            destination = capture_dir / f"{len(captured) + 1:04d}.params"
            destination.write_bytes(data)
            captured[name] = str(destination)
        digest = digests.get(name, {})
        if digest.get("hash"):
            algorithm = digest.get("hashFunctionName", "SHA-256").replace("-", "").lower()
            if hashlib.new(algorithm, data).hexdigest() != digest["hash"]:
                raise ValueError(f"response file differs from execution input digest: {name}")
        expanded.extend(expand_params(data.decode("utf-8").splitlines(), contents, execroot,
                                      capture_dir, captured, digests, (*stack, name)))
    return expanded


def parse_execution(path, invalidated, *, execroot=None, capture_dir=None, param_contents=None):
    """Saved param_contents maps execution-log @paths to exact response-file bytes/text."""
    execroot = Path(execroot) if execroot is not None else None
    capture_dir = Path(capture_dir) if capture_dir is not None else None
    roots, outputs, actions = set(), set(), []
    executed, hits, deps, unknown = 0, 0, 0, 0
    contents, captured, evidence_errors = dict(param_contents or {}), {}, []
    for spawn in json_objects(path):
        if not spawn.get("mnemonic", "").startswith("Rustc"):
            continue
        args = spawn.get("commandArgs", [])
        label = spawn.get("targetLabel", "")
        workspace = bool(re.match(r"^(?:@{1,2}(?:_main)?)?//crates/", label))
        argument_errors = []
        if workspace or not label or source_roots(args):
            digests = {item["path"]: item.get("digest", {})
                       for item in spawn.get("inputs", [])}
            try:
                args = expand_params(args, contents, execroot, capture_dir, captured, digests)
            except (OSError, ValueError) as error:
                argument_errors.append(str(error))
        sources = source_roots(args)
        workspace = workspace or bool(sources)
        if workspace and not sources:
            argument_errors.append("workspace Rustc source root unavailable")
        evidence_errors.extend(f"{label or 'unlabelled Rustc'}: {e}" for e in argument_errors)
        cached = spawn.get("cacheHit", False) or "cache hit" in spawn.get("runner", "")
        if cached:
            hits += 1
        else:
            executed += 1
            if not workspace and (label or any(a.startswith("external/") and a.endswith(".rs")
                                              for a in args)):
                deps += 1
            elif not workspace:
                unknown += 1
        outputs.update(spawn.get("listedOutputs", []))
        if workspace:
            if (not argument_errors and not cached and spawn.get("runner") and not spawn.get("status")
                    and int(spawn.get("exitCode", 0)) == 0):
                roots.update(sources)
            peak = int(spawn.get("metrics", {}).get("measuredMemoryPeakBytes", 0))
            actions.append({
                "label": spawn.get("targetLabel"), "sources": sorted(sources),
                "mnemonic": spawn["mnemonic"], "runner": spawn.get("runner"),
                "cache_hit": bool(cached), "exit_code": int(spawn.get("exitCode", 0)),
                "status": spawn.get("status", ""),
                "arguments_complete": not argument_errors, "argument_errors": argument_errors,
                "metadata_only": "--rustc-quit-on-rmeta" in args if not argument_errors else None,
                "test_mode": "--test" in args if not argument_errors else None,
                "frontend_thread_flags": (
                    [a for a in args if a.startswith("-Zthreads=")] if not argument_errors else None),
                "max_rss_bytes": peak if peak > 0 and not cached else None,
                "metrics": spawn.get("metrics", {}),
            })
    return {
        "rustc_executed": executed, "rustc_cache_hits": hits,
        "third_party_or_tool_rustc_executed": deps,
        "unclassified_rustc_executed": unknown,
        "argument_evidence_errors": evidence_errors,
        "captured_parameter_files": captured,
        "workspace_roots_executed": sorted(roots),
        "invalidated_roots_not_executed": sorted(set(invalidated) - roots),
        "invalidated_roots_not_executed_count": len(set(invalidated) - roots),
        "workspace_no_op": (
            None if unknown else not any(not a["cache_hit"] and a["runner"] for a in actions)),
        "workspace_actions": actions,
        "generated_output_paths": sorted(outputs),
        # No inference from /usr/bin/time: that measures the Bazel client.
        "compiler_max_rss_bytes": max(
            (a["max_rss_bytes"] for a in actions if a["max_rss_bytes"] is not None),
            default=None,
        ),
    }


def parse_log(text):
    processes = re.findall(r"INFO:\s+(\d+) process(?:es)?:\s*([^\r\n]+)", text)
    elapsed = re.findall(r"Elapsed time:\s*([\d.]+)s", text)
    total = re.findall(r"(\d+) total actions", text)
    return {
        "bazel_elapsed_seconds": float(elapsed[-1]) if elapsed else None,
        "process_summary_total": int(processes[-1][0]) if processes else None,
        "process_summary": processes[-1][1] if processes else None,
        "total_actions": int(total[-1]) if total else None,
    }


def candidate(value):
    parts = value.split(":")
    if (len(parts) != 3 or parts[0] not in ("dev", "perf")
            or parts[1] not in ("false", "true") or parts[2] not in ("1", "2", "4")):
        raise argparse.ArgumentTypeError("use PROFILE:PIPELINE:THREADS, e.g. dev:true:2")
    return value


def parser():
    result = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("targets", nargs="+", help="explicit //package:target labels")
    result.add_argument("--output-dir", required=True, type=Path)
    result.add_argument("--candidate", action="append", required=True, type=candidate)
    result.add_argument("--invalidate-source", action="append", required=True,
                        help="exact owned workspace Rust crate root, repeatable")
    result.add_argument("--mode", choices=("full", "build", "check"), default="full",
                        help="check builds only build_metadata; never links or runs tests")
    result.add_argument("--repetitions", type=int, default=2)
    result.add_argument("--seed", type=int, default=0)
    result.add_argument("--jobs", type=int, default=6)
    result.add_argument("--bazel", default="bazel")
    result.add_argument("--bazel-startup-option", action="append", default=[],
                        help="repeatable, e.g. --bazel-startup-option=--output_base=/path")
    return result


def build_command(options, config, directory):
    profile, pipeline, threads = config.split(":")
    command = [options.bazel, *options.bazel_startup_option, "build",
               f"--config={profile}",
               f"--//:workspace_rust_profile={profile}",
               f"--jobs={options.jobs}",
               f"--@rules_rust//rust/settings:pipelined_compilation={pipeline}",
               f"--@rules_rust//rust/settings:per_crate_rustc_flag=crates/@-Zthreads={threads}",
               f"--profile={directory / 'profile.gz'}",
               f"--build_event_json_file={directory / 'bep.json'}",
               f"--execution_log_json_file={directory / 'execution.json'}",
               "--materialize_param_files",
               "--noremote_upload_local_results", "--color=no", "--curses=no"]
    if options.mode == "check":
        command += ["--@rules_rust//rust/settings:always_enable_metadata_output_groups=true",
                    "--output_groups=build_metadata"]
    else:
        command += ["--output_groups=default"]
    return command + options.targets


def sample(options, config, directory, originals, root, token,
           run=subprocess.run, clock=time.monotonic, execroot=None):
    directory.mkdir()
    command = build_command(options, config, directory)
    row = {"candidate": config, "command": command, "exit_code": None,
           "wall_seconds": None, "errors": [], "eligible": False}
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    try:
        with invalidate(originals, token):
            with (directory / "build.log").open("w") as log:
                start = clock()
                try:
                    completed = run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
                    row["exit_code"] = completed.returncode
                except OSError as error:
                    row["errors"].append(str(error))
                finally:
                    row["wall_seconds"] = clock() - start
    except BaseException as error:
        row["errors"].append(f"{type(error).__name__}: {error}")
        raise
    finally:
        # Even interruption or restoration conflict leaves the raw outcome on disk.
        (directory / "sample.json").write_text(json.dumps(row, indent=2) + "\n")
    invalidated = [p.relative_to(root).as_posix() for p in originals]
    for name, read in (
        ("log", lambda: parse_log((directory / "build.log").read_text())),
        ("bep", lambda: parse_bep(directory / "bep.json")),
        ("execution", lambda: parse_execution(directory / "execution.json", invalidated,
                                              execroot=execroot, capture_dir=directory / "params")),
    ):
        try:
            row[name] = read()
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["errors"].append(f"{name}: {error}")
    if row["exit_code"] != 0:
        row["errors"].append("Bazel did not exit successfully")
    if not (directory / "profile.gz").is_file():
        row["errors"].append("Bazel profile missing")
    if "bep" in row and not row["bep"]["finished"].get("overallSuccess", False):
        row["errors"].append("BEP reports an unsuccessful build")
    if "execution" in row:
        execution = row["execution"]
        row["errors"].extend(execution["argument_evidence_errors"])
        if execution["invalidated_roots_not_executed"]:
            row["errors"].append("execution of invalidated roots not proven; no compile-speed evidence")
        if execution["third_party_or_tool_rustc_executed"]:
            row["errors"].append("third-party/tool compilation occurred; dependencies were not hot")
        if execution["unclassified_rustc_executed"]:
            row["errors"].append("Rustc execution ownership is unknown; dependency warmth not proven")
        requested_threads = f"-Zthreads={config.split(':')[2]}"
        if any(a["frontend_thread_flags"] != [requested_threads]
               for a in execution["workspace_actions"]
               if a["arguments_complete"] and not a["cache_hit"]
               and set(a["sources"]) & set(invalidated)):
            row["errors"].append("workspace frontend thread prefix did not match as requested")
        if options.mode == "check":
            metadata_roots = {
                source for action in execution["workspace_actions"]
                if action["metadata_only"] and not action["cache_hit"]
                for source in action["sources"]
            }
            if set(invalidated) - metadata_roots:
                row["errors"].append("metadata-only execution not proven for every invalidated root")
    row["eligible"] = not row["errors"]
    (directory / "sample.json").write_text(json.dumps(row, indent=2) + "\n")
    return row


def paired_results(samples, baseline):
    pairs = []
    for row in samples:
        if row["candidate"] == baseline:
            continue
        base = next((r for r in samples if r["repetition"] == row["repetition"]
                     and r["candidate"] == baseline), None)
        valid = bool(base and base["eligible"] and row["eligible"])
        pairs.append({
            "repetition": row["repetition"], "candidate": row["candidate"],
            "baseline": baseline, "eligible": valid,
            "wall_delta_seconds": row["wall_seconds"] - base["wall_seconds"] if valid else None,
            "wall_ratio": (row["wall_seconds"] / base["wall_seconds"]
                           if valid and base["wall_seconds"] > 0 else None),
        })
    return pairs


def measure(options, root, run=subprocess.run, clock=time.monotonic,
            check_output=subprocess.check_output):
    root = root.resolve()
    if options.repetitions < 1:
        raise ValueError("--repetitions must be positive")
    if options.jobs < 1:
        raise ValueError("--jobs must be positive")
    if len(set(options.candidate)) != len(options.candidate):
        raise ValueError("duplicate candidate")
    for target in options.targets:
        label = re.fullmatch(r"//([\w/.-]+):([\w.+-]+)", target)
        if (not label or "..." in label[1].split("/")
                or label[2] in ("all", "all-targets")):
            raise ValueError("use explicit //package:target labels, not patterns or flags")
    originals = {}
    for value in options.invalidate_source:
        relative = Path(value)
        path = root / relative
        if (relative.is_absolute() or ".." in relative.parts
                or not value.startswith("crates/") or relative.suffix != ".rs"
                or path.resolve() != path or path in originals):
            raise ValueError(f"invalid, symlinked, or duplicate --invalidate-source: {value}")
        originals[path] = path.read_bytes()
    output = options.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("--output-dir must be empty; existing artifacts are never replaced")
    output.mkdir(parents=True, exist_ok=True)
    options.output_dir = output
    report = {
        "method": "controlled source-edit rebuild with hot third-party dependencies",
        "mode": "full" if options.mode == "build" else options.mode,
        "targets": options.targets, "candidates": options.candidate,
        "invalidated_sources": options.invalidate_source, "seed": options.seed,
        "repetitions": options.repetitions, "jobs": options.jobs, "samples": [],
        "caveats": [
            "Warm the same output base first; dependency compilation makes a sample ineligible.",
            "Wall time includes the Bazel client, analysis, execution and logging, not just rustc.",
            "Stable flags bound configuration outputs by candidate, not by repetition.",
            "Caches remain enabled; Bazel may write source variants to the disk cache.",
            "noremote_upload_local_results prevents local-result remote uploads, not disk writes.",
            "Execution logs may be large; generated paths are execroot-relative, not cleanup authority.",
            "Restoration truncates only our verified marker suffix; original bytes are never rewritten.",
            "Opaque response-file arguments are unknown evidence, not proof of cold dependencies.",
            "Root execution does not prove every label sharing that root compiled or that tests ran.",
        ],
    }
    rng, run_id = random.Random(options.seed), uuid.uuid4().hex

    def save():
        report["pairs"] = paired_results(report["samples"], options.candidate[0])
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        command = [options.bazel, *options.bazel_startup_option, "info", "execution_root"]
        report["execution_root_command"] = command
        with (output / "execution-root.log").open("w") as log:
            execroot = Path(check_output(command, cwd=root, stderr=log, text=True).strip())
        if not execroot.is_absolute() or not execroot.is_dir():
            raise ValueError(f"Bazel returned an unavailable execution root: {execroot}")
        report["execution_root"] = str(execroot)
        save()
        for repetition in range(1, options.repetitions + 1):
            order = list(options.candidate)
            rng.shuffle(order)
            for config in order:
                number = len(report["samples"]) + 1
                directory = output / f"{number:03d}-{config.replace(':', '-')}"
                progress = f"candidate={config} repetition={repetition}/{options.repetitions}"
                print(f"{progress} start", file=sys.stderr, flush=True)
                row = sample(options, config, directory, originals, root,
                             f"{run_id}_{number}", run, clock, execroot)
                row.update(repetition=repetition, order=number, directory=str(directory))
                # Compare successful executions, not all declared or cached Rust actions.
                if row["eligible"]:
                    previous = next((r for r in report["samples"] if r["eligible"]), None)
                    if (previous and row["execution"]["workspace_roots_executed"]
                            != previous["execution"]["workspace_roots_executed"]):
                        row["eligible"] = False
                        row["errors"].append("executed workspace root set differs across samples")
                (directory / "sample.json").write_text(json.dumps(row, indent=2) + "\n")
                report["samples"].append(row)
                save()
                print(
                    f"{progress} finish wall_seconds={row['wall_seconds']:.3f} "
                    f"eligible={str(row['eligible']).lower()} "
                    f"errors={'; '.join(row['errors']) or 'none'}",
                    file=sys.stderr, flush=True,
                )
    except BaseException as error:
        report["fatal_error"] = f"{type(error).__name__}: {error}"
        save()
        raise
    return report


def workspace_root(environ=None, check_output=subprocess.check_output):
    environ = os.environ if environ is None else environ
    command = ["git"]
    if environ.get("BUILD_WORKSPACE_DIRECTORY"):
        command += ["-C", environ["BUILD_WORKSPACE_DIRECTORY"]]
    command += ["rev-parse", "--show-toplevel"]
    return Path(check_output(command, text=True).strip())


def main(argv=None):
    options = parser().parse_args(argv)

    def interrupted(signum, _frame):
        raise MeasurementInterrupted(signum)

    old = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        root = workspace_root()
        report = measure(options, root)
        print(options.output_dir / "results.json")
        return 0 if all(r["eligible"] for r in report["samples"]) else 1
    except MeasurementInterrupted as error:
        print(str(error), file=sys.stderr)
        return 128 + error.signum
    except (OSError, ValueError, SourceConflict, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        for signum, handler in old.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
