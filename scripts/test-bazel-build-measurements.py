#!/usr/bin/env python3
"""Behavioral tests; no Bazel server or build is started."""

import importlib.util
from contextlib import redirect_stderr
import io
import hashlib
import json
from pathlib import Path
import subprocess
import signal
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "measure_builds", Path(__file__).parent / "bazel" / "measure_builds.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class WorkspaceRoot(unittest.TestCase):
    def test_bazel_run_uses_workspace_directory_instead_of_runfiles_cwd(self):
        calls = []

        def git(command, **kwargs):
            calls.append((command, kwargs))
            return "/checkout with spaces\n"

        root = M.workspace_root(
            {"BUILD_WORKSPACE_DIRECTORY": "/checkout with spaces/subdirectory"}, git)
        self.assertEqual(root, Path("/checkout with spaces"))
        self.assertEqual(calls, [
            (["git", "-C", "/checkout with spaces/subdirectory",
              "rev-parse", "--show-toplevel"], {"text": True})])

    def test_without_bazel_environment_git_uses_current_directory(self):
        for environ in ({}, {"BUILD_WORKSPACE_DIRECTORY": ""}):
            with self.subTest(environ=environ):
                calls = []

                def git(command, **kwargs):
                    calls.append((command, kwargs))
                    return "/checkout\n"

                self.assertEqual(M.workspace_root(environ, git), Path("/checkout"))
                self.assertEqual(calls, [
                    (["git", "rev-parse", "--show-toplevel"], {"text": True})])


class Measurements(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "crates/domain/src/lib.rs"
        self.source.parent.mkdir(parents=True)
        self.original = b"pub fn value() {}\r\n"
        self.source.write_bytes(self.original)
        self.calls = []
        self.execroot = self.root / "execroot"
        self.execroot.mkdir()
        self.info_calls = []

    def options(self, *extra):
        return M.parser().parse_args([
            "--output-dir", str(self.root / "out"),
            "--candidate", "dev:false:1", "--candidate", "perf:true:2",
            "--invalidate-source", "crates/domain/src/lib.rs",
            "--repetitions", "2", "--seed", "42",
            "--bazel-startup-option=--output_base=/private/base",
            *extra, "//crates/domain:domain"])

    def fake_run(self, command, cwd, stdout, stderr):
        self.calls.append(command)
        self.assertIn(b"// tracedecay build measurement", self.source.read_bytes())
        self.assertEqual(cwd, self.root)
        self.assertEqual(stderr, subprocess.STDOUT)
        paths = {part.split("=", 1)[0]: Path(part.split("=", 1)[1])
                 for part in command if part.startswith(("--profile=",
                     "--build_event_json_file=", "--execution_log_json_file="))}
        paths["--profile"].write_bytes(b"profile")
        stdout.write("INFO: Elapsed time: 1.5s, Critical Path: 1.0s\n"
                     "INFO: 1018 processes: 638 disk cache hit, 378 internal, 2 darwin-sandbox.\n"
                     "INFO: Build completed successfully, 1018 total actions\n")
        events = [
            {"finished": {"overallSuccess": True, "exitCode": {"name": "SUCCESS"}}},
            {"buildMetrics": {"actionSummary": {
                "actionsExecuted": "1018", "actionsCreated": "1618",
                "actionData": [{"mnemonic": "Rustc", "actionsExecuted": "339"}],
                "runnerCount": [
                    {"name": "total", "count": 1018},
                    {"name": "disk cache hit", "count": 638},
                    {"name": "internal", "count": 378},
                    {"name": "darwin-sandbox", "count": 2}],
                "actionCacheStatistics": {"hits": 10}}}},
        ]
        paths["--build_event_json_file"].write_text(
            "\n".join(json.dumps(e) for e in events))
        threads = next(a.rsplit("=", 1)[1] for a in command if "@-Zthreads=" in a)
        args = ["rustc", "crates/domain/src/lib.rs", "--emit=link", f"-Zthreads={threads}"]
        if "--output_groups=build_metadata" in command:
            args += ["--rustc-quit-on-rmeta", "true"]
        spawns = [
            {"mnemonic": "Rustc", "commandArgs": args, "runner": "darwin-sandbox",
             "listedOutputs": ["bazel-out/config/bin/crates/domain/libdomain.rlib"],
             "targetLabel": "//crates/domain:domain"},
            {"mnemonic": "Rustc", "commandArgs": ["external/dep/lib.rs"],
             "cacheHit": True, "runner": "disk cache hit"},
        ]
        paths["--execution_log_json_file"].write_text(
            "\n".join(json.dumps(s, indent=2) for s in spawns))
        return subprocess.CompletedProcess(command, 0)

    def run_measure(self, options=None, runner=None):
        tick = iter(range(100))

        def info(command, **kwargs):
            self.info_calls.append((command, kwargs["cwd"]))
            self.assertEqual(self.source.read_bytes(), self.original)
            return f"{self.execroot}\n"

        return M.measure(options or self.options(), self.root,
                         runner or self.fake_run, lambda: float(next(tick)), check_output=info)

    def test_progress_is_flushed_for_each_sample(self):
        class Progress(io.StringIO):
            flush_count = 0

            def flush(self):
                self.flush_count += 1
                super().flush()

        progress = Progress()
        with redirect_stderr(progress):
            report = self.run_measure()
        lines = progress.getvalue().splitlines()
        self.assertEqual(len(lines), 2 * len(report["samples"]))
        self.assertEqual(progress.flush_count, len(lines))
        for index, sample in enumerate(report["samples"]):
            prefix = f"candidate={sample['candidate']} repetition={sample['repetition']}/2"
            self.assertEqual(lines[2 * index], f"{prefix} start")
            self.assertEqual(lines[2 * index + 1],
                             f"{prefix} finish wall_seconds=1.000 eligible=true errors=none")

    def test_paired_runs_counts_and_stable_flags_restore_exact_bytes(self):
        report = self.run_measure()
        self.assertEqual(self.info_calls, [
            (["bazel", "--output_base=/private/base", "info", "execution_root"], self.root)])
        self.assertEqual(report["execution_root"], str(self.execroot))
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(len(report["samples"]), 4)
        for offset in (0, 2):
            self.assertEqual({s["candidate"] for s in report["samples"][offset:offset+2]},
                             {"dev:false:1", "perf:true:2"})
        for row in report["samples"]:
            self.assertTrue(row["eligible"], row["errors"])
            self.assertEqual(row["wall_seconds"], 1)
            self.assertEqual(row["bep"]["actions_executed"], 1018)
            self.assertEqual(row["bep"]["actions_by_mnemonic"]["Rustc"], 339)
            self.assertEqual(row["bep"]["actual_processes"], 2)
            self.assertEqual(row["bep"]["cache_hit_processes"], 638)
            self.assertEqual(row["bep"]["internal_processes"], 378)
            self.assertEqual(row["execution"]["rustc_executed"], 1)
            self.assertEqual(row["execution"]["rustc_cache_hits"], 1)
            self.assertIsNone(row["execution"]["compiler_max_rss_bytes"])
            self.assertEqual(row["log"]["process_summary_total"], 1018)
            self.assertEqual(row["log"]["bazel_elapsed_seconds"], 1.5)
        self.assertEqual(len(report["pairs"]), 2)
        self.assertTrue(all(p["eligible"] for p in report["pairs"]))
        for config in ("dev:false:1", "perf:true:2"):
            commands = [c for c in self.calls if f"--config={config.split(':')[0]}" in c]
            flags = [[a for a in c if a.startswith("--@rules_rust")] for c in commands]
            self.assertEqual(flags[0], flags[1])
        self.assertEqual(self.calls[0][:3],
                         ["bazel", "--output_base=/private/base", "build"])
        self.assertTrue(all("--jobs=6" in c for c in self.calls))
        for command in self.calls:
            profile = next(a.split("=", 1)[1] for a in command if a.startswith("--config="))
            self.assertIn(f"--//:workspace_rust_profile={profile}", command)
        saved = json.loads((self.root / "out/results.json").read_text())
        self.assertEqual(saved["samples"], report["samples"])

    def test_explicit_jobs_override(self):
        report = self.run_measure(self.options("--jobs", "3"))
        self.assertEqual(report["jobs"], 3)
        self.assertTrue(all("--jobs=3" in c for c in self.calls))

    def test_workspace_actions_record_library_and_inline_test_compilations(self):
        path = self.root / "execution.json"
        spawns = [
            {"mnemonic": "Rustc", "runner": "darwin-sandbox",
             "targetLabel": "//crates/domain:domain",
             "commandArgs": ["rustc", "crates/domain/src/lib.rs"]},
            {"mnemonic": "Rustc", "runner": "darwin-sandbox",
             "targetLabel": "//crates/domain:domain_test",
             "commandArgs": ["rustc", "crates/domain/src/lib.rs", "--test"]},
        ]
        path.write_text("\n".join(json.dumps(spawn) for spawn in spawns))
        result = M.parse_execution(path, ["crates/domain/src/lib.rs"])
        self.assertEqual(
            [(action["label"], action["test_mode"]) for action in result["workspace_actions"]],
            [("//crates/domain:domain", False), ("//crates/domain:domain_test", True)])
        self.assertEqual(result["workspace_roots_executed"], ["crates/domain/src/lib.rs"])

    def test_failure_is_retained_and_sources_restored(self):
        def fail(*args, **kwargs):
            completed = self.fake_run(*args, **kwargs)
            completed.returncode = 1
            return completed
        report = self.run_measure(runner=fail)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(len(report["samples"]), 4)
        self.assertTrue(all(s["exit_code"] == 1 and not s["eligible"]
                            for s in report["samples"]))
        self.assertTrue(all(p["wall_ratio"] is None for p in report["pairs"]))

    def test_noop_and_cached_workspace_actions_are_not_compile_evidence(self):
        for cached in (False, True):
            with self.subTest(cached=cached):
                output = self.root / f"cache-{cached}"
                options = self.options("--output-dir", str(output))
                def noop(command, **kwargs):
                    result = self.fake_run(command, **kwargs)
                    path = Path(next(a.split("=", 1)[1] for a in command
                                     if a.startswith("--execution_log_json_file=")))
                    path.write_text(json.dumps({
                        "mnemonic": "Rustc", "commandArgs": ["crates/domain/src/lib.rs"],
                        "cacheHit": True, "runner": "disk cache hit"}) if cached else "")
                    return result
                report = self.run_measure(options, noop)
                self.assertTrue(all(not s["eligible"] for s in report["samples"]))

    def test_metadata_mode_is_distinct(self):
        report = self.run_measure(self.options("--mode", "check"))
        self.assertEqual(report["mode"], "check")
        self.assertTrue(all(s["eligible"] for s in report["samples"]))
        for command in self.calls:
            self.assertIn("--output_groups=build_metadata", command)
            self.assertIn(
                "--@rules_rust//rust/settings:always_enable_metadata_output_groups=true",
                command)

    def test_unexpected_peer_edit_is_not_overwritten(self):
        def peer_edit(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            self.source.write_bytes(b"peer owns this now\n")
            return result
        with self.assertRaises(M.SourceConflict):
            self.run_measure(runner=peer_edit)
        self.assertEqual(self.source.read_bytes(), b"peer owns this now\n")
        self.assertEqual(len(self.calls), 1)
        report = json.loads((self.root / "out/results.json").read_text())
        self.assertIn("SourceConflict", report["fatal_error"])

    def test_interruption_and_spawn_error_restore(self):
        def interrupt(*args, **kwargs):
            raise InterruptedError("SIGTERM")
        report = self.run_measure(runner=interrupt)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertTrue(all(not s["eligible"] for s in report["samples"]))

    def test_keyboard_interrupt_restores_and_checkpoints(self):
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_measure(runner=interrupt)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertIn("fatal_error", json.loads((self.root / "out/results.json").read_text()))

    def test_sigterm_stops_instead_of_starting_another_sample(self):
        def interrupt(*args, **kwargs):
            self.calls.append(args)
            raise M.MeasurementInterrupted(signal.SIGTERM)
        with self.assertRaises(M.MeasurementInterrupted):
            self.run_measure(runner=interrupt)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_partial_invalidation_restores_owned_files(self):
        other = self.root / "crates/domain/src/other.rs"
        other.write_bytes(b"peer edit\n")
        with self.assertRaises(M.SourceConflict):
            with M.invalidate({self.source: self.original, other: b"old bytes"}, "sample"):
                self.fail("must not run")
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(other.read_bytes(), b"peer edit\n")

    def test_partial_append_error_never_truncates_original_bytes(self):
        write = M.os.write
        for length in (0, 7):
            with self.subTest(length=length):
                def interrupted_append(descriptor, data):
                    if length:
                        write(descriptor, data[:length])
                    raise OSError("injected partial append failure")

                with patch.object(M.os, "write", interrupted_append):
                    with self.assertRaisesRegex(OSError, "partial append"):
                        with M.invalidate({self.source: self.original}, "sample"):
                            self.fail("invalidation must fail before the build")
                self.assertEqual(self.source.read_bytes(), self.original)

    def test_short_appends_complete_and_restore(self):
        write = M.os.write
        with patch.object(M.os, "write", lambda descriptor, data: write(descriptor, data[:3])):
            with M.invalidate({self.source: self.original}, "sample"):
                self.assertEqual(self.source.read_bytes(), self.original
                                 + b"\n// tracedecay build measurement sample\n")
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_partial_append_with_peer_suffix_is_not_removed(self):
        write = M.os.write

        def interrupted_append(descriptor, data):
            write(descriptor, data[:7])
            write(descriptor, b"peer edit\n")
            raise OSError("partial append plus peer edit")

        with patch.object(M.os, "write", interrupted_append):
            with self.assertRaisesRegex(M.SourceConflict, "unexpected edit"):
                with M.invalidate({self.source: self.original}, "sample"):
                    self.fail("invalidation must fail")
        self.assertEqual(self.source.read_bytes(), self.original + b"\n// tra" + b"peer edit\n")

    def test_peer_truncation_of_complete_marker_is_not_treated_as_our_partial_write(self):
        with self.assertRaisesRegex(M.SourceConflict, "unexpected edit"):
            with M.invalidate({self.source: self.original}, "sample"):
                self.source.write_bytes(self.original + b"\n// tra")
        self.assertEqual(self.source.read_bytes(), self.original + b"\n// tra")

    def test_restoration_errors_preserve_original_prefix_and_restore_other_files(self):
        other = self.root / "crates/domain/src/other.rs"
        other.write_bytes(b"other source\n")
        truncate = M.os.ftruncate
        calls = []

        def fail_first(descriptor, length):
            calls.append(length)
            if len(calls) == 1:
                raise OSError("injected restoration failure")
            return truncate(descriptor, length)

        with patch.object(M.os, "ftruncate", fail_first):
            with self.assertRaisesRegex(M.SourceConflict, "restoration error"):
                with M.invalidate({self.source: self.original, other: b"other source\n"}, "sample"):
                    pass
        self.assertEqual(self.source.read_bytes(),
                         self.original + b"\n// tracedecay build measurement sample\n")
        self.assertEqual(other.read_bytes(), b"other source\n")
        self.assertEqual(calls, [len(self.original), len(b"other source\n")])

    def test_reported_error_after_truncation_still_leaves_exact_original_bytes(self):
        truncate = M.os.ftruncate

        def fail_after(descriptor, length):
            truncate(descriptor, length)
            raise OSError("error reported after truncation")

        with patch.object(M.os, "ftruncate", fail_after):
            with self.assertRaisesRegex(M.SourceConflict, "restoration error"):
                with M.invalidate({self.source: self.original}, "sample"):
                    pass
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_signal_during_partial_append_restores(self):
        write = M.os.write

        def interrupt(descriptor, data):
            write(descriptor, data[:7])
            raise M.MeasurementInterrupted(signal.SIGTERM)

        with patch.object(M.os, "write", interrupt):
            with self.assertRaises(M.MeasurementInterrupted):
                with M.invalidate({self.source: self.original}, "sample"):
                    self.fail("invalidation must be interrupted")
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_response_files_are_captured_before_the_next_sample_overwrites_them(self):
        name = "bazel-out/darwin_arm64-fastbuild/bin/crates/domain/libdomain.rlib-0.params"
        response = self.execroot / name
        response.parent.mkdir(parents=True)

        def with_response(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            path = Path(next(a.split("=", 1)[1] for a in command
                             if a.startswith("--execution_log_json_file=")))
            spawns = list(M.json_objects(path))
            data = ("\n".join(spawns[0]["commandArgs"][1:] + ["--test"]) + "\n").encode()
            response.write_bytes(data)
            spawns[0]["commandArgs"] = [
                "bazel-out/darwin_arm64-opt-exec/bin/external/rules_rust+/process_wrapper",
                "--", "external/rust/bin/rustc", f"@{name}"]
            spawns[0]["inputs"] = [{"path": name, "digest": {
                "hash": hashlib.sha256(data).hexdigest(), "hashFunctionName": "SHA-256"}}]
            path.write_text("\n".join(json.dumps(s) for s in spawns))
            return result

        report = self.run_measure(runner=with_response)
        for row in report["samples"]:
            self.assertTrue(row["eligible"], row["errors"])
            action = row["execution"]["workspace_actions"][0]
            self.assertTrue(action["test_mode"])
            self.assertEqual(action["sources"], ["crates/domain/src/lib.rs"])
            captured = Path(row["execution"]["captured_parameter_files"][name])
            threads = row["candidate"].split(":")[2]
            self.assertIn(f"-Zthreads={threads}\n", captured.read_text())
            self.assertIn(captured, list(Path(row["directory"]).glob("params/*.params")))

    def test_saved_parameter_contents_can_reparse_raw_logs_without_live_execroot(self):
        name = "bazel-out/config/bin/crates/domain/libdomain.rlib-0.params"
        data = b"crates/domain/src/lib.rs\n-Zthreads=2\n--test\n--remap-path-prefix=a path=.\n"
        path = self.root / "saved-execution.json"
        path.write_text(json.dumps({
            "mnemonic": "Rustc", "targetLabel": "//crates/domain:domain_test",
            "runner": "darwin-sandbox", "commandArgs": ["process_wrapper", "--", "rustc", f"@{name}"],
            "inputs": [{"path": name, "digest": {"hash": hashlib.sha256(data).hexdigest()}}],
            "metrics": {"measuredMemoryPeakBytes": "2800000000"},
        }))
        raw = path.read_bytes()
        result = M.parse_execution(path, ["crates/domain/src/lib.rs"], param_contents={name: data})
        action = result["workspace_actions"][0]
        self.assertTrue(action["arguments_complete"])
        self.assertTrue(action["test_mode"])
        self.assertEqual(action["frontend_thread_flags"], ["-Zthreads=2"])
        self.assertEqual(result["compiler_max_rss_bytes"], 2800000000)
        self.assertEqual(result["third_party_or_tool_rustc_executed"], 0)
        self.assertEqual(path.read_bytes(), raw)

    def test_missing_workspace_response_file_is_unknown_not_cold_dependencies_or_noop(self):
        path = self.root / "opaque-execution.json"
        path.write_text(json.dumps({
            "mnemonic": "Rustc", "targetLabel": "//crates/domain:domain",
            "runner": "darwin-sandbox",
            "commandArgs": ["rustc", "@bazel-out/config/bin/crates/domain/libdomain.rlib-0.params"],
        }))
        result = M.parse_execution(path, ["crates/domain/src/lib.rs"])
        self.assertEqual(result["third_party_or_tool_rustc_executed"], 0)
        self.assertFalse(result["workspace_no_op"])
        self.assertFalse(result["workspace_actions"][0]["arguments_complete"])
        self.assertIsNone(result["workspace_actions"][0]["test_mode"])
        self.assertTrue(result["argument_evidence_errors"])

    def test_response_digest_mismatch_and_cycles_are_unknown_argument_evidence(self):
        name = "bazel-out/config/bin/crates/domain/libdomain.rlib-0.params"
        path = self.root / "bad-params-execution.json"
        for contents, digest in ((b"crates/domain/src/lib.rs\n", "0" * 64),
                                 (f"@{name}\n".encode(), None)):
            with self.subTest(digest=digest):
                path.write_text(json.dumps({
                    "mnemonic": "Rustc", "targetLabel": "//crates/domain:domain",
                    "runner": "darwin-sandbox", "commandArgs": ["rustc", f"@{name}"],
                    "inputs": [{"path": name, "digest": {"hash": digest} if digest else {}}],
                }))
                result = M.parse_execution(path, [], param_contents={name: contents})
                self.assertTrue(result["argument_evidence_errors"])
                self.assertFalse(result["workspace_actions"][0]["arguments_complete"])
                self.assertEqual(result["third_party_or_tool_rustc_executed"], 0)

    def test_missing_evidence_and_cold_dependencies_are_retained(self):
        def cold(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            path = Path(next(a.split("=", 1)[1] for a in command
                             if a.startswith("--execution_log_json_file=")))
            with path.open("a") as output:
                output.write(json.dumps({"mnemonic": "Rustc",
                    "commandArgs": ["external/dep/lib.rs"], "runner": "darwin-sandbox"}))
            return result
        report = self.run_measure(runner=cold)
        self.assertTrue(all(not s["eligible"] for s in report["samples"]))
        self.assertTrue(all(s["execution"]["third_party_or_tool_rustc_executed"] == 1
                            for s in report["samples"]))

    def test_unmatched_thread_prefix_is_not_compile_speed_evidence(self):
        def unmatched(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            path = Path(next(a.split("=", 1)[1] for a in command
                             if a.startswith("--execution_log_json_file=")))
            spawns = list(M.json_objects(path))
            spawns[0]["commandArgs"] = [
                a for a in spawns[0]["commandArgs"] if not a.startswith("-Zthreads=")]
            path.write_text("\n".join(json.dumps(s) for s in spawns))
            return result
        report = self.run_measure(runner=unmatched)
        self.assertTrue(all(not s["eligible"] for s in report["samples"]))
        self.assertTrue(all(any("prefix" in e for e in s["errors"])
                            for s in report["samples"]))

    def test_missing_or_malformed_bep_does_not_hide_exit_status(self):
        def malformed(command, **kwargs):
            result = self.fake_run(command, **kwargs)
            path = Path(next(a.split("=", 1)[1] for a in command
                             if a.startswith("--build_event_json_file=")))
            path.write_text("{")
            return result
        report = self.run_measure(runner=malformed)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertTrue(all(s["exit_code"] == 0 and not s["eligible"]
                            for s in report["samples"]))

    def test_target_patterns_are_rejected_before_running_or_mutating(self):
        for target in ("//crates/...:domain", "//crates/.../domain:domain",
                       "//...:domain", "//crates/domain:all",
                       "//crates/domain:all-targets", "//crates/domain:*",
                       "//crates/domain/...", "//...", "//crates/domain",
                       "crates/domain:domain", "--keep_going"):
            with self.subTest(target=target):
                options = self.options()
                options.targets = [target]
                with self.assertRaisesRegex(ValueError, "use explicit //package:target"):
                    self.run_measure(options)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.info_calls, [])
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse((self.root / "out").exists())

    def test_all_is_allowed_as_an_ordinary_package_name(self):
        options = self.options()
        options.targets = ["//crates/all:all_checks"]
        report = self.run_measure(options)
        self.assertEqual(report["targets"], options.targets)
        self.assertTrue(self.calls)
        self.assertTrue(all(s["eligible"] for s in report["samples"]))
        self.assertTrue(all(c[-1] == "//crates/all:all_checks" for c in self.calls))

    def test_invalid_inputs_never_run_or_mutate(self):
        for extra in (("--repetitions", "0"),
                      ("--jobs", "0"),
                      ("--invalidate-source", "../elsewhere.rs"),
                      ("--candidate", "dev:false:1")):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.run_measure(self.options(*extra))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.source.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
