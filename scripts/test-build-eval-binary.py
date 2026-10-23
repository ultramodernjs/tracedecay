#!/usr/bin/env python3
"""build-eval-binary.sh builds the shipping target and never reuses a stale binary."""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("build-eval-binary.sh")

# Fake bazel: records its argv; `build` exits $FAKE_BUILD_RC, `info` prints $FAKE_BAZEL_BIN.
FAKE_BAZEL = """#!/bin/sh
echo "$@" >> "$FAKE_BAZEL_LOG"
case "$1" in
  build) exit "${FAKE_BUILD_RC:-0}" ;;
  info) printf '%s\\n' "$FAKE_BAZEL_BIN" ;;
esac
"""


class BuildEvalBinaryTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.repo = root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy(SCRIPT, self.repo / "scripts" / SCRIPT.name)
        # `bazel info bazel-bin` can resolve into a custom output_base and
        # either the output path or the checkout can contain spaces.
        self.bazel_bin = root / "output base" / "bazel-bin"
        cli = self.bazel_bin / "crates" / "tracedecay-cli"
        cli.mkdir(parents=True)
        # A binary from an earlier build, present before the build runs.
        self.built = cli / ("tracedecay.exe" if os.name == "nt" else "tracedecay")
        self.built.write_text("#!/bin/sh\necho tracedecay 1.2.3\n")
        self.built.chmod(0o755)
        self.log = root / "bazel.log"
        self.fakes = root / "fakes"
        fakes = self.fakes
        fakes.mkdir()
        bazel = fakes / "bazel"
        bazel.write_text(FAKE_BAZEL)
        bazel.chmod(bazel.stat().st_mode | stat.S_IXUSR)
        self.env = {
            "PATH": f"{fakes}{os.pathsep}{os.environ['PATH']}",
            "FAKE_BAZEL_LOG": str(self.log),
            "FAKE_BAZEL_BIN": str(self.bazel_bin),
        }

    def run_script(self, **env):
        return subprocess.run(
            ["bash", str(self.repo / "scripts" / SCRIPT.name)],
            env={**self.env, **env},
            text=True,
            capture_output=True,
            check=False,
        )

    def test_builds_the_shipping_target_and_prints_its_identity(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), self.built)
        self.assertIn(
            "build --config=release //crates/tracedecay-cli:tracedecay",
            self.log.read_text(),
        )
        self.assertIn("tracedecay 1.2.3", result.stderr)
        self.assertIn("sha256 ", result.stderr)

    def test_windows_build_selects_the_executable_suffix(self):
        windows_binary = self.built.with_suffix(".exe")
        if self.built != windows_binary:
            self.built.rename(windows_binary)
        uname = self.fakes / "uname"
        uname.write_text("#!/bin/sh\necho MINGW64_NT-10.0\n")
        uname.chmod(0o755)
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), windows_binary)

    def test_native_windows_output_base_is_normalized_at_the_shell_boundary(self):
        # Exercise native Bazel's spelling even on a POSIX host. The shim maps
        # just this synthetic drive path to the fixture's actual output base.
        native = r"Q:\custom output base\execroot\_main\bazel-out\x64_windows-fastbuild\bin"
        cygpath = self.fakes / "cygpath"
        cygpath.write_text(
            '#!/bin/sh\n'
            'case "$1" in\n'
            '  -u) test "$2" = "$FAKE_NATIVE_BAZEL_BIN" || exit 4; '
            '(cd "$FAKE_REAL_BAZEL_BIN" && pwd) ;;\n'
            '  -am) printf "%s\\n" "$FAKE_EXPECTED_BINARY" ;;\n'
            '  *) exit 4 ;;\n'
            'esac\n'
        )
        cygpath.chmod(0o755)
        result = self.run_script(
            FAKE_BAZEL_BIN=native + "\r",
            FAKE_NATIVE_BAZEL_BIN=native,
            FAKE_REAL_BAZEL_BIN=str(self.bazel_bin),
            FAKE_EXPECTED_BINARY=str(self.built),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), self.built)
        self.assertIn("tracedecay 1.2.3", result.stderr)

    def test_bazel_info_accepts_windows_line_endings(self):
        result = self.run_script(FAKE_BAZEL_BIN=str(self.bazel_bin) + "\r")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), self.built)

    def test_config_override_reaches_bazel(self):
        result = self.run_script(TRACEDECAY_EVAL_BAZEL_CONFIG="dist")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("build --config=dist //crates", self.log.read_text())

    def test_failed_build_does_not_fall_back_to_the_stale_binary(self):
        result = self.run_script(FAKE_BUILD_RC="1")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("bazel build --config=release //crates/tracedecay-cli:tracedecay", result.stderr)

    def test_explicit_binary_skips_the_build(self):
        explicit = self.built.with_name("candidate")
        explicit.write_text("#!/bin/sh\necho tracedecay 9.9.9\n")
        explicit.chmod(0o755)
        result = self.run_script(TRACEDECAY_BIN=str(explicit))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), explicit)
        self.assertIn("tracedecay 9.9.9", result.stderr)
        self.assertFalse(self.log.exists())

    def test_isolated_reentry_reuses_the_selected_binary_without_another_build(self):
        outer = self.run_script()
        self.assertEqual(outer.returncode, 0, outer.stderr)
        with tempfile.TemporaryDirectory() as isolated_home:
            child = self.run_script(
                TRACEDECAY_BIN=outer.stdout.strip(),
                HOME=isolated_home,
                XDG_CACHE_HOME=str(Path(isolated_home) / ".cache"),
            )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout, outer.stdout)
        self.assertEqual(sum(line.startswith("build ") for line in self.log.read_text().splitlines()), 1)

    def test_missing_explicit_binary_names_the_build_command(self):
        result = self.run_script(TRACEDECAY_BIN=str(self.built.with_name("absent")))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("bazel build --config=release //crates/tracedecay-cli:tracedecay", result.stderr)


if __name__ == "__main__":
    unittest.main()
