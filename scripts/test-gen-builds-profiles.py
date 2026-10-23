#!/usr/bin/env python3
"""Workspace Cargo profile inheritance and unchanged external perf policy."""

from __future__ import annotations

import importlib.util
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "gen_builds", ROOT / "scripts/bazel/gen_builds.py",
)
assert SPEC is not None and SPEC.loader is not None
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class ProfileResolutionTests(unittest.TestCase):
    def level(self, profiles, profile, package, *, workspace_member=True):
        return GEN.package_opt_level(
            GEN.profile_opt_levels(profiles, profile), package,
            workspace_member=workspace_member,
        )

    def test_perf_inherits_dev_package_policy_before_its_global_default(self):
        profiles = {
            "dev": {
                "opt-level": 1,
                "package": {"glue": {"opt-level": 0}, "regex": {"opt-level": 2}},
            },
            "perf": {
                "inherits": "dev",
                "opt-level": 3,
                "package": {"kernel": {"opt-level": 2}, "glue": {"debug": 0}},
            },
        }
        self.assertEqual(self.level(profiles, "dev", "glue"), 0)
        self.assertEqual(self.level(profiles, "perf", "glue"), 0)
        self.assertEqual(self.level(profiles, "perf", "regex"), 2)
        self.assertEqual(self.level(profiles, "dev", "kernel"), 1)
        self.assertEqual(self.level(profiles, "perf", "kernel"), 2)
        self.assertEqual(self.level(profiles, "perf", "ordinary"), 3)

    def test_child_package_override_wins_through_multiple_inherited_profiles(self):
        profiles = {
            "dev": {"opt-level": 1, "package": {"glue": {"opt-level": 2}}},
            "test": {"package": {"glue": {"opt-level": 0}}},
            "feedback": {"inherits": "test", "opt-level": "s"},
            "perf": {"inherits": "feedback", "package": {"kernel": {"opt-level": "z"}}},
        }
        self.assertEqual(self.level(profiles, "perf", "glue"), 0)
        self.assertEqual(self.level(profiles, "perf", "ordinary"), "s")
        self.assertEqual(self.level(profiles, "perf", "kernel"), "z")

    def test_wildcard_is_external_only_and_named_overrides_win(self):
        profiles = {
            "dev": {
                "opt-level": 1,
                "package": {"*": {"opt-level": 2}, "named": {"opt-level": 0}},
            },
            "perf": {"inherits": "dev", "package": {"*": {"opt-level": 3}}},
        }
        self.assertEqual(self.level(profiles, "perf", "ordinary"), 1)
        self.assertEqual(
            self.level(profiles, "perf", "ordinary", workspace_member=False), 3,
        )
        self.assertEqual(
            self.level(profiles, "perf", "named", workspace_member=False), 0,
        )
        self.assertEqual(
            self.level(profiles, "dev", "ordinary", workspace_member=False), 2,
        )

    def test_cargo_builtin_defaults(self):
        for name, expected in (("dev", 0), ("test", 0), ("release", 3), ("bench", 3)):
            with self.subTest(profile=name):
                self.assertEqual(self.level({}, name, "ordinary"), expected)

    def test_rejects_unknown_or_incomplete_inheritance(self):
        with self.assertRaisesRegex(SystemExit, "unknown Cargo profile"):
            GEN.profile_opt_levels({"perf": {"inherits": "missing"}}, "perf")
        with self.assertRaisesRegex(SystemExit, "must declare inherits"):
            GEN.profile_opt_levels({"perf": {}}, "perf")
        with self.assertRaisesRegex(SystemExit, "profile inheritance cycle"):
            GEN.profile_opt_levels({
                "perf": {"inherits": "other"},
                "other": {"inherits": "perf"},
            }, "perf")

    def test_repository_profiles_keep_dev_glue_cheap_and_perf_kernels_optimized(self):
        profiles = tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]
        for name, dev, perf in (
            ("tracedecay-policy", 0, 1),
            ("tracedecay-contracts", 0, 0),
            ("tracedecay-domain", 1, 2),
            ("tracedecay-code-index", 1, 2),
            ("tracedecay-memory-ncm-core", 1, 1),
        ):
            with self.subTest(package=name):
                self.assertEqual(self.level(profiles, "dev", name), dev)
                self.assertEqual(self.level(profiles, "perf", name), perf)
        for name, perf in (
            ("regex", 2),
            ("tiktoken-rs", 2),
            ("grafeo-core", 2),
            ("sha2", 3),
        ):
            with self.subTest(external=name):
                self.assertEqual(
                    self.level(profiles, "perf", name, workspace_member=False), perf,
                )


class ExternalPerfFlagTests(unittest.TestCase):
    def flag(self, package, version, level):
        prefix = f"external/rules_rust++crate+c__{package}-{version}/"
        return f'build "--@rules_rust//rust/settings:per_crate_rustc_flag={prefix}@-Copt-level={level}"'

    def test_emits_only_global_perf_levels_for_each_external_version(self):
        profiles = {
            "dev": {
                "opt-level": 1,
                "package": {"regex": {"opt-level": 2}, "workspace-glue": {"opt-level": 0}},
            },
            "perf": {
                "inherits": "dev",
                "package": {"sha2": {"opt-level": 3}, "workspace-glue": {"opt-level": 1}},
            },
        }
        locked = [
            {"name": "sha2", "version": "0.11.1"},
            {"name": "ordinary", "version": "1.0.0"},
            {"name": "sha2", "version": "0.10.9"},
            {"name": "workspace-glue", "version": "1.0.0"},
            {"name": "regex", "version": "1.13.1"},
        ]
        self.assertEqual(
            GEN.external_perf_flags(
                locked, {"workspace-glue"}, GEN.profile_opt_levels(profiles, "perf"),
            ),
            [
                self.flag("regex", "1.13.1", 2),
                self.flag("sha2", "0.10.9", 3),
                self.flag("sha2", "0.11.1", 3),
            ],
        )


if __name__ == "__main__":
    unittest.main()
