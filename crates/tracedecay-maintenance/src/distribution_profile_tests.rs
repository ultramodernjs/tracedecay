#[test]
fn ordinary_release_and_dist_strip_symbols() {
    let cargo = include_str!("../../../Cargo.toml");
    let bazel = include_str!("../../../.bazelrc");
    let release = cargo
        .split_once("[profile.release]\n")
        .expect("ordinary release has an explicit profile")
        .1
        .split("\n[")
        .next()
        .unwrap();
    assert!(
        release
            .lines()
            .any(|line| line.trim() == "strip = \"symbols\"")
    );
    assert!(bazel.lines().any(|line| line
        == "build:release --@rules_rust//rust/settings:extra_rustc_flag=-Cstrip=symbols"));
    assert!(
        bazel.lines().any(|line| line
            == "build:dist --@rules_rust//rust/settings:extra_rustc_flag=-Cstrip=symbols")
    );
}
