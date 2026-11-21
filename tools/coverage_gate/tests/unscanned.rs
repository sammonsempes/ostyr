use coverage_gate::error::GateError;
use coverage_gate::metadata::{
    cargo_program, excluded_package, has_build_script, parse_metadata, refuse_excluded_packages, workspace_packages, workspace_packages_with,
    Dependency, Package, Target,
};
use coverage_gate::run::run;
use coverage_gate::scan::{find_sources, is_skipped};
use coverage_gate::unscanned::{canonical_entry, out_dir_allowed, out_dir_file, package_of_build_dir, proto_packages};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;


const WORKSPACE: &str = "[workspace]\nmembers = [\"crates/victim\", \"crates/gen\"]\nexclude = [\"crates/ebpf-probes/ebpf\"]\nresolver = \"2\"\n";


const HASH: &str = "0123456789abcdef";


const PROTO: &str = "syntax = \"proto3\";\npackage a.b;\n";


const NESTED: usize = 2;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const UNIX_ROOT: &str = "/";


fn put(root: &Path, relative: &str, text: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, text)?;
    Ok(())
}


fn manifest(name: &str, extra: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n{extra}")
}


fn workspace() -> anyhow::Result<(TempDir, PathBuf)> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    put(&root, "Cargo.toml", WORKSPACE)?;
    put(&root, "crates/victim/Cargo.toml", &manifest("victim", ""))?;
    put(&root, "crates/victim/src/lib.rs", "pub fn covered() {}\n")?;
    put(&root, "crates/gen/Cargo.toml", &manifest("gen", "build = \"build.rs\"\n"))?;
    put(&root, "crates/gen/src/lib.rs", "")?;
    put(&root, "crates/gen/build.rs", "fn main() {}\n")?;
    put(&root, "crates/gen/proto/a.proto", PROTO)?;
    Ok((dir, root))
}


fn entry(path: &Path, lines: u64, covered: u64) -> serde_json::Value {
    serde_json::json!({
        "filename": path.display().to_string(),
        "summary": {"lines": {"count": lines, "covered": covered}, "branches": {"count": 0, "covered": 0}}
    })
}


fn gate(root: &Path, listed: &[serde_json::Value]) -> Result<(bool, String), GateError> {
    let export = root.join("export.json");
    let text = serde_json::json!({"data": [{"files": listed}]}).to_string();
    fs::write(&export, text).map_err(GateError::Read)?;
    let arguments = vec!["coverage_gate".to_string(), export.display().to_string(), root.display().to_string()];
    let mut out = Vec::new();
    let passed = run(&arguments, &mut out)?;
    Ok((passed, String::from_utf8_lossy(&out).into_owned()))
}


fn victim_entry(root: &Path) -> serde_json::Value {
    entry(&root.join("crates/victim/src/lib.rs"), 1, 1)
}


fn out_file(root: &Path, directory: &str, name: &str) -> anyhow::Result<PathBuf> {
    let relative = format!("target/debug/build/{directory}/out/{name}");
    put(root, &relative, "pub fn generated() {}\n")?;
    Ok(root.join(relative))
}


fn package(name: &str, manifest_path: PathBuf, dependencies: Vec<Dependency>, kinds: &[&str]) -> Package {
    Package {
        name: name.to_string(),
        manifest_path,
        dependencies,
        targets: vec![Target {
            kind: kinds.iter().map(|kind| (*kind).to_string()).collect(),
        }],
    }
}


fn dependency(name: &str, path: Option<PathBuf>) -> Dependency {
    Dependency {
        name: name.to_string(),
        path,
    }
}


#[test]
fn a_clean_workspace_passes() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    assert!(gate(&root, &[victim_entry(&root)])?.0);
    Ok(())
}


#[test]
fn an_export_file_in_the_excluded_directory_is_refused_by_name() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let hidden = root.join("crates/ebpf-probes/ebpf/src/hidden.rs");
    put(&root, "crates/ebpf-probes/ebpf/src/hidden.rs", "pub fn h() {}\n")?;
    let error = gate(&root, &[victim_entry(&root), entry(&hidden, 1, 0)])
        .err()
        .ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(&error, GateError::UnscannedExportFile { path } if *path == hidden));
    assert!(error.to_string().contains("hidden.rs"));
    Ok(())
}


#[test]
fn a_vanished_file_under_the_root_is_refused_and_one_outside_is_not() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let ghost = root.join("crates/ghost/src/x.rs");
    let refused = gate(&root, &[victim_entry(&root), entry(&ghost, 1, 1)]);
    assert!(matches!(refused, Err(GateError::UnscannedExportFile { .. })));
    let outside = PathBuf::from("/nonexistent-registry/dependency/src/lib.rs");
    assert!(gate(&root, &[victim_entry(&root), entry(&outside, 1, 0)])?.0);
    Ok(())
}


#[test]
fn an_unresolvable_export_path_is_a_resolve_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let through_a_file = root.join("crates/victim/src/lib.rs/below");
    let error = canonical_entry(&through_a_file).err().ok_or_else(|| anyhow::anyhow!("resolved"))?;
    assert!(matches!(error, GateError::Resolve { .. }));
    assert!(error.source().is_some());
    assert!(canonical_entry(&root)? == root);
    Ok(())
}


#[test]
fn a_target_directory_below_a_crate_source_is_scanned() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/src/target/mod.rs", "pub fn in_target() {}\n")?;
    put(&root, "target/debug/src/generated.rs", "pub fn skipped() {}\n")?;
    let sources = find_sources(&root)?;
    assert!(sources.contains(&root.join("crates/victim/src/target/mod.rs")));
    assert!(!sources.iter().any(|source| source.starts_with(root.join("target"))));
    let listed = root.join("crates/victim/src/target/mod.rs");
    let (passed, text) = gate(&root, &[victim_entry(&root), entry(&listed, 1, 0)])?;
    assert!(!passed);
    assert!(text.contains("target/mod.rs"), "{text}");
    let (unlisted, text_unlisted) = gate(&root, &[victim_entry(&root)])?;
    assert!(!unlisted);
    assert!(text_unlisted.contains("absent"), "{text_unlisted}");
    assert!(is_skipped(OsStr::new("target"), 1));
    assert!(!is_skipped(OsStr::new("target"), NESTED));
    assert!(is_skipped(OsStr::new(".hidden"), NESTED));
    Ok(())
}


#[test]
fn generated_protobuf_in_a_build_script_out_dir_is_allowed() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let generated = out_file(&root, &format!("gen-{HASH}"), "a.b.rs")?;
    assert!(gate(&root, &[victim_entry(&root), entry(&generated, 1, 0)])?.0);
    Ok(())
}


#[test]
fn every_other_out_dir_file_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let cases = [
        ("gen-0123456789abcdef", "hidden.rs"),
        ("gen-0123456789abcdef", "a.b.txt"),
        ("gen-0123456789abcdef", "a.b"),
        ("victim-0123456789abcdef", "a.b.rs"),
        ("nobody-0123456789abcdef", "a.b.rs"),
        ("gen-0123456789abcdeg", "a.b.rs"),
        ("gen", "a.b.rs"),
    ];
    cases.iter().try_for_each(|(directory, name)| -> anyhow::Result<()> {
        let file = out_file(&root, directory, name)?;
        let outcome = gate(&root, &[victim_entry(&root), entry(&file, 1, 0)]);
        assert!(matches!(outcome, Err(GateError::UnscannedExportFile { .. })), "{directory}/{name}");
        Ok(())
    })
}


#[test]
fn an_out_dir_shaped_path_outside_the_workspace_build_directory_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/gen/build/gen-0123456789abcdef/out/a.b.rs", "pub fn h() {}\n")?;
    let file = root.join("crates/victim/gen/build/gen-0123456789abcdef/out/a.b.rs");
    let outcome = gate(&root, &[victim_entry(&root), entry(&file, 1, 0)]);
    assert!(matches!(outcome, Err(GateError::UnscannedExportFile { .. })));
    Ok(())
}


#[test]
fn another_crates_build_script_cannot_widen_the_allowance() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/build.rs", "fn main() {}\n")?;
    put(&root, "crates/victim/Cargo.toml", &manifest("victim", "build = \"build.rs\"\n"))?;
    let planted = out_file(&root, &format!("victim-{HASH}"), "a.b.rs")?;
    let outcome = gate(&root, &[victim_entry(&root), entry(&planted, 1, 0)]);
    assert!(matches!(outcome, Err(GateError::UnscannedExportFile { .. })));
    Ok(())
}


#[test]
fn out_dir_shapes_are_parsed_strictly() -> anyhow::Result<()> {
    let root = Path::new("/w");
    assert_eq!(
        out_dir_file(root, Path::new("/w/target/debug/build/gen-0123456789abcdef/out/a.b.rs")),
        Some(("gen", "a.b.rs"))
    );
    assert_eq!(
        out_dir_file(root, Path::new("/w/target/build/my-crate-0123456789abcdef/out/a.rs")),
        Some(("my-crate", "a.rs"))
    );
    assert_eq!(out_dir_file(root, Path::new("/w/crates/x/build/gen-0123456789abcdef/out/a.rs")), None);
    assert_eq!(
        out_dir_file(root, Path::new("/w/target/debug/build/gen-0123456789abcdef/out/sub/a.rs")),
        None
    );
    assert_eq!(out_dir_file(root, Path::new("/w/target/a.rs")), None);
    let odd = Path::new("/w/target/debug/build/gen-0123456789abcdef/out").join(OsStr::from_bytes(&INVALID_UTF8));
    assert_eq!(out_dir_file(root, &odd), Some(("gen", "")));
    assert_eq!(package_of_build_dir("gen-0123456789abcdef"), Some("gen"));
    assert_eq!(package_of_build_dir("gen-0123456789abcde"), None);
    assert_eq!(package_of_build_dir("gen-0123456789abcdeg"), None);
    assert_eq!(package_of_build_dir("gen"), None);
    Ok(())
}


#[test]
fn proto_packages_are_read_from_every_proto_outside_target() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(
        &root,
        "crates/gen/proto/more.proto",
        "  package c.d ;\nmessage package_x {}\npackage nosemicolon\n",
    )?;
    put(&root, "crates/gen/target/ignored.proto", "package ignored;\n")?;
    let mut found = proto_packages(&root.join("crates/gen"))?;
    found.sort();
    assert_eq!(found, vec!["a.b".to_string(), "c.d".to_string()]);
    assert!(matches!(proto_packages(&root.join("missing")), Err(GateError::Walk(_))));
    fs::create_dir(root.join("crates/gen/proto/dir.proto"))?;
    assert!(matches!(proto_packages(&root.join("crates/gen")), Err(GateError::ReadSource { .. })));
    Ok(())
}


#[test]
fn the_allowance_needs_an_owner_with_a_build_script_and_a_manifest_directory() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let owner = package("gen", root.join("crates/gen/Cargo.toml"), vec![], &["custom-build"]);
    let plain = package("gen", root.join("crates/gen/Cargo.toml"), vec![], &["lib"]);
    let orphan = package("gen", PathBuf::from(UNIX_ROOT), vec![], &["custom-build"]);
    assert!(out_dir_allowed(&[owner], "gen", "a.b.rs")?);
    assert!(!out_dir_allowed(&[plain], "gen", "a.b.rs")?);
    assert!(matches!(out_dir_allowed(&[orphan], "gen", "a.b.rs"), Err(GateError::Resolve { .. })));
    Ok(())
}


#[test]
fn a_package_depending_on_the_kernel_directory_is_refused_by_name() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/ebpf-probes/ebpf/helper/Cargo.toml", &manifest("helper", ""))?;
    put(&root, "crates/ebpf-probes/ebpf/helper/src/lib.rs", "pub fn helper_uncovered() {}\n")?;
    put(
        &root,
        "crates/victim/Cargo.toml",
        &manifest("victim", "[dependencies]\nhelper = { path = \"../ebpf-probes/ebpf/helper\" }\n"),
    )?;
    let outcome = gate(&root, &[victim_entry(&root)]);
    assert!(
        matches!(outcome, Err(GateError::ExcludedPackage { ref name }) if name == "helper"),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn a_symlink_into_the_kernel_directory_does_not_hide_a_dependency() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/ebpf-probes/ebpf/helper/Cargo.toml", &manifest("helper", ""))?;
    put(&root, "crates/ebpf-probes/ebpf/helper/src/lib.rs", "pub fn helper_uncovered() {}\n")?;
    symlink(root.join("crates/ebpf-probes/ebpf"), root.join("crates/victim/link"))?;
    put(
        &root,
        "crates/victim/Cargo.toml",
        &manifest("victim", "[dependencies]\nhelper = { path = \"link/helper\" }\n"),
    )?;
    let outcome = gate(&root, &[victim_entry(&root)]);
    assert!(
        matches!(outcome, Err(GateError::ExcludedPackage { ref name }) if name == "helper"),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn a_member_inside_the_kernel_directory_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/ebpf-probes/ebpf/helper/Cargo.toml", &manifest("helper", ""))?;
    put(&root, "crates/ebpf-probes/ebpf/helper/src/lib.rs", "")?;
    put(
        &root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/victim\", \"crates/gen\", \"crates/ebpf-probes/ebpf/helper\"]\nresolver = \"2\"\n",
    )?;
    assert!(gate(&root, &[victim_entry(&root)]).is_err());
    let packages = workspace_packages(&root)?;
    let helper = packages
        .iter()
        .find(|candidate| candidate.name == "helper")
        .ok_or_else(|| anyhow::anyhow!("no helper member"))?;
    assert_eq!(excluded_package(&root, helper)?, Some("helper".to_string()));
    Ok(())
}


#[test]
fn excluded_package_branches() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let victim_manifest = root.join("crates/victim/Cargo.toml");
    let elsewhere = package(
        "p",
        victim_manifest.clone(),
        vec![dependency("d", None), dependency("e", Some(root.join("crates/gen")))],
        &["lib"],
    );
    assert_eq!(excluded_package(&root, &elsewhere)?, None);
    let missing = package("p", victim_manifest, vec![dependency("gone", Some(root.join("crates/gone")))], &["lib"]);
    assert!(matches!(excluded_package(&root, &missing), Err(GateError::Resolve { .. })));
    assert!(matches!(refuse_excluded_packages(&root, &[missing]), Err(GateError::Resolve { .. })));
    refuse_excluded_packages(&root, &[elsewhere])?;
    put(&root, "crates/ebpf-probes/ebpf/Cargo.toml", "x")?;
    let inside = package("kernel", root.join("crates/ebpf-probes/ebpf/Cargo.toml"), vec![], &["lib"]);
    assert!(matches!(refuse_excluded_packages(&root, &[inside]), Err(GateError::ExcludedPackage { ref name }) if name == "kernel"));
    Ok(())
}


#[test]
fn build_scripts_are_recognised_by_target_kind() -> anyhow::Result<()> {
    let manifest_path = PathBuf::from("/x/Cargo.toml");
    assert!(has_build_script(&package("p", manifest_path.clone(), vec![], &["lib", "custom-build"])));
    assert!(!has_build_script(&package("p", manifest_path, vec![], &["lib"])));
    Ok(())
}


#[test]
fn cargo_metadata_failures_are_named_and_keep_their_cause() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    assert!(workspace_packages(&root)?.is_empty());
    put(&root, "Cargo.toml", "[workspace]\nmembers = [\"nowhere\"]\n")?;
    assert!(matches!(workspace_packages(&root), Err(GateError::MetadataFailed { .. })));
    let missing_program = OsString::from("/nonexistent/cargo");
    let error = workspace_packages_with(&missing_program, &root)
        .err()
        .ok_or_else(|| anyhow::anyhow!("ran"))?;
    assert!(matches!(error, GateError::MetadataRun(_)));
    assert!(error.source().is_some());
    let parse = parse_metadata(b"not json").err().ok_or_else(|| anyhow::anyhow!("parsed"))?;
    assert!(matches!(parse, GateError::MetadataParse(_)));
    assert!(parse.source().is_some());
    assert_eq!(cargo_program(None), OsString::from("cargo"));
    assert_eq!(cargo_program(Some(OsString::from("/x/cargo"))), OsString::from("/x/cargo"));
    let echo = workspace_packages_with(OsStr::new("true"), &root);
    assert!(matches!(echo, Err(GateError::MetadataParse(_))));
    Ok(())
}


#[test]
fn an_unreadable_manifest_location_is_a_read_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    put(dir.path(), "file", "x")?;
    let error = workspace_packages(&dir.path().join("file"))
        .err()
        .ok_or_else(|| anyhow::anyhow!("read"))?;
    assert!(matches!(error, GateError::ReadManifest { .. }));
    assert!(error.source().is_some());
    Ok(())
}
