use coverage_gate::error::GateError;
use coverage_gate::executable::has_executable_code;
use coverage_gate::manifest::is_boundary_entry;
use coverage_gate::run::run;
use coverage_gate::scan::find_sources;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;


const EMPTY_EXPORT: &str = r#"{"data":[{"files":[],"totals":{}}],"type":"llvm.coverage.json.export","version":"2.0.1"}"#;


const LIVE_FILE: &str = "#![cfg(feature = \"ebpf-live\")]\nfn live() {}\n";


const KERNEL_MANIFEST: &str = "[workspace]\nmembers = []\nexclude = [\"crates/ebpf-probes/ebpf\"]\n";


fn put(root: &Path, relative: &str, text: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, text)?;
    Ok(())
}


fn workspace(manifest: &str) -> anyhow::Result<(TempDir, PathBuf, Vec<String>)> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    put(&root, "Cargo.toml", manifest)?;
    let export = root.join("export.json");
    fs::write(&export, EMPTY_EXPORT)?;
    let arguments = vec!["coverage_gate".to_string(), export.display().to_string(), root.display().to_string()];
    Ok((dir, root, arguments))
}


fn report(arguments: &[String]) -> Result<(bool, String), GateError> {
    let mut out = Vec::new();
    let passed = run(arguments, &mut out)?;
    Ok((passed, String::from_utf8_lossy(&out).into_owned()))
}


#[test]
fn the_kernel_crate_directory_is_not_scanned() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(&root, "crates/ebpf-probes/ebpf/src/main.rs", "fn kernel() {}\n")?;
    assert!(report(&arguments)?.0);
    let sources = find_sources(&root)?;
    assert!(sources.is_empty());
    Ok(())
}


#[test]
fn without_the_exclude_the_kernel_crate_is_gated() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace("[workspace]\nmembers = []\n")?;
    put(&root, "crates/ebpf-probes/ebpf/src/main.rs", "fn kernel() {}\n")?;
    let (passed, text) = report(&arguments)?;
    assert!(!passed);
    assert!(text.contains("ebpf/src/main.rs"), "{text}");
    Ok(())
}


#[test]
fn a_live_gated_file_in_the_boundary_crate_is_skipped() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(&root, "crates/ebpf-probes/src/live.rs", LIVE_FILE)?;
    assert!(report(&arguments)?.0);
    Ok(())
}


#[test]
fn a_live_gated_file_outside_the_boundary_crate_still_fails() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(&root, "crates/demo/src/live.rs", LIVE_FILE)?;
    let (passed, text) = report(&arguments)?;
    assert!(!passed);
    assert!(text.contains("crates/demo/src/live.rs"), "{text}");
    Ok(())
}


#[test]
fn a_nested_path_named_like_the_boundary_crate_is_not_the_boundary() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(&root, "crates/demo/crates/ebpf-probes/src/live.rs", LIVE_FILE)?;
    assert!(!report(&arguments)?.0);
    Ok(())
}


#[test]
fn only_the_exact_live_gate_is_skipped() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(
        &root,
        "crates/ebpf-probes/src/other.rs",
        "#![cfg(any(feature = \"ebpf-live\", unix))]\nfn live() {}\n",
    )?;
    assert!(!report(&arguments)?.0);
    Ok(())
}


#[test]
fn an_uncovered_host_file_in_the_boundary_crate_still_fails() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace(KERNEL_MANIFEST)?;
    put(&root, "crates/ebpf-probes/src/lib.rs", "pub fn host() {}\n")?;
    let (passed, text) = report(&arguments)?;
    assert!(!passed);
    assert!(text.contains("crates/ebpf-probes/src/lib.rs"), "{text}");
    Ok(())
}


#[test]
fn the_live_gate_is_only_honoured_inside_the_boundary() -> anyhow::Result<()> {
    assert!(has_executable_code(LIVE_FILE, false)?);
    assert!(!has_executable_code(LIVE_FILE, true)?);
    assert!(has_executable_code("#![cfg(unix)]\nfn a() {}\n", true)?);
    assert!(has_executable_code("fn a() {}\n", true)?);
    assert!(has_executable_code("#![allow(dead_code)]\nfn a() {}\n", true)?);
    assert!(has_executable_code("#![no_std]\nfn a() {}\n", true)?);
    assert!(has_executable_code("#![doc = \"x\"]\nfn a() {}\n", true)?);
    assert!(!has_executable_code("#![cfg(windows)]\nfn a() {}\n", true)?);
    assert!(!has_executable_code("#![cfg(windows)]\nfn a() {}\n", false)?);
    assert!(!has_executable_code(
        "#![cfg(feature = \"ebpf-live\")]\n#![cfg(windows)]\nfn a() {}\n",
        true
    )?);
    Ok(())
}


#[test]
fn an_exclude_naming_a_normal_crate_is_refused() -> anyhow::Result<()> {
    let entries = [
        "crates/demo",
        "crates/ebpf-probes",
        "crates/ebpf-probes/src",
        "crates/ebpf-probes/ebpf/../..",
        "./crates/ebpf-probes/ebpf",
        "/crates/ebpf-probes/ebpf",
    ];
    for entry in entries {
        let manifest = format!("[workspace]\nexclude = [\"{entry}\"]\n");
        let (_dir, root, arguments) = workspace(&manifest)?;
        put(&root, "crates/demo/src/lib.rs", "pub fn demo() {}\n")?;
        let error = report(&arguments).err().ok_or_else(|| anyhow::anyhow!("{entry} accepted"))?;
        assert!(matches!(&error, GateError::ExcludeRefused { entry: named } if named == entry), "{entry}");
        assert!(error.to_string().contains(entry));
    }
    Ok(())
}


#[test]
fn the_boundary_entry_is_exactly_the_kernel_directory() -> anyhow::Result<()> {
    assert!(is_boundary_entry("crates/ebpf-probes/ebpf"));
    assert!(!is_boundary_entry("crates/ebpf-probes/ebpf/"));
    assert!(!is_boundary_entry("./crates/ebpf-probes/ebpf"));
    assert!(!is_boundary_entry("crates/ebpf-probes//ebpf"));
    assert!(!is_boundary_entry("crates/ebpf-probes/ebpf2"));
    Ok(())
}


#[test]
fn a_manifest_without_a_workspace_or_a_file_excludes_nothing() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace("[package]\nname = \"x\"\nversion = \"0.0.0\"\nedition = \"2021\"\n")?;
    put(&root, "src/lib.rs", "")?;
    put(&root, "crates/demo/src/lib.rs", "pub fn demo() {}\n")?;
    assert!(!report(&arguments)?.0);
    fs::remove_file(root.join("Cargo.toml"))?;
    assert!(!report(&arguments)?.0);
    Ok(())
}


#[test]
fn a_malformed_manifest_is_a_parse_error_with_its_cause() -> anyhow::Result<()> {
    let (_dir, _root, arguments) = workspace("[workspace\n")?;
    let error = report(&arguments).err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(error, GateError::ParseManifest { .. }));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn an_unreadable_manifest_is_a_read_error_with_its_cause() -> anyhow::Result<()> {
    let (_dir, root, arguments) = workspace("")?;
    fs::remove_file(root.join("Cargo.toml"))?;
    fs::create_dir(root.join("Cargo.toml"))?;
    let error = report(&arguments).err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(error, GateError::ReadManifest { .. }));
    assert!(error.source().is_some());
    Ok(())
}
