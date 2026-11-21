use coverage_gate::error::GateError;
use coverage_gate::executable::{has_path_module, inspect_source};
use coverage_gate::run::run;
use std::fs;
use std::path::Path;


const EMPTY_EXPORT: &str = r#"{"data":[{"files":[],"totals":{}}],"type":"llvm.coverage.json.export","version":"2.0.1"}"#;


const KERNEL_MANIFEST: &str = "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/ebpf-probes/ebpf\"]\n";


fn put(root: &Path, relative: &str, text: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, text)?;
    Ok(())
}


fn gate(files: &[(&str, &str)]) -> anyhow::Result<Result<bool, GateError>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    put(&root, "Cargo.toml", KERNEL_MANIFEST)?;
    files.iter().try_for_each(|(relative, text)| put(&root, relative, text))?;
    let export = root.join("export.json");
    fs::write(&export, EMPTY_EXPORT)?;
    let arguments = vec!["coverage_gate".to_string(), export.display().to_string(), root.display().to_string()];
    Ok(run(&arguments, Vec::new()))
}


#[test]
fn a_path_module_into_the_kernel_directory_is_refused() -> anyhow::Result<()> {
    let outcome = gate(&[
        ("crates/ebpf-probes/ebpf/src/x.rs", "pub fn hidden() {}\n"),
        ("crates/demo/src/lib.rs", "#[path = \"../../ebpf-probes/ebpf/src/x.rs\"]\nmod hidden;\n"),
    ])?;
    let error = outcome.err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(&error, GateError::PathModule { path } if path.ends_with("crates/demo/src/lib.rs")));
    assert!(error.to_string().contains("#[path]"));
    Ok(())
}


#[test]
fn a_nested_path_module_in_the_boundary_crate_is_refused() -> anyhow::Result<()> {
    let outcome = gate(&[(
        "crates/ebpf-probes/src/lib.rs",
        "mod outer {\n    #[path = \"live.rs\"]\n    mod live;\n}\n",
    )])?;
    assert!(matches!(outcome, Err(GateError::PathModule { .. })));
    Ok(())
}


#[test]
fn only_a_path_attribute_on_a_module_counts() -> anyhow::Result<()> {
    assert!(has_path_module("#[path = \"a.rs\"]\nmod a;\n")?);
    assert!(has_path_module("mod b {\n    #[path = \"a.rs\"]\n    mod a;\n}\n")?);
    assert!(!has_path_module("#[cfg(unix)]\nmod a;\n")?);
    assert!(!has_path_module("#[path = \"a.rs\"]\nfn a() {}\n")?);
    assert!(!has_path_module("mod a;\n")?);
    Ok(())
}


#[test]
fn an_unparsable_or_missing_source_is_an_error() -> anyhow::Result<()> {
    let outcome = gate(&[("crates/demo/src/lib.rs", "fn (\n")])?;
    assert!(matches!(outcome, Err(GateError::ParseSource { .. })));
    assert!(matches!(
        inspect_source(Path::new("/nonexistent/x.rs"), false),
        Err(GateError::ReadSource { .. })
    ));
    Ok(())
}
