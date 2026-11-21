use coverage_gate::error::GateError;
use coverage_gate::run::{print_kernel_answer, run};
use std::fs;
use std::io::{Error, ErrorKind, Write};
use std::path::Path;


const KERNEL_MANIFEST_PATH: &str = "crates/ebpf-probes/ebpf/Cargo.toml";


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(Error::from(ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn put(root: &Path, relative: &str, text: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, text)?;
    Ok(())
}


fn ask(files: &[(&str, &str)]) -> anyhow::Result<Result<String, GateError>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    files.iter().try_for_each(|(relative, text)| put(&root, relative, text))?;
    let arguments = vec!["coverage_gate".to_string(), "kernel-declared".to_string(), root.display().to_string()];
    let mut out = Vec::new();
    Ok(print_kernel_answer(&arguments, &mut out).map(|passed| format!("{passed}:{}", String::from_utf8_lossy(&out).trim())))
}


fn exclude(entry: &str) -> String {
    format!("[workspace]\nexclude = [{entry}]\n")
}


#[test]
fn the_exact_entry_is_declared_in_every_toml_quote_style() -> anyhow::Result<()> {
    let double = ask(&[("Cargo.toml", &exclude("\"crates/ebpf-probes/ebpf\"")), (KERNEL_MANIFEST_PATH, "x")])?;
    let single = ask(&[("Cargo.toml", &exclude("'crates/ebpf-probes/ebpf'")), (KERNEL_MANIFEST_PATH, "x")])?;
    assert_eq!(double?, "true:declared");
    assert_eq!(single?, "true:declared");
    Ok(())
}


#[test]
fn a_respelled_entry_is_refused_by_name() -> anyhow::Result<()> {
    let spellings = [
        "\"crates/ebpf-probes/ebpf/\"",
        "\"crates/ebpf-probes//ebpf\"",
        "\"./crates/ebpf-probes/ebpf\"",
        "'crates/ebpf-probes/ebpf/'",
        "\"crates/ebpf-probes/ebpf/../ebpf\"",
    ];
    spellings.iter().try_for_each(|spelling| {
        let outcome = ask(&[("Cargo.toml", &exclude(spelling)), (KERNEL_MANIFEST_PATH, "x")])?;
        assert!(matches!(outcome, Err(GateError::ExcludeRefused { .. })), "{spelling} was not refused");
        anyhow::Ok(())
    })
}


#[test]
fn an_inline_table_is_a_parse_error_not_a_skip() -> anyhow::Result<()> {
    let outcome = ask(&[
        ("Cargo.toml", "[workspace]\nexclude = { path = \"crates/ebpf-probes/ebpf\" }\n"),
        (KERNEL_MANIFEST_PATH, "x"),
    ])?;
    assert!(matches!(outcome, Err(GateError::ParseManifest { .. })));
    Ok(())
}


#[test]
fn a_kernel_manifest_without_the_entry_fails_by_name() -> anyhow::Result<()> {
    let no_entry = ask(&[("Cargo.toml", "[workspace]\nmembers = []\n"), (KERNEL_MANIFEST_PATH, "x")])?;
    let no_root = ask(&[(KERNEL_MANIFEST_PATH, "x")])?;
    let error = no_entry.err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(&error, GateError::KernelUndeclared { path } if path.ends_with(KERNEL_MANIFEST_PATH)));
    assert!(error.to_string().contains("kernel crate would escape the gate"));
    assert!(matches!(no_root, Err(GateError::KernelUndeclared { .. })));
    Ok(())
}


#[test]
fn without_entry_and_without_kernel_manifest_it_is_absent() -> anyhow::Result<()> {
    assert_eq!(
        ask(&[("Cargo.toml", "[workspace]\nmembers = []\n")])?.map_err(|error| anyhow::anyhow!("{error}"))?,
        "true:absent"
    );
    assert_eq!(ask(&[])?.map_err(|error| anyhow::anyhow!("{error}"))?, "true:absent");
    Ok(())
}


#[test]
fn declared_without_a_kernel_manifest_is_still_declared() -> anyhow::Result<()> {
    let outcome = ask(&[("Cargo.toml", &exclude("\"crates/ebpf-probes/ebpf\""))])?;
    assert_eq!(outcome?, "true:declared");
    Ok(())
}


#[test]
fn another_exclude_entry_is_refused() -> anyhow::Result<()> {
    let outcome = ask(&[("Cargo.toml", &exclude("\"crates/demo\""))])?;
    assert!(matches!(outcome, Err(GateError::ExcludeRefused { .. })));
    Ok(())
}


#[test]
fn an_unreadable_kernel_path_is_an_error() -> anyhow::Result<()> {
    let outcome = ask(&[("crates", "a file where a directory should be")])?;
    assert!(matches!(outcome, Err(GateError::ReadManifest { .. })));
    Ok(())
}


#[test]
fn the_root_defaults_to_the_working_directory_and_a_write_failure_is_reported() -> anyhow::Result<()> {
    let mut out = Vec::new();
    let arguments = vec!["coverage_gate".to_string(), "kernel-declared".to_string()];
    assert!(print_kernel_answer(&arguments, &mut out)?);
    assert_eq!(String::from_utf8_lossy(&out).trim(), "absent");
    assert!(matches!(print_kernel_answer(&arguments, &mut FailingWriter), Err(GateError::Write(_))));
    Ok(())
}


#[test]
fn run_dispatches_the_kernel_subcommand() -> anyhow::Result<()> {
    let arguments = vec!["coverage_gate".to_string(), "kernel-declared".to_string()];
    assert!(run(&arguments, Vec::new())?);
    Ok(())
}
