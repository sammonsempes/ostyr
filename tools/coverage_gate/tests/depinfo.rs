use coverage_gate::depinfo::{dep_info_files, dep_info_sources, in_scope, products, read_unit, refuse_unchecked, split_names, Product};
use coverage_gate::error::GateError;
use coverage_gate::metadata::{Package, Target};
use coverage_gate::run::{deps_directories, run, split_arguments};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;


const HASH: &str = "0123456789abcdef";


const PROTO: &str = "syntax = \"proto3\";\npackage a.b;\n";


const PRODUCT_UNITS: usize = 2;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


fn put(root: &Path, relative: &str, text: &str) -> anyhow::Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(path, text)?;
    Ok(())
}


fn manifest(name: &str, extra: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n{extra}")
}


fn lock(root: &Path) -> anyhow::Result<()> {
    let program = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(program)
        .args(["generate-lockfile", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}


fn dep_info(root: &Path, name: &str, sources: &[&str]) -> anyhow::Result<()> {
    let relative = format!("target/debug/build/{name}/{HASH}/out/{name}-{HASH}.d");
    let text = format!("{}: {}\n\n{}:\n", root.join(&relative).display(), sources.join(" "), sources.join(":\n"));
    put(root, &relative, &text)
}


fn workspace() -> anyhow::Result<(TempDir, PathBuf)> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    put(
        &root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/victim\", \"crates/gen\"]\nexclude = [\"crates/ebpf-probes/ebpf\"]\nresolver = \"2\"\n",
    )?;
    put(&root, "crates/victim/Cargo.toml", &manifest("victim", ""))?;
    put(&root, "crates/victim/src/lib.rs", "pub fn covered() {}\n")?;
    put(&root, "crates/gen/Cargo.toml", &manifest("gen", "build = \"build.rs\"\n"))?;
    put(&root, "crates/gen/src/lib.rs", "")?;
    put(&root, "crates/gen/build.rs", "fn main() {}\n")?;
    put(&root, "crates/gen/proto/a.proto", PROTO)?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs"])?;
    dep_info(&root, "gen", &["crates/gen/src/lib.rs"])?;
    lock(&root)?;
    Ok((dir, root))
}


fn gate_with(root: &Path, extra: &[&str]) -> Result<bool, GateError> {
    let export = root.join("export.json");
    let listed = root.join("crates/victim/src/lib.rs").display().to_string();
    let text = serde_json::json!({"data": [{"files": [{
        "filename": listed,
        "summary": {"lines": {"count": 1, "covered": 1}, "branches": {"count": 0, "covered": 0}}
    }]}]})
    .to_string();
    fs::write(&export, text).map_err(GateError::Read)?;
    let mut arguments = vec![
        "coverage_gate".to_string(),
        export.display().to_string(),
        root.display().to_string(),
        format!("--deps-dir={}", root.join("target").display()),
    ];
    arguments.extend(extra.iter().map(|argument| (*argument).to_string()));
    run(&arguments, Vec::new())
}


fn gate(root: &Path) -> Result<bool, GateError> {
    gate_with(root, &[])
}


fn refused_path(outcome: Result<bool, GateError>) -> anyhow::Result<String> {
    match outcome {
        Err(GateError::UncheckedCompiledFile { path }) => Ok(path.display().to_string()),
        other => Err(anyhow::anyhow!("not refused by name: {other:?}")),
    }
}


fn package(name: &str, kinds: &[&str], source: &str) -> Package {
    Package {
        id: format!("path+file://{name}"),
        name: name.to_string(),
        manifest_path: PathBuf::from(format!("/w/crates/{name}/Cargo.toml")),
        targets: vec![Target {
            name: name.to_string(),
            kind: kinds.iter().map(|kind| (*kind).to_string()).collect(),
            src_path: PathBuf::from(source),
        }],
    }
}


#[test]
fn a_clean_workspace_passes_with_a_unit_per_product() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    assert!(gate(&root)?);
    Ok(())
}


#[test]
fn dep_info_text_is_read_for_rust_prerequisites_only() -> anyhow::Result<()> {
    let text = "# env-dep:X: ignored.rs\n/t/x.d: a.rs b.txt c\\ d/e.rs\n\n/t/lib: a.rs\n\na.rs:\nb.txt:\n";
    assert_eq!(dep_info_sources(text), vec!["a.rs", "c d/e.rs", "a.rs"]);
    assert_eq!(split_names("  a  b\\ c d "), vec!["a", "b c", "d"]);
    assert!(dep_info_sources("").is_empty());
    Ok(())
}


#[test]
fn a_tests_helper_attribute_built_from_a_macro_is_refused_by_name() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/tests/support/payload.rs", "pub fn payload() {}\n")?;
    dep_info(
        &root,
        "victim",
        &["crates/victim/src/lib.rs", "crates/victim/src/../tests/support/payload.rs"],
    )?;
    assert!(refused_path(gate(&root))?.ends_with("crates/victim/tests/support/payload.rs"));
    Ok(())
}


#[test]
fn an_example_and_a_tests_named_file_are_refused_by_name() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/examples/payload.rs", "pub fn payload() {}\n")?;
    put(&root, "crates/victim/payload_tests.rs", "pub fn payload() {}\n")?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "crates/victim/examples/payload.rs"])?;
    assert!(refused_path(gate(&root))?.ends_with("examples/payload.rs"));
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "crates/victim/payload_tests.rs"])?;
    assert!(refused_path(gate(&root))?.ends_with("payload_tests.rs"));
    Ok(())
}


#[test]
fn a_file_in_the_kernel_directory_or_outside_the_root_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/ebpf-probes/ebpf/src/hidden.rs", "pub fn hidden() {}\n")?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "crates/ebpf-probes/ebpf/src/hidden.rs"])?;
    assert!(refused_path(gate(&root))?.ends_with("ebpf/src/hidden.rs"));
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "/nonexistent-registry/x/src/lib.rs"])?;
    assert!(refused_path(gate(&root))?.ends_with("/nonexistent-registry/x/src/lib.rs"));
    Ok(())
}


#[test]
fn an_out_dir_file_is_allowed_only_as_the_proto_package_of_its_own_crate() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/build.rs", "fn main() {}\n")?;
    put(&root, "crates/victim/Cargo.toml", &manifest("victim", "build = \"build.rs\"\n"))?;
    lock(&root)?;
    let victim_lib = "crates/victim/src/lib.rs";
    let cases = [
        (format!("target/debug/build/victim/{HASH}/out/evil.rs"), false),
        (format!("target/debug/build/victim/{HASH}/out/a.b.rs"), false),
        (format!("target/debug/build/victim-{HASH}/out/evil.rs"), false),
        (format!("target/debug/build/gen/{HASH}/out/hidden.rs"), false),
        (format!("target/debug/build/gen/{HASH}/out/a.b.rs"), true),
        (format!("target/debug/build/gen-{HASH}/out/a.b.rs"), true),
    ];
    cases.iter().try_for_each(|(relative, allowed)| -> anyhow::Result<()> {
        put(&root, relative, "pub fn generated() {}\n")?;
        dep_info(&root, "victim", &[victim_lib, relative])?;
        let outcome = gate(&root);
        assert_eq!(outcome.is_ok(), *allowed, "{relative}: {outcome:?}");
        assert!(*allowed || refused_path(outcome)?.ends_with(relative.as_str()));
        Ok(())
    })
}


#[test]
fn an_out_dir_shaped_file_outside_the_build_directory_is_not_generated_code() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let planted = "crates/victim/build/gen/0123456789abcdef/out/a.b.rs";
    put(&root, planted, "pub fn planted() {}\n")?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", planted])?;
    assert!(refused_path(gate(&root))?.ends_with(planted));
    Ok(())
}


#[test]
fn a_unit_with_no_product_root_is_not_judged() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/tests/t.rs", "")?;
    put(&root, "crates/victim/examples/payload.rs", "")?;
    put(&root, "crates/victim/build.rs", "fn main() {}\n")?;
    let unit = format!(
        "{}/target/test.d: crates/victim/tests/t.rs crates/victim/examples/payload.rs crates/victim/build.rs\n",
        root.display()
    );
    put(&root, "target/test.d", &unit)?;
    assert!(gate(&root)?);
    Ok(())
}


#[test]
fn a_missing_dep_info_for_a_product_target_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    fs::remove_file(root.join(format!("target/debug/build/victim/{HASH}/out/victim-{HASH}.d")))?;
    let outcome = gate(&root);
    assert!(
        matches!(&outcome, Err(GateError::MissingDepInfo { package, target }) if package == "victim" && target == "victim"),
        "{outcome:?}"
    );
    let error = outcome.err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(error.to_string().contains("victim"), "{error}");
    assert!(gate_with(&root, &["crates/gen"])?);
    assert!(matches!(gate_with(&root, &["crates/victim"]), Err(GateError::MissingDepInfo { .. })));
    Ok(())
}


#[test]
fn a_patched_dependency_into_the_kernel_directory_is_refused() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/ebpf-probes/ebpf/helper/Cargo.toml", &manifest("helper", ""))?;
    put(&root, "crates/ebpf-probes/ebpf/helper/src/lib.rs", "pub fn helper_uncovered() {}\n")?;
    put(
        &root,
        "crates/victim/Cargo.toml",
        &manifest("victim", "[dependencies]\nhelper = \"0.0.0\"\n"),
    )?;
    put(
        &root,
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/victim\", \"crates/gen\"]\nexclude = [\"crates/ebpf-probes/ebpf\"]\nresolver = \"2\"\n\n[patch.crates-io]\nhelper = { path = \"crates/ebpf-probes/ebpf/helper\" }\n",
    )?;
    lock(&root)?;
    let outcome = gate(&root);
    assert!(
        matches!(outcome, Err(GateError::ExcludedPackage { ref name }) if name == "helper"),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn unreadable_or_absent_dep_info_is_an_error_never_a_pass() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    fs::write(root.join("target/odd.d"), INVALID_UTF8)?;
    assert!(matches!(gate(&root), Err(GateError::ReadSource { .. })));
    fs::remove_file(root.join("target/odd.d"))?;
    fs::create_dir(root.join("target/dir.d"))?;
    put(&root, "target/notes.txt", "x")?;
    assert!(gate(&root)?);
    let missing = root.join("nowhere");
    assert!(matches!(dep_info_files(&[missing]), Err(GateError::Walk(_))));
    let found = dep_info_files(&[root.join("target")])?;
    assert_eq!(found.len(), PRODUCT_UNITS);
    Ok(())
}


#[test]
fn a_directory_argument_that_cannot_resolve_is_an_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let through_a_file = format!("--deps-dir={}", root.join("Cargo.toml/below").display());
    let outcome = gate_with(&root, &[&through_a_file]);
    assert!(matches!(outcome, Err(GateError::Resolve { .. })), "{outcome:?}");
    let none = Path::new("/nonexistent-deps").to_path_buf();
    assert!(dep_info_files(std::slice::from_ref(&none)).is_err());
    Ok(())
}


#[test]
fn a_source_that_cannot_resolve_is_an_error() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let unit = root.join("target/unit.d");
    fs::write(&unit, "x: crates/victim/src/lib.rs/below.rs\n")?;
    assert!(matches!(read_unit(&root, &unit), Err(GateError::Resolve { .. })));
    assert!(matches!(read_unit(&root, &root.join("absent.d")), Err(GateError::ReadSource { .. })));
    Ok(())
}


#[test]
fn a_path_with_a_space_is_one_source() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    put(&root, "crates/victim/src/my dir/x.rs", "")?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "crates/victim/src/my\\ dir/x.rs"])?;
    assert!(gate(&root)?);
    put(&root, "crates/victim/my dir/y.rs", "")?;
    dep_info(&root, "victim", &["crates/victim/src/lib.rs", "crates/victim/my\\ dir/y.rs"])?;
    assert!(refused_path(gate(&root))?.ends_with("my dir/y.rs"));
    Ok(())
}


#[test]
fn product_kinds_are_libraries_and_binaries_only() -> anyhow::Result<()> {
    let kept: Vec<Package> = ["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro", "bin"]
        .iter()
        .map(|kind| package(kind, &[kind], "/nonexistent/src/lib.rs"))
        .collect();
    let dropped: Vec<Package> = ["test", "example", "bench", "custom-build"]
        .iter()
        .map(|kind| package(kind, &[kind], "/nonexistent/src/lib.rs"))
        .collect();
    let all: Vec<&Package> = kept.iter().chain(dropped.iter()).collect();
    let found = products(&all)?;
    assert_eq!(found.len(), kept.len());
    assert_eq!(
        found.first(),
        Some(&Product {
            package: "lib".to_string(),
            target: "lib".to_string(),
            root: PathBuf::from("/nonexistent/src/lib.rs"),
            manifest: PathBuf::from("/w/crates/lib/Cargo.toml"),
        })
    );
    let unreadable = package("p", &["lib"], "/nonexistent/src/lib.rs/below");
    assert!(products(&[&unreadable])?.len() == 1);
    Ok(())
}


#[test]
fn scope_matches_the_package_directory() -> anyhow::Result<()> {
    let product = Product {
        package: "p".to_string(),
        target: "p".to_string(),
        root: PathBuf::from("/w/crates/p/src/lib.rs"),
        manifest: PathBuf::from("/w/crates/p/Cargo.toml"),
    };
    let root = Path::new("/w");
    assert!(in_scope(root, &product, &[]));
    assert!(in_scope(root, &product, &["crates/q".to_string(), "crates/p".to_string()]));
    assert!(!in_scope(root, &product, &["crates/q".to_string()]));
    Ok(())
}


#[test]
fn extra_arguments_split_into_dep_info_directories_and_scope() -> anyhow::Result<()> {
    let arguments: Vec<String> = ["gate", "export", "root", "--deps-dir=/a", "crates/x", "--deps-dir=/b"]
        .iter()
        .map(|argument| (*argument).to_string())
        .collect();
    let (directories, scope) = split_arguments(&arguments);
    assert_eq!(directories, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    assert_eq!(scope, vec!["crates/x".to_string()]);
    Ok(())
}


#[test]
fn a_transitive_path_dependency_into_the_kernel_directory_is_refused() -> anyhow::Result<()> {
    let (dir, root) = workspace()?;
    let outside = dir.path().canonicalize()?.join("outside");
    put(&root, "crates/ebpf-probes/ebpf/helper/Cargo.toml", &manifest("helper", ""))?;
    put(&root, "crates/ebpf-probes/ebpf/helper/src/lib.rs", "pub fn helper_uncovered() {}\n")?;
    let helper_path = root.join("crates/ebpf-probes/ebpf/helper");
    let middle = manifest(
        "middle",
        &format!("[dependencies]\nhelper = {{ path = \"{}\" }}\n", helper_path.display()),
    );
    put(&outside, "middle/Cargo.toml", &middle)?;
    put(&outside, "middle/src/lib.rs", "")?;
    let middle_path = outside.join("middle");
    let victim = manifest(
        "victim",
        &format!("[dependencies]\nmiddle = {{ path = \"{}\" }}\n", middle_path.display()),
    );
    put(&root, "crates/victim/Cargo.toml", &victim)?;
    lock(&root)?;
    let outcome = gate(&root);
    assert!(
        matches!(outcome, Err(GateError::ExcludedPackage { ref name }) if name == "helper"),
        "{outcome:?}"
    );
    Ok(())
}


#[test]
fn the_flags_win_and_the_llvm_cov_target_directory_is_the_fallback() -> anyhow::Result<()> {
    let flagged = vec![PathBuf::from("/a")];
    assert_eq!(deps_directories(flagged.clone(), Some(OsString::from("/env"))), flagged);
    assert_eq!(deps_directories(Vec::new(), Some(OsString::from("/env"))), vec![PathBuf::from("/env")]);
    assert!(deps_directories(Vec::new(), Some(OsString::new())).is_empty());
    assert!(deps_directories(Vec::new(), None).is_empty());
    Ok(())
}


#[test]
fn no_dep_info_directory_at_all_refuses_a_workspace_with_products() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let export = root.join("export.json");
    fs::write(&export, r#"{"data":[{"files":[]}]}"#)?;
    let binary = env!("CARGO_BIN_EXE_coverage_gate");
    let refused = Command::new(binary)
        .arg(&export)
        .arg(&root)
        .env_remove("CARGO_LLVM_COV_TARGET_DIR")
        .output()?;
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8(refused.stderr)?.contains("no dep-info for"));
    let listed = root.join("crates/victim/src/lib.rs").display().to_string();
    let covered = serde_json::json!({"data": [{"files": [{
        "filename": listed,
        "summary": {"lines": {"count": 1, "covered": 1}, "branches": {"count": 0, "covered": 0}}
    }]}]});
    fs::write(&export, covered.to_string())?;
    let fallback = Command::new(binary)
        .arg(&export)
        .arg(&root)
        .env("CARGO_LLVM_COV_TARGET_DIR", root.join("target"))
        .output()?;
    assert!(fallback.status.success(), "{}", String::from_utf8_lossy(&fallback.stderr));
    Ok(())
}


#[test]
fn a_workspace_with_no_product_target_never_reads_the_dep_info_directories() -> anyhow::Result<()> {
    let (_dir, root) = workspace()?;
    let no_products: Vec<&Package> = Vec::new();
    refuse_unchecked(&root, &[], &no_products, &[root.join("nowhere")], &[])?;
    Ok(())
}
