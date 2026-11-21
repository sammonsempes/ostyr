use coverage_gate::error::GateError;
use coverage_gate::executable::has_hidden_form;
use coverage_gate::run::run;
use std::fs;
use std::process::Command;


const EMPTY_EXPORT: &str = r#"{"data":[{"files":[],"totals":{}}],"type":"llvm.coverage.json.export","version":"2.0.1"}"#;


const STUB_MANIFEST: &str = "[package]\nname = \"stub\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[[test]]\nname = \"t\"\npath = \"t.rs\"\n";


const KERNEL_MANIFEST: &str = "[workspace]\nmembers = [\"stub\"]\nexclude = [\"crates/ebpf-probes/ebpf\"]\n";


fn gate(source: &str) -> anyhow::Result<Result<bool, GateError>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let lib = root.join("crates/demo/src/lib.rs");
    fs::create_dir_all(lib.parent().ok_or_else(|| anyhow::anyhow!("no parent"))?)?;
    fs::write(&lib, source)?;
    fs::write(root.join("Cargo.toml"), KERNEL_MANIFEST)?;
    fs::create_dir_all(root.join("stub"))?;
    fs::write(root.join("stub/Cargo.toml"), STUB_MANIFEST)?;
    fs::write(root.join("stub/t.rs"), "")?;
    fs::create_dir_all(root.join("target"))?;
    let program = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(program)
        .args(["generate-lockfile", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .output()?;
    assert!(output.status.success());
    let export = root.join("export.json");
    fs::write(&export, EMPTY_EXPORT)?;
    let deps = format!("--deps-dir={}", root.join("target").display());
    let arguments = vec![
        "coverage_gate".to_string(),
        export.display().to_string(),
        root.display().to_string(),
        deps,
    ];
    Ok(run(&arguments, Vec::new()))
}


fn refused(source: &str) -> anyhow::Result<bool> {
    Ok(has_hidden_form(source)?.is_some())
}


#[test]
fn a_cfg_attr_path_on_a_module_is_refused() -> anyhow::Result<()> {
    assert!(refused(
        "#[cfg_attr(all(), path = \"../../ebpf-probes/ebpf/src/hidden.rs\")]\nmod hidden;\n"
    )?);
    assert!(refused("#[cfg_attr(all(), cfg_attr(all(), path = \"hidden.rs\"))]\nmod hidden;\n")?);
    assert!(refused("mod outer {\n    #[cfg_attr(unix, path = \"hidden.rs\")]\n    mod hidden;\n}\n")?);
    assert!(refused(
        "macro_rules! m {\n    ($p:literal) => {\n        #[cfg_attr(all(), path = $p)]\n        mod hidden;\n    };\n}\n"
    )?);
    Ok(())
}


#[test]
fn a_path_attribute_inside_a_macro_body_is_refused() -> anyhow::Result<()> {
    assert!(refused(
        "macro_rules! m {\n    () => {\n        #[path = \"hidden.rs\"]\n        mod hidden;\n    };\n}\n"
    )?);
    Ok(())
}


#[test]
fn every_include_is_refused_however_it_is_built() -> anyhow::Result<()> {
    assert!(refused("include!(\"../../ebpf-probes/ebpf/src/hidden.rs\");\n")?);
    assert!(refused("include!(concat!(\"../../ebpf-probes/\", \"ebpf/src/hidden.rs\"));\n")?);
    assert!(refused("std::include!(\"hidden.rs\");\n")?);
    assert!(refused("mod outer {\n    include!(\"hidden.rs\");\n}\n")?);
    assert!(refused("macro_rules! m {\n    () => {\n        include!(\"hidden.rs\");\n    };\n}\n")?);
    Ok(())
}


#[test]
fn include_proto_takes_only_a_plain_package_name() -> anyhow::Result<()> {
    assert!(!refused("tonic::include_proto!(\"ostyr.agent.v1\");\n")?);
    assert!(refused("tonic::include_proto!(\"../../ebpf-probes/ebpf/src/hidden\");\n")?);
    assert!(refused("tonic::include_proto!(\"\");\n")?);
    assert!(refused("tonic::include_proto!(package);\n")?);
    assert!(refused("tonic::include_proto!(\"a b\");\n")?);
    Ok(())
}


#[test]
fn data_includes_and_ordinary_attributes_pass() -> anyhow::Result<()> {
    assert!(!refused(
        "const A: &str = include_str!(\"a.txt\");\nconst B: &[u8] = include_bytes!(\"b.bin\");\n"
    )?);
    assert!(!refused("#[cfg_attr(test, derive(Debug))]\nstruct A;\n")?);
    assert!(!refused("#[cfg_attr(test, serde(with = \"module\"))]\nstruct A;\n")?);
    assert!(!refused("#[derive(Debug)]\n#[doc = \"path\"]\nstruct A;\n")?);
    assert!(!refused("#[path_like]\nfn a() {}\n")?);
    assert!(!refused("fn a() { let include = 1; let _ = include + 1; other!(1); }\n")?);
    assert!(!refused("fn a() { include_proto(); }\n")?);
    Ok(())
}


#[test]
fn the_gate_refuses_a_source_with_a_hidden_form_by_name() -> anyhow::Result<()> {
    let attribute = gate("#[cfg_attr(all(), path = \"hidden.rs\")]\nmod hidden;\n")?;
    let include = gate("include!(\"hidden.rs\");\n")?;
    assert!(matches!(attribute, Err(GateError::HiddenInclude { .. })));
    let error = include.err().ok_or_else(|| anyhow::anyhow!("accepted"))?;
    assert!(matches!(&error, GateError::HiddenInclude { path, .. } if path.ends_with("crates/demo/src/lib.rs")));
    assert!(error.to_string().contains("include!"));
    assert!(gate("fn a() {}\n")?.is_ok());
    Ok(())
}


#[test]
fn odd_token_shapes_pass_without_panicking() -> anyhow::Result<()> {
    assert!(!refused("macro_rules! m {\n    () => {\n        #(path)\n    };\n}\n")?);
    assert!(!refused("macro_rules! m {\n    () => {\n        #[]\n    };\n}\n")?);
    assert!(!refused("macro_rules! m {\n    () => {\n        include_proto ? (1)\n    };\n}\n")?);
    Ok(())
}


#[test]
fn a_malformed_export_is_a_parse_error_through_the_gate() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let export = dir.path().join("export.json");
    fs::write(&export, "{not json")?;
    let arguments = vec![
        "coverage_gate".to_string(),
        export.display().to_string(),
        dir.path().display().to_string(),
    ];
    assert!(matches!(run(&arguments, Vec::new()), Err(GateError::Parse(_))));
    Ok(())
}
