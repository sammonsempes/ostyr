use anyhow::{bail, Context};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;


const CAP_FEATURES: [&str; 2] = ["max_level_debug", "release_max_level_debug"];


const TARGETS: [&str; 2] = ["", "x86_64-pc-windows-gnu"];


const SCRATCH_PARENT: &str = "../../target";


const CAPPED_LOG: &str = "log = { path = \"../../../stubs/log\", features = [\"max_level_debug\", \"release_max_level_debug\"] }";


const PLAIN_LOG: &str = "log = { path = \"../../../stubs/log\" }";


const UREQ_PATH: &str = "ureq = { path = \"../../../stubs/ureq\" }";


fn cargo_tree(manifest: &Path, extra: &[&str]) -> anyhow::Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["tree", "--offline", "--prefix", "none", "-e", "normal", "--manifest-path"])
        .arg(manifest)
        .args(extra)
        .output()
        .context("run cargo tree")?;
    if !output.status.success() {
        bail!("cargo tree failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?)
}


fn is_uncapped(tree: &str) -> bool {
    let holds_ureq = tree.lines().any(|line| line.starts_with("ureq v"));
    let log_lines = tree.lines().filter(|line| line.starts_with("log v")).collect::<Vec<_>>();
    let every_log_capped = log_lines.iter().all(|line| {
        line.trim_end_matches(" (*)")
            .rsplit(' ')
            .next()
            .is_some_and(|features| CAP_FEATURES.iter().all(|cap| features.split(',').any(|found| found == *cap)))
    });
    holds_ureq && !(!log_lines.is_empty() && every_log_capped)
}


pub fn uncapped_packages(manifest: &Path) -> anyhow::Result<Vec<String>> {
    let listing = cargo_tree(manifest, &["--workspace", "--depth", "0", "-f", "{p}"])?;
    let names = listing
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut uncapped = Vec::new();
    for name in &names {
        for target in TARGETS {
            let target_args: &[&str] = if target.is_empty() { &[] } else { &["--target", target] };
            let args = [&["-p", name.as_str(), "-f", "{p} {f}"], target_args].concat();
            let tree = cargo_tree(manifest, &args)?;
            if is_uncapped(&tree) && !uncapped.contains(name) {
                uncapped.push(name.clone());
            }
        }
    }
    Ok(uncapped)
}


#[test]
pub fn every_workspace_package_that_reaches_ureq_caps_the_log_level() -> anyhow::Result<()> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let uncapped = uncapped_packages(&manifest)?;
    assert!(uncapped.is_empty(), "packages that reach ureq without the log cap: {uncapped:?}");
    Ok(())
}


fn write_file(path: &Path, text: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}


fn package_header(name: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n")
}


fn write_crate(dir: &Path, name: &str, body: &str) -> anyhow::Result<()> {
    write_file(&dir.join("Cargo.toml"), &format!("{}{body}", package_header(name)))?;
    write_file(&dir.join("src/lib.rs"), "")
}


fn write_workspace(root: &Path, members: &[(&str, String)]) -> anyhow::Result<()> {
    let stubs = root.join("stubs");
    write_crate(
        &stubs.join("log"),
        "log",
        "[features]\nmax_level_debug = []\nrelease_max_level_debug = []\n",
    )?;
    write_crate(&stubs.join("ureq"), "ureq", "[dependencies]\nlog = { path = \"../log\" }\n")?;
    write_crate(&stubs.join("thirdparty"), "thirdparty", "[dependencies]\nureq = { path = \"../ureq\" }\n")?;
    write_file(
        &root.join("ws/Cargo.toml"),
        "[workspace]\nmembers = [\"pkgs/*\"]\nresolver = \"2\"\n[workspace.dependencies]\nureq = { path = \"../stubs/ureq\" }\n",
    )?;
    members
        .iter()
        .try_for_each(|(name, body)| write_crate(&root.join("ws/pkgs").join(name), name, body))
}


fn scratch() -> anyhow::Result<tempfile::TempDir> {
    Ok(tempfile::tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRATCH_PARENT))?)
}


#[test]
pub fn the_check_flags_every_bypass_and_accepts_a_capped_package() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let optional_log = "log = { path = \"../../../stubs/log\", optional = true, features = [\"max_level_debug\", \"release_max_level_debug\"] }";
    let members = [
        ("good", format!("[dependencies]\n{UREQ_PATH}\n{CAPPED_LOG}\n")),
        (
            "rename",
            format!("[dependencies]\nureq2 = {{ package = \"ureq\", path = \"../../../stubs/ureq\" }}\n{CAPPED_LOG}\n"),
        ),
        (
            "rename_uncapped",
            format!("[dependencies]\nureq2 = {{ package = \"ureq\", path = \"../../../stubs/ureq\" }}\n{PLAIN_LOG}\n"),
        ),
        (
            "table",
            format!("[dependencies.ureq]\npath = \"../../../stubs/ureq\"\n[dependencies]\n{PLAIN_LOG}\n"),
        ),
        ("workspace_dep", format!("[dependencies]\nureq.workspace = true\n{PLAIN_LOG}\n")),
        ("dev_only", format!("[dependencies]\n{UREQ_PATH}\n[dev-dependencies]\n{CAPPED_LOG}\n")),
        (
            "target_only",
            format!("[dependencies]\n{UREQ_PATH}\n[target.'cfg(windows)'.dependencies]\n{CAPPED_LOG}\n"),
        ),
        ("optional", format!("[dependencies]\n{UREQ_PATH}\n{optional_log}\n")),
        (
            "comment_only",
            format!("[dependencies]\n{UREQ_PATH}\n{PLAIN_LOG} # max_level_debug release_max_level_debug\n"),
        ),
        (
            "transitive",
            "[dependencies]\nthirdparty = { path = \"../../../stubs/thirdparty\" }\n".to_owned(),
        ),
        ("no_ureq", format!("[dependencies]\n{PLAIN_LOG}\n")),
    ];
    write_workspace(scratch.path(), &members)?;
    let mut uncapped = uncapped_packages(&scratch.path().join("ws/Cargo.toml"))?;
    uncapped.sort();
    assert_eq!(
        uncapped,
        [
            "comment_only",
            "dev_only",
            "optional",
            "rename_uncapped",
            "table",
            "target_only",
            "transitive",
            "workspace_dep"
        ]
    );
    Ok(())
}


#[test]
pub fn a_log_entry_under_features_is_an_invalid_manifest_the_check_reports() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let members = [("bad", format!("[dependencies]\n{UREQ_PATH}\n[features]\n{PLAIN_LOG}\n"))];
    write_workspace(scratch.path(), &members)?;
    let outcome = uncapped_packages(&scratch.path().join("ws/Cargo.toml"));
    assert!(outcome.is_err());
    Ok(())
}
