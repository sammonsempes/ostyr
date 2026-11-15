use anyhow::{bail, Context};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;
use toml_edit::DocumentMut;


const CAP_FEATURES: [&str; 2] = ["max_level_debug", "release_max_level_debug"];


const WORKERS: usize = 8;


const ALL_CONFIGS: usize = 3;


const TWO_CONFIGS: usize = 2;


const EXTRA_TARGETS: [&str; 4] = [
    "x86_64-pc-windows-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
];


const HOST_PREFIX: &str = "host: ";


const SCRATCH_PARENT: &str = "../../target";


const CAPPED_LOG: &str = "log = { path = \"../../../stubs/log\", features = [\"max_level_debug\", \"release_max_level_debug\"] }";


const PATCHED_LOG: &str =
    "log_patched = { package = \"log\", path = \"../../../patched_log\", features = [\"max_level_debug\", \"release_max_level_debug\"] }";


const PLAIN_LOG: &str = "log = { path = \"../../../stubs/log\" }";


const UREQ_PATH: &str = "ureq = { path = \"../../../stubs/ureq\" }";


fn workspace_root(manifest: &Path) -> &Path {
    manifest.parent().unwrap_or_else(|| Path::new("."))
}


pub fn host_triple(root: &Path) -> anyhow::Result<String> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc).arg("-vV").current_dir(root).output().context("run rustc -vV")?;
    let text = String::from_utf8(output.stdout)?;
    let host = text.lines().find_map(|line| line.strip_prefix(HOST_PREFIX));
    host.map(str::to_owned).context("rustc -vV has no host line")
}


pub fn targets(host: &str) -> Vec<String> {
    std::iter::once(host).chain(EXTRA_TARGETS).map(str::to_owned).collect()
}


fn cargo_tree(manifest: &Path, extra: &[&str]) -> anyhow::Result<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["tree", "--offline", "--prefix", "none", "-e", "normal", "--manifest-path"])
        .arg(manifest)
        .args(extra)
        .current_dir(workspace_root(manifest))
        .output()
        .context("run cargo tree")?;
    if !output.status.success() {
        bail!("cargo tree failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?)
}


fn is_sourced(line: &str) -> bool {
    line.trim_end_matches(" (*)").contains(" (")
}


pub fn is_uncapped(tree: &str, trusted_stubs: Option<&Path>) -> bool {
    let trusted = trusted_stubs.map(|stubs| format!(" ({}/", stubs.display()));
    let holds_ureq = tree.lines().any(|line| line.starts_with("ureq v") || line.starts_with("ureq-proto v"));
    let log_lines = tree.lines().filter(|line| line.starts_with("log v")).collect::<Vec<_>>();
    let sourced_from_path = tree
        .lines()
        .filter(|line| ["log v", "ureq v", "ureq-proto v"].iter().any(|prefix| line.starts_with(prefix)));
    let path_override = sourced_from_path
        .filter(|line| is_sourced(line))
        .any(|line| !trusted.as_ref().is_some_and(|prefix| line.contains(prefix.as_str())));
    let every_log_capped = log_lines.iter().all(|line| {
        line.trim_end_matches(" (*)")
            .rsplit(' ')
            .next()
            .is_some_and(|features| CAP_FEATURES.iter().all(|cap| features.split(',').any(|found| found == *cap)))
    });
    path_override || (holds_ureq && !(!log_lines.is_empty() && every_log_capped))
}


fn cargo_home() -> Option<std::path::PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".cargo")))
}


fn has_table(path: &Path, table: &str) -> anyhow::Result<bool> {
    let found = path.is_file().then(|| fs::read_to_string(path)).transpose()?;
    let document = found.map(|text| text.parse::<DocumentMut>()).transpose()?;
    Ok(document.is_some_and(|parsed| parsed.contains_table(table)))
}


pub fn refused_configuration(root: &Path, home: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let absolute = root.canonicalize()?;
    let config_dirs = absolute
        .ancestors()
        .map(|dir| dir.join(".cargo"))
        .chain(home.map(Path::to_path_buf))
        .collect::<Vec<_>>();
    let sources = config_dirs
        .iter()
        .flat_map(|dir| [dir.join("config.toml"), dir.join("config")])
        .map(|path| has_table(&path, "source").map(|found| found.then(|| format!("[source] in {}", path.display()))))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let manifest = root.join("Cargo.toml");
    let patch = has_table(&manifest, "patch")?.then(|| format!("[patch] in {}", manifest.display()));
    Ok(sources.into_iter().flatten().chain(patch).collect())
}


pub fn uncapped_packages(manifest: &Path, trusted_stubs: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let target_vec = targets(&host_triple(workspace_root(manifest))?);
    let target_list = target_vec.as_slice();
    let listing = cargo_tree(manifest, &["--workspace", "--depth", "0", "-f", "{p}"])?;
    let names = listing
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let chunk_size = names.len().div_ceil(WORKERS).max(1);
    let found = std::thread::scope(|scope| {
        let handles = names
            .chunks(chunk_size)
            .map(|chunk| scope.spawn(move || uncapped_in(manifest, chunk, target_list, trusted_stubs)))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| anyhow::anyhow!("worker thread panicked"))?)
            .collect::<anyhow::Result<Vec<_>>>()
    })?;
    Ok(found.concat())
}


fn uncapped_in(manifest: &Path, names: &[String], target_list: &[String], trusted_stubs: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let mut uncapped = Vec::new();
    for name in names {
        for target in target_list {
            let args = ["-p", name.as_str(), "-f", "{p} {f}", "--target", target.as_str()];
            if is_uncapped(&cargo_tree(manifest, &args)?, trusted_stubs) && !uncapped.contains(name) {
                uncapped.push(name.clone());
            }
        }
    }
    Ok(uncapped)
}


#[test]
pub fn every_workspace_package_that_reaches_ureq_caps_the_log_level() -> anyhow::Result<()> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let refused = refused_configuration(workspace_root(&manifest), cargo_home().as_deref())?;
    assert!(refused.is_empty(), "configuration the check cannot see through: {refused:?}");
    let uncapped = uncapped_packages(&manifest, None)?;
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
    write_crate(&stubs.join("ureq-proto"), "ureq-proto", "[dependencies]\nlog = { path = \"../log\" }\n")?;
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
        (
            "macos_ureq",
            format!("[target.'cfg(target_os = \"macos\")'.dependencies]\n{UREQ_PATH}\n[dependencies]\n{PLAIN_LOG}\n"),
        ),
        (
            "aarch64_ureq",
            format!("[target.'cfg(target_arch = \"aarch64\")'.dependencies]\n{UREQ_PATH}\n[dependencies]\n{PLAIN_LOG}\n"),
        ),
        (
            "proto_direct",
            "[dependencies]\nureq-proto = { path = \"../../../stubs/ureq-proto\" }\n".to_owned(),
        ),
        ("patched", format!("[dependencies]\n{UREQ_PATH}\n{CAPPED_LOG}\n{PATCHED_LOG}\n")),
        ("no_ureq", format!("[dependencies]\n{PLAIN_LOG}\n")),
    ];
    write_workspace(scratch.path(), &members)?;
    write_crate(
        &scratch.path().join("patched_log"),
        "log",
        "[features]\nmax_level_debug = []\nrelease_max_level_debug = []\n",
    )?;
    let patched_manifest = scratch.path().join("patched_log/Cargo.toml");
    fs::write(&patched_manifest, fs::read_to_string(&patched_manifest)?.replace("0.0.0", "0.0.1"))?;
    let mut uncapped = uncapped_packages(&scratch.path().join("ws/Cargo.toml"), Some(&scratch.path().join("stubs").canonicalize()?))?;
    uncapped.sort();
    assert_eq!(
        uncapped,
        [
            "aarch64_ureq",
            "comment_only",
            "dev_only",
            "macos_ureq",
            "optional",
            "patched",
            "proto_direct",
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
    let outcome = uncapped_packages(&scratch.path().join("ws/Cargo.toml"), Some(&scratch.path().join("stubs").canonicalize()?));
    assert!(outcome.is_err());
    Ok(())
}


#[test]
pub fn the_host_triple_is_always_the_first_of_five_targets() -> anyhow::Result<()> {
    let host = host_triple(Path::new("."))?;
    let list = targets(&host);
    assert_eq!(list.len(), EXTRA_TARGETS.len() + 1);
    assert_eq!(list.first(), Some(&host));
    Ok(())
}


#[test]
pub fn a_path_sourced_log_is_uncapped_unless_under_the_trusted_stubs() -> anyhow::Result<()> {
    let tree = "ureq v1.0.0 (/x/stubs/ureq) \nlog v0.4.0 (/other/log) max_level_debug,release_max_level_debug\n";
    assert!(is_uncapped(tree, Some(Path::new("/x/stubs"))));
    assert!(is_uncapped(tree, None));
    let registry = "ureq v1.0.0 \nlog v0.4.0 max_level_debug,release_max_level_debug\n";
    assert!(!is_uncapped(registry, None));
    Ok(())
}


#[test]
pub fn any_source_annotation_on_log_or_ureq_is_uncapped() -> anyhow::Result<()> {
    let capped = "log v0.4.0 {} max_level_debug,release_max_level_debug\n";
    let annotations = [
        "(file:///x/log#14e858c6)",
        "(https://example.org/log#14e858c6)",
        "(registry `mirror`)",
        "(/p/log)",
    ];
    annotations.iter().for_each(|annotation| {
        let tree = format!("ureq v1.0.0\n{}", capped.replace("{}", annotation));
        assert!(is_uncapped(&tree, Some(Path::new("/x/stubs"))), "{annotation}");
    });
    let plain = format!("ureq v1.0.0\n{}", capped.replace(" {}", ""));
    assert!(!is_uncapped(&plain, None));
    let repeated = format!("ureq v1.0.0\n{}", capped.replace(" {}", "").replace('\n', " (*)\n"));
    assert!(!is_uncapped(&repeated, None));
    Ok(())
}


fn run_git(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false"])
        .args(args)
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| !key.to_string_lossy().starts_with("GIT_")))
        .current_dir(dir)
        .status()?;
    anyhow::ensure!(status.success(), "git{args:?} failed");
    Ok(())
}


#[test]
pub fn a_git_sourced_log_is_flagged_in_a_real_tree() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let repo = scratch.path().join("logrepo");
    write_crate(&repo, "log", "[features]\nmax_level_debug = []\nrelease_max_level_debug = []\n")?;
    run_git(&repo, &["init", "-q"])?;
    run_git(&repo, &["add", "-A"])?;
    run_git(&repo, &["commit", "-q", "-m", "x"])?;
    let git_log = format!(
        "log = {{ git = \"file://{}\", features = [\"max_level_debug\", \"release_max_level_debug\"] }}",
        repo.canonicalize()?.display()
    );
    let members = [("viagit", format!("[dependencies]\n{UREQ_PATH}\n{git_log}\n"))];
    write_workspace(scratch.path(), &members)?;
    let manifest = scratch.path().join("ws/Cargo.toml");
    let fetched = Command::new("cargo")
        .args(["fetch", "--manifest-path"])
        .arg(&manifest)
        .current_dir(scratch.path())
        .status()?;
    anyhow::ensure!(fetched.success(), "cargo fetch failed");
    let uncapped = uncapped_packages(&manifest, Some(&scratch.path().join("stubs").canonicalize()?))?;
    assert_eq!(uncapped, ["viagit"]);
    Ok(())
}


#[test]
pub fn a_patch_table_or_a_source_replacement_is_refused() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(scratch.path(), &[])?;
    let root = scratch.path().join("ws");
    let home = scratch.path().join("home");
    assert!(refused_configuration(&root, Some(&home))?.is_empty());
    let manifest = root.join("Cargo.toml");
    let original = fs::read_to_string(&manifest)?;
    fs::write(&manifest, format!("{original}[patch.crates-io]\nlog = {{ path = \"../stubs/log\" }}\n"))?;
    assert_eq!(refused_configuration(&root, Some(&home))?.len(), 1);
    fs::write(&manifest, original)?;
    let replacement = "[source.crates-io]\nreplace-with = \"vendored\"\n[source.vendored]\ndirectory = \"vendor\"\n";
    write_file(&root.join(".cargo/config.toml"), replacement)?;
    write_file(&scratch.path().join(".cargo/config"), replacement)?;
    write_file(&home.join("config.toml"), replacement)?;
    assert_eq!(refused_configuration(&root, Some(&home))?.len(), ALL_CONFIGS);
    write_file(&root.join(".cargo/config.toml"), "[build]\njobs = 2\n")?;
    assert_eq!(refused_configuration(&root, Some(&home))?.len(), TWO_CONFIGS);
    write_file(&home.join("config.toml"), "not = [valid")?;
    assert!(refused_configuration(&root, Some(&home)).is_err());
    assert!(refused_configuration(&root, None).is_ok());
    Ok(())
}
