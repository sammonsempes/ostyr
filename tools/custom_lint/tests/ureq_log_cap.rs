use anyhow::{bail, Context};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::Command;
use toml_edit::DocumentMut;


const CAP_FEATURES: [&str; 2] = ["max_level_debug", "release_max_level_debug"];


const WORKERS: usize = 8;


const REFUSED_KEYS: [&str; 2] = ["patch", "replace"];


const ALL_CONFIGS: usize = 3;


const CAP_CRATES: [&str; 3] = ["log", "ureq", "ureq-proto"];


const DEPENDENCY_SECTIONS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];


const MANIFEST_KEYS: [&str; 17] = [
    "cargo-features",
    "package",
    "lib",
    "bin",
    "example",
    "test",
    "bench",
    "dependencies",
    "dev-dependencies",
    "build-dependencies",
    "target",
    "features",
    "lints",
    "profile",
    "workspace",
    "patch",
    "replace",
];


const EXTRA_TARGETS: [&str; 5] = [
    "x86_64-pc-windows-gnu",
    "x86_64-unknown-linux-musl",
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


const INHERITED_ROOT: &str = "[workspace]\nmembers = [\"pkgs/*\"]\nresolver = \"2\"\n[workspace.dependencies]\nlogcap = { package = \"log\", path = \"../stubs/log\" }\nother = { package = \"thirdparty\", path = \"../stubs/thirdparty\" }\n";


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
        .args(["tree", "--offline", "--prefix", "none", "-e", "normal,dev", "--manifest-path"])
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


pub fn refused_configuration(root: &Path, home: Option<&Path>) -> anyhow::Result<Vec<String>> {
    let absolute = root.canonicalize()?;
    let config_dirs = absolute
        .ancestors()
        .map(|dir| dir.join(".cargo"))
        .chain(home.map(Path::to_path_buf))
        .collect::<Vec<_>>();
    let configs = config_dirs
        .iter()
        .flat_map(|dir| [dir.join("config.toml"), dir.join("config")])
        .filter(|path| path.exists())
        .map(|path| format!("cargo configuration file {}", path.display()));
    let manifest = root.join("Cargo.toml");
    let document = fs::read_to_string(&manifest)?.parse::<DocumentMut>()?;
    let overrides = REFUSED_KEYS
        .iter()
        .filter(|key| document.contains_key(key))
        .map(|key| format!("`{key}` in {}", manifest.display()))
        .collect::<Vec<_>>();
    Ok(configs.chain(overrides).collect())
}


fn cargo_metadata(root: &Path) -> anyhow::Result<serde_json::Value> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--offline", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .current_dir(root)
        .output()
        .context("run cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}


fn path_manifests(root: &Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let metadata = cargo_metadata(root)?;
    let packages = metadata
        .get("packages")
        .and_then(|item| item.as_array())
        .context("cargo metadata has no packages")?;
    packages
        .iter()
        .filter(|package| package.get("source").is_some_and(serde_json::Value::is_null))
        .map(|package| {
            package
                .get("manifest_path")
                .and_then(|path| path.as_str())
                .map(std::path::PathBuf::from)
                .context("package without manifest_path")
        })
        .collect()
}


fn workspace_packages(root: &Path) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let document = fs::read_to_string(root.join("Cargo.toml"))?.parse::<DocumentMut>()?;
    let entries = document
        .get("workspace")
        .and_then(|item| item.get("dependencies"))
        .and_then(|item| item.as_table_like());
    Ok(entries
        .into_iter()
        .flat_map(|table| table.iter())
        .filter_map(|(key, value)| {
            let package = value
                .as_table_like()
                .and_then(|inner| inner.get("package"))
                .and_then(|name| name.as_str());
            package.map(|name| (key.to_owned(), name.to_owned()))
        })
        .collect())
}


fn resolved_package(key: &str, value: &toml_edit::Item, inherited: &std::collections::HashMap<String, String>) -> String {
    let inner = value.as_table_like();
    let own = inner.and_then(|table| table.get("package")).and_then(|name| name.as_str());
    let from_workspace = inner
        .and_then(|table| table.get("workspace"))
        .and_then(|flag| flag.as_bool())
        .unwrap_or(false);
    let root_name = inherited.get(key).map(String::as_str).filter(|_| from_workspace);
    own.or(root_name).unwrap_or(key).to_owned()
}


fn unknown_keys(table: &dyn toml_edit::TableLike, allowed: &[&str], place: &str, manifest: &Path) -> Vec<String> {
    table
        .iter()
        .filter(|(key, _)| !allowed.contains(key))
        .map(|(key, _)| format!("key `{key}` is not allowed in {place} of {}", manifest.display()))
        .collect()
}


fn target_dependencies(manifest: &Path, inherited: &std::collections::HashMap<String, String>) -> anyhow::Result<Vec<String>> {
    let document = fs::read_to_string(manifest)?.parse::<DocumentMut>()?;
    let top_level = unknown_keys(document.as_table(), &MANIFEST_KEYS, "the top level", manifest);
    let targets = document.get("target").and_then(|item| item.as_table_like());
    let per_target = targets
        .into_iter()
        .flat_map(|table| table.iter())
        .filter_map(|(target, item)| item.as_table_like().map(|inner| (target, inner)))
        .collect::<Vec<_>>();
    let unknown = per_target
        .iter()
        .flat_map(|(target, inner)| unknown_keys(*inner, &DEPENDENCY_SECTIONS, &format!("[target.{target}]"), manifest))
        .collect::<Vec<_>>();
    let found = per_target
        .iter()
        .flat_map(|(target, inner)| DEPENDENCY_SECTIONS.iter().map(move |section| (*target, *section, inner.get(section))))
        .filter_map(|(target, section, item)| item.and_then(|found| found.as_table_like()).map(|deps| (target, section, deps)))
        .flat_map(|(target, section, deps)| {
            deps.iter()
                .filter(|(key, value)| CAP_CRATES.contains(key) || CAP_CRATES.contains(&resolved_package(key, value, inherited).as_str()))
                .map(move |(key, _)| format!("`{key}` under [target.{target}.{section}] in {}", manifest.display()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    Ok(top_level.into_iter().chain(unknown).chain(found).collect())
}


pub fn refused_target_dependencies(root: &Path) -> anyhow::Result<Vec<String>> {
    let inherited = workspace_packages(root)?;
    let per_manifest = path_manifests(root)?
        .iter()
        .map(|manifest| target_dependencies(manifest, &inherited))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(per_manifest.concat())
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
    let target_declared = refused_target_dependencies(workspace_root(&manifest))?;
    assert!(
        target_declared.is_empty(),
        "log or ureq declared under a target table: {target_declared:?}"
    );
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
    write_crate(
        &stubs.join("thirdfeat"),
        "thirdfeat",
        "[dependencies]\nureq = { path = \"../ureq\", optional = true }\n[features]\nhttp = [\"dep:ureq\"]\n",
    )?;
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
        ("dev_ureq", format!("[dependencies]\n{PLAIN_LOG}\n[dev-dependencies]\n{UREQ_PATH}\n")),
        (
            "dev_third_party",
            format!("[dependencies]\n{PLAIN_LOG}\n[dev-dependencies]\nthirdparty = {{ path = \"../../../stubs/thirdparty\" }}\n"),
        ),
        (
            "dev_feature",
            format!(
                "[dependencies]\n{PLAIN_LOG}\n[dev-dependencies]\nthirdfeat = {{ path = \"../../../stubs/thirdfeat\", features = [\"http\"] }}\n"
            ),
        ),
        ("dev_capped", format!("[dependencies]\n{CAPPED_LOG}\n[dev-dependencies]\n{UREQ_PATH}\n")),
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
            "dev_feature",
            "dev_third_party",
            "dev_ureq",
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
pub fn the_host_triple_is_always_the_first_of_six_targets() -> anyhow::Result<()> {
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


fn refused_with_prefix(root: &Path, home: &Path, prefix: &str) -> anyhow::Result<usize> {
    let manifest = root.join("Cargo.toml");
    let original = fs::read_to_string(&manifest)?;
    fs::write(&manifest, format!("{prefix}{original}"))?;
    let count = refused_configuration(root, Some(home))?.len();
    fs::write(&manifest, original)?;
    Ok(count)
}


#[test]
pub fn a_patch_or_replace_in_any_form_is_refused_in_the_root_manifest() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(scratch.path(), &[])?;
    let root = scratch.path().join("ws");
    let home = scratch.path().join("home");
    assert!(refused_configuration(&root, Some(&home))?.is_empty());
    assert!(refused_configuration(&root, None)?.is_empty());
    let forms = [
        "[patch.crates-io]\nlog = { path = \"../stubs/log\" }\n",
        "[patch]\ncrates-io = { log = { git = \"file:///x\" } }\n",
        "patch = { crates-io = { log = { git = \"file:///x\" } } }\n",
        "patch.crates-io.log.git = \"file:///x\"\n",
        "[replace]\n\"log:0.4.0\" = { path = \"../stubs/log\" }\n",
        "replace = { \"log:0.4.0\" = { path = \"../stubs/log\" } }\n",
    ];
    for form in forms {
        assert_eq!(refused_with_prefix(&root, &home, form)?, 1, "{form}");
    }
    Ok(())
}


#[test]
pub fn any_cargo_configuration_file_is_refused_without_being_read() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(scratch.path(), &[])?;
    let root = scratch.path().join("ws");
    let home = scratch.path().join("home");
    let inline = "source = { crates-io = { replace-with = \"vendored\" }, vendored = { directory = \"vendor\" } }\n";
    write_file(&root.join(".cargo/config.toml"), inline)?;
    write_file(&scratch.path().join(".cargo/config"), "include = [\"extra.toml\"]\n")?;
    write_file(&home.join("config.toml"), "not = [valid")?;
    assert_eq!(refused_configuration(&root, Some(&home))?.len(), ALL_CONFIGS);
    assert_eq!(refused_configuration(&root, None)?.len(), ALL_CONFIGS - 1);
    Ok(())
}


#[test]
pub fn log_or_ureq_under_any_target_table_is_refused_in_every_form() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let forms = [
        "[target.'cfg(not(target_env = \"musl\"))'.dependencies]\nlog = { path = \"../../../stubs/log\", features = [\"max_level_debug\"] }\n",
        "[target.'cfg(target_env = \"musl\")'.dependencies]\nureq = { path = \"../../../stubs/ureq\" }\n",
        "[target.'cfg(unix)'.build-dependencies]\nureq-proto = { path = \"../../../stubs/ureq-proto\" }\n",
        "[target.'cfg(unix)'.dev-dependencies.log]\npath = \"../../../stubs/log\"\n",
        "[target.'cfg(unix)'.dependencies]\nlog.path = \"../../../stubs/log\"\n",
        "[target]\n'cfg(unix)' = { dependencies = { renamed = { package = \"log\", path = \"../../../stubs/log\" } } }\n",
        "[target.'cfg(not(target_arch = \"riscv64\"))'.dev_dependencies]\nlog = { path = \"../../../stubs/log\" }\n",
        "[target.'cfg(unix)'.build_dependencies]\nlog = { path = \"../../../stubs/log\" }\n",
        "[target.'cfg(unix)'.surprise]\nlog = { path = \"../../../stubs/log\" }\n",
        "[dev_dependencies]\nlog = { path = \"../../../stubs/log\" }\n",
        "[build_dependencies]\nlog = { path = \"../../../stubs/log\" }\n",
    ];
    for form in forms {
        write_workspace(scratch.path(), &[("bad", form.to_owned())])?;
        let refused = refused_target_dependencies(&scratch.path().join("ws"))?;
        assert_eq!(refused.len(), 1, "{form}");
    }
    Ok(())
}


#[test]
pub fn a_workspace_without_target_tables_or_with_literal_members_is_accepted() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(scratch.path(), &[("good", format!("[dependencies]\n{UREQ_PATH}\n{CAPPED_LOG}\n"))])?;
    let root = scratch.path().join("ws");
    assert!(refused_target_dependencies(&root)?.is_empty());
    write_file(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"pkgs/good\"]\nresolver = \"2\"\n")?;
    assert!(refused_target_dependencies(&root)?.is_empty());
    Ok(())
}


#[test]
pub fn a_member_reached_by_a_glob_is_read() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let target_log = "[target.'cfg(unix)'.dependencies]\nlog = { path = \"../../../stubs/log\" }\n";
    write_workspace(scratch.path(), &[("sglob", target_log.to_owned()), ("other", String::new())])?;
    let root = scratch.path().join("ws");
    write_file(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"pkgs/s*\"]\nresolver = \"2\"\n")?;
    assert_eq!(refused_target_dependencies(&root)?.len(), 1);
    Ok(())
}


#[test]
pub fn an_inherited_rename_under_a_target_table_is_refused() -> anyhow::Result<()> {
    let scratch = scratch()?;
    let target_inherit = "[target.'cfg(not(target_arch = \"riscv64\"))'.dependencies]\nlogcap = { workspace = true }\n";
    write_workspace(scratch.path(), &[("inherit", target_inherit.to_owned())])?;
    let root = scratch.path().join("ws");
    let renamed = INHERITED_ROOT;
    write_file(&root.join("Cargo.toml"), renamed)?;
    assert_eq!(refused_target_dependencies(&root)?.len(), 1);
    let harmless = "[target.'cfg(unix)'.dependencies]\nother = { workspace = true }\n";
    write_workspace(scratch.path(), &[("inherit", harmless.to_owned())])?;
    write_file(&root.join("Cargo.toml"), renamed)?;
    assert!(refused_target_dependencies(&root)?.is_empty());
    Ok(())
}


#[test]
pub fn a_path_package_outside_the_members_is_read() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(
        scratch.path(),
        &[("user", "[dependencies]\ncapper = { path = \"../../../vendor-capper\" }\n".to_owned())],
    )?;
    let capper = "[target.'cfg(unix)'.dependencies]\nlog = { path = \"../stubs/log\" }\n";
    write_crate(&scratch.path().join("vendor-capper"), "capper", capper)?;
    let root = scratch.path().join("ws");
    write_file(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"pkgs/*\"]\nexclude = [\"../vendor-capper\"]\nresolver = \"2\"\n",
    )?;
    let refused = refused_target_dependencies(&root)?;
    assert_eq!(refused.len(), 1, "{refused:?}");
    Ok(())
}


#[test]
pub fn a_workspace_cargo_cannot_resolve_is_an_error() -> anyhow::Result<()> {
    let scratch = scratch()?;
    write_workspace(scratch.path(), &[])?;
    let root = scratch.path().join("ws");
    write_file(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"pkgs/absent\"]\n")?;
    assert!(refused_target_dependencies(&root).is_err());
    Ok(())
}
