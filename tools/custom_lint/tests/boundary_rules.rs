use custom_lint::{
    rules_yaml::yaml_comments,
    run::read_file,
    scan::{lint_root, lint_source},
};
use std::path::Path;
use tempfile::tempdir;


const SRC_PATH: &str = "crates/x/src/lib.rs";


const BOUNDARY_PATH: &str = "crates/sys-windows/src/lib.rs";


const TESTS_PATH: &str = "crates/x/tests/it.rs";


fn report_at(path: &str, rule: &str, source: &str) -> anyhow::Result<Vec<String>> {
    Ok(lint_source(Path::new(path), source)?
        .iter()
        .filter(|violation| violation.rule == rule)
        .map(ToString::to_string)
        .collect())
}


fn line(path: &str, position: &str, rule: &str, message: &str) -> String {
    format!("{path}:{position}: {rule}: {message}")
}


#[test]
pub fn unsafe_outside_the_boundary_is_reported() -> anyhow::Result<()> {
    let rule = "unsafe-outside-boundary";
    let message = "`unsafe` is only allowed in the boundary crates";
    let source = "fn a() {\n    let s = \"unsafe\";\n    unsafe { }\n}\n";
    assert_eq!(report_at(SRC_PATH, rule, source)?, vec![line(SRC_PATH, "3:5", rule, message)]);
    assert!(report_at(BOUNDARY_PATH, rule, source)?.is_empty());
    assert!(report_at("crates/ebpf-probes/src/lib.rs", rule, source)?.is_empty());
    assert!(report_at("crates/sys-windows-extra/src/lib.rs", rule, "fn a() {}\n")?.is_empty());
    assert_eq!(report_at("crates/other/src/lib.rs", rule, source)?.len(), 1);
    assert_eq!(report_at("lib.rs", rule, source)?.len(), 1);
    Ok(())
}


#[test]
pub fn unsafe_blocks_need_an_adjacent_safety_comment() -> anyhow::Result<()> {
    let rule = "unsafe-without-safety";
    let block_message = "`unsafe` block needs a `// SAFETY: <reason>` comment on the line above";
    let good = "fn a() {\n    // SAFETY: the handle is valid\n    unsafe { }\n}\n";
    assert!(report_at(BOUNDARY_PATH, rule, good)?.is_empty());
    let separated = "fn a() {\n    // SAFETY: the handle is valid\n\n    unsafe { }\n}\n";
    assert_eq!(
        report_at(BOUNDARY_PATH, rule, separated)?,
        vec![line(BOUNDARY_PATH, "4:5", rule, block_message)]
    );
    let empty = "fn a() {\n    // SAFETY:   \n    unsafe { }\n}\n";
    assert_eq!(report_at(BOUNDARY_PATH, rule, empty)?.len(), 1);
    let wrong_kind = "fn a() {\n    /// SAFETY: doc\n    unsafe { }\n}\n";
    assert_eq!(report_at(BOUNDARY_PATH, rule, wrong_kind)?.len(), 1);
    let other_comment = "fn a() {\n    // note\n    unsafe { }\n}\n";
    assert_eq!(report_at(BOUNDARY_PATH, rule, other_comment)?.len(), 1);
    assert!(report_at(SRC_PATH, rule, other_comment)?.is_empty());
    Ok(())
}


#[test]
pub fn public_unsafe_fn_and_raw_pointers_are_reported() -> anyhow::Result<()> {
    let rule = "unsafe-without-safety";
    let source = "pub fn product(x: [u8; 2 * 3]) {}\npub unsafe fn a() {}\npub fn b(p: *const u8) {}\npub fn c() -> *mut u8 { todo() }\nfn d(p: *const u8) {}\npub(crate) fn e(p: *mut u8) {}\npub fn ok(x: u8) -> u8 { x * 2 }\nmod inner {\n    pub unsafe fn nested() {}\n}\nstruct S;\nimpl S {\n    pub unsafe fn m(&self) {}\n    pub fn n(&self, p: *mut u8) {}\n    fn private(&self, p: *mut u8) {}\n    const K: u8 = 1;\n}\n";
    let found = report_at(BOUNDARY_PATH, rule, source)?;
    assert_eq!(
        found,
        vec![
            line(BOUNDARY_PATH, "2:15", rule, "`pub unsafe fn a` is not allowed in the public API"),
            line(BOUNDARY_PATH, "3:8", rule, "`pub fn b` exposes a raw pointer"),
            line(BOUNDARY_PATH, "4:8", rule, "`pub fn c` exposes a raw pointer"),
            line(BOUNDARY_PATH, "9:19", rule, "`pub unsafe fn nested` is not allowed in the public API"),
            line(BOUNDARY_PATH, "13:19", rule, "`pub unsafe fn m` is not allowed in the public API"),
            line(BOUNDARY_PATH, "14:12", rule, "`pub fn n` exposes a raw pointer"),
        ]
    );
    Ok(())
}


#[test]
pub fn asserts_are_reported_outside_tests_only() -> anyhow::Result<()> {
    let rule = "assert-outside-tests";
    let source = "fn a() {\n    assert!(true);\n    debug_assert_eq!(1, 1);\n    let assert = 1;\n    assert_ne!(1, 2);\n}\n";
    assert_eq!(
        report_at(SRC_PATH, rule, source)?,
        vec![
            line(SRC_PATH, "2:5", rule, "`assert!` is only allowed in tests/"),
            line(SRC_PATH, "3:5", rule, "`debug_assert_eq!` is only allowed in tests/"),
            line(SRC_PATH, "5:5", rule, "`assert_ne!` is only allowed in tests/"),
        ]
    );
    assert!(report_at(TESTS_PATH, rule, source)?.is_empty());
    Ok(())
}


#[test]
pub fn tests_in_src_are_reported() -> anyhow::Result<()> {
    let rule = "test-in-src";
    let message = "tests belong under tests/, not src/";
    let source = "#[test]\nfn a() {}\n#[cfg(test)]\nmod tests {}\n#[derive(Debug)]\nstruct S;\n#[cfg(unix)]\nfn b() {}\nmod tested {}\n";
    let clean = "#[derive(Debug)]\nstruct S;\n#[cfg(unix)]\nfn b() {}\n";
    assert_eq!(
        report_at(SRC_PATH, rule, source)?,
        vec![
            line(SRC_PATH, "1:1", rule, message),
            line(SRC_PATH, "3:1", rule, message),
            line(SRC_PATH, "4:1", rule, message)
        ]
    );
    assert!(report_at(SRC_PATH, rule, clean)?.is_empty());
    assert!(report_at(TESTS_PATH, rule, "#[test]\nfn a() {}\n")?.is_empty());
    Ok(())
}


#[test]
pub fn silencers_are_reported() -> anyhow::Result<()> {
    let rule = "silencer";
    let message = "lint and coverage silencers are not allowed";
    let source = "#![allow(dead_code)]\n#[allow(unused)]\nfn a() {}\n#[expect(unused)]\nfn b() {}\n#[coverage(off)]\nfn c() {}\n#[coverage(on)]\nfn d() {}\n#[derive(Debug)]\nstruct S;\n";
    assert_eq!(
        report_at(SRC_PATH, rule, source)?,
        vec![
            line(SRC_PATH, "1:1", rule, message),
            line(SRC_PATH, "2:1", rule, message),
            line(SRC_PATH, "4:1", rule, message),
            line(SRC_PATH, "6:1", rule, message),
        ]
    );
    Ok(())
}


#[test]
pub fn let_underscore_is_reported() -> anyhow::Result<()> {
    let rule = "let-underscore";
    let source = "fn a() {\n    let _ = f();\n    let _x = 1;\n    let y = 2;\n}\n";
    assert_eq!(
        report_at(SRC_PATH, rule, source)?,
        vec![line(SRC_PATH, "2:5", rule, "`let _ =` discards a value silently")]
    );
    Ok(())
}


#[test]
pub fn shell_command_strings_are_reported() -> anyhow::Result<()> {
    let rule = "shell-c";
    let message = "running a shell with a command string is not allowed";
    let bad = [
        "fn a() {\n    Command::new(\"sh\").arg(\"-c\").arg(x).status();\n}\n",
        "fn a() {\n    Command::new(\"/bin/bash\").args([\"-c\", x]).status();\n}\n",
        "fn a() {\n    Command::new(\"cmd.exe\").arg(\"/C\").status();\n}\n",
        "fn a() {\n    Command::new(\"powershell\").arg(\"-Command\").status();\n}\n",
        "fn a() {\n    Command::new(\"zsh\").arg(\"-c\").status();\n}\n",
    ];
    bad.iter().try_for_each(|source| {
        assert_eq!(report_at(SRC_PATH, rule, source)?.len(), 1, "{source}");
        anyhow::Ok(())
    })?;
    let first = "fn a() {\n    Command::new(\"sh\").arg(\"-c\").arg(x).status();\n}\n";
    assert_eq!(report_at(SRC_PATH, rule, first)?, vec![line(SRC_PATH, "2:5", rule, message)]);
    let good = [
        "fn a() {\n    Command::new(\"sh\").arg(\"script.sh\").status();\n}\n",
        "fn a() {\n    Command::new(\"git\").arg(\"-c\").status();\n}\n",
        "fn a() {\n    Command::new(\"sh\");\n    other.arg(\"-c\");\n}\n",
        "fn a() {\n    Command::new(name).arg(\"-c\").status();\n}\n",
        "fn a() {\n    Command::new(\"\").arg(\"-c\").status();\n}\n",
        "fn a() {\n    Command::new(1).arg(\"-c\").status();\n}\n",
        "fn a() {\n    m!(Command;:new(\"sh\") \"-c\");\n}\n",
        "fn a() {\n    m!(Command:;new(\"sh\") \"-c\");\n}\n",
        "fn a() {\n    m!(Command::old(\"sh\") \"-c\");\n}\n",
        "fn a() {\n    m!(Command::new[\"sh\"] \"-c\");\n}\n",
    ];
    good.iter().try_for_each(|source| {
        assert!(report_at(SRC_PATH, rule, source)?.is_empty(), "{source}");
        anyhow::Ok(())
    })
}


#[test]
pub fn yaml_comments_are_reported_but_quoted_hashes_pass() -> anyhow::Result<()> {
    let path = Path::new("conf/a.yaml");
    let source = "# header\nkey: value # trailing\nquoted: \"#soc\"\nplain: a#b\nblock: |\n  # not a comment\nlist:\n  - '#x'\n";
    let found: Vec<String> = yaml_comments(path, source).iter().map(ToString::to_string).collect();
    let message = "comments are not allowed in YAML files";
    assert_eq!(
        found,
        vec![
            line("conf/a.yaml", "1:1", "yaml-comment", message),
            line("conf/a.yaml", "2:12", "yaml-comment", message)
        ]
    );
    assert!(yaml_comments(path, "quoted: \"#soc\"\n").is_empty());
    let broken: Vec<String> = yaml_comments(path, "# first\nkey: [\n").iter().map(ToString::to_string).collect();
    assert_eq!(broken, vec![line("conf/a.yaml", "1:1", "yaml-comment", message)]);
    Ok(())
}


#[test]
pub fn yaml_tree_is_scanned_without_target_git_and_cache() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    [
        ("crates/a/src/lib.rs", "fn alpha() {}\n"),
        ("tools/t/src/main.rs", "fn main() {}\n"),
        ("conf/rules.yml", "# bad\nk: v\n"),
        ("conf/ok.yaml", "k: \"#soc\"\n"),
        ("conf/notes.txt", "# fine\n"),
        ("crates/a/target/x.yaml", "# skipped\n"),
        (".git/x.yaml", "# skipped\n"),
        (".cache/x.yaml", "# skipped\n"),
    ]
    .iter()
    .try_for_each(|(relative, content)| {
        let path = workspace.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap_or(workspace.path()))?;
        std::fs::write(&path, content)?;
        anyhow::Ok(())
    })?;
    let found: Vec<String> = lint_root(workspace.path(), read_file)?.iter().map(ToString::to_string).collect();
    assert_eq!(
        found,
        vec![line("conf/rules.yml", "1:1", "yaml-comment", "comments are not allowed in YAML files")]
    );
    Ok(())
}


#[test]
pub fn recursion_is_detected_across_files_of_one_crate() -> anyhow::Result<()> {
    let workspace = tempdir()?;
    [
        ("crates/a/src/one.rs", "pub fn ping() {\n    pong();\n}\n"),
        ("crates/a/src/two.rs", "pub fn pong() {\n    ping();\n}\n"),
        ("crates/b/src/one.rs", "pub fn ping() {\n    pong();\n}\n"),
        ("crates/b/src/two.rs", "pub fn other() {}\n"),
        ("tools/t/src/main.rs", "fn main() {}\n"),
    ]
    .iter()
    .try_for_each(|(relative, content)| {
        let path = workspace.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap_or(workspace.path()))?;
        std::fs::write(&path, content)?;
        anyhow::Ok(())
    })?;
    let found: Vec<String> = lint_root(workspace.path(), read_file)?.iter().map(ToString::to_string).collect();
    assert_eq!(
        found,
        vec![
            line("crates/a/src/one.rs", "1:8", "recursion", "function `ping` is recursive"),
            line("crates/a/src/two.rs", "1:8", "recursion", "function `pong` is recursive"),
        ]
    );
    Ok(())
}
