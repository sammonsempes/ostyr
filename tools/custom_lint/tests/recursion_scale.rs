use custom_lint::{rules_recursion::recursive_functions, run::read_file, scan::lint_root, types::CallGraph};
use std::collections::BTreeSet;


const CHAIN_LENGTH: usize = 10_000;


const FILE_FUNCTIONS: usize = 100;


const CYCLE_SIZE: usize = 2;


fn chain_graph() -> CallGraph {
    (0..CHAIN_LENGTH)
        .map(|i| {
            let targets: BTreeSet<String> = (i + 1 < CHAIN_LENGTH).then(|| format!("f{}", i + 1)).into_iter().collect();
            (format!("f{i}"), targets)
        })
        .chain([
            ("cycle_a".to_string(), BTreeSet::from(["cycle_b".to_string()])),
            ("cycle_b".to_string(), BTreeSet::from(["cycle_a".to_string()])),
        ])
        .collect()
}


#[test]
pub fn long_chain_reach_finds_only_the_cycle() -> anyhow::Result<()> {
    let graph = chain_graph();
    let reach = recursive_functions(&graph);
    assert_eq!(reach.recursive, BTreeSet::from(["cycle_a", "cycle_b"]));
    Ok(())
}


#[test]
pub fn generated_crate_with_long_chain_reports_only_the_cycle() -> anyhow::Result<()> {
    let workspace = tempfile::tempdir()?;
    std::fs::create_dir_all(workspace.path().join("tools"))?;
    let source_dir = workspace.path().join("crates/x/src");
    std::fs::create_dir_all(&source_dir)?;
    (0..CHAIN_LENGTH / FILE_FUNCTIONS).try_for_each(|file| {
        let body: String = (file * FILE_FUNCTIONS..(file + 1) * FILE_FUNCTIONS)
            .map(|i| format!("pub fn f{i}() {{\n    f{}();\n}}\n\n\n", i + 1))
            .collect();
        std::fs::write(source_dir.join(format!("m{file}.rs")), body.trim_end().to_string() + "\n")
    })?;
    std::fs::write(
        source_dir.join("end.rs"),
        format!("pub fn f{CHAIN_LENGTH}() {{}}\n\n\npub fn cycle_a() {{\n    cycle_b();\n}}\n\n\npub fn cycle_b() {{\n    cycle_a();\n}}\n"),
    )?;
    let found: Vec<String> = lint_root(workspace.path(), read_file)?
        .iter()
        .filter(|violation| violation.rule == "recursion")
        .map(ToString::to_string)
        .collect();
    assert_eq!(found.len(), CYCLE_SIZE);
    Ok(())
}


#[test]
pub fn self_call_is_recursive_and_plain_call_is_not() -> anyhow::Result<()> {
    let graph: CallGraph = [
        ("a".to_string(), BTreeSet::from(["a".to_string()])),
        ("b".to_string(), BTreeSet::from(["a".to_string()])),
    ]
    .into_iter()
    .collect();
    assert_eq!(recursive_functions(&graph).recursive, BTreeSet::from(["a"]));
    Ok(())
}
