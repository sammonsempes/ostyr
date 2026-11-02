use std::path::Path;


const CLEAN_SOURCE: &str = "fn clean() {}\n";


const DIRTY_SOURCE: &str = "fn dirty() {\n    // note\n}\n";


const SKIPPED_SOURCE: &str = "this is not rust";


pub const EXPECTED_REPORT: &str = "tools/t/src/main.rs:2:5: line-comment: comments are not allowed in src/ or tests/\n";


pub fn write_workspace(root: &Path) -> anyhow::Result<()> {
    [
        ("crates/a/src/lib.rs", CLEAN_SOURCE),
        ("crates/a/target/generated.rs", SKIPPED_SOURCE),
        ("crates/a/notes.txt", SKIPPED_SOURCE),
        ("tools/t/src/main.rs", DIRTY_SOURCE),
    ]
    .iter()
    .try_for_each(|(relative, content)| {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap_or(root))?;
        std::fs::write(&path, content)?;
        anyhow::Ok(())
    })
}
