use crate::{error::LintError, scan::lint_root, types::FileReader};
use std::{ffi::OsString, io::Write, path::Path};


pub fn read_file(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}


pub fn run<Output: Write>(arguments: impl Iterator<Item = OsString>, output: &mut Output, read: FileReader) -> Result<usize, LintError> {
    let collected: Vec<OsString> = arguments.collect();
    match collected.as_slice() {
        [root] => {
            let violations = lint_root(Path::new(root), read)?;
            violations.iter().try_for_each(|violation| writeln!(output, "{violation}"))?;
            Ok(violations.len())
        }
        _ => Err(LintError::Usage),
    }
}
