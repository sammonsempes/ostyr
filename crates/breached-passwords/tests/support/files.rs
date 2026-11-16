use std::error::Error;
use std::path::PathBuf;


pub fn write_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    let path = dir.path().join(name);
    std::fs::write(&path, content)?;
    Ok(path)
}
