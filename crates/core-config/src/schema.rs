use crate::error::ConfigError;
use crate::model::{ModuleConfig, PlatformConfig};
use schemars::{schema_for, JsonSchema};
use std::fs;
use std::path::{Path, PathBuf};


pub const PLATFORM_SCHEMA_FILE: &str = "platform.schema.json";


pub const MODULE_SCHEMA_FILE: &str = "module.schema.json";


/// Keys are sorted explicitly: `yara-x` turns on `serde_json/preserve_order` workspace-wide, which would otherwise reorder the file.
pub fn schema_text<Schema: JsonSchema>() -> String {
    let mut value = schema_for!(Schema).as_value().clone();
    value.sort_all_objects();
    format!("{value:#}\n")
}


fn write_text(path: &Path, text: &str) -> Result<(), ConfigError> {
    fs::write(path, text).map_err(|source| ConfigError::Io {
        file: path.display().to_string(),
        source,
    })
}


/// Writes one JSON Schema per top-level type into `dir` and returns the files written.
pub fn write_schemas(dir: &Path) -> Result<Vec<PathBuf>, ConfigError> {
    fs::create_dir_all(dir).map_err(|source| ConfigError::Io {
        file: dir.display().to_string(),
        source,
    })?;
    let platform = dir.join(PLATFORM_SCHEMA_FILE);
    let module = dir.join(MODULE_SCHEMA_FILE);
    write_text(&platform, &schema_text::<PlatformConfig>())?;
    write_text(&module, &schema_text::<ModuleConfig>())?;
    Ok(vec![platform, module])
}
