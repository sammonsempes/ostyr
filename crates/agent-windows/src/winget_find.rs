//! Finds `winget.exe` and the VCLibs directory under the fixed WindowsApps parent: never PATH, never a setting.

use crate::types::ListFn;
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;


pub const WINDOWSAPPS_DIR: &str = r"C:\Program Files\WindowsApps";


pub const MAX_WINDOWSAPPS_ENTRIES: usize = 5_000;


pub const APP_INSTALLER_PREFIX: &str = "Microsoft.DesktopAppInstaller";


pub const VCLIBS_PREFIX: &str = "Microsoft.VCLibs.140.00.UWPDesktop";


pub const ARCH_SUFFIX: &str = "_x64__8wekyb3d8bbwe";


pub const WINGET_EXE: &str = "winget.exe";


pub const VERSION_PARTS: usize = 4;


pub const MAX_VERSION_PART_DIGITS: usize = 5;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub directory: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub winget: String,
    pub vclibs_dir: String,
}


#[derive(Debug, Error)]
pub enum FindError {
    #[error("the WindowsApps directory cannot be read")]
    Unreadable(#[source] io::Error),
    #[error("the WindowsApps directory holds more than {MAX_WINDOWSAPPS_ENTRIES} entries")]
    TooLarge,
    #[error("no matching App Installer or VCLibs directory")]
    NotFound,
}


pub fn finding_name(error: &FindError) -> &'static str {
    match error {
        FindError::Unreadable(_) => "windowsapps_unreadable",
        FindError::TooLarge => "windowsapps_too_large",
        FindError::NotFound => "winget_not_found",
    }
}


/// A reparse point (a junction or a symbolic link) is never a candidate.
#[cfg(windows)]
pub fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_ATTRIBUTE: u32 = 0x400;
    metadata.file_attributes() & REPARSE_ATTRIBUTE != 0
}


#[cfg(not(windows))]
pub fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}


pub fn entry_of(entry: &fs::DirEntry) -> io::Result<Entry> {
    let metadata = fs::symlink_metadata(entry.path())?;
    Ok(Entry {
        name: entry.file_name().to_string_lossy().into_owned(),
        directory: metadata.is_dir() && !is_reparse_point(&metadata),
    })
}


/// One `read_dir`, at most `MAX_WINDOWSAPPS_ENTRIES` entries read (one more is `TooLarge` upstream).
pub fn list_directory(path: &Path) -> io::Result<Vec<Entry>> {
    fs::read_dir(path)?
        .take(MAX_WINDOWSAPPS_ENTRIES + 1)
        .map(|found| found.and_then(|entry| entry_of(&entry)))
        .collect()
}


/// `a.b.c.d`: four plain decimal `u16` parts without a leading zero.
pub fn parse_version(text: &str) -> Option<[u16; VERSION_PARTS]> {
    let parts: Vec<u16> = text
        .split('.')
        .map(|part| {
            let plain = !part.is_empty()
                && part.len() <= MAX_VERSION_PART_DIGITS
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            plain.then(|| part.parse::<u16>().ok()).flatten()
        })
        .collect::<Option<Vec<u16>>>()?;
    <[u16; VERSION_PARTS]>::try_from(parts).ok()
}


pub fn version_of(entry: &Entry, prefix: &str) -> Option<[u16; VERSION_PARTS]> {
    let middle = entry.name.strip_prefix(prefix)?.strip_prefix('_')?.strip_suffix(ARCH_SUFFIX)?;
    entry.directory.then(|| parse_version(middle)).flatten()
}


/// The directory name of the highest version, compared numerically part by part.
pub fn highest<'a>(entries: &'a [Entry], prefix: &str) -> Option<&'a str> {
    entries
        .iter()
        .filter_map(|entry| version_of(entry, prefix).map(|version| (version, entry.name.as_str())))
        .max_by_key(|(version, _)| *version)
        .map(|(_, name)| name)
}


pub fn locate_in(parent: &str, entries: &[Entry]) -> Result<Located, FindError> {
    if entries.len() > MAX_WINDOWSAPPS_ENTRIES {
        Err(FindError::TooLarge)
    } else {
        let installer = highest(entries, APP_INSTALLER_PREFIX).ok_or(FindError::NotFound)?;
        let vclibs = highest(entries, VCLIBS_PREFIX).ok_or(FindError::NotFound)?;
        Ok(Located {
            winget: format!(r"{parent}\{installer}\{WINGET_EXE}"),
            vclibs_dir: format!(r"{parent}\{vclibs}"),
        })
    }
}


pub fn locate_with(parent: &str, list: ListFn) -> Result<Located, FindError> {
    let entries = list(Path::new(parent)).map_err(FindError::Unreadable)?;
    locate_in(parent, &entries)
}


/// The production lookup under the fixed parent.
pub fn locate_winget() -> Result<Located, FindError> {
    locate_with(WINDOWSAPPS_DIR, list_directory)
}
