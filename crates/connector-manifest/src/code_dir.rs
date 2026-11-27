use crate::elf::check_static_elf;
use crate::error::ConnectorError;
use crate::model::{Runtime, Verified};
use crate::package::{digest_bytes, io_at};
use crate::scan::{errno_error, open_entry, precheck_entry};
use crate::types::NamerFn;
use core_config::trusted_dir::open_trusted_dir;
use rustix::fs::{fchmod, mkdirat, openat, unlinkat, AtFlags, Mode, OFlags, RawMode, CWD};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};


pub const CODE_DIRECTORY_MODE: RawMode = 0o755;


pub const ENTRY_MODE: RawMode = 0o555;


pub const FILE_MODE: RawMode = 0o444;


pub const CREATE_MODE: RawMode = 0o600;


pub const GATE_NAME: &str = ".gate.sh";


pub const GATE_SCRIPT: &str = "read -r gate || exit 1\nexec \"$@\"\n";


/// A fresh directory under the trusted runner root holding the private copy of one run; removed through its handle on drop.
#[derive(Debug)]
pub struct CodeDir {
    pub path: PathBuf,
    pub name: String,
    pub root: OwnedFd,
    pub handle: OwnedFd,
    pub files: Vec<String>,
}


/// `mkdirat` relative to the checked trusted root, then opened once; `fchmod` makes the mode independent of the umask.
pub fn create_code_dir(trusted_root: &Path, trusted_uid: u32, namer: NamerFn) -> Result<CodeDir, ConnectorError> {
    let root = open_trusted_dir(trusted_root, trusted_uid)?;
    let name = namer().map_err(io_at("code directory name"))?;
    let label = format!("{}/{name}", trusted_root.display());
    mkdirat(root.as_fd(), name.as_str(), Mode::from_bits_truncate(CODE_DIRECTORY_MODE)).map_err(errno_error(&label))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let handle = openat(root.as_fd(), name.as_str(), flags, Mode::empty()).map_err(errno_error(&label));
    let guard = handle.map(|opened| CodeDir {
        path: trusted_root.join(&name),
        name: name.clone(),
        root,
        handle: opened,
        files: Vec::new(),
    });
    guard.and_then(|code| {
        fchmod(code.handle.as_fd(), Mode::from_bits_truncate(CODE_DIRECTORY_MODE)).map_err(errno_error(&label))?;
        Ok(code)
    })
}


/// Created `O_EXCL | O_NOFOLLOW` relative to the held directory, written, then `fchmod`ed read-only.
pub fn write_code_file(code: &mut CodeDir, name: &str, bytes: &[u8], mode: RawMode) -> Result<(), ConnectorError> {
    code.files.push(name.to_owned());
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = openat(code.handle.as_fd(), name, flags, Mode::from_bits_truncate(CREATE_MODE)).map_err(errno_error(name))?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes).map_err(io_at(name))?;
    fchmod(file.as_fd(), Mode::from_bits_truncate(mode)).map_err(errno_error(name))
}


/// The bytes read through a fresh judged handle must hash to the signed digest before they are written; a native entry is judged on those same bytes.
pub fn copy_file(code: &mut CodeDir, package: &OwnedFd, verified: &Verified, name: &str) -> Result<(), ConnectorError> {
    let expected = verified.files.get(name).ok_or(ConnectorError::MissingEntry)?;
    precheck_entry(package, name)?;
    let mut handle = open_entry(package, name)?;
    let mut bytes = Vec::new();
    Read::take(&mut handle, expected.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_at(name))?;
    (digest_bytes(&bytes) == *expected)
        .then_some(())
        .ok_or_else(|| ConnectorError::FileChanged { path: name.to_owned() })?;
    let is_entry = name == verified.manifest.entry;
    if is_entry && verified.manifest.runtime == Runtime::Native {
        check_static_elf(&bytes)?;
    }
    write_code_file(code, name, &bytes, if is_entry { ENTRY_MODE } else { FILE_MODE })
}


/// Every signed file is copied into a fresh code directory, with the gate script beside them.
pub fn copy_package(verified: &Verified, package: &Path, trusted_root: &Path, trusted_uid: u32, namer: NamerFn) -> Result<CodeDir, ConnectorError> {
    verified
        .files
        .contains_key(&verified.manifest.entry)
        .then_some(())
        .ok_or(ConnectorError::MissingEntry)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let source = openat(CWD, package, flags, Mode::empty()).map_err(errno_error(&package.display().to_string()))?;
    let mut code = create_code_dir(trusted_root, trusted_uid, namer)?;
    verified.files.keys().try_for_each(|name| copy_file(&mut code, &source, verified, name))?;
    write_code_file(&mut code, GATE_NAME, GATE_SCRIPT.as_bytes(), FILE_MODE)?;
    Ok(code)
}


impl Drop for CodeDir {
    fn drop(&mut self) {
        let unlinked = self
            .files
            .iter()
            .filter(|name| unlinkat(self.handle.as_fd(), name.as_str(), AtFlags::empty()).is_err())
            .count();
        let removed = unlinkat(self.root.as_fd(), self.name.as_str(), AtFlags::REMOVEDIR).is_err();
        let failures = unlinked + usize::from(removed);
        if failures > 0 {
            log::warn!("{failures} entries of a code directory were not removed");
        }
    }
}
