use crate::devices::{claim_devices, parse_device_file, MAX_DEVICES};
use crate::error::DeviceError;
use crate::model::{Claims, LoadResult};
use core_config::error::ConfigError;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};


pub const MAX_FILE_ENTRIES: usize = 256;


pub const EXTENSIONS: [&str; 2] = ["yaml", "yml"];


/// Maps an I/O failure on `file` to the error, once, so every call site shares one closure.
pub fn from_io(file: &str) -> impl FnOnce(io::Error) -> DeviceError + '_ {
    move |source| {
        DeviceError::Config(ConfigError::Io {
            file: file.to_owned(),
            source,
        })
    }
}


/// Opens a file for reading without following a symlink and without blocking on a pipe.
#[cfg(unix)]
pub fn open_regular(path: &Path) -> io::Result<File> {
    use rustix::fs::OFlags;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
        .open(path)
}


#[cfg(not(unix))]
pub fn open_regular(path: &Path) -> io::Result<File> {
    fs::symlink_metadata(path).and_then(|found| {
        if found.is_symlink() {
            Err(io::Error::other("symbolic link"))
        } else {
            File::open(path)
        }
    })
}


/// The `.yaml` and `.yml` entries of `directory`, sorted; more than `MAX_FILE_ENTRIES` entries of any kind are refused before any is read.
pub fn yaml_files(directory: &Path) -> Result<Vec<PathBuf>, DeviceError> {
    let label = directory.display().to_string();
    let entries = fs::read_dir(directory)
        .map_err(from_io(&label))?
        .take(MAX_FILE_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_io(&label))?;
    (entries.len() <= MAX_FILE_ENTRIES)
        .then_some(())
        .ok_or(DeviceError::TooManyEntries { directory: label })?;
    let mut paths: Vec<PathBuf> = entries
        .iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| EXTENSIONS.contains(&extension))
        })
        .collect();
    paths.sort();
    Ok(paths)
}


/// One device file through the handle that was checked: a symlink, a pipe or a directory is refused.
pub fn load_file(path: &Path) -> Result<LoadResult, DeviceError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path).map_err(from_io(&file))?;
    handle
        .metadata()
        .is_ok_and(|found| found.is_file())
        .then_some(())
        .ok_or_else(|| DeviceError::NotRegular { file: file.clone() })?;
    parse_device_file(&mut handle, &file)
}


/// Every device file of the directory; a name or an address may not repeat for a tenant across files.
pub fn load_devices(directory: &Path) -> Result<LoadResult, DeviceError> {
    let label = directory.display().to_string();
    let (total, _claims) = yaml_files(directory)?
        .iter()
        .try_fold((LoadResult::default(), Claims::default()), |(mut total, mut claims), path| {
            let loaded = load_file(path)?;
            claim_devices(&mut claims, &loaded.devices, &path.display().to_string())?;
            total.devices.extend(loaded.devices);
            total.warnings.extend(loaded.warnings);
            (total.devices.len() <= MAX_DEVICES)
                .then_some((total, claims))
                .ok_or_else(|| DeviceError::TooManyDevicesInAll { directory: label.clone() })
        })?;
    Ok(total)
}
