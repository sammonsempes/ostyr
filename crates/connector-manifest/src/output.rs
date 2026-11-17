use crate::error::ConnectorError;
use crate::model::{MANIFEST_NAME, OPERATIONS_NAME};
use crate::skeleton::Skeleton;
use crate::types::WriteFn;
use crate::verify::write_all_bytes;
use std::path::Path;
#[cfg(target_os = "linux")]
use {
    crate::model::{DIRECTORY_MODE, FILE_MODE},
    crate::package::io_at,
    crate::scan::errno_error,
    core_config::trusted_dir::open_trusted_dir,
    rustix::fs::{mkdirat, openat, renameat, unlinkat, AtFlags, Mode, OFlags},
    rustix::io::Errno,
    rustix::process::geteuid,
    std::fs::File,
    std::os::fd::OwnedFd,
    std::path::PathBuf,
};


pub const STAGED_SUFFIX: &str = ".tmp";


pub const FILES: [&str; 2] = [MANIFEST_NAME, OPERATIONS_NAME];


pub fn write_skeleton(directory: &Path, skeleton: &Skeleton) -> Result<(), ConnectorError> {
    write_skeleton_with(write_all_bytes, directory, skeleton)
}


#[cfg(not(target_os = "linux"))]
pub fn write_skeleton_with(_writer: WriteFn, _directory: &Path, _skeleton: &Skeleton) -> Result<(), ConnectorError> {
    Err(ConnectorError::Unsupported)
}


/// The new directory, held by its trusted parent: removed with what was written into it unless the package was completed.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Package {
    pub parent: OwnedFd,
    pub name: String,
    pub complete: bool,
}


#[cfg(target_os = "linux")]
pub fn report_failure(errno: Errno) {
    let kind = std::io::Error::from(errno).kind();
    log::warn!("could not remove part of the partial skeleton: {kind}");
}


/// The files written and the directory, relative to the held parent; a missing entry is fine, any other failure is returned.
#[cfg(target_os = "linux")]
pub fn remove_package(parent: &OwnedFd, name: &str) -> Vec<Errno> {
    let staged: Vec<String> = FILES.iter().map(|file| format!("{file}{STAGED_SUFFIX}")).collect();
    FILES
        .iter()
        .map(|file| format!("{name}/{file}"))
        .chain(staged.iter().map(|file| format!("{name}/{file}")))
        .map(|path| unlinkat(parent, path.as_str(), AtFlags::empty()))
        .chain(std::iter::once(name).map(|directory| unlinkat(parent, directory, AtFlags::REMOVEDIR)))
        .filter_map(Result::err)
        .filter(|errno| *errno != Errno::NOENT)
        .collect()
}


#[cfg(target_os = "linux")]
impl Drop for Package {
    fn drop(&mut self) {
        let failures = if self.complete {
            Vec::new()
        } else {
            remove_package(&self.parent, &self.name)
        };
        failures.into_iter().for_each(report_failure);
    }
}


/// The absolute parent and the final name of the target; a target with no name (`/`, `..`) is refused.
#[cfg(target_os = "linux")]
pub fn split_target(directory: &Path, label: &str) -> Result<(PathBuf, String), ConnectorError> {
    let absolute = std::path::absolute(directory).map_err(io_at(label))?;
    let name = absolute.file_name().and_then(|text| text.to_str()).map(str::to_owned);
    let parent = absolute.parent().map(Path::to_path_buf);
    parent.zip(name).ok_or(ConnectorError::Invalid { field: "out-dir" })
}


#[cfg(target_os = "linux")]
pub const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);


#[cfg(target_os = "linux")]
pub fn open_parent(path: &Path) -> Result<OwnedFd, ConnectorError> {
    Ok(open_trusted_dir(path, geteuid().as_raw())?)
}


/// `mkdirat` fails on any existing name, a symbolic link included, so there is no check-then-create window.
#[cfg(target_os = "linux")]
pub fn create_package(parent: OwnedFd, name: String, label: &str) -> Result<Package, ConnectorError> {
    mkdirat(&parent, name.as_str(), Mode::from_raw_mode(DIRECTORY_MODE)).map_err(errno_error(label))?;
    Ok(Package {
        parent,
        name,
        complete: false,
    })
}


/// Staged in the new directory under a name only this process creates (`O_EXCL`), then renamed within it; the writer is injected.
#[cfg(target_os = "linux")]
pub fn write_staged_with(writer: WriteFn, package: &Package, file_name: &str, text: &str) -> Result<(), ConnectorError> {
    let target = format!("{}/{file_name}", package.name);
    let staged = format!("{target}{STAGED_SUFFIX}");
    let mut file =
        File::from(openat(&package.parent, staged.as_str(), CREATE_FLAGS, Mode::from_raw_mode(FILE_MODE)).map_err(errno_error(file_name))?);
    writer(&mut file, text.as_bytes()).map_err(io_at(file_name))?;
    renameat(&package.parent, staged.as_str(), &package.parent, target.as_str()).map_err(errno_error(file_name))
}


#[cfg(target_os = "linux")]
pub fn write_skeleton_with(writer: WriteFn, directory: &Path, skeleton: &Skeleton) -> Result<(), ConnectorError> {
    let label = directory.display().to_string();
    let (parent_path, name) = split_target(directory, &label)?;
    let mut package = create_package(open_parent(&parent_path)?, name, &label)?;
    write_staged_with(writer, &package, MANIFEST_NAME, &skeleton.manifest)?;
    write_staged_with(writer, &package, OPERATIONS_NAME, &skeleton.operations)?;
    package.complete = true;
    Ok(())
}
