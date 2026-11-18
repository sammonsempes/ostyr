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
    crate::scan::{errno_error, open_at, raw_entries},
    crate::types::OpenFn,
    core_config::trusted_dir::open_trusted_dir,
    rustix::fs::{fchmod, fstat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags},
    rustix::io::Errno,
    rustix::process::geteuid,
    std::fs::File,
    std::os::fd::{AsFd, OwnedFd},
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
    pub directory: OwnedFd,
    pub name: String,
    pub complete: bool,
}


#[cfg(target_os = "linux")]
pub fn report_failure(errno: Errno) {
    let kind = std::io::Error::from(errno).kind();
    log::warn!("could not remove part of the partial skeleton: {kind}");
}


/// The entry at `name` on the parent is removed only if it is the held directory (same device and inode); an impostor is left in place.
#[cfg(target_os = "linux")]
pub fn remove_directory_entry(parent: &OwnedFd, directory: &OwnedFd, name: &str) -> Result<(), Errno> {
    let same = fstat(directory)
        .and_then(|held| statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map(|found| (held.st_dev, held.st_ino) == (found.st_dev, found.st_ino)))?;
    if same {
        unlinkat(parent, name, AtFlags::REMOVEDIR)
    } else {
        log::warn!("the skeleton directory was replaced, the entry at its name is left in place");
        Ok(())
    }
}


/// The files through the held directory, then the directory through the held parent; a missing entry is fine, any other failure is returned.
#[cfg(target_os = "linux")]
pub fn remove_package(parent: &OwnedFd, directory: &OwnedFd, name: &str) -> Vec<Errno> {
    let staged: Vec<String> = FILES.iter().map(|file| format!("{file}{STAGED_SUFFIX}")).collect();
    FILES
        .iter()
        .map(|file| (*file).to_owned())
        .chain(staged)
        .map(|file| unlinkat(directory, file.as_str(), AtFlags::empty()))
        .chain(std::iter::once(name).map(|directory_name| remove_directory_entry(parent, directory, directory_name)))
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
            remove_package(&self.parent, &self.directory, &self.name)
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
pub const MAX_EMPTY_ENTRIES: usize = 2;


#[cfg(target_os = "linux")]
pub const PERMISSION_MASK: u32 = 0o777;


#[cfg(target_os = "linux")]
pub const SPECIAL_MASK: u32 = 0o7000;


#[cfg(target_os = "linux")]
pub const SETGID_BIT: u32 = 0o2000;


#[cfg(target_os = "linux")]
pub const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);


#[cfg(target_os = "linux")]
pub const DIRECTORY_FLAGS: OFlags = OFlags::DIRECTORY.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC).union(OFlags::RDONLY);


#[cfg(target_os = "linux")]
pub fn open_parent(path: &Path) -> Result<OwnedFd, ConnectorError> {
    Ok(open_trusted_dir(path, geteuid().as_raw())?)
}


/// `mkdirat` fails on any existing name, a symbolic link included; the new directory is then held, and every file is made relative to that handle.
#[cfg(target_os = "linux")]
pub fn create_package(parent: OwnedFd, name: String, label: &str) -> Result<Package, ConnectorError> {
    create_package_with(open_at, parent, name, label)
}


/// The held handle must be an empty directory owned by this user with mode 0700 and no special bit but the setgid its parent has.
#[cfg(target_os = "linux")]
pub fn check_held_directory(parent: &OwnedFd, directory: &OwnedFd, label: &str) -> Result<(), ConnectorError> {
    let inherited = fstat(parent).map_err(errno_error(label))?.st_mode & SETGID_BIT;
    fstat(directory)
        .map_err(errno_error(label))
        .and_then(|stat| {
            let shaped = [
                stat.st_mode & SPECIAL_MASK & !inherited == 0,
                FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
                stat.st_uid == geteuid().as_raw(),
                stat.st_mode & PERMISSION_MASK == DIRECTORY_MODE,
            ]
            .iter()
            .all(|check| *check);
            shaped.then_some(()).ok_or(ConnectorError::Invalid { field: "out-dir" })
        })
        .and_then(|()| raw_entries(directory, MAX_EMPTY_ENTRIES + 1).map_err(errno_error(label)))
        .and_then(|entries| {
            (entries.len() <= MAX_EMPTY_ENTRIES)
                .then_some(())
                .ok_or(ConnectorError::Invalid { field: "out-dir" })
        })
}


/// The held directory is made 0700 whatever the umask, then checked; a refusal removes the entry only if it is the directory just made; the opener is injected.
#[cfg(target_os = "linux")]
pub fn create_package_with(opener: OpenFn, parent: OwnedFd, name: String, label: &str) -> Result<Package, ConnectorError> {
    mkdirat(&parent, name.as_str(), Mode::from_raw_mode(DIRECTORY_MODE)).map_err(errno_error(label))?;
    let held = opener(parent.as_fd(), name.as_str(), DIRECTORY_FLAGS);
    held.as_ref()
        .err()
        .map(|_| unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR))
        .and_then(Result::err)
        .into_iter()
        .for_each(report_failure);
    let directory = held.map_err(errno_error(label))?;
    let verdict = fstat(&parent)
        .and_then(|stat| fchmod(&directory, Mode::from_raw_mode(DIRECTORY_MODE | stat.st_mode & SETGID_BIT)))
        .map_err(errno_error(label))
        .and_then(|()| check_held_directory(&parent, &directory, label));
    verdict
        .as_ref()
        .err()
        .map(|_| remove_directory_entry(&parent, &directory, name.as_str()))
        .and_then(Result::err)
        .into_iter()
        .for_each(report_failure);
    verdict?;
    Ok(Package {
        parent,
        directory,
        name,
        complete: false,
    })
}


/// Staged in the new directory under a name only this process creates (`O_EXCL`), then renamed within it; the writer is injected.
#[cfg(target_os = "linux")]
pub fn write_staged_with(writer: WriteFn, package: &Package, file_name: &str, text: &str) -> Result<(), ConnectorError> {
    let staged = format!("{file_name}{STAGED_SUFFIX}");
    let mut file =
        File::from(openat(&package.directory, staged.as_str(), CREATE_FLAGS, Mode::from_raw_mode(FILE_MODE)).map_err(errno_error(file_name))?);
    writer(&mut file, text.as_bytes()).map_err(io_at(file_name))?;
    renameat(&package.directory, staged.as_str(), &package.directory, file_name).map_err(errno_error(file_name))
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
