#![cfg(target_os = "linux")]
use connector_manifest::error::ConnectorError;
use connector_manifest::output::{create_package, create_package_with, open_parent, write_staged_with};
use connector_manifest::verify::write_all_bytes;
use rustix::fs::{fstat, Mode, OFlags};
use rustix::io::Errno;
use rustix::process::umask;
use std::error::Error;
use std::fs;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;


const STRIPPING_UMASK: u32 = 0o277;


const CLOSED_UMASK: u32 = 0o777;


const PERMISSION_MASK: u32 = 0o777;


const PRIVATE_MODE: u32 = 0o700;


const FILE_MODE: u32 = 0o600;


struct UmaskGuard {
    previous: Mode,
}


impl Drop for UmaskGuard {
    fn drop(&mut self) {
        umask(self.previous);
    }
}


fn strip_owner_bits() -> UmaskGuard {
    UmaskGuard {
        previous: umask(Mode::from_raw_mode(STRIPPING_UMASK)),
    }
}


fn path_opener(parent: BorrowedFd<'_>, name: &str, _flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(parent, name, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
}


fn procfs_opener(_parent: BorrowedFd<'_>, _name: &str, _flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::open("/proc/self/status", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
}


fn assert_private_files(directory: &Path) -> Result<(), Box<dyn Error>> {
    ["connector.yaml", "operations.yaml"]
        .iter()
        .try_for_each(|file| -> Result<(), Box<dyn Error>> {
            assert_eq!(fs::metadata(directory.join(file))?.permissions().mode() & PERMISSION_MASK, FILE_MODE);
            Ok(())
        })
}


fn write_both(package: &connector_manifest::output::Package) -> Result<(), Box<dyn Error>> {
    write_staged_with(write_all_bytes, package, "connector.yaml", "text")?;
    write_staged_with(write_all_bytes, package, "operations.yaml", "text")?;
    Ok(())
}


#[test]
fn umask_cases_run_in_sequence_in_the_only_test_of_this_binary() -> Result<(), Box<dyn Error>> {
    let parent = TempDir::new()?;
    let unprivate = create_package_with(procfs_opener, open_parent(parent.path())?, "package".to_owned(), "package");
    assert!(matches!(unprivate, Err(ConnectorError::Io { .. })));
    assert_eq!(fs::read_dir(parent.path())?.count(), 0);
    let guard = strip_owner_bits();
    let refused = create_package_with(path_opener, open_parent(parent.path())?, "package".to_owned(), "package");
    assert!(matches!(refused, Err(ConnectorError::Io { .. })));
    assert_eq!(fs::read_dir(parent.path())?.count(), 0);
    let package = create_package(open_parent(parent.path())?, "package".to_owned(), "package")?;
    assert_eq!(
        fs::metadata(parent.path().join("package"))?.permissions().mode() & PERMISSION_MASK,
        PRIVATE_MODE
    );
    assert_eq!(fstat(&package.directory)?.st_mode & PERMISSION_MASK, PRIVATE_MODE);
    write_both(&package)?;
    assert_private_files(&parent.path().join("package"))?;
    drop(guard);
    let closed = UmaskGuard {
        previous: umask(Mode::from_raw_mode(CLOSED_UMASK)),
    };
    let closed_package = create_package(open_parent(parent.path())?, "closed".to_owned(), "closed")?;
    assert_eq!(fstat(&closed_package.directory)?.st_mode & PERMISSION_MASK, PRIVATE_MODE);
    write_both(&closed_package)?;
    assert_private_files(&parent.path().join("closed"))?;
    drop(closed);
    Ok(())
}
