use agent_channel::error::{AppError, SpoolDirReason};
use agent_channel::spool::effective_uid;
use std::fs::File;
use std::path::{Path, PathBuf};


const PROC_FD_DIRECTORY: &str = "/proc/self/fd";


/// The judged directory of the agent spool and the path of the spool file through that handle; the handle must outlive every append.
#[derive(Debug)]
pub struct AgentSpool {
    pub directory: File,
    pub spool_path: PathBuf,
}


/// The collector must run as the user that owns the agent spool directory: the agent refuses a directory of another user.
pub fn user_fault(owner: u32, process_uid: u32) -> Option<SpoolDirReason> {
    (owner != process_uid).then_some(SpoolDirReason::WrongOwner)
}


/// The path of `name` inside the directory held by `descriptor`: it follows the judged handle, never the directory's current name.
pub fn through_handle(descriptor: i32, name: &std::ffi::OsStr) -> PathBuf {
    Path::new(PROC_FD_DIRECTORY).join(descriptor.to_string()).join(name)
}


/// Judges the directory that holds the agent spool file as the agent does, then requires its owner to be `process_uid`.
#[cfg(unix)]
pub fn open_agent_spool_as(path: &Path, process_uid: u32) -> Result<AgentSpool, AppError> {
    use agent_channel::spool_dirs::open_parent;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let (directory, _) = open_parent(path)?;
    let owner = directory.metadata()?.uid();
    let name = path.file_name().ok_or_else(|| AppError::SpoolDir {
        path: path.to_path_buf(),
        reason: SpoolDirReason::NotDirectory,
    })?;
    match user_fault(owner, process_uid) {
        Some(reason) => Err(AppError::SpoolDir {
            path: path.to_path_buf(),
            reason,
        }),
        None => Ok(AgentSpool {
            spool_path: through_handle(directory.as_raw_fd(), name),
            directory,
        }),
    }
}


/// The collector is Linux-only: any other host refuses to forward.
#[cfg(not(unix))]
pub fn open_agent_spool_as(path: &Path, _process_uid: u32) -> Result<AgentSpool, AppError> {
    Err(AppError::SpoolDir {
        path: path.to_path_buf(),
        reason: SpoolDirReason::NotDirectory,
    })
}


/// `open_agent_spool_as` for the effective user of the process; call it once before any forward.
pub fn open_agent_spool(path: &Path) -> Result<AgentSpool, AppError> {
    open_agent_spool_as(path, effective_uid())
}
