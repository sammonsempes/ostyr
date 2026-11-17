use crate::error::ScanError;
use crate::limits::Limits;
use crate::model::{Cluster, Findings, KubeconfigFault};
use crate::prowler::parse_prowler_ocsf;
use core_config::secret_file::{judge_secret, SecretFileError};
use core_config::trusted_dir::open_trusted_dir;
use net_topology::model::RunFailure;
use net_topology::runner::run_command_with_env;
use rustix::fs::{fstat, openat2, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;
use tracing::{debug, info, warn};


pub const BENEATH_FLAGS: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS).union(ResolveFlags::NO_XDEV);


pub const KUBECONFIG_LABEL: &str = "kubeconfig";


pub const OUTPUT_STEM: &str = "posture";


pub const OUTPUT_FILE: &str = "posture.ocsf.json";


pub const WORKDIR_MODE: u32 = 0o700;


pub const WORKDIR_PREFIX: &str = "posture-";


pub const STDOUT_CAP_BYTES: u64 = 4_194_304;


pub const SEARCH_PATH: &str = "/usr/local/bin:/usr/bin:/bin";


pub const FIXED_ARGUMENTS: [&str; 1] = ["kubernetes"];


/// The handle check that refused the file, without its path (open failures never reach it: `fault_of_errno`).
pub fn kubeconfig_fault(error: &SecretFileError) -> KubeconfigFault {
    match error {
        SecretFileError::Mode { .. } => KubeconfigFault::Mode,
        SecretFileError::Owner { .. } => KubeconfigFault::Owner,
        _ => KubeconfigFault::NotRegular,
    }
}


/// The kubeconfig opened beneath the tenant directory, itself opened beneath the secrets directory, never crossing a link or a mount.
pub fn open_kubeconfig(cluster: &Cluster) -> Result<File, KubeconfigFault> {
    let (secrets, tenant) = split_tenant_directory(&cluster.tenant_directory).ok_or(KubeconfigFault::Unreadable)?;
    let secrets_handle = open_directory_nofollow(secrets)?;
    let tenant_handle = openat2(
        &secrets_handle,
        tenant,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        BENEATH_FLAGS,
    )
    .map_err(fault_of_errno)?;
    let opened = openat2(
        &tenant_handle,
        &cluster.kubeconfig_file,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        BENEATH_FLAGS,
    )
    .map_err(fault_of_errno)?;
    let stat = fstat(&opened).map_err(|_| KubeconfigFault::Unreadable)?;
    let is_file = stat.st_mode & libc::S_IFMT == libc::S_IFREG;
    judge_secret(KUBECONFIG_LABEL, is_file, stat.st_mode, stat.st_uid, rustix::process::geteuid().as_raw())
        .map_err(|error| kubeconfig_fault(&error))?;
    if stat.st_nlink == 1 {
        Ok(File::from(opened))
    } else {
        Err(KubeconfigFault::Linked)
    }
}


/// The secrets directory and the tenant name of a tenant directory.
pub fn split_tenant_directory(directory: &Path) -> Option<(&Path, &std::ffi::OsStr)> {
    directory.parent().zip(directory.file_name())
}


/// The secrets directory, opened without following a link in its last component.
pub fn open_directory_nofollow(directory: &Path) -> Result<rustix::fd::OwnedFd, KubeconfigFault> {
    rustix::fs::open(
        directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fault_of_errno)
}


/// A link, an escape or a mount crossing (`EXDEV`) is `Symlink`; a kernel without `openat2` (`ENOSYS`) is `Unreadable`, never a path open.
pub fn fault_of_errno(errno: Errno) -> KubeconfigFault {
    if errno == Errno::LOOP || errno == Errno::XDEV {
        KubeconfigFault::Symlink
    } else {
        KubeconfigFault::Unreadable
    }
}


/// A run failure as a fixed error: only the exit code survives.
pub fn scan_error_of(failure: RunFailure) -> ScanError {
    match failure {
        RunFailure::TimedOut => ScanError::Timeout,
        RunFailure::Failed { code, .. } => ScanError::Failed { code },
        RunFailure::Spawn => ScanError::Spawn,
        RunFailure::TooLarge | RunFailure::Io | RunFailure::Refused | RunFailure::Unwaitable => ScanError::Failed { code: None },
    }
}


/// The output file, opened once with `O_NOFOLLOW`: it must exist, be a regular file with one link and belong to the running user.
pub fn open_output(directory: &Path) -> Result<File, ScanError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(OUTPUT_FILE))
        .map_err(|error| {
            let kind = error.kind();
            debug!(?kind, "the prowler output file cannot be opened");
            if kind == ErrorKind::NotFound {
                ScanError::NoOutput
            } else {
                ScanError::BadOutputFile
            }
        })?;
    let owned_file = file
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == rustix::process::geteuid().as_raw());
    if owned_file {
        Ok(file)
    } else {
        Err(ScanError::BadOutputFile)
    }
}


/// The kubeconfig as the child sees the checked handle: the parent's descriptor, so a swap of the path after the check is never read.
pub fn kubeconfig_argument(handle: &File) -> String {
    format!("/proc/{}/fd/{}", std::process::id(), handle.as_raw_fd())
}


/// A failed removal of the work directory is logged with the directory name, never silent.
pub fn log_removal(name: &str, result: io::Result<()>) {
    if let Err(error) = result {
        let kind = error.kind();
        warn!(name, ?kind, "the work directory could not be removed");
    }
}


/// Removes the work directory and logs a failure.
pub fn remove_directory(directory: TempDir) {
    let name = directory.path().to_string_lossy().into_owned();
    log_removal(&name, directory.close());
}


/// Runs Prowler read-only on one declared cluster and parses its OCSF output for `tenant`, with the declared context as the account.
pub fn cluster_scan(
    program: &Path,
    tenant: &str,
    cluster: &Cluster,
    workdir: &Path,
    limits: &Limits,
    deadline: Duration,
) -> Result<Findings, ScanError> {
    open_trusted_dir(workdir, rustix::process::geteuid().as_raw()).map_err(ScanError::UntrustedWorkdir)?;
    let kubeconfig = open_kubeconfig(cluster).map_err(|fault| ScanError::Kubeconfig { fault })?;
    let directory = tempfile::Builder::new()
        .prefix(WORKDIR_PREFIX)
        .permissions(Permissions::from_mode(WORKDIR_MODE))
        .tempdir_in(workdir)
        .map_err(ScanError::Workdir)?;
    let result = scan_directory(program, tenant, cluster, &kubeconfig, directory.path(), limits, deadline);
    remove_directory(directory);
    result
}


/// The run and the parse inside the work directory.
pub fn scan_directory(
    program: &Path,
    tenant: &str,
    cluster: &Cluster,
    kubeconfig: &File,
    directory: &Path,
    limits: &Limits,
    deadline: Duration,
) -> Result<Findings, ScanError> {
    let config_path = kubeconfig_argument(kubeconfig);
    let output_directory = directory.to_string_lossy().into_owned();
    let arguments = FIXED_ARGUMENTS
        .iter()
        .copied()
        .chain([
            "--kubeconfig-file",
            &config_path,
            "--context",
            &cluster.context,
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            &output_directory,
            "--output-filename",
            OUTPUT_STEM,
            "--ignore-exit-code-3",
        ])
        .collect::<Vec<_>>();
    let environment = [("HOME", output_directory.as_str()), ("PATH", SEARCH_PATH)];
    run_command_with_env(program, &arguments, &environment, STDOUT_CAP_BYTES, deadline).map_err(scan_error_of)?;
    let output = open_output(directory)?;
    let findings = parse_prowler_ocsf(output, tenant, &cluster.context, limits)?;
    let kept = findings.items.len();
    info!(kept, "cluster scan parsed");
    Ok(findings)
}
