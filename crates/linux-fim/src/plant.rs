use crate::cli::role_of;
use crate::content::{token_content, RANDOM_BYTES};
use crate::error::{CliError, PlantError, PlantRefusal};
use crate::model::{Honeytoken, Limits, PlantReport, PlantedIdentity, Role};
use crate::policy::kernel_device;
use crate::types::{ClaimFn, ListFn, RandomFn, StepFn};
use core_config::trusted_dir::{open_trusted_dir, GROUP_OTHER_WRITE};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{
    fchmod, fchown, fstat, makedev, mkdirat, openat, renameat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags, RawMode, Stat, CWD,
};
use rustix::io::Errno;
use rustix::process::{geteuid, Uid};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};


pub const DIRECTORY_MODE: RawMode = 0o700;


pub const FILE_MODE: RawMode = 0o600;


pub const PERMISSION_MASK: RawMode = 0o7777;


pub const MINOR_BITS: u32 = 20;


pub const MINOR_MASK: u32 = 0xf_ffff;


pub const TEMPORARY_RANDOM_BYTES: usize = 8;


pub const DIRECTORY_PROBE: usize = 3;


pub const RANDOM_SOURCE: &str = "/dev/urandom";


pub const TETRA_BINARY: &str = "/usr/local/bin/tetra";


pub const POLICY_PREFIX: &str = "ostyr-fim";


pub const MAX_LIST_BYTES: usize = 1 << 20;


pub const READ_CHUNK_BYTES: usize = 4096;


pub const MAX_LIST_READS: usize = MAX_LIST_BYTES / READ_CHUNK_BYTES + 1;


pub const LIST_DEADLINE: Duration = Duration::from_secs(30);


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);


/// The root the walk starts from (`/` in production, a temporary tree in a test) and the system calls a test replaces.
#[derive(Debug, Clone)]
pub struct PlantOps {
    pub root: PathBuf,
    pub fill_random: RandomFn,
    pub list_policies: ListFn,
    pub claim: ClaimFn,
    pub after_open: StepFn,
    pub after_make: StepFn,
    pub after_create: StepFn,
}


/// The walk so far: the held directory, its path and the identity of every directory held above it.
#[derive(Debug)]
pub struct Walk {
    pub parent: OwnedFd,
    pub path: String,
    pub identities: Vec<PlantedIdentity>,
}


/// What a file at a token path must look like to be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub regular: bool,
    pub single_link: bool,
    pub uid: u32,
    pub mode: u32,
    pub has_content: bool,
}


impl From<Errno> for PlantRefusal {
    fn from(errno: Errno) -> Self {
        Self::Io(std::io::Error::from(errno))
    }
}


impl From<Errno> for PlantError {
    fn from(errno: Errno) -> Self {
        Self::Io(std::io::Error::from(errno))
    }
}


/// The real system calls, planting under `/`.
pub fn os_ops() -> PlantOps {
    PlantOps {
        root: PathBuf::from("/"),
        fill_random: os_random,
        list_policies: os_list_policies,
        claim: os_claim,
        after_open: no_step,
        after_make: no_step,
        after_create: no_step,
    }
}


/// Reads the bytes from the OS random source.
pub fn os_random(buffer: &mut [u8]) -> std::io::Result<()> {
    File::open(RANDOM_SOURCE).and_then(|mut source| source.read_exact(buffer))
}


/// Lists the policies with the real `tetra`, within `LIST_DEADLINE`.
pub fn os_list_policies() -> std::io::Result<String> {
    list_from(TETRA_BINARY, LIST_DEADLINE)
}


/// Runs `<binary> tracingpolicy list` within `deadline`; a missing binary means no policy is loaded, any other failure is an error.
pub fn list_from(binary: &str, deadline: Duration) -> std::io::Result<String> {
    match Command::new(binary)
        .args(["tracingpolicy", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
        Ok(child) => read_listing(child, deadline),
    }
}


/// The child's output, kept only when it succeeded within the deadline and `MAX_LIST_BYTES`; a child that overruns is killed and reaped.
pub fn read_listing(mut child: Child, deadline: Duration) -> std::io::Result<String> {
    let read = child
        .stdout
        .take()
        .ok_or(std::io::Error::other("no output pipe"))
        .and_then(|mut out| read_until(&mut out, Instant::now() + deadline));
    let status = if read.is_ok() {
        child.wait()
    } else {
        child.kill().and_then(|()| child.wait())
    };
    let bytes = read?;
    status.and_then(|done| {
        done.success()
            .then(|| String::from_utf8_lossy(&bytes).into_owned())
            .ok_or_else(|| std::io::Error::other("tetra exited with an error"))
    })
}


/// Reads to end of file, each read waiting at most until `until`; a listing longer than `MAX_LIST_BYTES` is an error.
pub fn read_until(out: &mut ChildStdout, until: Instant) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [u8::MIN; READ_CHUNK_BYTES];
    let mut done = false;
    let mut reads = 0;
    while !done && reads < MAX_LIST_READS {
        wait_readable(out, until)?;
        let count = out.read(&mut chunk)?;
        bytes.extend(chunk.iter().take(count));
        done = count == 0;
        reads += 1;
    }
    done.then_some(bytes).ok_or(std::io::Error::other("listing too long"))
}


/// Waits until the pipe is readable or `until` passes (`TimedOut`).
pub fn wait_readable(out: &ChildStdout, until: Instant) -> std::io::Result<()> {
    let remaining = until.saturating_duration_since(Instant::now());
    let timeout = Timespec {
        tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(remaining.subsec_nanos()),
    };
    let mut fds = [PollFd::new(out, PollFlags::IN)];
    let ready = poll(&mut fds, Some(&timeout)).map_err(std::io::Error::from)?;
    (ready > 0).then_some(()).ok_or(std::io::Error::from(std::io::ErrorKind::TimedOut))
}


/// The number of listed policies whose name starts with `POLICY_PREFIX`.
pub fn loaded_count(listing: &str) -> usize {
    listing.split_whitespace().filter(|word| word.starts_with(POLICY_PREFIX)).count()
}


/// Refuses to plant while any Ostyr FIM policy is loaded: the planter's own writes would raise honeytoken alerts.
pub fn check_unloaded(ops: &PlantOps) -> Result<(), PlantError> {
    (ops.list_policies)()
        .map_err(PlantError::PolicyList)
        .and_then(|listing| match loaded_count(&listing) {
            0 => Ok(()),
            count => Err(PlantError::PoliciesLoaded { count }),
        })
}


/// `fchown` to the user, then `fchmod`, on the held handle.
pub fn os_claim(handle: &OwnedFd, uid: u32, mode: RawMode) -> Result<(), Errno> {
    fchown(handle, Some(Uid::from_raw(uid)), None).and_then(|()| fchmod(handle, Mode::from_raw_mode(mode)))
}


pub fn no_step(_parent: &OwnedFd, _name: &str) {}


/// The first check that failed, if any.
pub fn first_failure(checks: &[(bool, &'static str)]) -> Option<&'static str> {
    checks.iter().find(|(passed, _)| !passed).map(|(_, reason)| *reason)
}


/// A directory above a token is owned by root or the token owner and is not writable by group or others (no sticky exception).
pub fn directory_verdict(uid: u32, mode: u32, owner_uid: u32) -> Result<(), PlantRefusal> {
    let failure = first_failure(&[
        ([0, owner_uid].contains(&uid), "not owned by root or the token owner"),
        (mode & GROUP_OTHER_WRITE == 0, "writable by group or others"),
    ]);
    failure.map_or(Ok(()), |reason| Err(PlantRefusal::Directory(reason)))
}


/// A file kept at a token path is a regular, non-empty, single-link file of the token owner with mode 0600.
pub fn file_verdict(facts: &FileFacts, owner_uid: u32) -> Result<(), PlantRefusal> {
    let failure = first_failure(&[
        (facts.regular, "not a regular file"),
        (facts.single_link, "more than one link"),
        (facts.uid == owner_uid, "not owned by the token owner"),
        (facts.mode & PERMISSION_MASK == FILE_MODE, "mode is not 0600"),
        (facts.has_content, "empty"),
    ]);
    failure.map_or(Ok(()), |reason| Err(PlantRefusal::File(reason)))
}


pub fn facts_of(stat: &Stat) -> FileFacts {
    FileFacts {
        regular: FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        single_link: stat.st_nlink == 1,
        uid: stat.st_uid,
        mode: stat.st_mode,
        has_content: stat.st_size > 0,
    }
}


/// The handle is judged on its own `fstat`.
pub fn judge_directory(handle: &OwnedFd, owner_uid: u32) -> Result<Stat, PlantRefusal> {
    fstat(handle)
        .map_err(PlantRefusal::from)
        .and_then(|stat| directory_verdict(stat.st_uid, stat.st_mode, owner_uid).map(|()| stat))
}


/// The identity of a held inode: `stat` device and inode, the device converted to the kernel number.
pub fn identity_of(path: &str, stat: &Stat) -> PlantedIdentity {
    PlantedIdentity {
        path: path.to_string(),
        device: kernel_device(stat.st_dev),
        inode: stat.st_ino,
    }
}


/// The `st_dev` that `kernel_device` turns into this kernel device number.
pub fn stat_device(device: u32) -> u64 {
    makedev(device >> MINOR_BITS, device & MINOR_MASK)
}


/// Opens the name below the held parent as a directory, making it (0700, given to the owner) only when it does not exist.
pub fn open_or_make(ops: &PlantOps, owner_uid: u32, parent: &OwnedFd, name: &str) -> Result<OwnedFd, PlantRefusal> {
    match openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Err(Errno::NOENT) => make_directory(ops, owner_uid, parent, name),
        other => other.map_err(PlantRefusal::from),
    }
}


pub fn make_directory(ops: &PlantOps, owner_uid: u32, parent: &OwnedFd, name: &str) -> Result<OwnedFd, PlantRefusal> {
    mkdirat(parent, name, Mode::from_raw_mode(DIRECTORY_MODE))
        .and_then(|()| {
            (ops.after_make)(parent, name);
            openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
        })
        .map_err(PlantRefusal::from)
        .and_then(|child| {
            judge_made(&child).and_then(|()| (ops.claim)(&child, owner_uid, DIRECTORY_MODE).map_err(PlantRefusal::from).map(|()| child))
        })
}


/// A directory just made is judged on the handle opened by name: owned by the effective user and empty, or a swapped-in one is refused.
pub fn made_verdict(uid: u32, effective_uid: u32, empty: bool) -> Result<(), PlantRefusal> {
    let failure = first_failure(&[
        (uid == effective_uid, "made directory is not owned by the planter"),
        (empty, "made directory is not empty"),
    ]);
    failure.map_or(Ok(()), |reason| Err(PlantRefusal::Directory(reason)))
}


pub fn judge_made(handle: &OwnedFd) -> Result<(), PlantRefusal> {
    let entries: Result<Vec<bool>, Errno> = Dir::read_from(handle).and_then(|dir| {
        dir.take(DIRECTORY_PROBE)
            .map(|entry| entry.map(|found| !matches!(found.file_name().to_bytes(), b"." | b"..")))
            .collect()
    });
    entries.map_err(PlantRefusal::from).and_then(|names| {
        fstat(handle)
            .map_err(PlantRefusal::from)
            .and_then(|stat| made_verdict(stat.st_uid, geteuid().as_raw(), !names.contains(&true)))
    })
}


/// One step down: the held parent is judged, the child is opened through it and its identity is read from the handle just opened.
pub fn descend(ops: &PlantOps, owner_uid: u32, walk: Walk, name: &str) -> Result<Walk, PlantRefusal> {
    let Walk { parent, path, identities } = walk;
    judge_directory(&parent, owner_uid)
        .and_then(|_| open_or_make(ops, owner_uid, &parent, name))
        .and_then(|child| {
            (ops.after_open)(&parent, name);
            let child_path = format!("{path}/{name}");
            fstat(&child).map_err(PlantRefusal::from).map(|stat| Walk {
                identities: identities.into_iter().chain(std::iter::once(identity_of(&child_path, &stat))).collect(),
                parent: child,
                path: child_path,
            })
        })
}


/// The directories of a token path held one after the other from the root.
pub fn walk_directories(ops: &PlantOps, owner_uid: u32, directories: &[&str]) -> Result<Walk, PlantRefusal> {
    openat(CWD, ops.root.as_path(), DIRECTORY_FLAGS, Mode::empty())
        .map_err(PlantRefusal::from)
        .and_then(|root| {
            let start = Walk {
                parent: root,
                path: String::new(),
                identities: Vec::new(),
            };
            directories.iter().try_fold(start, |walk, name| descend(ops, owner_uid, walk, name))
        })
}


/// A new token: created `O_EXCL` without following a link, given to the owner, written and synced, then read back on the same handle.
pub fn fresh_token(ops: &PlantOps, owner_uid: u32, parent: &OwnedFd, leaf: &str, handle: OwnedFd, content: &str) -> Result<Stat, PlantRefusal> {
    (ops.after_create)(parent, leaf);
    (ops.claim)(&handle, owner_uid, FILE_MODE)
        .map_err(PlantRefusal::from)
        .and_then(|()| write_synced(&handle, content))
        .or_else(|refusal| remove_partial(parent, leaf, &handle).map_err(PlantRefusal::from).and(Err(refusal)))
        .and_then(|()| fstat(&handle).map_err(PlantRefusal::from))
}


pub fn write_synced(handle: &OwnedFd, content: &str) -> Result<(), PlantRefusal> {
    write_and_sync(handle, content).map_err(PlantRefusal::Io)
}


pub fn write_and_sync(handle: &OwnedFd, content: &str) -> std::io::Result<()> {
    handle
        .try_clone()
        .map(File::from)
        .and_then(|mut file| file.write_all(content.as_bytes()).and_then(|()| file.sync_all()))
}


/// Unlinks the name below the held parent only when it still is the inode of the handle.
pub fn remove_partial(parent: &OwnedFd, leaf: &str, handle: &OwnedFd) -> Result<(), Errno> {
    fstat(handle)
        .and_then(|held| statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map(|named| (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)))
        .and_then(|same| if same { unlinkat(parent, leaf, AtFlags::empty()) } else { Ok(()) })
}


/// A token already there is kept when `statat` without following says it is exactly what a plant makes; it is never opened (an open fires the honeytoken hook).
pub fn existing_token(parent: &OwnedFd, leaf: &str, owner_uid: u32) -> Result<Stat, PlantRefusal> {
    statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(PlantRefusal::from)
        .and_then(|named| file_verdict(&facts_of(&named), owner_uid).map(|()| named))
}


/// The token file in the held directory: created if the name is free, otherwise kept when it is exactly what a plant makes.
pub fn plant_leaf(ops: &PlantOps, owner_uid: u32, parent: &OwnedFd, leaf: &str, content: &str) -> Result<Stat, PlantRefusal> {
    match openat(parent, leaf, CREATE_FLAGS, Mode::from_raw_mode(FILE_MODE)) {
        Err(Errno::EXIST) => existing_token(parent, leaf, owner_uid),
        created => created
            .map_err(PlantRefusal::from)
            .and_then(|handle| fresh_token(ops, owner_uid, parent, leaf, handle, content)),
    }
}


/// Random bytes from the injected source.
pub fn random_bytes(ops: &PlantOps) -> Result<[u8; RANDOM_BYTES], PlantRefusal> {
    let mut bytes = [u8::MIN; RANDOM_BYTES];
    (ops.fill_random)(&mut bytes).map(|()| bytes).map_err(PlantRefusal::Io)
}


/// Plants one decoy and returns the identity of every directory above it (outermost first) and of the file, all read from held handles.
pub fn plant_token(ops: &PlantOps, token: &Honeytoken) -> Result<Vec<PlantedIdentity>, PlantRefusal> {
    let names: Vec<&str> = token.path.split('/').filter(|part| !part.is_empty()).collect();
    names.split_last().ok_or(PlantRefusal::Path).and_then(|(leaf, directories)| {
        random_bytes(ops).map(|bytes| token_content(token.kind, &bytes)).and_then(|content| {
            walk_directories(ops, token.owner_uid, directories).and_then(|walk| {
                judge_directory(&walk.parent, token.owner_uid)
                    .and_then(|_| plant_leaf(ops, token.owner_uid, &walk.parent, leaf, &content))
                    .map(|stat| {
                        walk.identities
                            .into_iter()
                            .chain(std::iter::once(identity_of(&token.path, &stat)))
                            .collect()
                    })
            })
        })
    })
}


/// Plants every honeytoken of a role; a token refused is reported by index while the others are planted.
pub fn plant_role(role: &Role, limits: &Limits, ops: &PlantOps) -> Result<PlantReport, PlantError> {
    let count = role.honeytokens.len();
    (count <= limits.max_honeytokens)
        .then_some(())
        .ok_or(PlantError::TooMany {
            count,
            max: limits.max_honeytokens,
        })
        .and_then(|()| check_unloaded(ops))
        .map(|()| {
            let empty = PlantReport {
                planted: Vec::new(),
                refused: Vec::new(),
            };
            role.honeytokens
                .iter()
                .enumerate()
                .map(|(index, token)| (index, plant_token(ops, token)))
                .fold(empty, |report, (index, result)| merge_result(report, index, result))
        })
}


/// Adds the identities of one token (a path already recorded is kept once) or its refusal to the report.
pub fn merge_result(report: PlantReport, index: usize, result: Result<Vec<PlantedIdentity>, PlantRefusal>) -> PlantReport {
    let PlantReport { mut planted, mut refused } = report;
    match result {
        Ok(identities) => identities.into_iter().for_each(|identity| {
            if !planted.iter().any(|known| known.path == identity.path) {
                planted.push(identity);
            }
        }),
        Err(refusal) => refused.push((index, refusal)),
    }
    PlantReport { planted, refused }
}


/// One line per identity: `path`, `st_dev` and `inode` separated by tabs, the format `parse_planted` reads.
pub fn planted_text(identities: &[PlantedIdentity]) -> String {
    identities
        .iter()
        .map(|identity| format!("{}\t{}\t{}\n", identity.path, stat_device(identity.device), identity.inode))
        .collect()
}


/// The text goes to a 0600 file of a random name in the held directory (`O_EXCL`), is synced, then renamed over the output name.
pub fn stage_text(ops: &PlantOps, parent: &OwnedFd, name: &str, text: &str) -> Result<(), PlantError> {
    let mut suffix = [u8::MIN; TEMPORARY_RANDOM_BYTES];
    (ops.fill_random)(&mut suffix).map_err(PlantError::Io).and_then(|()| {
        let staged = format!(".{name}.{}.tmp", suffix.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        openat(parent, staged.as_str(), CREATE_FLAGS, Mode::from_raw_mode(FILE_MODE))
            .map_err(PlantError::from)
            .and_then(|handle| {
                write_and_sync(&handle, text)
                    .map_err(PlantError::Io)
                    .and_then(|()| renameat(parent, staged.as_str(), parent, name).map_err(PlantError::from))
                    .or_else(|failure| {
                        remove_partial(parent, staged.as_str(), &handle)
                            .map_err(PlantError::from)
                            .and(Err(failure))
                    })
            })
    })
}


/// Writes the identities to `path` through its trusted parent directory.
pub fn write_planted(ops: &PlantOps, path: &Path, identities: &[PlantedIdentity]) -> Result<(), PlantError> {
    let parts = path.parent().zip(path.file_name().and_then(|name| name.to_str()));
    parts.ok_or(PlantError::OutputPath).and_then(|(directory, name)| {
        open_trusted_dir(directory, geteuid().as_raw())
            .map_err(PlantError::from)
            .and_then(|parent| stage_text(ops, &parent, name, &planted_text(identities)))
    })
}


/// Plants the role's decoys, writes `planted_path` with what was planted and prints `planted N refused M` and each refusal; returns M.
pub fn plant_command<Output: Write>(
    table_path: &Path,
    role_name: &str,
    planted_path: &Path,
    limits: &Limits,
    ops: &PlantOps,
    out: &mut Output,
) -> Result<usize, CliError> {
    let role = role_of(table_path, role_name, limits)?;
    plant_role(&role, limits, ops)
        .map_err(CliError::from)
        .and_then(|report| write_planted(ops, planted_path, &report.planted).map_err(CliError::from).map(|()| report))
        .and_then(|report| print_report(&role, &report, out).map(|()| report.refused.len()))
}


/// `planted N refused M`, then each refusal by index with its fixed reason.
pub fn print_report<Output: Write>(role: &Role, report: &PlantReport, out: &mut Output) -> Result<(), CliError> {
    writeln!(
        out,
        "planted {} refused {}",
        role.honeytokens.len().saturating_sub(report.refused.len()),
        report.refused.len()
    )?;
    report
        .refused
        .iter()
        .try_for_each(|(index, refusal)| writeln!(out, "refused {index}: {refusal}"))?;
    Ok(())
}
