use crate::classify::declared;
use crate::limits::{MAX_PATH_BYTES, UNRESOLVED_NAME};
use crate::model::{FileEvidence, FimEvent, Manager, PackageOps, PackageVerdict, ToolOutput, WatchSets};
use crate::plant::{log_unjudged, pick_binary, read_until, reap, wait_until, NEW_PROCESS_GROUP, PROGRAM_CHANGED, TETRA_OWNER_UID};
use crate::policy::kernel_device;
use crate::types::{Identity, Sha256Digest};
use core_config::trusted_program::same_program;
use rustix::fs::{statat, AtFlags, CWD};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};


pub const RPM: &str = "/usr/bin/rpm";


pub const DPKG_QUERY: &str = "/usr/bin/dpkg-query";


pub const DPKG_DIVERT: &str = "/usr/bin/dpkg-divert";


pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";


pub const RPM_DATABASES: [&str; 2] = ["/var/lib/rpm", "/usr/lib/sysimage/rpm"];


pub const RPM_FORMAT: &str =
    "H %{NAME} %{EVR}.%{ARCH} %{INSTALLTIME} %{FILEDIGESTALGO}\n[F %{FILEFLAGS} %{FILEVERIFYFLAGS} %{FILESTATES} %{FILEDIGESTS} %{FILENAMES}\n]";


pub const CONFFILES_FORMAT: &str = "${Conffiles}\n";


pub const TOOL_DEADLINE: Duration = Duration::from_secs(10);


pub const TOOL_ENV: [(&str, &str); 2] = [("LC_ALL", "C"), ("PATH", "/usr/bin:/bin")];


pub const SIGNALLED_CODE: i32 = -1;


pub const NOT_FOUND_CODE: i32 = 1;


pub const FILE_FIELDS: usize = 5;


pub const MAX_TOKEN_BYTES: usize = 128;


pub const MAX_DIGEST_BYTES: usize = 128;


pub const TOKEN_PUNCTUATION: &str = "._+~^:-";


pub const PATH_PUNCTUATION: &str = "._/-+@";


pub const RPMFILE_CONFIG: u32 = 1;


pub const RPMVERIFY_FILEDIGEST: u32 = 1;


pub const STATE_NORMAL: u8 = 0;


pub const ALGO_SHA256: &str = "sha256";


pub const ALGO_MD5: &str = "md5";


pub const REASON_PATH: &str = "path_not_exact";


pub const REASON_EVIDENCE: &str = "evidence_for_another_path";


pub const REASON_NO_MANAGER: &str = "no_package_manager";


pub const REASON_COMMAND: &str = "command_failed";


pub const REASON_UNPARSED: &str = "output_not_parsed";


pub const REASON_DUPLICATE: &str = "duplicate_entry";


pub const REASON_DIVERTED: &str = "diverted";


pub const REASON_CHANGED: &str = "file_changed";


/// The path a package update can explain: a content event with an exact path, or a rename onto a declared path.
pub fn subject_of<'a>(event: &'a FimEvent, content: bool, sets: &WatchSets) -> Option<&'a str> {
    match event {
        FimEvent::Write {
            path,
            name_match: false,
            mount_ambiguous: false,
            foreign_mount_ns: false,
            dentry_path: None,
            ..
        } if content => Some(path),
        FimEvent::Rename {
            target,
            honeytoken: false,
            mount_ambiguous: false,
            foreign_mount_ns: false,
            ..
        } if target != UNRESOLVED_NAME && declared(target, sets) => Some(target),
        _ => None,
    }
}


/// Annotates an event: `content` is `classify::content_line` of its export line; the severity of the event is never touched.
pub fn annotate(event: &FimEvent, content: bool, evidence: &FileEvidence, sets: &WatchSets, ops: &PackageOps) -> PackageVerdict {
    subject_of(event, content, sets).map_or(PackageVerdict::NotApplicable, |subject| verdict_for(subject, evidence, ops))
}


/// The verdict for one path; every failure is that path's named `Unverified`.
pub fn verdict_for(subject: &str, evidence: &FileEvidence, ops: &PackageOps) -> PackageVerdict {
    let outcome = ensure(path_is_exact(subject), REASON_PATH)
        .and_then(|()| ensure(evidence.path == subject, REASON_EVIDENCE))
        .and_then(|()| manager_of(ops))
        .and_then(|manager| match manager {
            Manager::Rpm => rpm_verdict(subject, &evidence.sha256, ops),
            Manager::Dpkg => dpkg_verdict(subject, ops),
        })
        .and_then(|found| unchanged(subject, evidence.identity, ops).map(|()| found));
    outcome.unwrap_or_else(unverified)
}


/// The named `Unverified` verdict, logged once.
pub fn unverified(reason: &'static str) -> PackageVerdict {
    tracing::warn!(reason, "package check unverified");
    PackageVerdict::Unverified { reason }
}


pub fn ensure(condition: bool, reason: &'static str) -> Result<(), &'static str> {
    condition.then_some(()).ok_or(reason)
}


/// An absolute path of the role grammar's characters, at most `MAX_PATH_BYTES`, so it is safe as a command argument.
pub fn path_is_exact(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_PATH_BYTES
        && path
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || PATH_PUNCTUATION.contains(character))
}


/// A package name or version as a command argument or a field: starts with a letter or digit, bounded, no space.
pub fn token_ok(text: &str) -> bool {
    text.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && text.len() <= MAX_TOKEN_BYTES
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(character))
}


/// The package manager of the host: dpkg when its status file exists, else rpm when a database directory does.
pub fn manager_of(ops: &PackageOps) -> Result<Manager, &'static str> {
    if (ops.exists)(DPKG_STATUS) {
        Ok(Manager::Dpkg)
    } else if RPM_DATABASES.iter().any(|database| (ops.exists)(database)) {
        Ok(Manager::Rpm)
    } else {
        Err(REASON_NO_MANAGER)
    }
}


/// The path still names the file that was hashed.
pub fn unchanged(path: &str, identity: Identity, ops: &PackageOps) -> Result<(), &'static str> {
    let now = (ops.identity)(path).map_err(|error| {
        let reason = error.to_string();
        tracing::warn!(reason, "file cannot be judged again");
        REASON_CHANGED
    });
    now.and_then(|seen| ensure(seen == identity, REASON_CHANGED))
}


/// Runs a tool through the injected runner; a failure to run is `command_failed`, logged.
pub fn run_ok(ops: &PackageOps, tool: &str, args: &[&str]) -> Result<ToolOutput, &'static str> {
    (ops.run)(tool, args).map_err(|error| {
        let reason = error.to_string();
        tracing::warn!(tool, reason, "package tool failed");
        REASON_COMMAND
    })
}


/// The standard output of a tool that exited with 0.
pub fn successful(output: ToolOutput) -> Result<String, &'static str> {
    ensure(output.code == 0, REASON_COMMAND).map(|()| output.stdout)
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmHeader {
    pub name: String,
    pub evra: String,
    pub installed_at: u64,
    pub algo: &'static str,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmFile {
    pub flags: u32,
    pub verify: u32,
    pub state: u8,
    pub digest: String,
    pub path: String,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpmLine {
    Header(RpmHeader),
    File(RpmFile),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpmEntry {
    pub header: RpmHeader,
    pub file: RpmFile,
}


/// The package that owns the path according to rpm, and whether its database digest is what was hashed.
pub fn rpm_verdict(path: &str, sha256: &Sha256Digest, ops: &PackageOps) -> Result<PackageVerdict, &'static str> {
    let output = run_ok(ops, RPM, &["-qf", "--qf", RPM_FORMAT, "--", path])?;
    let not_owned = format!("file {path} is not owned by any package\n");
    if output.code == NOT_FOUND_CODE && output.stdout == not_owned {
        Ok(PackageVerdict::Unowned)
    } else {
        successful(output)
            .and_then(|text| entries_of(&text, path))
            .map(|entries| rpm_decision(&entries, sha256))
    }
}


/// The entries of the queried path in the rpm output: every line must parse, only exact path lines in state 0 are kept, once per owner.
pub fn entries_of(stdout: &str, path: &str) -> Result<Vec<RpmEntry>, &'static str> {
    let folded =
        stdout
            .lines()
            .filter(|text| !text.is_empty())
            .try_fold((None::<RpmHeader>, Vec::new()), |(header, mut kept), text| {
                match parse_line(text).ok_or(REASON_UNPARSED)? {
                    RpmLine::Header(next) => Ok((Some(next), kept)),
                    RpmLine::File(file) => {
                        let owner = header.clone().ok_or(REASON_UNPARSED)?;
                        if file.path == path && file.state == STATE_NORMAL {
                            kept.push(RpmEntry { header: owner, file });
                        }
                        Ok((header, kept))
                    }
                }
            });
    folded.and_then(|(_, mut kept)| {
        kept.sort_by_key(|entry| (entry.header.name.clone(), entry.header.evra.clone()));
        let owners: BTreeSet<(&str, &str)> = kept
            .iter()
            .map(|entry| (entry.header.name.as_str(), entry.header.evra.as_str()))
            .collect();
        ensure(owners.len() == kept.len(), REASON_DUPLICATE).map(|()| kept.clone())
    })
}


/// One output line: `H name evra installed algo` or `F flags verify state digest path`; anything else is `None`.
pub fn parse_line(text: &str) -> Option<RpmLine> {
    if let Some(rest) = text.strip_prefix("H ") {
        match rest.split(' ').collect::<Vec<_>>().as_slice() {
            [name, evra, installed, algo] if token_ok(name) && token_ok(evra) => Some(RpmLine::Header(RpmHeader {
                name: (*name).to_string(),
                evra: (*evra).to_string(),
                installed_at: installed.parse().ok()?,
                algo: algo_name(algo),
            })),
            _ => None,
        }
    } else if let Some(rest) = text.strip_prefix("F ") {
        match rest.splitn(FILE_FIELDS, ' ').collect::<Vec<_>>().as_slice() {
            [flags, verify, state, digest, path] if digest_ok(digest) => Some(RpmLine::File(RpmFile {
                flags: flags.parse().ok()?,
                verify: verify.parse().ok()?,
                state: state.parse().ok()?,
                digest: (*digest).to_string(),
                path: (*path).to_string(),
            })),
            _ => None,
        }
    } else {
        None
    }
}


/// A digest field is empty or hexadecimal, bounded.
pub fn digest_ok(digest: &str) -> bool {
    digest.len() <= MAX_DIGEST_BYTES && digest.chars().all(|character| character.is_ascii_hexdigit())
}


/// The name of an rpm digest algorithm number; an absent or unknown one is `unknown`.
pub fn algo_name(token: &str) -> &'static str {
    match token {
        "1" => ALGO_MD5,
        "2" => "sha1",
        "8" => ALGO_SHA256,
        "9" => "sha384",
        "10" => "sha512",
        _ => "unknown",
    }
}


/// The verdict of the kept entries: none is unowned, owners that disagree are ambiguous, else the first one decides.
pub fn rpm_decision(entries: &[RpmEntry], sha256: &Sha256Digest) -> PackageVerdict {
    match entries.split_first() {
        None => PackageVerdict::Unowned,
        Some((first, rest)) => {
            if rest.iter().all(|other| agree(first, other)) {
                entry_verdict(first, entries, sha256)
            } else {
                PackageVerdict::AmbiguousOwner
            }
        }
    }
}


/// Two owners agree when they give the same digest, flags and algorithm.
pub fn agree(first: &RpmEntry, other: &RpmEntry) -> bool {
    first.file.digest == other.file.digest
        && first.file.flags == other.file.flags
        && first.file.verify == other.file.verify
        && first.header.algo == other.header.algo
}


/// A config file or one verified without its digest is `Config`; no usable digest is `UnverifiableDigest`; else the digests are compared.
pub fn entry_verdict(first: &RpmEntry, entries: &[RpmEntry], sha256: &Sha256Digest) -> PackageVerdict {
    let hex: String = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
    let config = first.file.flags & RPMFILE_CONFIG != 0 || first.file.verify & RPMVERIFY_FILEDIGEST == 0;
    let package = entries.iter().map(|entry| entry.header.name.as_str()).collect::<Vec<_>>().join(",");
    let evra = entries.iter().map(|entry| entry.header.evra.as_str()).collect::<Vec<_>>().join(",");
    if config {
        PackageVerdict::Config
    } else if first.header.algo != ALGO_SHA256 || first.file.digest.is_empty() {
        PackageVerdict::UnverifiableDigest { algo: first.header.algo }
    } else if first.file.digest.eq_ignore_ascii_case(&hex) {
        PackageVerdict::Match {
            package,
            evra,
            algo: ALGO_SHA256,
            installed_at: first.header.installed_at,
        }
    } else {
        PackageVerdict::Mismatch { package, evra }
    }
}


/// dpkg: a diverted path is unverified, an unowned or multiply owned one says so, a conffile is `Config`, any other is MD5-only.
pub fn dpkg_verdict(path: &str, ops: &PackageOps) -> Result<PackageVerdict, &'static str> {
    let diversions = successful(run_ok(ops, DPKG_DIVERT, &["--list", path])?)?;
    ensure(diversions.trim().is_empty(), REASON_DIVERTED)?;
    let search = run_ok(ops, DPKG_QUERY, &["-S", "--", path])?;
    let owners = if search.code == NOT_FOUND_CODE && search.stdout.is_empty() {
        BTreeSet::new()
    } else {
        owners_of(&successful(search)?, path)?
    };
    match owners.iter().collect::<Vec<_>>().as_slice() {
        [] => Ok(PackageVerdict::Unowned),
        [package] => conffile_verdict(package, path, ops),
        _ => Ok(PackageVerdict::AmbiguousOwner),
    }
}


/// The packages listed for the exact path by `dpkg-query -S`; a line of another shape or a diversion is a refusal.
pub fn owners_of(stdout: &str, path: &str) -> Result<BTreeSet<String>, &'static str> {
    stdout
        .lines()
        .filter(|text| !text.is_empty())
        .try_fold(BTreeSet::new(), |mut found, text| {
            ensure(!text.starts_with("diversion by "), REASON_DIVERTED)?;
            let names = text.strip_suffix(&format!(": {path}")).ok_or(REASON_UNPARSED)?;
            names.split(", ").try_for_each(|name| ensure(token_ok(name), REASON_UNPARSED))?;
            found.extend(names.split(", ").map(str::to_string));
            Ok(found)
        })
}


/// `Config` when the package lists the path among its conffiles, else the MD5 digest dpkg keeps cannot be trusted.
pub fn conffile_verdict(package: &str, path: &str, ops: &PackageOps) -> Result<PackageVerdict, &'static str> {
    let listing = successful(run_ok(ops, DPKG_QUERY, &["-W", "-f", CONFFILES_FORMAT, package])?)?;
    let listed = listing.lines().any(|text| text.split_whitespace().next() == Some(path));
    Ok(if listed {
        PackageVerdict::Config
    } else {
        PackageVerdict::UnverifiableDigest { algo: ALGO_MD5 }
    })
}


/// Runs the real tool at its constant path.
pub fn os_run(binary: &str, args: &[&str]) -> std::io::Result<ToolOutput> {
    run_first(binary, args, TETRA_OWNER_UID, TOOL_DEADLINE)
}


/// Runs a tool only when `pick_binary` accepts it and the path still names the judged program.
pub fn run_first(binary: &str, args: &[&str], owner: u32, deadline: Duration) -> std::io::Result<ToolOutput> {
    pick_binary(&[binary], owner).and_then(|found| {
        found
            .ok_or(std::io::Error::from(std::io::ErrorKind::NotFound))
            .and_then(|(path, handle)| run_checked(path, &handle, owner, deadline, args))
    })
}


/// Runs the tool when the path still names the program the handle holds; a failed re-judgement is logged and refuses the run.
pub fn run_checked(binary: &str, handle: &OwnedFd, owner: u32, deadline: Duration, args: &[&str]) -> std::io::Result<ToolOutput> {
    same_program(handle, Path::new(binary), owner)
        .inspect_err(log_unjudged)
        .unwrap_or(false)
        .then_some(())
        .ok_or(std::io::Error::other(PROGRAM_CHANGED))
        .and_then(|()| run_tool(binary, args, deadline))
}


/// The tool starts with a cleared environment, a null stdin, a piped stdout and its own process group.
pub fn spawn_tool(binary: &str, args: &[&str]) -> std::io::Result<Child> {
    Command::new(binary)
        .args(args)
        .env_clear()
        .envs(TOOL_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(NEW_PROCESS_GROUP)
        .spawn()
}


/// The exit code and output of the tool within the deadline and the shared byte cap; a child that overruns is killed with its group and reaped.
pub fn run_tool(binary: &str, args: &[&str], deadline: Duration) -> std::io::Result<ToolOutput> {
    let until = Instant::now() + deadline;
    let mut child = spawn_tool(binary, args)?;
    let read = child
        .stdout
        .take()
        .ok_or(std::io::Error::other("no output pipe"))
        .and_then(|out| read_until(&mut File::from(OwnedFd::from(out)), until));
    let status = read
        .as_ref()
        .map_err(|error| std::io::Error::from(error.kind()))
        .and_then(|_| wait_until(&mut child, until));
    if status.is_err() {
        reap(&mut child);
    }
    let bytes = read?;
    status.map(|done| ToolOutput {
        code: exit_code(done),
        stdout: String::from_utf8_lossy(&bytes).into_owned(),
    })
}


/// The exit code, or `SIGNALLED_CODE` for a child a signal ended.
pub fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(SIGNALLED_CODE)
}


/// The kernel device and inode of the path, a final link not followed.
pub fn os_identity(path: &str) -> std::io::Result<Identity> {
    statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
        .map(|stat| (kernel_device(stat.st_dev), stat.st_ino))
        .map_err(std::io::Error::from)
}


/// Whether the path exists; an error other than "not found" is logged and counts as absent.
pub fn os_exists(path: &str) -> bool {
    Path::new(path).try_exists().unwrap_or_else(|error| {
        let reason = error.to_string();
        tracing::warn!(path, reason, "package database path cannot be checked");
        false
    })
}
