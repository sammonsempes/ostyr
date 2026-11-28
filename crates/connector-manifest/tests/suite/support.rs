use crate::common::types::{Failure, TestResult};
use crate::common::{key_file_text, signing_key, KEY_ID, NOT_AFTER, PUBLISHER, VALID_MANIFEST};
use connector_manifest::code_dir::GATE_NAME;
use connector_manifest::keys::parse_trusted_keys;
use connector_manifest::kill::{sleep_poll, KillHost, KILL_POLLS, KILL_ROUNDS};
use connector_manifest::model::{Verified, MANIFEST_NAME};
use connector_manifest::package::read_package;
use connector_manifest::run::{check_program, spawn_piped, LaunchPlan, Programs, RunHost, RunSpec, PRLIMIT_PATH, PYTHON_PATH, SHELL_PATH};
use connector_manifest::verify::{sign_package, verify_package, write_signature};
use script_library::cgroup::SYSTEM_CGROUP;
use script_library::model::{Limits, RunAs};
use serde_json::value::RawValue;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;


pub const RUN_UID: u32 = 59_001;


pub const RUN_GID: u32 = 59_001;


pub const NOW: u64 = 1_000;


pub const DEADLINE_SECONDS: u64 = 20;


pub const SHORT_DEADLINE_MILLISECONDS: u64 = 1_500;


pub const OPEN_MODE: u32 = 0o755;


pub const MEMORY_BYTES: u64 = 536_870_912;


pub const PIDS: u64 = 256;


pub const CONTROLLERS: &str = "+cpu +memory +pids";


pub const ANCESTOR_LEVELS: usize = 3;


pub const POLL_PAUSE_MILLISECONDS: u64 = 5;


pub const POLL_FACTOR: u64 = 4;


pub struct Fixture {
    pub package: TempDir,
    pub code_root: TempDir,
    pub verified: Verified,
}


/// An empty cgroup below the test process's own with the controllers enabled for its children; removed when dropped.
pub struct ParentCgroup {
    pub path: PathBuf,
}


impl Drop for ParentCgroup {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir(&self.path) {
            log::warn!("cannot remove the test cgroup: {:?}", error.kind());
        }
    }
}


pub fn enable_controllers(path: &Path) -> io::Result<ParentCgroup> {
    let parent = ParentCgroup { path: path.to_path_buf() };
    fs::create_dir(&parent.path)?;
    fs::write(parent.path.join("cgroup.subtree_control"), CONTROLLERS)?;
    Ok(parent)
}


pub fn own_cgroup_root() -> Result<ParentCgroup, Failure> {
    let text = fs::read_to_string("/proc/self/cgroup")?;
    let probe = script_library::fsdir::random_name()?;
    let own = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|relative| Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
        .ok_or("this host has no cgroup v2 hierarchy: the confinement tests cannot run")?;
    let found = own.ancestors().take(ANCESTOR_LEVELS).try_fold(String::new(), |failures, base| {
        enable_controllers(&base.join(&probe)).map_or_else(|error| Ok(format!("{failures} {}: {error};", base.display())), Err)
    });
    match found {
        Err(parent) => Ok(parent),
        Ok(failures) => Err(format!("no writable cgroup v2 with {CONTROLLERS} for the confinement tests:{failures}").into()),
    }
}


pub fn open_directory(directory: &TempDir) -> TestResult {
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(OPEN_MODE))?;
    Ok(())
}


pub fn manifest_text(entry: &str, runtime: &str) -> String {
    VALID_MANIFEST
        .replacen("entry: main.py", &format!("entry: {entry}"), 1)
        .replacen("runtime: python3", &format!("runtime: {runtime}"), 1)
}


/// A signed and verified package whose entry file holds `code`; the code root is an open directory of the runner.
pub fn fixture(entry: &str, runtime: &str, code: &[u8]) -> Result<Fixture, Failure> {
    let package = tempfile::tempdir()?;
    fs::write(package.path().join(MANIFEST_NAME), manifest_text(entry, runtime))?;
    fs::write(package.path().join(entry), code)?;
    let text = sign_package(&read_package(package.path())?, KEY_ID, &signing_key())?;
    write_signature(package.path(), &text)?;
    let keys = parse_trusted_keys(&key_file_text(KEY_ID, PUBLISHER, &crate::common::public_hex(), NOT_AFTER), "keys.yaml")?;
    let verified = verify_package(package.path(), &keys, NOW)?;
    let code_root = tempfile::tempdir()?;
    open_directory(&code_root)?;
    Ok(Fixture {
        package,
        code_root,
        verified,
    })
}


pub fn python_fixture(code: &str) -> Result<Fixture, Failure> {
    fixture("main.py", "python3", code.as_bytes())
}


pub fn dropping_launcher(plan: &LaunchPlan) -> Command {
    let mut command = Command::new(plan.argv.first().map_or("false", |program| program.to_str().unwrap_or("false")));
    command.args(plan.argv.iter().skip(1)).uid(plan.run_as.uid).gid(plan.run_as.gid);
    command
}


pub fn plain_launcher(plan: &LaunchPlan) -> Command {
    let mut command = Command::new(plan.argv.first().map_or("false", |program| program.to_str().unwrap_or("false")));
    command.args(plan.argv.iter().skip(1));
    command
}


pub fn pause_briefly(_pause: Duration) {
    sleep_poll(Duration::from_millis(POLL_PAUSE_MILLISECONDS));
}


pub fn kill_host() -> KillHost {
    KillHost {
        pause: pause_briefly,
        proc_root: PathBuf::from("/proc"),
        rounds: KILL_ROUNDS,
        polls: KILL_POLLS * POLL_FACTOR,
    }
}


pub fn system_programs() -> Programs {
    Programs {
        shell: PathBuf::from(SHELL_PATH),
        prlimit: PathBuf::from(PRLIMIT_PATH),
        python: PathBuf::from(PYTHON_PATH),
    }
}


pub fn generated_name() -> io::Result<String> {
    script_library::fsdir::random_name()
}


pub fn runner_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}


pub fn host() -> RunHost {
    RunHost {
        launch: dropping_launcher,
        spawn: spawn_piped,
        kill: kill_host(),
        cgroup: SYSTEM_CGROUP,
        namer: generated_name,
        programs: system_programs(),
        runner_uid: runner_uid(),
    }
}


pub fn limits() -> Limits {
    Limits {
        memory_bytes: MEMORY_BYTES,
        pids: PIDS,
        cpu_percent: None,
    }
}


pub fn params(text: &str) -> Result<Box<RawValue>, Failure> {
    Ok(RawValue::from_string(text.to_owned())?)
}


pub fn spec<'a>(fixture: &'a Fixture, cgroup_root: &'a Path, deadline: Duration, params: &'a RawValue) -> RunSpec<'a> {
    RunSpec {
        verified: &fixture.verified,
        package: fixture.package.path(),
        code_root: fixture.code_root.path(),
        cgroup_root,
        run_as: RunAs { uid: RUN_UID, gid: RUN_GID },
        limits: limits(),
        deadline,
        action: "restart-service",
        params,
    }
}


pub fn long_deadline() -> Duration {
    Duration::from_secs(DEADLINE_SECONDS)
}


pub fn short_deadline() -> Duration {
    Duration::from_millis(SHORT_DEADLINE_MILLISECONDS)
}


pub fn checked(path: &Path) -> Result<(), connector_manifest::error::ConnectorError> {
    check_program(path, 0)
}


pub fn leftovers(dir: &Path) -> Result<usize, Failure> {
    Ok(fs::read_dir(dir)?.count())
}


pub fn gate_name() -> &'static str {
    GATE_NAME
}


pub fn processes_with(marker: &str) -> Result<usize, Failure> {
    let found = fs::read_dir("/proc")?
        .flatten()
        .flat_map(|entry| fs::read(entry.path().join("cmdline")))
        .filter(|bytes| bytes.split(|byte| *byte == 0).any(|argument| argument == marker.as_bytes()))
        .count();
    Ok(found)
}


pub const ELF_IDENT: [u8; 8] = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];


pub const IDENT_PADDING: usize = 8;


pub const ET_EXEC: u64 = 2;


pub const EM_X86_64: u64 = 0x3e;


pub const LOAD_BASE: u64 = 0x40_0000;


pub const HEADER_BYTES: u64 = 64;


pub const PHDR_BYTES: u64 = 56;


pub const CODE_OFFSET: u64 = HEADER_BYTES + PHDR_BYTES;


pub const PT_LOAD: u64 = 1;


pub const PT_INTERP: u64 = 3;


pub const PF_RX: u64 = 5;


pub const PAGE: u64 = 0x1000;


pub const EHSIZE_FIELD: u64 = 64;


pub const MOV_EAX: u8 = 0xb8;


pub const MOV_EDI: u8 = 0xbf;


pub const MOV_EDX: u8 = 0xba;


pub const LEA_RSI: [u8; 3] = [0x48, 0x8d, 0x35];


pub const SYSCALL: [u8; 2] = [0x0f, 0x05];


pub const XOR_EDI: [u8; 2] = [0x31, 0xff];


pub const SYS_WRITE: u64 = 1;


pub const SYS_EXIT: u64 = 60;


pub const MESSAGE_FROM_LEA: u64 = 16;


pub const WORD: usize = 4;


pub const QUAD: usize = 8;


pub const SHORT: usize = 2;


pub fn le(value: u64, width: usize) -> Vec<u8> {
    value.to_le_bytes().iter().copied().take(width).collect()
}


/// An ELF64 header announcing `count` program headers right after it.
pub fn elf_header(count: u64) -> Vec<u8> {
    [
        ELF_IDENT.to_vec(),
        vec![0; IDENT_PADDING],
        le(ET_EXEC, SHORT),
        le(EM_X86_64, SHORT),
        le(1, WORD),
        le(LOAD_BASE + CODE_OFFSET, QUAD),
        le(HEADER_BYTES, QUAD),
        le(0, QUAD),
        le(0, WORD),
        le(EHSIZE_FIELD, SHORT),
        le(PHDR_BYTES, SHORT),
        le(count, SHORT),
        le(0, SHORT),
        le(0, SHORT),
        le(0, SHORT),
    ]
    .concat()
}


pub fn program_header(kind: u64, size: u64) -> Vec<u8> {
    [
        le(kind, WORD),
        le(PF_RX, WORD),
        le(0, QUAD),
        le(LOAD_BASE, QUAD),
        le(LOAD_BASE, QUAD),
        le(size, QUAD),
        le(size, QUAD),
        le(PAGE, QUAD),
    ]
    .concat()
}


/// A header and bare program headers of the given types, for the static-ELF check.
pub fn elf_with_types(kinds: &[u64]) -> Vec<u8> {
    kinds
        .iter()
        .fold(elf_header(kinds.len() as u64), |bytes, kind| [bytes, program_header(*kind, 0)].concat())
}


/// A static x86-64 program that writes `message` to stdout and exits 0.
pub fn tiny_elf(message: &[u8]) -> Vec<u8> {
    let code = [
        vec![MOV_EAX],
        le(SYS_WRITE, WORD),
        vec![MOV_EDI],
        le(1, WORD),
        LEA_RSI.to_vec(),
        le(MESSAGE_FROM_LEA, WORD),
        vec![MOV_EDX],
        le(message.len() as u64, WORD),
        SYSCALL.to_vec(),
        vec![MOV_EAX],
        le(SYS_EXIT, WORD),
        XOR_EDI.to_vec(),
        SYSCALL.to_vec(),
    ]
    .concat();
    let total = CODE_OFFSET + code.len() as u64 + message.len() as u64;
    [elf_header(1), program_header(PT_LOAD, total), code, message.to_vec()].concat()
}
