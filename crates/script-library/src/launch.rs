use crate::argv::argv_with_script;
use crate::cgroup::{create_cgroup, kill_cgroup, place_in_cgroup};
use crate::check::{check_manifest, ensure};
use crate::digest::check_digest;
use crate::error::ScriptError;
use crate::model::{Captured, Interpreter, LaunchRequest, Manifest, Outcome, ParamKind, ParamValue};
use crate::params::validate_params;
use crate::path::is_under_prefixes;
use crate::types::{Params, PlaceFn, WaitFn};
use rustix::io::Errno;
use rustix::process::{geteuid, kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;
use tempfile::{Builder, TempDir};
use tracing::debug;
use wait_timeout::ChildExt;


pub const ENV_ALLOWLIST: [&str; 3] = ["PATH", "LANG", "LC_ALL"];


pub const PRIVATE_FILE_MODE: u32 = 0o600;


pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;


pub const PRIVATE_DIRECTORY_PREFIX: &str = "script-";


pub const NEW_PROCESS_GROUP: i32 = 0;


pub const WRITABLE_BY_OTHERS: u32 = 0o022;


pub const BASH_PATHS: &[&str] = &["/usr/bin/bash", "/bin/bash"];


pub const PYTHON_PATHS: &[&str] = &["/usr/bin/python3", "/bin/python3"];


pub const POWERSHELL_PATHS: &[&str] = &["/usr/bin/pwsh", "/opt/microsoft/powershell/7/pwsh"];


pub const DEFAULT_KILL_GRACE_SECONDS: u64 = 5;


pub const SHELL_PATHS: &[&str] = &["/bin/sh", "/usr/bin/sh"];


pub const GATE_FILE: &str = "gate.sh";


pub const GATE_SCRIPT: &str = "read -r gate\nexec \"$@\" </dev/null\n";


pub const GATE_RELEASE: &[u8] = b"\n";


fn declared_paths(interpreter: Interpreter) -> &'static [&'static str] {
    match interpreter {
        Interpreter::Powershell => POWERSHELL_PATHS,
        Interpreter::Bash => BASH_PATHS,
        Interpreter::Python => PYTHON_PATHS,
    }
}


/// The first declared absolute path that is a file; the caller's `PATH` is never consulted.
pub fn resolve_interpreter(candidates: &[&str]) -> Result<String, ScriptError> {
    candidates
        .iter()
        .find(|candidate| Path::new(candidate).is_file())
        .map(|candidate| candidate.to_string())
        .ok_or(ScriptError::NoInterpreter)
}


/// The work root must be a directory owned by `owner` that neither group nor others can write (a sticky shared directory is refused).
pub fn check_work_root(root: &Path, owner: u32) -> Result<(), ScriptError> {
    let metadata = fs::metadata(root).map_err(io_error("cannot inspect the work root"))?;
    ensure(
        metadata.is_dir() && metadata.uid() == owner && metadata.mode() & WRITABLE_BY_OTHERS == 0,
        ScriptError::UnsafeWorkRoot,
    )
}


fn private_file_name(interpreter: Interpreter) -> &'static str {
    match interpreter {
        Interpreter::Powershell => "script.ps1",
        Interpreter::Bash => "script.sh",
        Interpreter::Python => "script.py",
    }
}


fn io_error(context: &'static str) -> impl Fn(io::Error) -> ScriptError {
    move |source| ScriptError::Io { context, source }
}


/// Only the allowlisted variables survive; everything else of the caller's environment is dropped.
pub fn allowed_environment(environment: &[(String, String)]) -> Vec<(String, String)> {
    environment
        .iter()
        .filter(|(name, _)| ENV_ALLOWLIST.contains(&name.as_str()))
        .cloned()
        .collect()
}


fn resolve_path(name: &str, text: &str, prefixes: &[String]) -> Result<String, ScriptError> {
    let canonical = fs::canonicalize(text).map_err(|source| ScriptError::PathUnresolved {
        name: name.to_string(),
        source,
    })?;
    let canonical_text = canonical.to_str().ok_or_else(|| ScriptError::MalformedPath(name.to_string()))?;
    let allowed: Vec<String> = prefixes
        .iter()
        .filter_map(|prefix| {
            fs::canonicalize(prefix)
                .inspect_err(|error| debug!(%error, "allowed prefix does not resolve"))
                .ok()
                .and_then(|resolved| resolved.to_str().map(str::to_string))
        })
        .collect();
    ensure(
        is_under_prefixes(canonical_text, &allowed),
        ScriptError::PathOutsidePrefixes(name.to_string()),
    )?;
    Ok(canonical_text.to_string())
}


/// Path parameters are replaced by their symlink-free form, which must still be under the (also resolved) allowed prefixes.
pub fn resolve_paths(manifest: &Manifest, params: &Params) -> Result<Params, ScriptError> {
    params
        .iter()
        .map(|(name, value)| {
            let resolved = match (manifest.parameters.get(name), value) {
                (Some(ParamKind::Path { allowed_prefixes }), ParamValue::Text(text)) => ParamValue::Text(resolve_path(name, text, allowed_prefixes)?),
                _ => value.clone(),
            };
            Ok((name.clone(), resolved))
        })
        .collect()
}


/// A fresh directory (mode 0700, created by `mkdir`) holding one file created with `O_EXCL` and mode 0600; both go when the guard drops.
pub fn write_private_script(work_root: &Path, file_name: &str, bytes: &[u8]) -> Result<(TempDir, PathBuf), ScriptError> {
    let directory = Builder::new()
        .prefix(PRIVATE_DIRECTORY_PREFIX)
        .permissions(Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        .tempdir_in(work_root)
        .map_err(io_error("cannot create the private script directory"))?;
    let path = write_private_file(directory.path(), file_name, bytes)?;
    Ok((directory, path))
}


/// One more `O_EXCL` file of mode 0600 in an existing private directory.
pub fn write_private_file(directory: &Path, file_name: &str, bytes: &[u8]) -> Result<PathBuf, ScriptError> {
    let path = directory.join(file_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&path)
        .map_err(io_error("cannot create the private script file"))?;
    file.write_all(bytes).map_err(io_error("cannot write the private script file"))?;
    Ok(path)
}


/// Keeps at most `cap` bytes and counts, without buffering, what comes after.
pub fn capture<Source: Read>(mut source: Source, cap: u64) -> io::Result<Captured> {
    let mut bytes = Vec::new();
    io::copy(&mut source.by_ref().take(cap), &mut bytes)?;
    let dropped = io::copy(&mut source, &mut io::sink())?;
    Ok(Captured { bytes, dropped })
}


/// Production wait: blocks up to `deadline`, `None` when the child is still running.
pub fn wait_deadline(child: &mut Child, deadline: Duration) -> io::Result<Option<std::process::ExitStatus>> {
    child.wait_timeout(deadline)
}


fn spawn_in_group(program: &str, args: &[String], environment: &[(String, String)], writer: io::PipeWriter) -> io::Result<Child> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (OsString::from(name), OsString::from(value))))
        .stdin(Stdio::piped())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .process_group(NEW_PROCESS_GROUP);
    command.spawn()
}


/// An empty group (no background job left) is the normal case, not a failure.
pub fn tolerate_empty_group(result: Result<(), Errno>) -> Result<(), ScriptError> {
    match result {
        Err(Errno::SRCH) => Ok(()),
        other => Ok(other?),
    }
}


fn kill_group(child: &Child) -> Result<(), ScriptError> {
    tolerate_empty_group(kill_process_group(Pid::from_child(child), Signal::KILL))
}


fn collect(receiver: &Receiver<io::Result<Captured>>, deadline: Duration) -> Result<Captured, ScriptError> {
    receiver.recv_timeout(deadline)?.map_err(io_error("cannot read the script output"))
}


/// Lets the gated script go: closing the pipe ends the wrapper's `read`, which then execs the interpreter inside the cgroup.
pub fn release_gate(child: &mut Child) -> io::Result<()> {
    child.stdin.take().into_iter().try_for_each(|mut stdin| stdin.write_all(GATE_RELEASE))
}


/// The wait after the kill has a deadline: a process that survives it is reported, never waited on forever.
pub fn reap(child: &mut Child, grace: Duration, wait: WaitFn) -> Result<ExitStatus, ScriptError> {
    wait(child, grace)
        .map_err(io_error("cannot reap the script process"))?
        .ok_or(ScriptError::Io {
            context: "the script process is still running after the kill",
            source: io::Error::from(io::ErrorKind::TimedOut),
        })
}


fn run_child(request: &LaunchRequest, script: &Path, gate: &Path, cgroup: &Path, wait: WaitFn, place: PlaceFn) -> Result<Outcome, ScriptError> {
    let manifest = &request.manifest;
    let script_text = script.to_str().ok_or_else(|| ScriptError::MalformedPath(manifest.name.clone()))?;
    let params = resolve_paths(manifest, &request.params)?;
    let argv = argv_with_script(manifest, &params, script_text);
    let interpreter = resolve_interpreter(declared_paths(manifest.interpreter))?;
    let program = resolve_interpreter(SHELL_PATHS)?;
    let gated: Vec<String> = [gate.to_string_lossy().into_owned(), interpreter].into_iter().chain(argv.args).collect();
    let (reader, writer) = io::pipe().map_err(io_error("cannot create the output pipe"))?;
    let mut child =
        spawn_in_group(&program, &gated, &allowed_environment(&request.environment), writer).map_err(io_error("cannot start the interpreter"))?;
    let placed = place(cgroup, child.id())
        .map_err(io_error("cannot place the script in its cgroup"))
        .and_then(|()| release_gate(&mut child).map_err(io_error("cannot release the script")));
    let cap = manifest.max_output_bytes;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(capture(reader, cap)));
    let deadline = Duration::from_secs(manifest.timeout_seconds);
    let waited = match &placed {
        Ok(()) => wait(&mut child, deadline),
        Err(_) => Ok(None),
    };
    let timed_out = !matches!(waited, Ok(Some(_)));
    let group_killed = kill_group(&child);
    let cgroup_killed = kill_cgroup(cgroup).map_err(io_error("cannot kill the script cgroup"));
    let status = reap(&mut child, request.kill_grace, wait_deadline);
    let captured = collect(&receiver, request.kill_grace);
    placed?;
    waited.map_err(io_error("cannot wait for the script process"))?;
    group_killed?;
    cgroup_killed?;
    let exit_code = status?.code();
    let output = captured?;
    Ok(Outcome {
        exit_code,
        timed_out,
        output: output.bytes,
        dropped_bytes: output.dropped,
    })
}


/// Checks the manifest, the parameters, the digest and the work root, writes the digested bytes to a private file and runs it in its own cgroup.
pub fn run_script(request: &LaunchRequest, wait: WaitFn, place: PlaceFn) -> Result<Outcome, ScriptError> {
    check_manifest(&request.manifest)?;
    validate_params(&request.manifest, &request.params)?;
    let bytes = check_digest(&request.manifest, request.script_bytes.clone())?;
    let root = std::path::absolute(&request.work_root).map_err(io_error("cannot resolve the work root"))?;
    check_work_root(&root, geteuid().as_raw())?;
    let (directory, script) = write_private_script(&root, private_file_name(request.manifest.interpreter), &bytes)?;
    let gate = write_private_file(directory.path(), GATE_FILE, GATE_SCRIPT.as_bytes())?;
    let name: String = directory.path().file_name().into_iter().map(|entry| entry.to_string_lossy()).collect();
    let cgroup = create_cgroup(&request.cgroup_root, &name).map_err(io_error("cannot create the script cgroup"))?;
    run_child(request, &script, &gate, &cgroup.path, wait, place)
}


pub fn launch_script(request: &LaunchRequest) -> Result<Outcome, ScriptError> {
    run_script(request, wait_deadline, place_in_cgroup)
}
