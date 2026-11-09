use crate::argv::argv_with_script;
use crate::check::{check_manifest, ensure};
use crate::digest::check_digest;
use crate::error::ScriptError;
use crate::model::{Captured, Interpreter, LaunchRequest, Manifest, Outcome, ParamKind, ParamValue};
use crate::params::validate_params;
use crate::path::is_under_prefixes;
use crate::types::{Params, WaitFn};
use rustix::process::{kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    let path = directory.path().join(file_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&path)
        .map_err(io_error("cannot create the private script file"))?;
    file.write_all(bytes).map_err(io_error("cannot write the private script file"))?;
    Ok((directory, path))
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
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .process_group(NEW_PROCESS_GROUP);
    command.spawn()
}


fn kill_group(child: &Child) -> Result<(), ScriptError> {
    Ok(kill_process_group(Pid::from_child(child), Signal::KILL)?)
}


fn collect(receiver: &Receiver<io::Result<Captured>>) -> Result<Captured, ScriptError> {
    receiver.recv()?.map_err(io_error("cannot read the script output"))
}


fn run_child(request: &LaunchRequest, script: &Path, wait: WaitFn) -> Result<Outcome, ScriptError> {
    let manifest = &request.manifest;
    let script_text = script.to_str().ok_or_else(|| ScriptError::MalformedPath(manifest.name.clone()))?;
    let params = resolve_paths(manifest, &request.params)?;
    let argv = argv_with_script(manifest, &params, script_text);
    let (reader, writer) = io::pipe().map_err(io_error("cannot create the output pipe"))?;
    let mut child = spawn_in_group(&argv.program, &argv.args, &allowed_environment(&request.environment), writer)
        .map_err(io_error("cannot start the interpreter"))?;
    let cap = manifest.max_output_bytes;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(capture(reader, cap)));
    let waited = wait(&mut child, Duration::from_secs(manifest.timeout_seconds));
    let timed_out = !matches!(waited, Ok(Some(_)));
    let killed = if timed_out { kill_group(&child) } else { Ok(()) };
    let status = child.wait().map_err(io_error("cannot reap the script process"));
    let captured = collect(&receiver);
    waited.map_err(io_error("cannot wait for the script process"))?;
    killed?;
    let exit_code = status?.code();
    let output = captured?;
    Ok(Outcome {
        exit_code,
        timed_out,
        output: output.bytes,
        dropped_bytes: output.dropped,
    })
}


/// Checks the manifest, the parameters and the digest, writes the digested bytes to a private file and runs that file; `wait` is the clock.
pub fn run_script(request: &LaunchRequest, wait: WaitFn) -> Result<Outcome, ScriptError> {
    check_manifest(&request.manifest)?;
    validate_params(&request.manifest, &request.params)?;
    let bytes = check_digest(&request.manifest, request.script_bytes.clone())?;
    let root = std::path::absolute(&request.work_root).map_err(io_error("cannot resolve the work root"))?;
    let (_directory, script) = write_private_script(&root, private_file_name(request.manifest.interpreter), &bytes)?;
    run_child(request, &script, wait)
}


pub fn launch_script(request: &LaunchRequest) -> Result<Outcome, ScriptError> {
    run_script(request, wait_deadline)
}
