use crate::argv::argv_with_script;
use crate::cgroup::{create_cgroup, CgroupOps, SYSTEM_CGROUP};
use crate::check::{check_manifest, ensure};
use crate::digest::check_digest;
use crate::error::ScriptError;
use crate::fsdir::{create_private_directory, open_to_script_user, open_work_root, random_name, write_private_file_as};
use crate::model::{Captured, Interpreter, LaunchRequest, Manifest, Outcome, ParamKind, ParamValue, RunAs, READ_SLACK_COUNT, REDACTION_SLACK_BYTES};
use crate::params::validate_params;
use crate::path::is_under_prefixes;
use crate::pattern::compile_secret_patterns;
use crate::redact::redact_capped;
use crate::types::{Params, WaitFn};
use regex::bytes::Regex;
use rustix::io::Errno;
use rustix::process::{getegid, geteuid, getgroups, kill_process_group, Pid, Signal};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;
use tracing::debug;
use wait_timeout::ChildExt;


pub const ENV_ALLOWLIST: [&str; 3] = ["PATH", "LANG", "LC_ALL"];


pub const NEW_PROCESS_GROUP: i32 = 0;


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


/// Reads `cap` plus two slacks and redacts only what starts before the last slack (a secret is at most one slack long, so none is cut), then keeps `cap`.
pub fn capture<Source: Read>(mut source: Source, cap: u64, patterns: &[Regex]) -> io::Result<Captured> {
    let reading = cap.saturating_add(REDACTION_SLACK_BYTES.saturating_mul(READ_SLACK_COUNT));
    let mut raw = Vec::new();
    io::copy(&mut source.by_ref().take(reading), &mut raw)?;
    let beyond = io::copy(&mut source, &mut io::sink())?;
    let complete = u64::try_from(raw.len()).is_ok_and(|length| length < reading);
    let slack = usize::try_from(REDACTION_SLACK_BYTES).unwrap_or(usize::MAX);
    let boundary = if complete { raw.len() } else { raw.len().saturating_sub(slack) };
    let (bytes, consumed) = redact_capped(&raw, patterns, boundary, usize::try_from(cap).unwrap_or(usize::MAX));
    let unkept = u64::try_from(raw.len().saturating_sub(consumed)).unwrap_or(u64::MAX);
    Ok(Captured {
        bytes,
        dropped: beyond.saturating_add(unkept),
    })
}


/// Production wait: blocks up to `deadline`, `None` when the child is still running.
pub fn wait_deadline(child: &mut Child, deadline: Duration) -> io::Result<Option<std::process::ExitStatus>> {
    child.wait_timeout(deadline)
}


fn spawn_in_group(
    program: &str,
    args: &[String],
    environment: &[(String, String)],
    writer: io::PipeWriter,
    run_as: Option<&RunAs>,
) -> io::Result<Child> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (OsString::from(name), OsString::from(value))))
        .stdin(Stdio::piped())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .process_group(NEW_PROCESS_GROUP);
    if let Some(user) = run_as {
        command.gid(user.gid).uid(user.uid);
    }
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


fn run_child(
    request: &LaunchRequest,
    script: &Path,
    gate: &Path,
    cgroup: BorrowedFd<'_>,
    wait: WaitFn,
    ops: &CgroupOps,
) -> Result<Outcome, ScriptError> {
    let manifest = &request.manifest;
    let script_text = script.to_str().ok_or_else(|| ScriptError::MalformedPath(manifest.name.clone()))?;
    let params = resolve_paths(manifest, &request.params)?;
    let argv = argv_with_script(manifest, &params, script_text);
    let interpreter = resolve_interpreter(declared_paths(manifest.interpreter))?;
    let program = resolve_interpreter(SHELL_PATHS)?;
    let gated: Vec<String> = [gate.to_string_lossy().into_owned(), interpreter].into_iter().chain(argv.args).collect();
    let patterns = compile_secret_patterns(&manifest.secret_patterns)?;
    let (reader, writer) = io::pipe().map_err(io_error("cannot create the output pipe"))?;
    let mut child = spawn_in_group(
        &program,
        &gated,
        &allowed_environment(&request.environment),
        writer,
        request.run_as.as_ref(),
    )
    .map_err(io_error("cannot start the interpreter"))?;
    let placed = (ops.limit)(cgroup, &manifest.limits)
        .map_err(io_error("cannot apply the script limits"))
        .and_then(|()| (ops.place)(cgroup, child.id()).map_err(io_error("cannot place the script in its cgroup")))
        .and_then(|()| release_gate(&mut child).map_err(io_error("cannot release the script")));
    let cap = manifest.max_output_bytes;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(capture(reader, cap, &patterns)));
    let deadline = Duration::from_secs(manifest.timeout_seconds);
    let waited = match &placed {
        Ok(()) => wait(&mut child, deadline),
        Err(_) => Ok(None),
    };
    let timed_out = !matches!(waited, Ok(Some(_)));
    let group_killed = if timed_out { kill_group(&child) } else { Ok(()) };
    let cgroup_killed = (ops.kill)(cgroup).map_err(io_error("cannot kill the script cgroup"));
    let status = reap(&mut child, request.kill_grace, wait_deadline);
    let captured = collect(&receiver, request.kill_grace);
    let limit_hit = (ops.events)(cgroup).map_err(io_error("cannot read the cgroup events"));
    placed?;
    waited.map_err(io_error("cannot wait for the script process"))?;
    group_killed?;
    cgroup_killed?;
    let exit_code = status?.code();
    let output = captured?;
    let hit = limit_hit?;
    Ok(Outcome {
        exit_code,
        timed_out,
        output: output.bytes,
        dropped_bytes: output.dropped,
        limit_hit: hit,
    })
}


/// A dedicated uid and gid only: root and the agent's own uid and gid are refused (fail closed).
pub fn check_run_as(run_as: Option<&RunAs>, agent_uid: u32, agent_gid: u32, agent_groups: &[u32]) -> Result<(), ScriptError> {
    ensure(
        run_as
            .is_none_or(|user| user.uid != 0 && user.uid != agent_uid && user.gid != 0 && user.gid != agent_gid && !agent_groups.contains(&user.gid)),
        ScriptError::InvalidRunAs,
    )
}


/// Checks the manifest, the parameters, the digest and the work root, writes the digested bytes to a private file and runs it in its own cgroup.
pub fn run_script(request: &LaunchRequest, wait: WaitFn, ops: &CgroupOps) -> Result<Outcome, ScriptError> {
    check_manifest(&request.manifest)?;
    let groups: Vec<u32> = getgroups()?.iter().map(|group| group.as_raw()).collect();
    check_run_as(request.run_as.as_ref(), geteuid().as_raw(), getegid().as_raw(), &groups)?;
    validate_params(&request.manifest, &request.params)?;
    let bytes = check_digest(&request.manifest, request.script_bytes.clone())?;
    let root = open_work_root(&request.work_root, geteuid().as_raw())?;
    let directory = create_private_directory(&root, &mut random_name)?;
    let owner = request.run_as.as_ref();
    let script = write_private_file_as(&directory, private_file_name(request.manifest.interpreter), &bytes, owner)?;
    let gate = write_private_file_as(&directory, GATE_FILE, GATE_SCRIPT.as_bytes(), owner)?;
    owner.map_or(Ok(()), |_user| open_to_script_user(&directory))?;
    let name: String = directory.path.file_name().into_iter().map(|entry| entry.to_string_lossy()).collect();
    let cgroup = create_cgroup(&request.cgroup_root, &name, ops.check)?;
    run_child(request, &script, &gate, cgroup.leaf.as_fd(), wait, ops)
}


pub fn launch_script(request: &LaunchRequest) -> Result<Outcome, ScriptError> {
    run_script(request, wait_deadline, &SYSTEM_CGROUP)
}
