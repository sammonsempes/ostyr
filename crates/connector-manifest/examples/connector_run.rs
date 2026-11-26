#[cfg(target_os = "linux")]
mod linux {
    use connector_manifest::cli::epoch_seconds;
    use connector_manifest::keys::load_trusted_keys;
    use connector_manifest::kill::system_kill_host;
    use connector_manifest::run::{run_connector, spawn_piped, LaunchPlan, Programs, RunHost, RunSpec, PRLIMIT_PATH, PYTHON_PATH, SHELL_PATH};
    use connector_manifest::verify::verify_package;
    use script_library::cgroup::SYSTEM_CGROUP;
    use script_library::fsdir::random_name;
    use script_library::model::{Limits, RunAs};
    use serde_json::value::RawValue;
    use std::io::{stderr, stdout, Write};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};


    const STDERR_BROKEN: u8 = 2;


    const USAGE: &str = "connector_run <package> <keys.yaml> <code-root> <cgroup-root> <action> <params-json> <uid> <gid> <deadline-seconds>";


    fn launcher(plan: &LaunchPlan) -> Command {
        let mut command = Command::new(plan.argv.first().map_or("false", |program| program.to_str().unwrap_or("false")));
        command.args(plan.argv.iter().skip(1)).uid(plan.run_as.uid).gid(plan.run_as.gid);
        command
    }


    fn runner(words: &[String]) -> Result<String, Box<dyn std::error::Error>> {
        match words {
            [package, keys, code_root, cgroup_root, action, params, uid, gid, deadline] => {
                run_with(package, keys, code_root, cgroup_root, action, params, (uid, gid, deadline))
            }
            _ => Err(USAGE.into()),
        }
    }


    fn run_with(
        package: &str,
        keys: &str,
        code_root: &str,
        cgroup_root: &str,
        action: &str,
        params: &str,
        (uid, gid, deadline): (&str, &str, &str),
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = epoch_seconds(SystemTime::now().duration_since(UNIX_EPOCH))?;
        let verified = verify_package(Path::new(package), &load_trusted_keys(Path::new(keys))?, now)?;
        let value = RawValue::from_string(params.to_owned())?;
        let host = RunHost {
            launch: launcher,
            spawn: spawn_piped,
            kill: system_kill_host(),
            cgroup: SYSTEM_CGROUP,
            namer: random_name,
            programs: Programs {
                shell: PathBuf::from(SHELL_PATH),
                prlimit: PathBuf::from(PRLIMIT_PATH),
                python: PathBuf::from(PYTHON_PATH),
            },
            runner_uid: rustix::process::geteuid().as_raw(),
        };
        let spec = RunSpec {
            verified: &verified,
            package: Path::new(package),
            code_root: Path::new(code_root),
            cgroup_root: Path::new(cgroup_root),
            run_as: RunAs {
                uid: uid.parse()?,
                gid: gid.parse()?,
            },
            limits: Limits::default(),
            deadline: Duration::from_secs(deadline.parse()?),
            action,
            params: &value,
        };
        Ok(format!("{:?}", run_connector(&spec, &host)?))
    }


    pub fn run_example() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        match runner(&args) {
            Ok(line) => match writeln!(stdout(), "{line}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(STDERR_BROKEN),
            },
            Err(error) => match writeln!(stderr(), "{error}") {
                Ok(()) => ExitCode::FAILURE,
                Err(_) => ExitCode::from(STDERR_BROKEN),
            },
        }
    }
}


#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::run_example()
}


#[cfg(not(target_os = "linux"))]
fn main() {}
