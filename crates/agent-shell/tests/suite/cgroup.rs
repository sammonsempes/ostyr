use crate::cleanup::{linked_root, own_uid, pid_of, plan_for, trapping_child};
use crate::support::private_tempdir;
use crate::types::TestResult;
use agent_shell::cgroup::{
    cgroup_cleanup, clear_session, collect_names, component_ok, count_removal, create_session, hang_up, is_cgroup2_filesystem, is_populated,
    kill_members, kill_round, kill_session, member_groups, mkdir_refusal, open_agent_directory, open_directory_at, parse_populated,
    parse_self_cgroup, parse_tgid, production_host, read_capped, read_pids, read_tids, remove_session, session_cleanup, session_component,
    session_left, session_names, tgid_of, wait_unpopulated, write_kill, CgroupHost, CGROUP_ROOT, MAX_COMPONENT_BYTES, MAX_PROCS_FILE_BYTES,
    MAX_SESSION_CGROUPS,
};
use agent_shell::cleanup::{SweepPlan, MAX_SCANNED_PROCESSES, MAX_SWEEP_ROUNDS};
use agent_shell::error::CgroupError;
use rustix::io::Errno;
use rustix::process::Signal;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;


const KILL_POLLS: u64 = 2;


const KILL_ROUNDS: usize = 3;


const CAP: u64 = 3;


const BAD_BYTE: u8 = 0xff;


const GRACE_POLLS: u64 = 50;


const SETTLE_POLLS: u64 = 20;


const TWO: usize = 2;


const NEVER_TID: i32 = 4_000_001;


const GROUP_ID: i32 = 77;


const NEVER_PID: &str = "4000000\n";


const HOPPER_REPORTS: usize = 5;


const HOPPER: &str = "import os, signal, sys\n\
signal.signal(signal.SIGHUP, signal.SIG_IGN)\n\
os.write(1, b'ready\\n')\n\
sys.stdin.readline()\n\
for generation in range(3000):\n\
\x20\x20\x20\x20if os.fork(): os._exit(0)\n\
\x20\x20\x20\x20os.write(1, ('%d\\n' % os.getpid()).encode())\n\
os.write(1, b'done\\n')";


const ZOMBIE_HOPPER: &str = "import ctypes, os, signal, sys, threading, time\n\
signal.signal(signal.SIGHUP, signal.SIG_IGN)\n\
def hop():\n\
\x20\x20\x20\x20for generation in range(200):\n\
\x20\x20\x20\x20\x20\x20\x20\x20if os.fork(): os._exit(0)\n\
\x20\x20\x20\x20\x20\x20\x20\x20os.write(1, ('%d\\n' % os.getpid()).encode())\n\
\x20\x20\x20\x20os._exit(0)\n\
def live():\n\
\x20\x20\x20\x20sys.stdin.readline()\n\
\x20\x20\x20\x20while open('/proc/%d/status' % os.getpid()).read().split('State:')[1].split()[0] != 'Z': time.sleep(0.01)\n\
\x20\x20\x20\x20os.write(1, b'zombie\\n')\n\
\x20\x20\x20\x20for spawned in range(1000):\n\
\x20\x20\x20\x20\x20\x20\x20\x20if os.fork() == 0: hop()\n\
\x20\x20\x20\x20\x20\x20\x20\x20time.sleep(0.05)\n\
threading.Thread(target=live).start()\n\
os.write(1, b'ready\\n')\n\
ctypes.CDLL(None).pthread_exit(None)";


fn always_cgroup2(_directory: &OwnedFd) -> io::Result<bool> {
    Ok(true)
}


fn never_cgroup2(_directory: &OwnedFd) -> io::Result<bool> {
    Ok(false)
}


fn failing_check(_directory: &OwnedFd) -> io::Result<bool> {
    Err(io::Error::other("check failed"))
}


fn keep_session(_agent: &OwnedFd, _name: &str) -> io::Result<()> {
    Ok(())
}


fn remove_with_files(agent: &OwnedFd, name: &str) -> io::Result<()> {
    std::fs::remove_dir_all(format!("/proc/self/fd/{}/{name}", agent.as_raw_fd()))
}


fn no_pause(_interval: Duration) {}


pub fn host_in(directory: &Path) -> CgroupHost {
    CgroupHost {
        root: directory.join("root"),
        self_cgroup: directory.join("self"),
        grace_polls: 0,
        kill_polls: KILL_POLLS,
        kill_rounds: KILL_ROUNDS,
        is_cgroup2: always_cgroup2,
        remove: remove_with_files,
        pause: no_pause,
    }
}


fn tree_with_self(self_text: &str, with_kill: bool) -> Result<TempDir, Box<dyn std::error::Error>> {
    let directory = private_tempdir()?;
    std::fs::create_dir_all(directory.path().join("root/agent"))?;
    std::fs::write(directory.path().join("self"), self_text)?;
    if with_kill {
        std::fs::write(directory.path().join("root/agent/cgroup.kill"), "")?;
    }
    Ok(directory)
}


pub fn tree() -> Result<TempDir, Box<dyn std::error::Error>> {
    tree_with_self("0::/agent\n", true)
}


fn session_files(directory: &Path, name: &str, procs: &str, events: &str) -> TestResult {
    let session = directory.join("root/agent").join(name);
    std::fs::create_dir_all(&session)?;
    std::fs::write(session.join("cgroup.procs"), procs)?;
    std::fs::write(session.join("cgroup.threads"), procs)?;
    std::fs::write(session.join("cgroup.events"), events)?;
    std::fs::write(session.join("cgroup.kill"), "0")?;
    Ok(())
}


fn plan_in(directory: &Path) -> Result<SweepPlan, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(directory.join("proc"))?;
    Ok(plan_for(&directory.join("proc"), own_uid()?, 0, 1))
}


fn refused(text: &str) -> Option<String> {
    parse_self_cgroup(text).err().map(|error| format!("{error:?}"))
}


#[test]
fn the_own_cgroup_line_is_one_cgroup_v2_path_or_refused() -> TestResult {
    assert_eq!(
        parse_self_cgroup("0::/system.slice/ostyr-agent.service\n")?,
        "/system.slice/ostyr-agent.service"
    );
    assert_eq!(
        parse_self_cgroup("0::/system.slice/ostyr@1:a.service\n")?,
        "/system.slice/ostyr@1:a.service"
    );
    assert_eq!(parse_self_cgroup("0::/\n")?, "/");
    assert_eq!(refused("0::/agent"), Some("SelfCgroupShape".to_owned()));
    assert_eq!(refused("1:name=systemd:/a\n0::/agent\n"), Some("SelfCgroupShape".to_owned()));
    assert_eq!(refused("1:cpu:/agent\n"), Some("SelfCgroupShape".to_owned()));
    assert_eq!(refused("0::/agent\n\n"), Some("SelfCgroupShape".to_owned()));
    assert_eq!(refused(""), Some("SelfCgroupShape".to_owned()));
    [
        "0::/x (deleted)\n",
        "0::/a\\x2db.service\n",
        "0::/a/../b\n",
        "0::/a//b\n",
        "0::/a/\n",
        "0::a\n",
        "0::/./a\n",
        "0::\n",
        "0::/a b\n",
    ]
    .iter()
    .try_for_each(|text| {
        if refused(text) == Some("PathRefused".to_owned()) {
            Ok(())
        } else {
            Err(format!("accepted {text:?}"))
        }
    })?;
    assert!(component_ok(&"a".repeat(MAX_COMPONENT_BYTES)));
    assert!(!component_ok(&"a".repeat(MAX_COMPONENT_BYTES + 1)));
    assert!(!component_ok(""));
    assert!(!component_ok("."));
    assert!(!component_ok(".."));
    assert!(!component_ok("caf\u{e9}"));
    Ok(())
}


#[test]
fn a_capped_read_refuses_one_byte_over() -> TestResult {
    assert_eq!(read_capped(&mut &b"abc"[..], CAP)?, "abc");
    assert!(matches!(read_capped(&mut &b"abcd"[..], CAP), Err(CgroupError::TooLarge)));
    assert!(matches!(read_capped(&mut &[BAD_BYTE][..], CAP), Err(CgroupError::Io(_))));
    Ok(())
}


#[test]
fn the_agent_directory_is_opened_only_under_every_check() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (_agent, relative) = open_agent_directory(&host)?;
    assert_eq!(relative, "agent");
    let no_self = CgroupHost {
        self_cgroup: directory.path().join("absent"),
        ..host.clone()
    };
    assert!(matches!(open_agent_directory(&no_self), Err(CgroupError::Io(_))));
    let not_v2 = CgroupHost {
        is_cgroup2: never_cgroup2,
        ..host.clone()
    };
    assert!(matches!(open_agent_directory(&not_v2), Err(CgroupError::NotCgroup2)));
    let broken = CgroupHost {
        is_cgroup2: failing_check,
        ..host.clone()
    };
    assert!(matches!(open_agent_directory(&broken), Err(CgroupError::Io(_))));
    let no_root = CgroupHost {
        root: directory.path().join("absent"),
        ..host.clone()
    };
    assert!(matches!(open_agent_directory(&no_root), Err(CgroupError::Sys(_))));
    let no_agent = tree_with_self("0::/other\n", true)?;
    assert!(matches!(open_agent_directory(&host_in(no_agent.path())), Err(CgroupError::Sys(_))));
    let no_kill = tree_with_self("0::/agent\n", false)?;
    assert!(matches!(open_agent_directory(&host_in(no_kill.path())), Err(CgroupError::KillMissing(_))));
    let hybrid = tree_with_self("1:cpu:/x\n0::/agent\n", true)?;
    assert!(matches!(open_agent_directory(&host_in(hybrid.path())), Err(CgroupError::SelfCgroupShape)));
    let escape = tree_with_self("0::/agent/../agent\n", true)?;
    assert!(matches!(open_agent_directory(&host_in(escape.path())), Err(CgroupError::PathRefused)));
    let at_root = tree_with_self("0::/\n", false)?;
    std::fs::write(at_root.path().join("root/cgroup.kill"), "")?;
    let (_root, root_relative) = open_agent_directory(&host_in(at_root.path()))?;
    assert_eq!(root_relative, "");
    Ok(())
}


#[test]
fn the_cgroup_filesystem_check_refuses_a_plain_directory() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let plain = rustix::fs::open(
        &host.root,
        rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )?;
    assert!(!is_cgroup2_filesystem(&plain)?);
    let real_host = production_host();
    assert_eq!(real_host.root, Path::new(CGROUP_ROOT));
    assert_eq!((real_host.grace_polls, real_host.kill_polls), (GRACE_POLLS, SETTLE_POLLS));
    assert_eq!(real_host.kill_rounds, MAX_SWEEP_ROUNDS);
    Ok(())
}


#[test]
fn a_session_cgroup_is_made_once_and_never_for_a_bad_id() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let procs = create_session(&host, "session-1")?;
    assert_eq!(Path::new(&procs), directory.path().join("root/agent/shell-session-1/cgroup.procs"));
    assert!(directory.path().join("root/agent/shell-session-1").is_dir());
    assert!(matches!(create_session(&host, "session-1"), Err(CgroupError::Exists)));
    ["../x", "", "a/b", "-x", "a b"].iter().try_for_each(|id| {
        if matches!(session_component(id), Err(CgroupError::SessionId)) && matches!(create_session(&host, id), Err(CgroupError::SessionId)) {
            Ok(())
        } else {
            Err(format!("accepted {id:?}"))
        }
    })?;
    assert_eq!(session_component("a.b_c-1")?, "shell-a.b_c-1");
    assert!(matches!(mkdir_refusal(Errno::ACCESS), CgroupError::Sys(_)));
    assert!(matches!(mkdir_refusal(Errno::EXIST), CgroupError::Exists));
    let no_agent = tree_with_self("0::/other\n", true)?;
    assert!(create_session(&host_in(no_agent.path()), "s").is_err());
    Ok(())
}


#[test]
fn the_session_cgroups_are_the_shell_children_and_are_bounded() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    session_files(directory.path(), "shell-old", "", "populated 0\n")?;
    std::fs::create_dir(directory.path().join("root/agent/other"))?;
    let (agent, _relative) = open_agent_directory(&host)?;
    assert_eq!(session_names(&agent)?, vec!["shell-old".to_owned()]);
    (0..=MAX_SESSION_CGROUPS).try_for_each(|index| std::fs::create_dir_all(directory.path().join(format!("root/agent/shell-x{index}"))))?;
    assert!(matches!(session_names(&agent), Err(CgroupError::TooManySessions)));
    let failing = vec![Ok("shell-a".to_owned()), Err(Errno::IO)];
    assert!(matches!(collect_names(&mut failing.into_iter()), Err(CgroupError::Sys(_))));
    let file = rustix::fs::open(directory.path().join("self"), rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty())?;
    assert!(matches!(session_names(&file), Err(CgroupError::Sys(_))));
    Ok(())
}


#[test]
fn the_members_and_the_populated_flag_are_read_strictly() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    session_files(directory.path(), "shell-a", "11\n12\n", "populated 1\nfrozen 0\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    assert_eq!(read_pids(&session)?.len(), TWO);
    assert!(is_populated(&session)?);
    assert_eq!(session_left(&session, true)?, TWO);
    assert_eq!(session_left(&session, false)?, 0);
    let empty = directory.path().join("root/agent/shell-a");
    std::fs::write(empty.join("cgroup.procs"), "")?;
    assert_eq!(session_left(&session, true)?, TWO);
    std::fs::write(empty.join("cgroup.threads"), "")?;
    assert_eq!(session_left(&session, true)?, 1);
    std::fs::write(empty.join("cgroup.procs"), "11\n")?;
    assert_eq!(session_left(&session, true)?, 1);
    std::fs::write(empty.join("cgroup.procs"), "x\n")?;
    assert!(matches!(read_pids(&session), Err(CgroupError::Malformed)));
    std::fs::write(empty.join("cgroup.procs"), "0\n")?;
    assert!(matches!(read_pids(&session), Err(CgroupError::Malformed)));
    std::fs::write(empty.join("cgroup.procs"), "1\n".repeat(MAX_SCANNED_PROCESSES + 1))?;
    assert!(matches!(read_pids(&session), Err(CgroupError::TooManyProcesses)));
    std::fs::write(empty.join("cgroup.procs"), vec![b'1'; usize::try_from(MAX_PROCS_FILE_BYTES)? + 1])?;
    assert!(matches!(read_pids(&session), Err(CgroupError::TooLarge)));
    assert!(!parse_populated("populated 0\n")?);
    assert!(matches!(parse_populated("frozen 0\n"), Err(CgroupError::Malformed)));
    assert!(matches!(parse_populated("populated 2\n"), Err(CgroupError::Malformed)));
    Ok(())
}


#[test]
fn the_wait_ends_when_the_cgroup_empties_or_the_bound_is_hit() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    session_files(directory.path(), "shell-a", "", "populated 1\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    assert!(wait_unpopulated(&host, &session, KILL_POLLS)?);
    assert!(wait_unpopulated(&host, &session, 0)?);
    std::fs::write(directory.path().join("root/agent/shell-a/cgroup.events"), "populated 0\n")?;
    assert!(!wait_unpopulated(&host, &session, KILL_POLLS)?);
    Ok(())
}


#[test]
fn a_hangup_reaches_only_the_members_of_the_account() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let (child, mut reader) = trapping_child()?;
    let pid = pid_of(i32::try_from(child.id())?)?;
    session_files(directory.path(), "shell-a", &format!("{}\n", child.id()), "populated 1\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    let foreign = linked_root(&[child.id()])?;
    hang_up(&plan_for(foreign.path(), own_uid()? + 1, 0, 1), &session)?;
    hang_up(&plan_for(linked_root(&[child.id()])?.path(), own_uid()?, 0, 1), &session)?;
    let mut seen = String::new();
    reader.read_line(&mut seen)?;
    rustix::process::kill_process(pid, Signal::USR1)?;
    reader.read_to_string(&mut seen)?;
    assert_eq!(seen, "hup\nusr1\n");
    drop(child);
    Ok(())
}


#[test]
fn the_kill_file_gets_one_and_the_directory_is_removed() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    session_files(directory.path(), "shell-a", "", "populated 0\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    let plan = plan_in(directory.path())?;
    assert!(!kill_session(&host, &plan, &session)?);
    assert_eq!(std::fs::read_to_string(directory.path().join("root/agent/shell-a/cgroup.kill"))?, "1");
    let kept = CgroupHost {
        remove: keep_session,
        ..host.clone()
    };
    assert_eq!(clear_session(&kept, &plan, &agent, "shell-a")?, 0);
    assert!(directory.path().join("root/agent/shell-a").is_dir());
    assert_eq!(clear_session(&host, &plan, &agent, "shell-a")?, 0);
    assert!(!directory.path().join("root/agent/shell-a").exists());
    assert!(clear_session(&host, &plan, &agent, "shell-a").is_err());
    Ok(())
}


#[test]
fn a_cgroup_that_does_not_empty_or_cannot_be_removed_is_counted() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let plan = plan_in(directory.path())?;
    session_files(directory.path(), "shell-busy", NEVER_PID, "populated 1\n")?;
    let kept = CgroupHost {
        remove: keep_session,
        ..host.clone()
    };
    assert_eq!(clear_session(&kept, &plan, &agent, "shell-busy")?, 1);
    session_files(directory.path(), "shell-files", "", "populated 0\n")?;
    let real_remove = CgroupHost {
        remove: remove_session,
        ..host.clone()
    };
    assert_eq!(clear_session(&real_remove, &plan, &agent, "shell-files")?, 1);
    assert!(directory.path().join("root/agent/shell-files").is_dir());
    assert_eq!(count_removal(Ok(())), 0);
    assert_eq!(count_removal(Err(io::Error::other("busy"))), 1);
    Ok(())
}


#[test]
fn every_stale_session_cgroup_is_cleared_before_a_session() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let plan = plan_in(directory.path())?;
    session_files(directory.path(), "shell-one", "", "populated 0\n")?;
    session_files(directory.path(), "shell-two", "", "populated 0\n")?;
    session_files(directory.path(), "keep", "", "populated 0\n")?;
    assert_eq!(cgroup_cleanup(&host, &plan)?, 0);
    assert!(!directory.path().join("root/agent/shell-one").exists());
    assert!(!directory.path().join("root/agent/shell-two").exists());
    assert!(directory.path().join("root/agent/keep").exists());
    session_files(directory.path(), "shell-three", "", "populated 0\n")?;
    assert_eq!(session_cleanup(&host, &plan)?, 0);
    assert!(!directory.path().join("root/agent/shell-three").exists());
    let broken = CgroupHost {
        is_cgroup2: never_cgroup2,
        ..host.clone()
    };
    assert!(session_cleanup(&broken, &plan).is_err());
    let unreadable = CgroupHost {
        root: directory.path().join("absent"),
        ..host
    };
    assert!(cgroup_cleanup(&unreadable, &plan).is_err());
    Ok(())
}


#[test]
fn the_kill_runs_round_by_round_and_reports_a_cgroup_that_stays_populated() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let plan = plan_in(directory.path())?;
    session_files(directory.path(), "shell-busy", NEVER_PID, "populated 1\n")?;
    let busy = open_directory_at(&agent, "shell-busy")?;
    assert!(kill_round(&host, &plan, &busy)?);
    assert!(kill_session(&host, &plan, &busy)?);
    assert_eq!(std::fs::read_to_string(directory.path().join("root/agent/shell-busy/cgroup.kill"))?, "1");
    let no_rounds = CgroupHost {
        kill_rounds: 0,
        ..host.clone()
    };
    assert!(kill_session(&no_rounds, &plan, &busy)?);
    session_files(directory.path(), "shell-empty", "", "populated 0\n")?;
    let empty = open_directory_at(&agent, "shell-empty")?;
    assert!(!kill_session(&host, &plan, &empty)?);
    std::fs::remove_file(directory.path().join("root/agent/shell-empty/cgroup.kill"))?;
    assert!(write_kill(&empty).is_err());
    assert!(kill_round(&host, &plan, &empty).is_err());
    assert!(kill_session(&host, &plan, &empty).is_err());
    Ok(())
}


#[test]
fn the_pidfd_pass_kills_the_listed_members_of_the_account_only() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let (mut child, _reader) = trapping_child()?;
    session_files(directory.path(), "shell-a", &format!("{}\n", child.id()), "populated 1\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    let foreign = linked_root(&[child.id()])?;
    kill_members(&plan_for(foreign.path(), own_uid()? + 1, 0, 1), &session)?;
    assert!(child.try_wait()?.is_none());
    kill_members(&plan_for(linked_root(&[child.id()])?.path(), own_uid()?, 0, 1), &session)?;
    assert_eq!(child.wait()?.signal(), Some(Signal::KILL.as_raw()));
    std::fs::write(directory.path().join("root/agent/shell-a/cgroup.procs"), "x\n")?;
    assert!(matches!(kill_members(&plan_in(directory.path())?, &session), Err(CgroupError::Malformed)));
    Ok(())
}


pub struct TestCgroup {
    pub host: CgroupHost,
    pub plan: SweepPlan,
    pub parent: PathBuf,
    pub scratch: TempDir,
}


impl Drop for TestCgroup {
    fn drop(&mut self) {
        if let Err(error) = cgroup_cleanup(&self.host, &self.plan) {
            tracing::error!(?error, "test cgroup cleanup failed");
        }
        if let Err(error) = std::fs::remove_dir(&self.parent) {
            tracing::error!(?error, "test cgroup not removed");
        }
    }
}


fn test_cgroup() -> Result<TestCgroup, Box<dyn std::error::Error>> {
    let own = parse_self_cgroup(&std::fs::read_to_string("/proc/self/cgroup")?)?;
    let scratch = private_tempdir()?;
    let unique = scratch
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("scratch name")?
        .trim_start_matches('.')
        .to_owned();
    let relative = format!("{}/ostyr-test-{}-{unique}", own.trim_end_matches('/'), std::process::id());
    let parent = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/'));
    std::fs::create_dir(&parent)?;
    std::fs::write(scratch.path().join("self"), format!("0::{relative}\n"))?;
    let host = CgroupHost {
        self_cgroup: scratch.path().join("self"),
        grace_polls: 0,
        ..production_host()
    };
    Ok(TestCgroup {
        host,
        plan: plan_for(Path::new("/proc"), own_uid()?, 0, 1),
        parent,
        scratch,
    })
}


struct Hopper {
    child: Child,
    reader: BufReader<ChildStdout>,
    procs: String,
}


fn start_hopper(cgroup: &TestCgroup, program: &str) -> Result<Hopper, Box<dyn std::error::Error>> {
    let procs = create_session(&cgroup.host, "hopper-test")?;
    let mut child = Command::new("python3")
        .args(["-I", "-c", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("stdout")?);
    let mut ready = String::new();
    reader.read_line(&mut ready)?;
    assert_eq!(ready, "ready\n");
    std::fs::write(&procs, child.id().to_string())?;
    Ok(Hopper { child, reader, procs })
}


fn release_and_collect(hopper: &mut Hopper, skip_lines: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    hopper.child.stdin.take().ok_or("stdin")?.write_all(b"\n")?;
    let mut seen = Vec::new();
    (0..skip_lines + HOPPER_REPORTS).try_for_each(|_report| {
        let mut report = String::new();
        hopper.reader.read_line(&mut report).map(|_count| seen.push(report))
    })?;
    Ok(seen)
}


fn assert_everything_gone(cgroup: &TestCgroup, hopper: &mut Hopper, seen: &[String]) -> TestResult {
    assert_eq!(cgroup_cleanup(&cgroup.host, &cgroup.plan)?, 0);
    let mut rest = String::new();
    hopper.reader.read_to_string(&mut rest)?;
    hopper.child.wait()?;
    assert!(!Path::new(&hopper.procs).exists());
    rest.lines()
        .chain(seen.iter().map(String::as_str))
        .filter_map(|text| text.trim().parse::<u32>().ok())
        .try_for_each(|pid| {
            if Path::new(&format!("/proc/{pid}")).exists() {
                Err(format!("process {pid} survived"))
            } else {
                Ok(())
            }
        })?;
    Ok(())
}


#[test]
fn a_session_cgroup_kills_a_fork_hopper_that_ignores_the_hangup() -> TestResult {
    if rustix::process::getuid().is_root() {
        let cgroup = test_cgroup()?;
        let mut hopper = start_hopper(&cgroup, HOPPER)?;
        let seen = release_and_collect(&mut hopper, 0)?;
        assert_everything_gone(&cgroup, &mut hopper, &seen)?;
    }
    Ok(())
}


#[test]
fn a_session_cgroup_kills_a_zombie_led_group_whose_live_thread_forks_hoppers() -> TestResult {
    if rustix::process::getuid().is_root() {
        let cgroup = test_cgroup()?;
        let mut hopper = start_hopper(&cgroup, ZOMBIE_HOPPER)?;
        let seen = release_and_collect(&mut hopper, 1)?;
        assert_eq!(seen.first().map(String::as_str), Some("zombie\n"));
        assert_everything_gone(&cgroup, &mut hopper, &seen)?;
    }
    Ok(())
}


#[test]
fn two_test_cgroups_never_touch_each_other() -> TestResult {
    if rustix::process::getuid().is_root() {
        let first = test_cgroup()?;
        let second = test_cgroup()?;
        assert_ne!(first.parent, second.parent);
        create_session(&first.host, "hopper-test")?;
        assert!(create_session(&second.host, "hopper-test").is_ok());
        assert_eq!(cgroup_cleanup(&second.host, &second.plan)?, 0);
        assert!(first.parent.join("shell-hopper-test").is_dir());
        assert!(!second.parent.join("shell-hopper-test").exists());
        assert!(first.scratch.path().exists());
    }
    Ok(())
}


#[test]
fn a_thread_listed_alone_is_killed_through_its_group() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let (mut child, _reader) = trapping_child()?;
    session_files(directory.path(), "shell-a", "", "populated 1\n")?;
    std::fs::write(directory.path().join("root/agent/shell-a/cgroup.threads"), format!("{}\n", child.id()))?;
    let session = open_directory_at(&agent, "shell-a")?;
    let linked = linked_root(&[child.id()])?;
    let plan = plan_for(linked.path(), own_uid()?, 0, 1);
    assert_eq!(read_tids(&session)?.len(), 1);
    assert_eq!(member_groups(&plan, &session)?.len(), 1);
    kill_members(&plan, &session)?;
    assert_eq!(child.wait()?.signal(), Some(Signal::KILL.as_raw()));
    Ok(())
}


#[test]
fn a_group_listed_as_pid_and_as_thread_is_signalled_once() -> TestResult {
    let directory = tree()?;
    let host = host_in(directory.path());
    let (agent, _relative) = open_agent_directory(&host)?;
    let (mut child, _reader) = trapping_child()?;
    session_files(directory.path(), "shell-a", &format!("{}\n", child.id()), "populated 1\n")?;
    let session = open_directory_at(&agent, "shell-a")?;
    let linked = linked_root(&[child.id()])?;
    let plan = plan_for(linked.path(), own_uid()?, 0, 1);
    assert_eq!(member_groups(&plan, &session)?.len(), 1);
    std::fs::write(directory.path().join("root/agent/shell-a/cgroup.threads"), "x\n")?;
    assert!(matches!(member_groups(&plan, &session), Err(CgroupError::Malformed)));
    assert!(matches!(read_tids(&session), Err(CgroupError::Malformed)));
    let many = "1\n".repeat(MAX_SCANNED_PROCESSES + 1);
    std::fs::write(directory.path().join("root/agent/shell-a/cgroup.threads"), many)?;
    assert!(matches!(read_tids(&session), Err(CgroupError::TooManyProcesses)));
    std::fs::remove_file(directory.path().join("root/agent/shell-a/cgroup.threads"))?;
    assert!(read_tids(&session).is_err());
    child.kill()?;
    child.wait()?;
    Ok(())
}


#[test]
fn a_thread_status_is_read_for_its_group_and_a_bad_one_is_skipped() -> TestResult {
    let directory = tree()?;
    let plan = plan_in(directory.path())?;
    let tid = pid_of(NEVER_TID)?;
    assert_eq!(tgid_of(&plan, tid), None);
    let status = directory.path().join("proc").join(NEVER_TID.to_string());
    std::fs::create_dir_all(&status)?;
    std::fs::write(status.join("status"), format!("Name:\tx\nTgid:\t{GROUP_ID}\nPid:\t1\n"))?;
    assert_eq!(tgid_of(&plan, tid), Some(pid_of(GROUP_ID)?));
    std::fs::write(status.join("status"), "Name:\tx\n")?;
    assert_eq!(tgid_of(&plan, tid), None);
    std::fs::write(status.join("status"), "")?;
    assert_eq!(tgid_of(&plan, tid), None);
    std::fs::remove_file(status.join("status"))?;
    std::fs::create_dir(status.join("status"))?;
    assert_eq!(tgid_of(&plan, tid), None);
    assert_eq!(parse_tgid("Tgid:\t0\n"), None);
    assert_eq!(parse_tgid("Tgid:\tx\n"), None);
    Ok(())
}


#[test]
fn a_host_prints_its_settings_for_the_logs() -> TestResult {
    let directory = tree()?;
    assert!(format!("{:?}", host_in(directory.path())).contains("kill_rounds"));
    Ok(())
}
