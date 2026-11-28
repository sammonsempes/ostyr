#![cfg(feature = "ebpf-live-test")]

use ebpf_probes::drain::{KernelDropped, MAX_DRAIN_PER_POLL};
use ebpf_probes::loader::{attach_probes, drain_exec, drain_probes, prepare_exec_probe_from_bytes, Probe, ProbeDrained};
use ebpf_probes::object::{read_object, EXEC_OBJECT_PATH};
use ebpf_probes::record::FileRecord;
use ebpf_probes::shape::{EXEC_PROBE, FILE_PROBE};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};


const O_WRONLY: u32 = 0o1;


const O_CREAT: u32 = 0o100;


const O_TRUNC: u32 = 0o1000;


const O_PATH: u32 = 0o10000000;


const STORM_OPENS: u32 = 3000;


const RACE_OPENS: usize = 800;


const DEEP_LEVELS: u32 = 7;


const SCRATCH: &str = "/tmp/t919b-live";


const TRUE_BINARY: &str = "/usr/bin/true";


const IA32_BINARY: &str = "/opt/t919/ia32_open";


const UNPRIVILEGED_ID: u32 = 1000;


const WRITES_EXPECTED: usize = 2;


const HELPER: &str = include_str!("live_helper.py");


struct Run {
    pid: u32,
    output: String,
}


fn probe() -> Result<Probe, Box<dyn Error>> {
    let bytes = read_object(Path::new(EXEC_OBJECT_PATH))?;
    let mut loaded = prepare_exec_probe_from_bytes(&bytes)?;
    attach_probes(&mut loaded)?;
    assert!(loaded.unavailable.is_empty(), "{:?}", loaded.unavailable);
    Ok(loaded)
}


fn file_records(loaded: &mut Probe) -> Result<Vec<FileRecord>, Box<dyn Error>> {
    let drains = drain_probes(loaded, MAX_DRAIN_PER_POLL);
    let names: Vec<&str> = drains.iter().map(|entry| entry.name).collect();
    assert_eq!(names, [EXEC_PROBE.name, FILE_PROBE.name]);
    let records = drains.into_iter().find_map(|entry| match entry.drained {
        ProbeDrained::File(drained) => Some(drained.records),
        ProbeDrained::Exec(_) => None,
    });
    Ok(records.ok_or("no file drain")?)
}


fn scratch(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let directory = Path::new(SCRATCH).join(name);
    if directory.exists() {
        std::fs::remove_dir_all(&directory)?;
    }
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}


fn run(command: &mut Command) -> Result<Run, Box<dyn Error>> {
    let child = command.stdout(Stdio::piped()).spawn()?;
    let pid = child.id();
    let output = child.wait_with_output()?;
    Ok(Run {
        pid,
        output: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}


fn helper_command(mode: &str, arguments: &[&str]) -> Command {
    let mut command = Command::new("python3");
    command.arg("-I").arg("-c").arg(HELPER).arg(mode).args(arguments);
    command
}


fn helper(mode: &str, arguments: &[&str]) -> Result<Run, Box<dyn Error>> {
    run(&mut helper_command(mode, arguments))
}


fn identity(run: &Run) -> Result<(u32, u64), Box<dyn Error>> {
    let line = run.output.lines().next().ok_or("helper printed nothing")?;
    let mut fields = line.split_whitespace();
    let device: u32 = fields.next().ok_or("no device")?.parse()?;
    let inode: u64 = fields.next().ok_or("no inode")?.parse()?;
    Ok((device, inode))
}


fn by_pid(records: &[FileRecord], pid: u32) -> Vec<&FileRecord> {
    records.iter().filter(|record| record.pid == pid).collect()
}


fn mount_namespace_of_self() -> Result<u32, Box<dyn Error>> {
    let link = std::fs::read_link("/proc/self/ns/mnt")?;
    let text = link.to_string_lossy().to_string();
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}


#[test]
fn touch_and_tee_make_two_write_records_and_a_cat_makes_none() -> Result<(), Box<dyn Error>> {
    let target = scratch("three-ops")?.join("f");
    let text = target.to_string_lossy().to_string();
    let mut loaded = probe()?;
    Command::new("touch").arg(&target).status()?;
    Command::new("tee").arg(&target).stdin(Stdio::null()).stdout(Stdio::null()).status()?;
    Command::new("cat").arg(&target).status()?;
    let ours: Vec<FileRecord> = file_records(&mut loaded)?.into_iter().filter(|record| record.path == text).collect();
    assert_eq!(ours.len(), WRITES_EXPECTED, "{ours:?}");
    assert!(ours.iter().all(|record| !record.too_long && !record.path_error && !record.unlinked));
    Ok(())
}


#[test]
fn a_read_only_open_never_reaches_the_ring() -> Result<(), Box<dyn Error>> {
    let mut loaded = probe()?;
    let run = helper("write", &["/etc/hostname", "0"])?;
    let records = file_records(&mut loaded)?;
    assert!(by_pid(&records, run.pid).is_empty(), "{records:?}");
    Ok(())
}


#[test]
fn open_creat_openat_and_openat2_are_each_recorded_with_the_real_path() -> Result<(), Box<dyn Error>> {
    let directory = scratch("entries")?;
    let mut loaded = probe()?;
    let run = helper("opens", &[&directory.to_string_lossy()])?;
    let records = file_records(&mut loaded)?;
    let paths: Vec<String> = by_pid(&records, run.pid).iter().map(|record| record.path.clone()).collect();
    let expected: Vec<String> = ["e-open", "e-creat", "e-openat", "e-openat2"]
        .iter()
        .map(|name| directory.join(name).to_string_lossy().to_string())
        .collect();
    assert_eq!(paths, expected);
    Ok(())
}


#[test]
fn a_32_bit_process_using_int_0x80_is_recorded() -> Result<(), Box<dyn Error>> {
    let directory = scratch("ia32")?;
    let mut loaded = probe()?;
    let names = ["a-openat", "b-open", "c-creat"].map(|name| directory.join(name).to_string_lossy().to_string());
    let run = run(Command::new(IA32_BINARY).args(&names))?;
    let records = file_records(&mut loaded)?;
    let paths: Vec<String> = by_pid(&records, run.pid).iter().map(|record| record.path.clone()).collect();
    assert_eq!(paths, names, "{records:?}");
    Ok(())
}


#[test]
fn an_io_uring_openat_is_recorded() -> Result<(), Box<dyn Error>> {
    let target = scratch("uring")?.join("u");
    let mut loaded = probe()?;
    let run = helper("uring", &[&target.to_string_lossy()])?;
    let records = file_records(&mut loaded)?;
    let paths: Vec<&str> = records
        .iter()
        .filter(|record| record.pid == run.pid)
        .map(|record| record.path.as_str())
        .collect();
    assert_eq!(paths, [target.to_string_lossy().as_ref()], "{records:?}");
    Ok(())
}


#[test]
fn a_second_process_rewriting_the_path_buffer_never_changes_what_a_record_names() -> Result<(), Box<dyn Error>> {
    let directory = scratch("race")?;
    let mut loaded = probe()?;
    let run = helper("race", &[&directory.to_string_lossy(), &RACE_OPENS.to_string()])?;
    let records = file_records(&mut loaded)?;
    let seen: Vec<&str> = run.output.lines().collect();
    let recorded: Vec<&str> = records
        .iter()
        .filter(|record| record.pid == run.pid)
        .map(|record| record.path.as_str())
        .collect();
    assert_eq!(seen.len(), RACE_OPENS);
    assert_eq!(recorded, seen);
    let flipped = seen.iter().filter(|path| path.ends_with("race-b")).count();
    assert!(
        flipped > 0 && flipped < RACE_OPENS,
        "the buffer never changed under the opener: {flipped}"
    );
    Ok(())
}


#[test]
fn an_untouched_file_backed_page_as_the_path_buffer_gives_the_real_path() -> Result<(), Box<dyn Error>> {
    let directory = scratch("filebacked")?;
    let mut loaded = probe()?;
    let run = helper("filebacked", &[&directory.to_string_lossy()])?;
    let records = file_records(&mut loaded)?;
    let mine = by_pid(&records, run.pid);
    let expected = directory.join("fb-target").to_string_lossy().to_string();
    assert!(mine.iter().any(|record| record.path == expected && !record.path_error), "{mine:?}");
    Ok(())
}


#[test]
fn a_path_over_256_bytes_is_flagged_with_an_empty_field_and_names_the_file_by_device_and_inode() -> Result<(), Box<dyn Error>> {
    let directory = scratch("deep")?;
    let mut loaded = probe()?;
    let run = helper("longname", &[&directory.to_string_lossy(), &DEEP_LEVELS.to_string()])?;
    let records = file_records(&mut loaded)?;
    let mine = by_pid(&records, run.pid);
    let leaf: Vec<&&FileRecord> = mine.iter().filter(|record| record.too_long).collect();
    assert_eq!(leaf.len(), 1, "{mine:?}");
    assert!(leaf.iter().all(|record| record.path.is_empty() && !record.path_error));
    let (device, inode) = identity(&run)?;
    assert!(
        leaf.iter().all(|record| record.inode == inode && record.device == device),
        "{leaf:?} {device} {inode}"
    );
    Ok(())
}


#[test]
fn o_tmpfile_is_flagged_unlinked_and_a_file_named_deleted_is_not() -> Result<(), Box<dyn Error>> {
    let directory = scratch("tmpfile")?;
    let mut loaded = probe()?;
    let run = helper("tmpfile", &[&directory.to_string_lossy()])?;
    let named = directory.join("x (deleted)");
    std::fs::write(&named, b"")?;
    let second = helper("write", &[&named.to_string_lossy(), &(O_WRONLY | O_CREAT).to_string()])?;
    let records = file_records(&mut loaded)?;
    let mine = by_pid(&records, run.pid);
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert!(mine.iter().all(|record| record.unlinked));
    let (device, inode) = identity(&run)?;
    let linked = std::fs::metadata(directory.join("linked"));
    assert!(linked.is_ok());
    assert!(mine.iter().all(|record| record.inode == inode && record.device == device));
    let other = by_pid(&records, second.pid);
    assert_eq!(other.len(), 1, "{other:?}");
    assert!(other
        .iter()
        .all(|record| !record.unlinked && record.path.ends_with("x (deleted)") && !record.too_long && !record.path_error));
    Ok(())
}


#[test]
fn write_intent_covers_truncate_and_create_and_leaves_read_and_path_opens_out() -> Result<(), Box<dyn Error>> {
    let directory = scratch("intent")?;
    let existing = directory.join("existing");
    std::fs::write(&existing, b"data")?;
    let fresh = directory.join("fresh");
    let path_only = directory.join("path-only");
    std::fs::write(&path_only, b"data")?;
    let mut loaded = probe()?;
    let truncate = helper("write", &[&existing.to_string_lossy(), &O_TRUNC.to_string()])?;
    let create_new = helper("write", &[&fresh.to_string_lossy(), &O_CREAT.to_string()])?;
    let create_old = helper("write", &[&existing.to_string_lossy(), &O_CREAT.to_string()])?;
    let path_flag = helper("write", &[&path_only.to_string_lossy(), &(O_PATH | O_WRONLY).to_string()])?;
    let records = file_records(&mut loaded)?;
    assert_eq!(by_pid(&records, truncate.pid).len(), 1, "{records:?}");
    assert_eq!(by_pid(&records, create_new.pid).len(), 1, "{records:?}");
    assert!(by_pid(&records, create_old.pid).is_empty(), "{records:?}");
    assert!(by_pid(&records, path_flag.pid).is_empty(), "{records:?}");
    Ok(())
}


#[test]
fn a_denied_open_is_not_recorded_and_the_next_allowed_open_is() -> Result<(), Box<dyn Error>> {
    let directory = scratch("denied")?;
    let denied = directory.join("denied");
    let allowed = directory.join("allowed");
    std::fs::write(&denied, b"")?;
    std::fs::write(&allowed, b"")?;
    let mut loaded = probe()?;
    let run = helper(
        "fanotify",
        &[&denied.to_string_lossy(), &allowed.to_string_lossy(), &directory.to_string_lossy()],
    )?;
    assert!(run.output.contains("refused"), "{}", run.output);
    let records = file_records(&mut loaded)?;
    let paths: Vec<&str> = records.iter().map(|record| record.path.as_str()).collect();
    let denied_text = denied.to_string_lossy().to_string();
    let allowed_text = allowed.to_string_lossy().to_string();
    assert!(!paths.contains(&denied_text.as_str()), "{paths:?}");
    assert!(paths.contains(&allowed_text.as_str()), "{paths:?}");
    Ok(())
}


const APPARMOR_DIRECTORY: &str = "/sys/kernel/security/apparmor";


const SELINUX_DIRECTORY: &str = "/sys/fs/selinux";


const DENY_SCRIPT: &str =
    "import sys\ntry:\n    open(sys.argv[1], 'w')\nexcept OSError as error:\n    print('refused', error.errno)\nopen(sys.argv[2], 'w')\n";


#[test]
fn an_lsm_denied_open_is_not_recorded_where_apparmor_runs_and_the_lsm_is_named_elsewhere() -> Result<(), Box<dyn Error>> {
    let directory = scratch("lsm")?;
    let denied = directory.join("denied");
    let allowed = directory.join("allowed");
    let profile = directory.join("profile");
    std::fs::write(
        &profile,
        format!(
            "profile t919deny {{\n  file,\n  capability,\n  deny {} w,\n}}\n",
            denied.to_string_lossy()
        ),
    )?;
    let apparmor = Path::new(APPARMOR_DIRECTORY).exists();
    assert!(
        apparmor || Path::new(SELINUX_DIRECTORY).exists(),
        "neither AppArmor nor SELinux is present"
    );
    if apparmor {
        assert!(Command::new("apparmor_parser").arg("-r").arg(&profile).status()?.success());
        let mut loaded = probe()?;
        let run = run(Command::new("aa-exec")
            .args(["-p", "t919deny", "--", "python3", "-I", "-c", DENY_SCRIPT])
            .arg(&denied)
            .arg(&allowed))?;
        let records = file_records(&mut loaded)?;
        Command::new("apparmor_parser").arg("-R").arg(&profile).status()?;
        assert!(run.output.contains("refused 13"), "{}", run.output);
        let denied_text = denied.to_string_lossy().to_string();
        let allowed_text = allowed.to_string_lossy().to_string();
        assert!(records.iter().all(|record| record.path != denied_text), "{records:?}");
        assert!(records.iter().any(|record| record.path == allowed_text), "{records:?}");
    }
    Ok(())
}


#[test]
fn a_chroot_names_the_file_in_the_openers_root_and_the_device_and_inode_name_the_real_file() -> Result<(), Box<dyn Error>> {
    let directory = scratch("chroot")?;
    let mut loaded = probe()?;
    let run = helper("chroot", &[&directory.to_string_lossy()])?;
    let records = file_records(&mut loaded)?;
    let mine = by_pid(&records, run.pid);
    let (device, inode) = identity(&run)?;
    assert!(
        mine.iter()
            .any(|record| record.path == "/inner" && record.inode == inode && record.device == device),
        "{mine:?}"
    );
    Ok(())
}


#[test]
fn a_bind_mount_and_an_open_tree_clone_keep_the_real_device_and_inode() -> Result<(), Box<dyn Error>> {
    let directory = scratch("bind")?;
    let source = directory.join("source");
    let bound = directory.join("bound");
    std::fs::create_dir_all(&source)?;
    std::fs::create_dir_all(&bound)?;
    assert!(Command::new("mount").arg("--bind").arg(&source).arg(&bound).status()?.success());
    let mut loaded = probe()?;
    let through_bind = helper("write", &[&bound.join("f").to_string_lossy(), &(O_WRONLY | O_CREAT).to_string()])?;
    let through_clone = helper("opentree", &[&source.to_string_lossy()])?;
    let records = file_records(&mut loaded)?;
    Command::new("umount").arg(&bound).status()?;
    let bind_identity = identity(&through_bind)?;
    let clone_identity = identity(&through_clone)?;
    let bind_records = by_pid(&records, through_bind.pid);
    let clone_records = by_pid(&records, through_clone.pid);
    assert!(
        bind_records
            .iter()
            .any(|record| (record.device, record.inode) == bind_identity && record.path == bound.join("f").to_string_lossy()),
        "{bind_records:?}"
    );
    assert!(
        clone_records.iter().any(|record| (record.device, record.inode) == clone_identity),
        "{clone_records:?}"
    );
    Ok(())
}


#[test]
fn a_process_in_a_user_namespace_reports_its_own_mount_namespace() -> Result<(), Box<dyn Error>> {
    let directory = scratch("userns")?;
    let target = directory.join("f");
    let mut loaded = probe()?;
    let mut command = Command::new("unshare");
    command.args(["-Urm", "touch"]).arg(&target);
    let run = run(&mut command)?;
    let own = helper("write", &[&directory.join("g").to_string_lossy(), &(O_WRONLY | O_CREAT).to_string()])?;
    let records = file_records(&mut loaded)?;
    let target_text = target.to_string_lossy().to_string();
    let inside: Vec<&FileRecord> = by_pid(&records, run.pid)
        .into_iter()
        .filter(|record| record.path == target_text)
        .collect();
    let outside = by_pid(&records, own.pid);
    assert_eq!(inside.len(), 1, "{inside:?}");
    assert_eq!(outside.len(), 1, "{outside:?}");
    assert!(inside
        .iter()
        .zip(outside.iter())
        .all(|(first, second)| first.mount_namespace != second.mount_namespace));
    assert_eq!(
        outside.iter().map(|record| record.mount_namespace).collect::<Vec<u32>>(),
        [mount_namespace_of_self()?]
    );
    Ok(())
}


#[test]
fn an_overlay_write_by_an_unprivileged_user_is_recorded_with_the_merged_path() -> Result<(), Box<dyn Error>> {
    let directory = scratch("overlay")?;
    ["lower", "upper", "work", "merged"]
        .iter()
        .try_for_each(|name| std::fs::create_dir_all(directory.join(name)))?;
    std::fs::write(directory.join("lower/f"), b"data")?;
    Command::new("chmod").arg("-R").arg("a+rwX").arg(&directory).status()?;
    let options = format!("lowerdir={0}/lower,upperdir={0}/upper,workdir={0}/work", directory.to_string_lossy());
    assert!(Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o"])
        .arg(&options)
        .arg(directory.join("merged"))
        .status()?
        .success());
    let mut loaded = probe()?;
    let merged = directory.join("merged/f").to_string_lossy().to_string();
    let uid_text = UNPRIVILEGED_ID.to_string();
    let run = run(Command::new("setpriv")
        .args(["--reuid", &uid_text, "--regid", &uid_text, "--clear-groups", "python3", "-I", "-c"])
        .arg(HELPER)
        .args(["write", &merged, "1"]))?;
    let records = file_records(&mut loaded)?;
    Command::new("umount").arg(directory.join("merged")).status()?;
    let mine = by_pid(&records, run.pid);
    assert!(
        mine.iter().any(|record| record.path == merged && record.uid == UNPRIVILEGED_ID),
        "{mine:?}"
    );
    let summary: Vec<(String, u32)> = records
        .iter()
        .filter(|record| record.path.contains("t919b-live/overlay"))
        .map(|record| (record.path.clone(), record.uid))
        .collect();
    assert!(summary.iter().all(|(_, uid)| *uid == 0 || *uid == UNPRIVILEGED_ID), "{summary:?}");
    Ok(())
}


#[test]
fn a_write_storm_leaves_a_kernel_drop_count_and_exec_records_keep_flowing() -> Result<(), Box<dyn Error>> {
    let target = scratch("storm")?.join("f");
    let mut loaded = probe()?;
    let mut storm = Command::new("python3");
    storm
        .arg("-I")
        .arg("-c")
        .arg("import os,sys\nfor _ in range(int(sys.argv[1])): os.close(os.open(sys.argv[2], 0o101))")
        .arg(STORM_OPENS.to_string())
        .arg(&target);
    storm.status()?;
    let child = Command::new(TRUE_BINARY)
        .spawn()
        .and_then(|mut process| process.wait().map(|_| process.id()))?;
    let exec = drain_exec(&mut loaded, MAX_DRAIN_PER_POLL);
    assert!(exec.records.iter().any(|record| record.pid == child), "no exec record for {child}");
    let drains = drain_probes(&mut loaded, MAX_DRAIN_PER_POLL);
    let found = drains.into_iter().find_map(|entry| match entry.drained {
        ProbeDrained::File(drained) => Some(drained),
        ProbeDrained::Exec(_) => None,
    });
    let file = found.ok_or("no file drain")?;
    assert!(
        matches!(file.report.kernel_dropped, KernelDropped::Counted(count) if count > 0),
        "{:?}",
        file.report
    );
    Ok(())
}
