#![cfg(unix)]
#[path = "common/fake.rs"]
mod fake;
#[path = "common/types.rs"]
mod types;


use cloud_posture::error::{ParseError, ScanError};
use cloud_posture::limits::Limits;
use cloud_posture::model::{Cluster, KubeconfigFault};
use cloud_posture::run::{cluster_scan, open_output, scan_error_of, STDOUT_CAP_BYTES};
use fake::{install_script, scratch};
use net_topology::model::RunFailure;
use std::error::Error;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use types::TestResult;


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/prowler-k3s-ocsf.json");


const TENANT: &str = "lab";


const KUBE_BODY: &str = "apiVersion: v1\nTOKEN-IN-KUBECONFIG\n";


const PATIENT: Duration = Duration::from_secs(120);


const IMPATIENT: Duration = Duration::from_millis(300);


const NOBODY: &str = "65534";


const OTHER_USER_MODE: u32 = 0o604;


const OWNER_ONLY_MODE: u32 = 0o600;


const GROUP_READ_MODE: u32 = 0o640;


const DIRECTORY_LINE: usize = 8;


const KUBECONFIG_LINE: usize = 2;


const NAMED_VARIABLES: usize = 2;


const EXIT_THREE: i32 = 3;


const EXIT_TWO: i32 = 2;


const NINE_BYTES: u64 = 9;


const MARKER_REPEATS: usize = 20;


struct Setup {
    root: tempfile::TempDir,
    work: PathBuf,
    kubeconfig: PathBuf,
    cluster: Cluster,
}


fn setup(context: &str) -> Result<Setup, Box<dyn Error>> {
    let root = scratch()?;
    let work = root.path().join("work");
    std::fs::create_dir(&work)?;
    let kubeconfig = root.path().join("kubeconfig");
    std::fs::write(&kubeconfig, KUBE_BODY)?;
    std::fs::set_permissions(&kubeconfig, std::fs::Permissions::from_mode(OWNER_ONLY_MODE))?;
    let cluster = Cluster {
        name: "lab-cluster".to_owned(),
        kubeconfig_file: kubeconfig.clone(),
        context: context.to_owned(),
    };
    Ok(Setup {
        root,
        work,
        kubeconfig,
        cluster,
    })
}


fn find_directory(body: &str) -> String {
    format!("dir=\"\"; while [ $# -gt 0 ]; do case \"$1\" in --output-directory) dir=\"$2\";; esac; shift; done\n{body}")
}


fn scan(setup: &Setup, program: &Path, deadline: Duration) -> Result<cloud_posture::model::Findings, ScanError> {
    cluster_scan(program, TENANT, &setup.cluster, &setup.work, &Limits::default(), deadline)
}


fn work_is_empty(setup: &Setup) -> Result<bool, Box<dyn Error>> {
    Ok(std::fs::read_dir(&setup.work)?.next().is_none())
}


fn recording_prowler(setup: &Setup, record: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let copy = find_directory(&format!("cp {FIXTURE} \"$dir/posture.ocsf.json\""));
    let body = format!(
        "printf '%s\\n' \"$@\" > {record}\nprintenv | cut -d= -f1 | sort > {record}.env\nprintenv HOME > {record}.home\n\
         for arg in \"$@\"; do case \"$arg\" in /proc/*) cat \"$arg\" > {record}.kube;; esac; done\n{copy}",
        record = record.display()
    );
    install_script(setup.root.path(), "prowler", &body)
}


#[test]
fn a_good_run_passes_the_fixed_arguments_and_cleans_up() -> TestResult {
    let setup = setup("default")?;
    let record = setup.root.path().join("record");
    let program = recording_prowler(&setup, &record)?;
    let findings = scan(&setup, &program, PATIENT)?;
    assert!(!findings.items.is_empty());
    assert_eq!(findings.skipped.foreign_account, 0);
    assert_eq!(findings.account, "default");
    let arguments = std::fs::read_to_string(&record)?;
    let lines = arguments.lines().collect::<Vec<_>>();
    let directory = lines.get(DIRECTORY_LINE).ok_or("no directory")?;
    assert!(directory.starts_with(setup.work.to_str().ok_or("path")?));
    let kubeconfig = lines.get(KUBECONFIG_LINE).ok_or("no kubeconfig")?;
    assert!(kubeconfig.starts_with("/proc/"));
    assert_eq!(
        lines,
        vec![
            "kubernetes",
            "--kubeconfig-file",
            kubeconfig,
            "--context",
            "default",
            "--output-formats",
            "json-ocsf",
            "--output-directory",
            directory,
            "--output-filename",
            "posture",
            "--ignore-exit-code-3"
        ]
    );
    assert_eq!(std::fs::read_to_string(format!("{}.kube", record.display()))?, KUBE_BODY);
    assert_eq!(
        std::fs::read_to_string(format!("{}.env", record.display()))?
            .lines()
            .filter(|name| ["HOME", "PATH"].contains(name))
            .count(),
        NAMED_VARIABLES
    );
    let names = std::fs::read_to_string(format!("{}.env", record.display()))?;
    assert!(names.lines().all(|name| ["HOME", "PATH", "PWD", "SHLVL", "_", "OLDPWD"].contains(&name)));
    assert!(std::fs::read_to_string(format!("{}.home", record.display()))?
        .trim()
        .starts_with(setup.work.to_str().ok_or("path")?));
    assert!(work_is_empty(&setup)?);
    Ok(())
}


#[test]
fn findings_of_another_context_are_foreign() -> TestResult {
    let setup = setup("another")?;
    let program = recording_prowler(&setup, &setup.root.path().join("record"))?;
    let findings = scan(&setup, &program, PATIENT)?;
    assert!(findings.items.is_empty());
    assert!(findings.skipped.foreign_account > 0);
    Ok(())
}


#[test]
fn a_run_past_the_deadline_is_a_timeout_and_the_directory_is_gone() -> TestResult {
    let setup = setup("default")?;
    let program = install_script(setup.root.path(), "prowler", "sleep 60")?;
    assert!(matches!(scan(&setup, &program, IMPATIENT), Err(ScanError::Timeout)));
    assert!(work_is_empty(&setup)?);
    Ok(())
}


#[test]
fn no_output_file_is_no_output() -> TestResult {
    let setup = setup("default")?;
    let program = install_script(setup.root.path(), "prowler", "exit 0")?;
    assert!(matches!(scan(&setup, &program, PATIENT), Err(ScanError::NoOutput)));
    assert!(work_is_empty(&setup)?);
    Ok(())
}


#[test]
fn a_symlink_at_the_output_name_is_refused_and_its_target_not_read() -> TestResult {
    let setup = setup("default")?;
    let body = find_directory(&format!("ln -s {FIXTURE} \"$dir/posture.ocsf.json\""));
    let program = install_script(setup.root.path(), "prowler", &body)?;
    assert!(matches!(scan(&setup, &program, PATIENT), Err(ScanError::BadOutputFile)));
    assert!(work_is_empty(&setup)?);
    Ok(())
}


#[test]
fn a_fifo_at_the_output_name_is_refused() -> TestResult {
    let setup = setup("default")?;
    let body = find_directory("mkfifo \"$dir/posture.ocsf.json\"");
    let program = install_script(setup.root.path(), "prowler", &body)?;
    assert!(matches!(scan(&setup, &program, PATIENT), Err(ScanError::BadOutputFile)));
    Ok(())
}


#[test]
fn an_output_file_of_another_user_is_refused() -> TestResult {
    let setup = setup("default")?;
    let body = find_directory(&format!(
        "cp {FIXTURE} \"$dir/posture.ocsf.json\"\nchown {NOBODY} \"$dir/posture.ocsf.json\""
    ));
    let program = install_script(setup.root.path(), "prowler", &body)?;
    assert!(matches!(scan(&setup, &program, PATIENT), Err(ScanError::BadOutputFile)));
    Ok(())
}


#[test]
fn a_failing_prowler_leaks_nothing_it_printed() -> TestResult {
    let setup = setup("default")?;
    let program = install_script(setup.root.path(), "prowler", "echo token=SECRET-TOKEN >&2\necho SECRET-TOKEN\nexit 1")?;
    let error = scan(&setup, &program, PATIENT).err().ok_or("accepted")?;
    assert!(matches!(error, ScanError::Failed { code: Some(1) }));
    let text = format!("{error} {error:?}");
    assert!(!text.contains("SECRET-TOKEN"));
    assert!(!text.contains(setup.kubeconfig.to_str().ok_or("path")?));
    let exit_three = install_script(setup.root.path(), "prowler3", "exit 3")?;
    assert!(matches!(
        scan(&setup, &exit_three, PATIENT),
        Err(ScanError::Failed { code: Some(EXIT_THREE) })
    ));
    Ok(())
}


#[test]
fn a_flood_on_stdout_and_a_missing_program_are_typed() -> TestResult {
    let setup = setup("default")?;
    let flood = install_script(setup.root.path(), "flood", &format!("head -c {} /dev/zero", STDOUT_CAP_BYTES + 1))?;
    assert!(matches!(scan(&setup, &flood, PATIENT), Err(ScanError::Failed { code: None })));
    assert!(matches!(scan(&setup, &setup.root.path().join("absent"), PATIENT), Err(ScanError::Spawn)));
    Ok(())
}


#[test]
fn the_failure_mapping_is_total() -> TestResult {
    assert!(matches!(scan_error_of(RunFailure::TimedOut), ScanError::Timeout));
    assert!(matches!(scan_error_of(RunFailure::Spawn), ScanError::Spawn));
    assert!(matches!(
        scan_error_of(RunFailure::Failed {
            code: Some(EXIT_TWO),
            read: NINE_BYTES
        }),
        ScanError::Failed { code: Some(EXIT_TWO) }
    ));
    assert!(matches!(scan_error_of(RunFailure::Io), ScanError::Failed { code: None }));
    Ok(())
}


#[test]
fn a_bad_kubeconfig_is_refused_before_any_spawn() -> TestResult {
    let setup = setup("default")?;
    let counter = setup.root.path().join("runs");
    let program = install_script(setup.root.path(), "prowler", &format!("echo run >> {}", counter.display()))?;
    std::fs::set_permissions(&setup.kubeconfig, std::fs::Permissions::from_mode(GROUP_READ_MODE))?;
    let fault = |error: Option<ScanError>| match error {
        Some(ScanError::Kubeconfig { fault }) => Some(fault),
        _ => None,
    };
    assert_eq!(fault(scan(&setup, &program, PATIENT).err()), Some(KubeconfigFault::Mode));
    std::fs::set_permissions(&setup.kubeconfig, std::fs::Permissions::from_mode(OTHER_USER_MODE))?;
    let chown = Command::new("chown").arg(format!("{NOBODY}:{NOBODY}")).arg(&setup.kubeconfig).status()?;
    assert!(chown.success());
    assert_eq!(fault(scan(&setup, &program, PATIENT).err()), Some(KubeconfigFault::Owner));
    let link = setup.root.path().join("link");
    symlink(&setup.kubeconfig, &link)?;
    let linked = Cluster {
        kubeconfig_file: link,
        ..setup.cluster.clone()
    };
    let by_link = cluster_scan(&program, TENANT, &linked, &setup.work, &Limits::default(), PATIENT);
    assert_eq!(fault(by_link.err()), Some(KubeconfigFault::Symlink));
    let directory = Cluster {
        kubeconfig_file: setup.work.clone(),
        ..setup.cluster.clone()
    };
    let by_directory = cluster_scan(&program, TENANT, &directory, &setup.work, &Limits::default(), PATIENT);
    assert_eq!(fault(by_directory.err()), Some(KubeconfigFault::NotRegular));
    let absent = Cluster {
        kubeconfig_file: setup.root.path().join("absent"),
        ..setup.cluster.clone()
    };
    let by_absent = cluster_scan(&program, TENANT, &absent, &setup.work, &Limits::default(), PATIENT);
    assert_eq!(fault(by_absent.err()), Some(KubeconfigFault::Unreadable));
    assert!(!counter.exists());
    Ok(())
}


#[test]
fn a_missing_work_directory_is_a_typed_error() -> TestResult {
    let setup = setup("default")?;
    let program = install_script(setup.root.path(), "prowler", "exit 0")?;
    let result = cluster_scan(
        &program,
        TENANT,
        &setup.cluster,
        &setup.root.path().join("none"),
        &Limits::default(),
        PATIENT,
    );
    assert!(matches!(result, Err(ScanError::Workdir(_))));
    Ok(())
}


#[test]
fn a_hostile_document_fails_with_no_peer_text_in_the_error_chain() -> TestResult {
    let marker = "MARKER".repeat(MARKER_REPEATS);
    let bodies = [format!("{{\"a\":\"{marker}\"}}"), format!("[{marker}]"), format!("\"{marker}\"")];
    bodies.iter().try_for_each(|body| -> TestResult {
        let setup = setup("default")?;
        std::fs::write(setup.root.path().join("body.json"), body)?;
        let script = find_directory(&format!("cp {}/body.json \"$dir/posture.ocsf.json\"", setup.root.path().display()));
        let program = install_script(setup.root.path(), "prowler", &script)?;
        let error = scan(&setup, &program, PATIENT).err().ok_or("accepted")?;
        let chain = std::iter::successors(error.source(), |next| (*next).source())
            .fold(format!("{error} {error:?} {error:#?}"), |text, next| format!("{text} {next} {next:?}"));
        assert!(matches!(error, ScanError::Parse(ParseError::Malformed { .. })));
        assert!(!chain.contains("MARKER"));
        Ok(())
    })
}


#[test]
fn open_output_reports_each_state() -> TestResult {
    let setup = setup("default")?;
    assert!(matches!(open_output(&setup.work), Err(ScanError::NoOutput)));
    std::fs::write(setup.work.join("posture.ocsf.json"), "[]")?;
    assert!(open_output(&setup.work).is_ok());
    Ok(())
}
