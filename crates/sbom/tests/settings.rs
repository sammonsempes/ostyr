#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadOutcome};
use core_config::types::SharedAuditFn;
use sbom::error::{SettingsError, TargetError};
use sbom::settings::{open_settings, settings_state, source_argument, validate_settings, OpenError, SyftSettings, Target};
use std::fs;
use std::io;
use std::path::PathBuf;
use tempfile::TempDir;
use types::TestResult;


const MIN_HELPERS: usize = sbom::limits::HELPERS_PER_RUN;


const FIRST_DEADLINE: u64 = 1000;


const SECOND_DEADLINE: u64 = 2000;


const GOOD: &str =
    "binary: /usr/bin/syft\nwork_dir: /var/lib/sbom\ndeadline_millis: 1000\nmax_stdout_bytes: 100\nmax_components: 10\nmax_stderr_bytes: 10\nhelper_grace_millis: 100\nmax_live_helpers: 4\n";


fn audit() -> Box<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Box::new(move |entry| append(&log, entry))
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "sbom".to_owned(),
        tenant: "example".to_owned(),
        module: "sbom".to_owned(),
        target: "syft.yaml".to_owned(),
        request_id: "sbom-reload".to_owned(),
    }
}


fn valid() -> SyftSettings {
    SyftSettings {
        binary: PathBuf::from("/usr/bin/syft"),
        work_dir: PathBuf::from("/var/lib/sbom"),
        deadline_millis: 1,
        max_stdout_bytes: 1,
        max_components: 1,
        max_stderr_bytes: 1,
        helper_grace_millis: 1,
        max_live_helpers: MIN_HELPERS,
        max_memory_bytes: sbom::limits::MIN_MEMORY_BYTES,
        max_file_bytes: sbom::limits::MIN_FILE_BYTES,
        max_archive_bytes: sbom::limits::MIN_FILE_BYTES,
    }
}


#[test]
fn each_setting_is_validated() -> TestResult {
    assert!(validate_settings(&valid()).is_ok());
    let cases = [
        SyftSettings {
            binary: PathBuf::from("syft"),
            ..valid()
        },
        SyftSettings {
            work_dir: PathBuf::from("w"),
            ..valid()
        },
        SyftSettings {
            deadline_millis: 0,
            ..valid()
        },
        SyftSettings {
            max_stdout_bytes: 0,
            ..valid()
        },
        SyftSettings {
            max_components: 0,
            ..valid()
        },
        SyftSettings {
            max_stderr_bytes: 0,
            ..valid()
        },
        SyftSettings {
            helper_grace_millis: 0,
            ..valid()
        },
        SyftSettings {
            max_live_helpers: 1,
            ..valid()
        },
        SyftSettings {
            max_memory_bytes: sbom::limits::MIN_MEMORY_BYTES - 1,
            ..valid()
        },
        SyftSettings {
            max_file_bytes: sbom::limits::MAX_RESOURCE_BYTES + 1,
            ..valid()
        },
        SyftSettings {
            max_archive_bytes: 0,
            ..valid()
        },
    ];
    let names = [
        "binary",
        "work_dir",
        "deadline_millis",
        "max_stdout_bytes",
        "max_components",
        "max_stderr_bytes",
        "helper_grace_millis",
        "max_live_helpers",
        "max_memory_bytes",
        "max_file_bytes",
        "max_archive_bytes",
    ];
    cases.iter().zip(names).try_for_each(|(case, name)| match validate_settings(case) {
        Err(SettingsError::Invalid(found)) if found == name => Ok(()),
        other => Err(format!("{name}: {other:?}")),
    })?;
    Ok(())
}


#[test]
fn targets_become_typed_sources() -> TestResult {
    assert_eq!(source_argument(&Target::Directory(PathBuf::from("/srv/t")))?, "dir:/srv/t");
    assert_eq!(source_argument(&Target::OciArchive(PathBuf::from("/a.tar")))?, "oci-archive:/a.tar");
    assert_eq!(source_argument(&Target::DockerArchive(PathBuf::from("/a.tar")))?, "docker-archive:/a.tar");
    Ok(())
}


#[test]
fn hostile_targets_are_refused() -> TestResult {
    assert!(matches!(
        source_argument(&Target::Directory(PathBuf::from("rel"))),
        Err(TargetError::Relative)
    ));
    assert!(matches!(
        source_argument(&Target::Directory(PathBuf::from("-x"))),
        Err(TargetError::LeadingDash)
    ));
    assert!(matches!(
        source_argument(&Target::Directory(PathBuf::from("/a\u{7}"))),
        Err(TargetError::Control)
    ));
    assert!(matches!(source_argument(&Target::Directory(PathBuf::new())), Err(TargetError::Relative)));
    Ok(())
}


#[cfg(unix)]
#[test]
fn non_utf8_target_is_refused() -> TestResult {
    use std::os::unix::ffi::OsStrExt;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(b"/a\xff"));
    assert!(matches!(source_argument(&Target::Directory(path)), Err(TargetError::NotUtf8)));
    Ok(())
}


#[test]
fn settings_load_and_reload_live() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("syft.yaml");
    fs::write(&path, GOOD)?;
    let engine = open_settings(path.clone(), audit(), context())?;
    assert_eq!(current_config(&engine).deadline_millis, FIRST_DEADLINE);
    assert_eq!(settings_state(&current_config(&engine)).len(), 1);
    fs::write(&path, GOOD.replace("1000", "2000"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).deadline_millis, SECOND_DEADLINE);
    fs::write(&path, GOOD.replace("1000", "0"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).deadline_millis, SECOND_DEADLINE);
    Ok(())
}


const EXPLICIT_MEMORY: u64 = 134_217_728;


#[test]
fn resource_limits_default_and_can_be_set() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("syft.yaml");
    fs::write(&path, GOOD)?;
    let engine = open_settings(path.clone(), audit(), context())?;
    let defaults = current_config(&engine);
    assert_eq!(defaults.max_memory_bytes, sbom::limits::DEFAULT_MAX_MEMORY_BYTES);
    assert_eq!(defaults.max_file_bytes, sbom::limits::DEFAULT_MAX_FILE_BYTES);
    assert_eq!(defaults.max_archive_bytes, sbom::limits::DEFAULT_MAX_ARCHIVE_BYTES);
    let explicit = format!("{GOOD}max_memory_bytes: 134217728\nmax_file_bytes: 2097152\nmax_archive_bytes: 3145728\n");
    fs::write(&path, explicit)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).max_memory_bytes, EXPLICIT_MEMORY);
    Ok(())
}


#[test]
fn invalid_first_settings_do_not_open() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("syft.yaml");
    fs::write(&path, GOOD.replace("1000", "0"))?;
    assert!(matches!(open_settings(path.clone(), audit(), context()), Err(OpenError::Invalid(_))));
    fs::write(&path, "nonsense: true\n")?;
    assert!(matches!(open_settings(path, audit(), context()), Err(OpenError::Config(_))));
    Ok(())
}
